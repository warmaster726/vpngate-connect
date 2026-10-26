use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cache::{
    ActiveSessionState, AppPaths, Ikev1StateInfo, MONITOR_INTERVAL_SECONDS, PublicIpTrace,
    atomic_write_json, fix_owner, get_public_ip_trace, get_servers_cached, load_cooldowns,
    load_watchdog_pref, now_unix_secs, read_json_opt, save_cooldowns,
};
use crate::ikev1::{probe_tcp, verify_l2tp_psk_vpn};
use crate::ikev1_daemon::VPNGATE_XFRM_REQID;
use crate::profile::{OvpnPatchOptions, build_patched_ovpn};
use crate::protocol::{
    OpenVpnCompat, ProtocolFilter, SortBy, TargetPlatform, VpnProtocol, WindowsOvpnDriver,
};
use crate::server::{VpnServer, filter_by_country, filter_by_protocol, sort_servers};

pub const NM_PROFILE_PREFIX: &str = "vpngate-";
pub const WIN_VPN_PROFILE_NAME: &str = "VPNGate-L2TP";
const NFT_COMMENT_TAG: &str = "vpngate-l2tp";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub gw: String,
    pub dev: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinnedRouteRecord {
    pub server_ip: String,
    pub gw: String,
    pub dev: String,
}

pub fn which_bin(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    for dir in env::split_paths(&path_var) {
        for ext in exts {
            let cand = dir.join(format!("{name}{ext}"));
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

pub fn is_root_or_admin() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        Command::new("net")
            .args(["session"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

pub fn detect_host_os_label() -> String {
    if cfg!(target_os = "windows") {
        "Windows 11".to_string()
    } else if cfg!(target_os = "macos") {
        "macOS".to_string()
    } else {
        if let Ok(os_rel) = fs::read_to_string("/etc/os-release") {
            for ln in os_rel.lines() {
                if let Some(val) = ln.strip_prefix("PRETTY_NAME=") {
                    return val.trim_matches('"').to_string();
                }
            }
        }
        "Linux".to_string()
    }
}

pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: signal 0 checks process existence without sending a signal.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

pub fn pid_matches_cmdline(pid: u32, needle: &str) -> bool {
    if !is_pid_alive(pid) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) {
            let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
            return text.contains(&needle.to_ascii_lowercase());
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = needle;
        true
    }
}

pub fn terminate_pid(pid: u32, force: bool) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    #[cfg(unix)]
    {
        let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
        // SAFETY: sending SIGTERM/SIGKILL to verified PID.
        unsafe {
            let _ = libc::kill(pid as libc::pid_t, sig);
        }
    }
    #[cfg(windows)]
    {
        let mut args = vec!["/PID".to_string(), pid.to_string()];
        if force {
            args.insert(0, "/F".to_string());
        }
        let _ = Command::new("taskkill")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub fn get_running_monitor_pid(paths: &AppPaths) -> u32 {
    let Ok(txt) = fs::read_to_string(&paths.monitor_pid) else {
        return 0;
    };
    let Ok(pid) = txt.trim().parse::<u32>() else {
        return 0;
    };
    if pid != std::process::id() && pid_matches_cmdline(pid, "_monitor") {
        pid
    } else {
        0
    }
}

pub fn stop_monitor_daemon(paths: &AppPaths) {
    let pid = get_running_monitor_pid(paths);
    if pid > 0 {
        terminate_pid(pid, false);
        for _ in 0..15 {
            if !is_pid_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        if is_pid_alive(pid) {
            terminate_pid(pid, true);
        }
    }
    let _ = fs::remove_file(&paths.monitor_pid);
}

pub fn get_default_gateway() -> GatewayInfo {
    if cfg!(target_os = "linux") {
        if let Ok(out) = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let dev = parts
                    .windows(2)
                    .find(|w| w[0] == "dev")
                    .map(|w| w[1])
                    .unwrap_or("");
                if dev.is_empty() || dev.starts_with("tun") || dev.starts_with("ppp") {
                    continue;
                }
                let gw = parts
                    .windows(2)
                    .find(|w| w[0] == "via")
                    .map(|w| w[1])
                    .unwrap_or("");
                return GatewayInfo {
                    gw: gw.to_string(),
                    dev: dev.to_string(),
                };
            }
        }
    } else if cfg!(target_os = "macos") {
        if let Ok(out) = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
        {
            let mut gw = String::new();
            let mut dev = String::new();
            for ln in String::from_utf8_lossy(&out.stdout).lines() {
                let t = ln.trim();
                if let Some(v) = t.strip_prefix("gateway:") {
                    gw = v.trim().to_string();
                } else if let Some(v) = t.strip_prefix("interface:") {
                    dev = v.trim().to_string();
                }
            }
            if !dev.starts_with("utun") && !dev.starts_with("ppp") {
                return GatewayInfo { gw, dev };
            }
        }
    } else if cfg!(target_os = "windows")
        && let Ok(out) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop",
            ])
            .output()
    {
        let gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !gw.is_empty() && gw != "0.0.0.0" {
            return GatewayInfo {
                gw,
                dev: "Ethernet/Wi-Fi".to_string(),
            };
        }
    }
    GatewayInfo::default()
}

fn query_linux_ifaces(prefixes: &[&str]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if cfg!(target_os = "linux")
        && let Ok(out) = Command::new("ip")
            .args(["-4", "-o", "addr", "show"])
            .output()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let dev = parts[1];
                if prefixes.iter().any(|p| dev.starts_with(p))
                    && let Some(ip_part) = parts
                        .windows(2)
                        .find(|w| w[0] == "inet")
                        .map(|w| w[1].split('/').next().unwrap_or(""))
                    && !ip_part.is_empty()
                {
                    map.insert(dev.to_string(), ip_part.to_string());
                }
            }
        }
    }
    map
}

pub fn get_ppp_interfaces() -> BTreeMap<String, String> {
    if cfg!(target_os = "windows") {
        let mut map = BTreeMap::new();
        if let Ok(out) = Command::new("rasdial").output() {
            let txt = String::from_utf8_lossy(&out.stdout);
            if txt.contains(WIN_VPN_PROFILE_NAME) {
                map.insert(WIN_VPN_PROFILE_NAME.to_string(), "connected".to_string());
            }
        }
        return map;
    }
    query_linux_ifaces(&["ppp"])
}

pub fn get_tun_interfaces() -> BTreeMap<String, String> {
    if cfg!(target_os = "macos") {
        let mut map = BTreeMap::new();
        if let Ok(out) = Command::new("ifconfig").output() {
            let mut cur_if = String::new();
            for ln in String::from_utf8_lossy(&out.stdout).lines() {
                if !ln.starts_with('\t')
                    && !ln.starts_with(' ')
                    && let Some((name, _)) = ln.split_once(':')
                {
                    cur_if = name.to_string();
                } else if cur_if.starts_with("utun")
                    && let Some(rest) = ln.trim().strip_prefix("inet ")
                    && let Some(ip) = rest.split_whitespace().next()
                {
                    map.insert(cur_if.clone(), ip.to_string());
                }
            }
        }
        return map;
    }
    query_linux_ifaces(&["tun", "tap"])
}

pub fn prune_stale_state_if_dead(paths: &AppPaths) {
    if !paths.active_state.exists() || get_running_monitor_pid(paths) > 0 {
        return;
    }
    if let Some(st) = read_json_opt::<ActiveSessionState>(&paths.active_state)
        && st.status == "reconnecting"
    {
        return;
    }
    if !get_ppp_interfaces().is_empty() || !get_tun_interfaces().is_empty() {
        return;
    }
    if which_bin("nmcli").is_some()
        && let Ok(out) = Command::new("nmcli")
            .args(["-t", "-f", "NAME", "connection", "show", "--active"])
            .output()
        && String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l.trim().starts_with(NM_PROFILE_PREFIX))
    {
        return;
    }
    let _ = fs::remove_file(&paths.active_state);
}

pub fn find_openvpn_bin() -> Option<PathBuf> {
    if let Some(p) = which_bin("openvpn") {
        return Some(p);
    }
    if cfg!(target_os = "windows") {
        for cand in [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
        ] {
            let p = PathBuf::from(cand);
            if p.is_file() {
                return Some(p);
            }
        }
    } else {
        for cand in [
            "/usr/sbin/openvpn",
            "/sbin/openvpn",
            "/opt/homebrew/sbin/openvpn",
            "/usr/local/sbin/openvpn",
        ] {
            let p = PathBuf::from(cand);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

pub fn detect_openvpn_compat(ovpn_bin: &Path) -> OpenVpnCompat {
    let Ok(out) = Command::new(ovpn_bin).arg("--version").output() else {
        return OpenVpnCompat::OpenVpn26;
    };
    let line = String::from_utf8_lossy(&out.stdout);
    let first = line.lines().next().unwrap_or("");
    for tok in first.split_whitespace() {
        let nums: Vec<u32> = tok.split('.').filter_map(|p| p.parse().ok()).collect();
        if nums.len() >= 2 && nums[0] == 2 {
            return if nums[1] >= 6 {
                OpenVpnCompat::OpenVpn26
            } else if nums[1] == 5 {
                OpenVpnCompat::OpenVpn25
            } else {
                OpenVpnCompat::OpenVpn24
            };
        }
    }
    OpenVpnCompat::OpenVpn26
}

fn manage_linux_l2tp_firewall(enable: bool) {
    if !cfg!(target_os = "linux") || !is_root_or_admin() {
        return;
    }

    // Prefer native nftables first (preserves pure single-backend nftables on Kali Linux!)
    if which_bin("nft").is_some()
        && let Ok(out) = Command::new("nft")
            .args(["-a", "list", "chain", "inet", "filter", "input"])
            .output()
        && out.status.success()
    {
        let chain_txt = String::from_utf8_lossy(&out.stdout);
        // Remove any prior tagged rules cleanly by handle
        for ln in chain_txt.lines() {
            if ln.contains(NFT_COMMENT_TAG)
                && let Some((_, handle_str)) = ln.rsplit_once("# handle ")
                && let Ok(h) = handle_str.trim().parse::<u64>()
            {
                let _ = Command::new("nft")
                    .args([
                        "delete",
                        "rule",
                        "inet",
                        "filter",
                        "input",
                        "handle",
                        &h.to_string(),
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        if enable {
            for rule_expr in [
                r#"iifname "ppp*" accept comment "vpngate-l2tp""#,
                r#"iifname "tun*" accept comment "vpngate-l2tp""#,
                r#"meta secpath exists accept comment "vpngate-l2tp""#,
            ] {
                let mut args = vec!["insert", "rule", "inet", "filter", "input"];
                args.extend(rule_expr.split_whitespace());
                let _ = Command::new("nft")
                    .args(&args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        return;
    }

    // Fallback to iptables only on distros without an active `inet filter` nftables table
    if which_bin("iptables").is_some() {
        let specs: &[(&str, &[&str])] = &[
            (
                "INPUT",
                &[
                    "-m",
                    "policy",
                    "--dir",
                    "in",
                    "--pol",
                    "ipsec",
                    "-m",
                    "comment",
                    "--comment",
                    NFT_COMMENT_TAG,
                    "-j",
                    "ACCEPT",
                ],
            ),
            (
                "INPUT",
                &[
                    "-i",
                    "ppp+",
                    "-m",
                    "comment",
                    "--comment",
                    NFT_COMMENT_TAG,
                    "-j",
                    "ACCEPT",
                ],
            ),
        ];
        for (chain, spec) in specs {
            if enable {
                let mut chk = vec!["-C", *chain];
                chk.extend_from_slice(spec);
                if Command::new("iptables")
                    .args(&chk)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| !s.success())
                    .unwrap_or(true)
                {
                    let mut ins = vec!["-I", *chain, "1"];
                    ins.extend_from_slice(spec);
                    let _ = Command::new("iptables")
                        .args(&ins)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            } else {
                let mut del = vec!["-D", *chain];
                del.extend_from_slice(spec);
                while Command::new("iptables")
                    .args(&del)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
                {}
            }
        }
    }
}

fn snapshot_and_apply_linux_sysctls(paths: &AppPaths, l2tp_mode: bool) {
    if !cfg!(target_os = "linux") || !is_root_or_admin() {
        return;
    }
    let mut keys = vec![
        ("net.ipv6.conf.all.disable_ipv6", "1"),
        ("net.ipv6.conf.default.disable_ipv6", "1"),
    ];
    if l2tp_mode {
        keys.push(("net.ipv4.conf.all.rp_filter", "2"));
        keys.push(("net.ipv4.conf.default.rp_filter", "2"));
    }

    let mut snap: BTreeMap<String, String> =
        read_json_opt(&paths.sysctl_backup).unwrap_or_default();
    for (k, val) in keys {
        let proc_p = PathBuf::from("/proc/sys").join(k.replace('.', "/"));
        if !snap.contains_key(k)
            && let Ok(cur) = fs::read_to_string(&proc_p)
        {
            snap.insert(k.to_string(), cur.trim().to_string());
        }
        let _ = fs::write(&proc_p, format!("{val}\n"));
    }
    let _ = atomic_write_json(&paths.sysctl_backup, &snap);
}

fn restore_linux_sysctls(paths: &AppPaths) {
    if !cfg!(target_os = "linux") || !is_root_or_admin() || !paths.sysctl_backup.exists() {
        return;
    }
    if let Some(snap) = read_json_opt::<BTreeMap<String, String>>(&paths.sysctl_backup) {
        for (k, v) in snap {
            let proc_p = PathBuf::from("/proc/sys").join(k.replace('.', "/"));
            let _ = fs::write(&proc_p, format!("{v}\n"));
        }
    }
    let _ = fs::remove_file(&paths.sysctl_backup);
}

fn stop_ikev1_daemon_and_xfrm(paths: &AppPaths) {
    if let Ok(txt) = fs::read_to_string(&paths.ikev1_pid)
        && let Ok(pid) = txt.trim().parse::<u32>()
        && pid_matches_cmdline(pid, "_ikev1")
    {
        terminate_pid(pid, false);
        for _ in 0..16 {
            if !is_pid_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if is_pid_alive(pid) {
            terminate_pid(pid, true);
        }
    }
    let _ = fs::remove_file(&paths.ikev1_pid);

    if cfg!(target_os = "linux") && is_root_or_admin() && which_bin("ip").is_some() {
        let _ = Command::new("ip")
            .args(["xfrm", "policy", "deleteall", "priority", "1701"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("ip")
            .args(["xfrm", "state", "deleteall", "reqid", VPNGATE_XFRM_REQID])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = fs::remove_file(&paths.ikev1_state);
}

/// Tears down any active or partial VPN session and restores routes, DNS, firewall, and sysctls.
pub fn cleanup_existing_vpn(paths: &AppPaths, full_teardown: bool, stop_monitor: bool) {
    let _ = paths.ensure_dirs();
    if stop_monitor {
        stop_monitor_daemon(paths);
    }
    let _ = fs::remove_file(&paths.active_state);

    if cfg!(target_os = "windows") {
        if let Ok(txt) = fs::read_to_string(&paths.ovpn_pid)
            && let Ok(pid) = txt.trim().parse::<u32>()
        {
            terminate_pid(pid, true);
        }
        let _ = fs::remove_file(&paths.ovpn_pid);
        let _ = Command::new("rasdial")
            .args([WIN_VPN_PROFILE_NAME, "/DISCONNECT"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Some(rt) = read_json_opt::<PinnedRouteRecord>(&paths.l2tp_route) {
            let _ = Command::new("route")
                .args(["delete", &rt.server_ip])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = fs::remove_file(&paths.l2tp_route);
        }
        return;
    }

    // NetworkManager profiles on Linux
    if which_bin("nmcli").is_some()
        && let Ok(out) = Command::new("nmcli")
            .args(["-t", "-f", "UUID,NAME,TYPE", "connection", "show"])
            .output()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[1].starts_with(NM_PROFILE_PREFIX) {
                let uuid = parts[0];
                let _ = Command::new("nmcli")
                    .args(["--wait", "5", "connection", "down", "uuid", uuid])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = Command::new("nmcli")
                    .args(["connection", "delete", "uuid", uuid])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    // Standalone OpenVPN daemon
    if let Ok(txt) = fs::read_to_string(&paths.ovpn_pid)
        && let Ok(pid) = txt.trim().parse::<u32>()
        && pid_matches_cmdline(pid, "openvpn")
    {
        terminate_pid(pid, false);
        std::thread::sleep(Duration::from_millis(400));
    }
    let _ = fs::remove_file(&paths.ovpn_pid);

    if is_root_or_admin() {
        if paths.l2tp_resolv_bak.exists() {
            let resolv = Path::new("/etc/resolv.conf");
            if !resolv.is_symlink() {
                let _ = fs::copy(&paths.l2tp_resolv_bak, resolv);
            }
            let _ = fs::remove_file(&paths.l2tp_resolv_bak);
        }

        let xl_pid_file = paths.l2tp_run_dir.join("xl2tpd.pid");
        if let Ok(txt) = fs::read_to_string(&xl_pid_file)
            && let Ok(pid) = txt.trim().parse::<u32>()
            && pid_matches_cmdline(pid, "xl2tpd")
        {
            terminate_pid(pid, false);
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = Command::new("pkill")
            .args(["-9", "-x", "xl2tpd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        stop_ikev1_daemon_and_xfrm(paths);

        if let Some(rt) = read_json_opt::<PinnedRouteRecord>(&paths.l2tp_route) {
            if cfg!(target_os = "linux") {
                let _ = Command::new("ip")
                    .args(["-4", "route", "del", &format!("{}/32", rt.server_ip)])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            } else if cfg!(target_os = "macos") {
                let _ = Command::new("route")
                    .args(["-n", "delete", "-host", &rt.server_ip])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = fs::remove_file(&paths.l2tp_route);
        }
        let _ = fs::remove_dir_all(&paths.l2tp_run_dir);

        if full_teardown {
            manage_linux_l2tp_firewall(false);
            restore_linux_sysctls(paths);
        }
    }
}

/// Connects Linux L2TP/IPsec using our built-in pure-Rust `_ikev1` + kernel XFRM + `xl2tpd`.
pub async fn connect_l2tp_linux_builtin(
    paths: &AppPaths,
    server: &VpnServer,
    dns_servers: &[String],
    timeout_secs: u64,
) -> std::result::Result<String, String> {
    let xl2tpd_bin = which_bin("xl2tpd")
        .or_else(|| {
            let p = PathBuf::from("/usr/sbin/xl2tpd");
            p.is_file().then_some(p)
        })
        .ok_or("`xl2tpd` not installed (`sudo apt install -y xl2tpd ppp`)")?;

    let gw = get_default_gateway();
    if gw.dev.is_empty() {
        return Err("No active physical IPv4 default gateway detected".to_string());
    }

    snapshot_and_apply_linux_sysctls(paths, true);
    manage_linux_l2tp_firewall(true);

    // Stop any conflicting system-wide L2TP/IKE daemons
    for svc in ["xl2tpd.service", "strongswan.service", "ipsec.service"] {
        let _ = Command::new("systemctl")
            .args(["stop", svc])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    stop_ikev1_daemon_and_xfrm(paths);
    fs::create_dir_all(&paths.l2tp_run_dir).map_err(|e| e.to_string())?;

    // Pin /32 route to VPN server via physical gateway
    let mut rt_args = vec![
        "-4".to_string(),
        "route".to_string(),
        "replace".to_string(),
        format!("{}/32", server.ip),
    ];
    if !gw.gw.is_empty() {
        rt_args.push("via".to_string());
        rt_args.push(gw.gw.clone());
    }
    rt_args.push("dev".to_string());
    rt_args.push(gw.dev.clone());
    let _ = Command::new("ip")
        .args(&rt_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = atomic_write_json(
        &paths.l2tp_route,
        &PinnedRouteRecord {
            server_ip: server.ip.clone(),
            gw: gw.gw,
            dev: gw.dev,
        },
    );

    let before_ppp = get_ppp_interfaces();

    // Spawn built-in `vpngate _ikev1 <ip> <state_file>` subprocess
    let _ = fs::remove_file(&paths.ikev1_state);
    let self_exe = env::current_exe().map_err(|e| e.to_string())?;
    let mut ike_child = Command::new(self_exe)
        .arg("_ikev1")
        .arg(&server.ip)
        .arg(&paths.ikev1_state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed spawning _ikev1 daemon: {e}"))?;
    let _ = fs::write(&paths.ikev1_pid, format!("{}\n", ike_child.id()));
    fix_owner(&paths.ikev1_pid);

    // Wait up to 9s for Phase 1 + Quick Mode + XFRM SA installation
    let ike_deadline = Instant::now() + Duration::from_secs(9);
    let mut ike_ready = false;
    while Instant::now() < ike_deadline {
        if let Some(st) = read_json_opt::<Ikev1StateInfo>(&paths.ikev1_state) {
            if st.status == "ready" {
                ike_ready = true;
                break;
            } else if st.status == "error" {
                let _ = ike_child.kill();
                stop_ikev1_daemon_and_xfrm(paths);
                return Err(format!("IKEv1 negotiation failed: {}", st.error));
            }
        }
        if ike_child.try_wait().ok().flatten().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    if !ike_ready {
        let _ = ike_child.kill();
        stop_ikev1_daemon_and_xfrm(paths);
        return Err("IKEv1 Phase 1/2 timed out before XFRM installation".to_string());
    }

    // Write isolated ppp-options + xl2tpd.conf and dial L2TP over XFRM-protected UDP 1701
    let ppp_opts = paths.l2tp_run_dir.join("ppp-options");
    let pppd_log = paths.l2tp_run_dir.join("pppd.log");
    let _ = fs::remove_file(&pppd_log);
    fs::write(
        &ppp_opts,
        format!(
            "ipcp-accept-local\nipcp-accept-remote\nnoccp\nnoauth\nlcp-echo-interval 30\nlcp-echo-failure 4\nconnect-delay 2000\nmtu 1400\nmru 1400\nnodefaultroute\nusepeerdns\nrefuse-eap\nname \"vpn\"\npassword \"vpn\"\nlogfile {}\n",
            pppd_log.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&ppp_opts, fs::Permissions::from_mode(0o600));
    }

    let xl_conf = paths.l2tp_run_dir.join("xl2tpd.conf");
    let xl_pid = paths.l2tp_run_dir.join("xl2tpd.pid");
    let xl_ctl = paths.l2tp_run_dir.join("xl2tpd-control");
    fs::write(
        &xl_conf,
        format!(
            "[global]\nport = 1701\naccess control = no\n\n[lac l2tp]\nlns = {}\nppp debug = yes\npppoptfile = {}\nautodial = yes\nredial = no\ntunnel rws = 8\ntx bps = 100000000\nrx bps = 100000000\n",
            server.ip,
            ppp_opts.display()
        ),
    )
    .map_err(|e| e.to_string())?;

    let xl_status = Command::new(xl2tpd_bin)
        .arg("-c")
        .arg(&xl_conf)
        .arg("-p")
        .arg(&xl_pid)
        .arg("-C")
        .arg(&xl_ctl)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("Failed starting xl2tpd: {e}"))?;
    if !xl_status.success() {
        stop_ikev1_daemon_and_xfrm(paths);
        return Err("xl2tpd exited immediately with non-zero status".to_string());
    }

    let ppp_deadline = Instant::now() + Duration::from_secs(timeout_secs.max(14));
    let mut ppp_dev = String::new();
    while Instant::now() < ppp_deadline {
        let cur = get_ppp_interfaces();
        if let Some(new_d) = cur.keys().find(|d| !before_ppp.contains_key(*d)) {
            ppp_dev = new_d.clone();
            break;
        }
        if let Ok(log_txt) = fs::read_to_string(&pppd_log) {
            let low = log_txt.to_ascii_lowercase();
            if low.contains("authentication failed")
                || low.contains("connection terminated")
                || low.contains("modem hangup")
            {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(350)).await;
    }

    if ppp_dev.is_empty() {
        let _ = Command::new("pkill")
            .args(["-9", "-x", "xl2tpd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        stop_ikev1_daemon_and_xfrm(paths);
        return Err("L2TP/PPP timed out waiting for pppX interface".to_string());
    }

    // Install split-default routes (0.0.0.0/1 + 128.0.0.0/1) & lock Cloudflare DNS
    for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
        let _ = Command::new("ip")
            .args(["-4", "route", "replace", cidr, "dev", &ppp_dev])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    if !dns_servers.is_empty() && which_bin("resolvectl").is_some() {
        let mut args = vec!["dns".to_string(), ppp_dev.clone()];
        args.extend(dns_servers.iter().cloned());
        let _ = Command::new("resolvectl")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("resolvectl")
            .args(["domain", &ppp_dev, "~."])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Ok(ppp_dev)
}

/// Connects Windows 11 Native L2TP/IPsec (`RASMAN`/`IKEEXT`, `PSK = 'vpn'`, zero IKEv2).
pub async fn connect_l2tp_windows(
    paths: &AppPaths,
    server: &VpnServer,
    dns_servers: &[String],
    timeout_secs: u64,
) -> std::result::Result<String, String> {
    let gw = get_default_gateway();
    if !gw.gw.is_empty() {
        let _ = Command::new("route")
            .args([
                "add",
                &server.ip,
                "mask",
                "255.255.255.255",
                &gw.gw,
                "metric",
                "5",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = atomic_write_json(
            &paths.l2tp_route,
            &PinnedRouteRecord {
                server_ip: server.ip.clone(),
                gw: gw.gw,
                dev: gw.dev,
            },
        );
    }

    let _ = Command::new("rasdial")
        .args([WIN_VPN_PROFILE_NAME, "/DISCONNECT"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let ps_script = format!(
        "Start-Service PolicyAgent, IKEEXT, RasMan -ErrorAction SilentlyContinue; \
         $ex = Get-VpnConnection -Name '{WIN_VPN_PROFILE_NAME}' -ErrorAction SilentlyContinue; \
         if ($null -ne $ex) {{ Set-VpnConnection -Name '{WIN_VPN_PROFILE_NAME}' -ServerAddress '{}' -TunnelType L2tp -L2tpPsk 'vpn' -AuthenticationMethod Pap,Chap,MSChapv2 -EncryptionLevel Optional -SplitTunneling:$false -RememberCredential -Force | Out-Null }} \
         else {{ Add-VpnConnection -Name '{WIN_VPN_PROFILE_NAME}' -ServerAddress '{}' -TunnelType L2tp -L2tpPsk 'vpn' -AuthenticationMethod Pap,Chap,MSChapv2 -EncryptionLevel Optional -SplitTunneling:$false -RememberCredential -Force | Out-Null }}",
        server.ip, server.ip
    );
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let dial = tokio::time::timeout(
        Duration::from_secs(timeout_secs.max(30)),
        tokio::process::Command::new("rasdial")
            .args([WIN_VPN_PROFILE_NAME, "vpn", "vpn"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await
    .map_err(|_| "Windows rasdial timed out".to_string())?
    .map_err(|e| format!("rasdial error: {e}"))?;

    if !dial.success() {
        return Err("Windows rasdial returned non-zero status".to_string());
    }

    if !dns_servers.is_empty() {
        let joined = dns_servers
            .iter()
            .map(|d| format!("'{d}'"))
            .collect::<Vec<_>>()
            .join(",");
        let dns_ps = format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{WIN_VPN_PROFILE_NAME}' -ServerAddresses @({joined}) -ErrorAction SilentlyContinue"
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &dns_ps])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Ok(WIN_VPN_PROFILE_NAME.to_string())
}

/// Connects OpenVPN on Desktop (`nmcli` optional on Linux, plus direct `openvpn` daemon across Linux/macOS/Windows).
pub async fn connect_openvpn_desktop(
    paths: &AppPaths,
    server: &VpnServer,
    transport: VpnProtocol,
    engine: &str,
    dns_servers: &[String],
    timeout_secs: u64,
) -> std::result::Result<(String, String), String> {
    let ovpn_bin = find_openvpn_bin().ok_or("OpenVPN binary (`openvpn`) not found")?;
    let compat = detect_openvpn_compat(&ovpn_bin);

    let opts = OvpnPatchOptions {
        platform: TargetPlatform::current(),
        compat,
        transport,
        windows_driver: WindowsOvpnDriver::TapWindows6,
        dns_servers: dns_servers.to_vec(),
    };
    let patched = build_patched_ovpn(server, &opts).map_err(|e| e.to_string())?;
    let profile_name = format!(
        "{NM_PROFILE_PREFIX}{}-{}",
        server.country_short.to_ascii_lowercase(),
        server.hostname
    );
    let ovpn_path = paths.cache_dir.join(format!("{profile_name}.ovpn"));
    fs::write(&ovpn_path, patched).map_err(|e| e.to_string())?;
    fix_owner(&ovpn_path);

    if cfg!(target_os = "linux") {
        snapshot_and_apply_linux_sysctls(paths, false);
    }

    // Try NetworkManager first on Linux if requested (`auto` or `nm`)
    if cfg!(target_os = "linux")
        && (engine == "auto" || engine == "nm")
        && which_bin("nmcli").is_some()
        && let Ok(imp) = Command::new("nmcli")
            .args(["connection", "import", "type", "openvpn", "file"])
            .arg(&ovpn_path)
            .output()
        && imp.status.success()
    {
        let stem = ovpn_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&profile_name);
        let dns_csv = dns_servers.join(",");
        let _ = Command::new("nmcli")
            .args([
                "connection",
                "modify",
                stem,
                "connection.id",
                &profile_name,
                "connection.autoconnect",
                "no",
                "ipv6.method",
                "disabled",
                "ipv4.dns",
                &dns_csv,
                "ipv4.ignore-auto-dns",
                "yes",
                "ipv4.dns-priority",
                "-50",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let up = Command::new("nmcli")
            .args([
                "--wait",
                &timeout_secs.to_string(),
                "connection",
                "up",
                &profile_name,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if up.map(|s| s.success()).unwrap_or(false) {
            let dev = get_tun_interfaces()
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| "tun0".to_string());
            return Ok((dev, "nmcli-openvpn".to_string()));
        }
        let _ = Command::new("nmcli")
            .args(["connection", "delete", &profile_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Direct OpenVPN daemon fallback (Linux, macOS, Windows)
    let before_tun = get_tun_interfaces();
    let log_path = paths.cache_dir.join("openvpn.log");
    let _ = fs::remove_file(&log_path);

    let mut cmd = Command::new(&ovpn_bin);
    cmd.arg("--config")
        .arg(&ovpn_path)
        .arg("--log")
        .arg(&log_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if !cfg!(target_os = "windows") {
        cmd.arg("--daemon").arg("--writepid").arg(&paths.ovpn_pid);
        let st = cmd.status().map_err(|e| format!("openvpn error: {e}"))?;
        if !st.success() {
            return Err("openvpn --daemon exited with error".to_string());
        }
    } else {
        let child = cmd.spawn().map_err(|e| format!("openvpn spawn: {e}"))?;
        let _ = fs::write(&paths.ovpn_pid, format!("{}\n", child.id()));
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(15));
    while Instant::now() < deadline {
        if let Ok(log_txt) = fs::read_to_string(&log_path) {
            if log_txt.contains("Initialization Sequence Completed") {
                let cur = get_tun_interfaces();
                let dev = cur
                    .keys()
                    .find(|d| !before_tun.contains_key(*d))
                    .or_else(|| cur.keys().next())
                    .cloned()
                    .unwrap_or_else(|| "tun0".to_string());

                if cfg!(target_os = "linux")
                    && !dns_servers.is_empty()
                    && which_bin("resolvectl").is_some()
                {
                    let mut args = vec!["dns".to_string(), dev.clone()];
                    args.extend(dns_servers.iter().cloned());
                    let _ = Command::new("resolvectl")
                        .args(&args)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    let _ = Command::new("resolvectl")
                        .args(["domain", &dev, "~."])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                return Ok((dev, "openvpn-daemon".to_string()));
            }
            if log_txt.contains("AUTH_FAILED") || log_txt.contains("Exiting due to fatal error") {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(350)).await;
    }

    Err("OpenVPN handshake timed out".to_string())
}

/// Verifies end-to-end tunnel routing and confirms public IPv4 egress changed from `initial_ip`.
pub async fn verify_tunnel_egress(initial_ip: &str) -> Option<PublicIpTrace> {
    tokio::time::sleep(Duration::from_millis(1200)).await;
    for attempt in 0..4 {
        if let Some(trace) = get_public_ip_trace(Duration::from_secs(5)).await
            && !trace.ip.is_empty()
            && (initial_ip.is_empty() || trace.ip != initial_ip)
        {
            return Some(trace);
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(1400)).await;
        }
    }
    None
}

/// Checks active VPN session link + optional data-plane egress health for `vpngate _monitor`.
pub async fn is_vpn_tunnel_healthy(
    paths: &AppPaths,
    state: &ActiveSessionState,
    check_dataplane: bool,
) -> (bool, String) {
    let is_l2tp = state.protocol.contains("L2TP");
    if is_l2tp {
        if get_ppp_interfaces().is_empty() {
            return (false, "PPP interface went down".to_string());
        }
        if cfg!(target_os = "linux") {
            let pid = fs::read_to_string(&paths.ikev1_pid)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(0);
            if pid == 0 || !pid_matches_cmdline(pid, "_ikev1") {
                return (false, "built-in IKEv1/XFRM daemon exited".to_string());
            }
        }
    } else if get_tun_interfaces().is_empty() && !cfg!(target_os = "windows") {
        return (false, "TUN interface went down".to_string());
    }

    if check_dataplane {
        let Some(trace) = get_public_ip_trace(Duration::from_secs(5)).await else {
            return (false, "tunnel data-plane trace timed out".to_string());
        };
        if !state.pre_vpn_ip.is_empty() && trace.ip == state.pre_vpn_ip {
            return (
                false,
                format!("egress reverted to pre-VPN IP ({})", state.pre_vpn_ip),
            );
        }
    }
    (true, "ok".to_string())
}

pub fn spawn_auto_reconnect_monitor(paths: &AppPaths) -> u32 {
    let existing = get_running_monitor_pid(paths);
    if existing > 0 {
        return existing;
    }
    let Ok(self_exe) = env::current_exe() else {
        return 0;
    };
    let Ok(child) = Command::new(self_exe)
        .arg("_monitor")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return 0;
    };
    let pid = child.id();
    let _ = fs::write(&paths.monitor_pid, format!("{pid}\n"));
    fix_owner(&paths.monitor_pid);
    pid
}

fn append_monitor_log(paths: &AppPaths, msg: &str) {
    let ts = now_unix_secs();
    let line = format!("[{ts}] {msg}\n");
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.monitor_log)
    {
        use std::io::Write as _;
        let _ = f.write_all(line.as_bytes());
    }
    fix_owner(&paths.monitor_log);
}

#[derive(Debug, Clone)]
pub struct ConnectSessionConfig {
    pub region_label: String,
    pub proto_filter: ProtocolFilter,
    pub sort_by: SortBy,
    pub limit: usize,
    pub timeout_secs: u64,
    pub engine: String,
    pub dns_servers: Vec<String>,
    pub start_index: usize,
    pub auto_reconnect: bool,
    pub in_monitor: bool,
}

/// Attempts connection across ranked `candidates` following `L2TP/IPsec -> OVPN UDP -> OVPN TCP`.
pub async fn engage_candidates(
    paths: &AppPaths,
    candidates: &[VpnServer],
    cfg: &ConnectSessionConfig,
    mut on_log: impl FnMut(&str),
) -> i32 {
    if candidates.is_empty() {
        return 1;
    }

    cleanup_existing_vpn(paths, false, !cfg.in_monitor);
    let initial_ip = get_public_ip_trace(Duration::from_secs(4))
        .await
        .map(|t| t.ip)
        .unwrap_or_default();

    let start_pos = cfg.start_index.saturating_sub(1);
    let mut ordered: Vec<VpnServer> = candidates.iter().skip(start_pos).cloned().collect();
    if cfg.limit > 0 && ordered.len() > cfg.limit {
        ordered.truncate(cfg.limit);
    }

    let mut cooldowns = load_cooldowns(paths);
    let total = ordered.len();

    for (idx, srv) in ordered.iter().enumerate() {
        let protos = srv.candidate_protocols(cfg.proto_filter);
        if protos.is_empty() {
            continue;
        }
        on_log(&format!(
            "[{}/{}] Testing {} ({} - {}, {:.1} Mbps) ...",
            idx + 1,
            total,
            srv.hostname,
            srv.ip,
            srv.country_short,
            srv.speed_mbps()
        ));

        for proto in protos {
            if cooldowns.is_on_cooldown(&srv.ip, proto) {
                continue;
            }
            match proto {
                VpnProtocol::L2tpIpsec => {
                    let Ok(ip_v4) = srv.ip.parse() else {
                        continue;
                    };
                    let pre =
                        verify_l2tp_psk_vpn(ip_v4, Duration::from_millis(1400), 2, b"vpn").await;
                    if !pre.is_verified() {
                        on_log(&format!("  -> L2TP pre-flight skipped ({pre:?})"));
                        cooldowns.mark_failed(&srv.ip, proto);
                        save_cooldowns(paths, &mut cooldowns);
                        continue;
                    }
                    on_log(&format!(
                        "  -> Engaging L2TP/IPsec (PSK='vpn', Zero IKEv2) on {} ...",
                        srv.ip
                    ));
                    let res = if cfg!(target_os = "windows") {
                        connect_l2tp_windows(paths, srv, &cfg.dns_servers, cfg.timeout_secs)
                            .await
                            .map(|d| (d, "win-ras-l2tp".to_string()))
                    } else if cfg!(target_os = "linux") {
                        connect_l2tp_linux_builtin(paths, srv, &cfg.dns_servers, cfg.timeout_secs)
                            .await
                            .map(|d| {
                                let label = format!("builtin-xfrm-{d}");
                                (d, label)
                            })
                    } else {
                        Err(
                            "Automated L2TP on macOS uses Apple profile; falling back to OpenVPN"
                                .to_string(),
                        )
                    };

                    match res {
                        Ok((dev, backend)) => {
                            if let Some(trace) = verify_tunnel_egress(&initial_ip).await {
                                cooldowns.clear_server(&srv.ip);
                                save_cooldowns(paths, &mut cooldowns);
                                record_active_session(
                                    paths,
                                    srv,
                                    "L2TP/IPsec",
                                    &backend,
                                    &dev,
                                    &trace,
                                    &initial_ip,
                                    cfg,
                                );
                                if cfg.auto_reconnect && !cfg.in_monitor {
                                    spawn_auto_reconnect_monitor(paths);
                                }
                                return 0;
                            }
                            on_log("  -> L2TP interface came up, but egress verification failed.");
                            cleanup_existing_vpn(paths, false, !cfg.in_monitor);
                        }
                        Err(e) => {
                            on_log(&format!("  -> L2TP failed: {e}"));
                            cleanup_existing_vpn(paths, false, !cfg.in_monitor);
                        }
                    }
                    cooldowns.mark_failed(&srv.ip, proto);
                    save_cooldowns(paths, &mut cooldowns);
                }
                VpnProtocol::OpenVpnUdp | VpnProtocol::OpenVpnTcp => {
                    if proto == VpnProtocol::OpenVpnTcp
                        && srv.tcp_port > 0
                        && let Ok(ip_v4) = srv.ip.parse()
                    {
                        let addr =
                            std::net::SocketAddr::new(std::net::IpAddr::V4(ip_v4), srv.tcp_port);
                        if probe_tcp(addr, Duration::from_millis(2000)).await.is_none() {
                            on_log(&format!(
                                "  -> TCP port {} unreachable; skipping.",
                                srv.tcp_port
                            ));
                            cooldowns.mark_failed(&srv.ip, proto);
                            save_cooldowns(paths, &mut cooldowns);
                            continue;
                        }
                    }
                    on_log(&format!(
                        "  -> Engaging {} on {} ...",
                        proto.as_label(),
                        srv.ip
                    ));
                    match connect_openvpn_desktop(
                        paths,
                        srv,
                        proto,
                        &cfg.engine,
                        &cfg.dns_servers,
                        cfg.timeout_secs,
                    )
                    .await
                    {
                        Ok((dev, backend)) => {
                            if let Some(trace) = verify_tunnel_egress(&initial_ip).await {
                                cooldowns.clear_server(&srv.ip);
                                save_cooldowns(paths, &mut cooldowns);
                                record_active_session(
                                    paths,
                                    srv,
                                    proto.as_label(),
                                    &backend,
                                    &dev,
                                    &trace,
                                    &initial_ip,
                                    cfg,
                                );
                                if cfg.auto_reconnect && !cfg.in_monitor {
                                    spawn_auto_reconnect_monitor(paths);
                                }
                                return 0;
                            }
                            on_log("  -> OpenVPN connected, but egress verification failed.");
                            cleanup_existing_vpn(paths, false, !cfg.in_monitor);
                        }
                        Err(e) => {
                            on_log(&format!("  -> {} failed: {e}", proto.as_label()));
                            cleanup_existing_vpn(paths, false, !cfg.in_monitor);
                        }
                    }
                    cooldowns.mark_failed(&srv.ip, proto);
                    save_cooldowns(paths, &mut cooldowns);
                }
            }
        }
    }

    cleanup_existing_vpn(paths, !cfg.in_monitor, !cfg.in_monitor);
    1
}

#[allow(clippy::too_many_arguments)]
fn record_active_session(
    paths: &AppPaths,
    srv: &VpnServer,
    proto_label: &str,
    backend: &str,
    dev: &str,
    trace: &PublicIpTrace,
    initial_ip: &str,
    cfg: &ConnectSessionConfig,
) {
    let profile_name = format!(
        "{NM_PROFILE_PREFIX}{}-{}",
        srv.country_short.to_ascii_lowercase(),
        srv.hostname
    );
    let st = ActiveSessionState {
        status: "connected".to_string(),
        profile_name,
        protocol: proto_label.to_string(),
        backend: backend.to_string(),
        device: dev.to_string(),
        hostname: srv.hostname.clone(),
        server_ip: srv.ip.clone(),
        egress_ip: trace.ip.clone(),
        egress_loc: trace.loc.clone(),
        pre_vpn_ip: initial_ip.to_string(),
        country_short: srv.country_short.clone(),
        country_long: srv.country_long.clone(),
        region_label: cfg.region_label.clone(),
        proto_choice: cfg.proto_filter.as_cli_str().to_string(),
        sort_key: cfg.sort_by.as_cli_str().to_string(),
        engine: cfg.engine.clone(),
        dns: cfg.dns_servers.join(" "),
        timeout: cfg.timeout_secs,
        auto_reconnect: cfg.auto_reconnect || load_watchdog_pref(paths),
        connected_at: now_unix_secs(),
        last_drop_reason: String::new(),
    };
    let _ = atomic_write_json(&paths.active_state, &st);
}

/// Background Auto-Reconnect Watchdog (`vpngate _monitor`).
pub async fn run_monitor_daemon(paths: &AppPaths) -> i32 {
    if !is_root_or_admin() {
        return 1;
    }
    let _ = paths.ensure_dirs();
    let _ = fs::write(&paths.monitor_pid, format!("{}\n", std::process::id()));
    fix_owner(&paths.monitor_pid);
    append_monitor_log(
        paths,
        &format!(
            "Auto-Reconnect Monitor started (PID {}).",
            std::process::id()
        ),
    );

    let mut tick = 0u64;
    loop {
        for _ in 0..MONITOR_INTERVAL_SECONDS {
            if !paths.active_state.exists() {
                append_monitor_log(paths, "State file removed; monitor exiting.");
                return 0;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let Some(mut state) = read_json_opt::<ActiveSessionState>(&paths.active_state) else {
            return 0;
        };
        if !state.auto_reconnect {
            append_monitor_log(paths, "Auto-reconnect disabled; monitor exiting.");
            return 0;
        }
        if get_default_gateway().dev.is_empty() {
            append_monitor_log(paths, "Physical network gateway unavailable; waiting...");
            continue;
        }

        tick += 1;
        let (healthy, reason) = is_vpn_tunnel_healthy(paths, &state, tick.is_multiple_of(2)).await;
        if healthy {
            continue;
        }

        append_monitor_log(
            paths,
            &format!(
                "Tunnel {} ({}) dropped: {reason}. Failing over...",
                state.hostname, state.region_label
            ),
        );
        cleanup_existing_vpn(paths, false, false);
        state.status = "reconnecting".to_string();
        state.last_drop_reason = reason.clone();
        let _ = atomic_write_json(&paths.active_state, &state);

        let Ok(servers) = get_servers_cached(paths, false).await else {
            continue;
        };
        let pfilter = ProtocolFilter::from_cli_str(&state.proto_choice).unwrap_or_default();
        let sby = SortBy::from_cli_str(&state.sort_key).unwrap_or_default();
        let mut cands = filter_by_country(
            &filter_by_protocol(&servers, pfilter),
            Some(&state.region_label),
        );
        sort_servers(&mut cands, sby, pfilter);
        cands.retain(|s| s.ip != state.server_ip);

        let dns_vec: Vec<String> = state
            .dns
            .split_whitespace()
            .map(ToString::to_string)
            .collect();
        let cfg = ConnectSessionConfig {
            region_label: state.region_label.clone(),
            proto_filter: pfilter,
            sort_by: sby,
            limit: 12,
            timeout_secs: state.timeout,
            engine: state.engine.clone(),
            dns_servers: if dns_vec.is_empty() {
                vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
            } else {
                dns_vec
            },
            start_index: 1,
            auto_reconnect: true,
            in_monitor: true,
        };
        let _ = engage_candidates(paths, &cands, &cfg, |msg| append_monitor_log(paths, msg)).await;
    }
}
