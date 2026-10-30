use std::collections::BTreeMap;
use std::env;
use std::fs;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cache::{
    ActiveSessionState, AppPaths, Ikev1StateInfo, MONITOR_INTERVAL_SECONDS, PublicIpTrace,
    atomic_write_json, fix_owner, get_public_ip_trace, get_servers_cached, load_cooldowns,
    load_watchdog_pref, now_unix_secs, read_json_opt, save_cooldowns,
};
use crate::discovery::ProgressEvent;
use crate::ikev1::{probe_tcp, verify_l2tp_psk_vpn};
use crate::ikev1_daemon::VPNGATE_XFRM_REQID;
use crate::profile::{OvpnPatchOptions, build_patched_ovpn};
use crate::protocol::{
    OpenVpnCompat, ProtocolFilter, SortBy, TargetPlatform, VpnProtocol, WindowsOvpnDriver,
};
use crate::server::{VpnServer, filter_by_country, filter_by_protocol, sort_servers};

pub const NM_PROFILE_PREFIX: &str = "vpngate-";
pub const WIN_VPN_PROFILE_NAME: &str = "VPNGate-L2TP";
/// Exit status when the user interrupts connect (`Ctrl+C`): rollback done, do not treat as a hard crash.
pub const INTERRUPTED_EXIT: i32 = 130;
const NFT_COMMENT_TAG: &str = "vpngate-l2tp";

#[cfg(windows)]
pub const WIN_CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
pub const WIN_DETACHED_FLAGS: u32 = 0x0000_0008 | 0x0000_0200 | 0x0800_0000;

#[cfg(windows)]
mod win_ffi {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const STILL_ACTIVE: u32 = 259;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: u32 = 20;
    const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002usize as *mut c_void;
    const RRF_RT_REG_DWORD: u32 = 0x0000_0010;

    #[repr(C)]
    #[derive(Default)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        pub fn IsUserAnAdmin() -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            process_handle: *mut c_void,
            desired_access: u32,
            token_handle: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn RegGetValueW(
            hkey: *mut c_void,
            lp_sub_key: *const u16,
            lp_value: *const u16,
            dw_flags: u32,
            pdw_type: *mut u32,
            pv_data: *mut c_void,
            pcb_data: *mut u32,
        ) -> i32;
    }

    #[repr(C)]
    struct SystemInfo {
        w_processor_architecture: u16,
        w_reserved: u16,
        dw_page_size: u32,
        lp_minimum_application_address: *mut c_void,
        lp_maximum_application_address: *mut c_void,
        dw_active_processor_mask: usize,
        dw_number_of_processors: u32,
        dw_processor_type: u32,
        dw_allocation_granularity: u32,
        w_processor_level: u16,
        w_processor_revision: u16,
    }

    const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
    const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetNativeSystemInfo(lp_system_info: *mut SystemInfo);
        pub fn OpenProcess(
            desired_access: u32,
            inherit_handle: i32,
            process_id: u32,
        ) -> *mut c_void;
        pub fn GetExitCodeProcess(process: *mut c_void, exit_code: *mut u32) -> i32;
        pub fn CloseHandle(object: *mut c_void) -> i32;
    }

    fn native_processor_architecture() -> u16 {
        // SAFETY: `GetNativeSystemInfo` writes a well-defined `SYSTEM_INFO` and never fails.
        unsafe {
            let mut info = SystemInfo {
                w_processor_architecture: 0,
                w_reserved: 0,
                dw_page_size: 0,
                lp_minimum_application_address: null_mut(),
                lp_maximum_application_address: null_mut(),
                dw_active_processor_mask: 0,
                dw_number_of_processors: 0,
                dw_processor_type: 0,
                dw_allocation_granularity: 0,
                w_processor_level: 0,
                w_processor_revision: 0,
            };
            GetNativeSystemInfo(&mut info);
            info.w_processor_architecture
        }
    }

    pub fn native_processor_is_amd64() -> bool {
        native_processor_architecture() == PROCESSOR_ARCHITECTURE_AMD64
    }

    pub fn native_processor_is_arm64() -> bool {
        native_processor_architecture() == PROCESSOR_ARCHITECTURE_ARM64
    }

    pub fn is_current_process_elevated() -> bool {
        // SAFETY: Queries `TOKEN_ELEVATION` on the current process token, falling back to `IsUserAnAdmin`.
        unsafe {
            let mut h_token: *mut c_void = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token) != 0
                && !h_token.is_null()
            {
                let mut elev = TokenElevation::default();
                let mut ret_len: u32 = 0;
                let ok = GetTokenInformation(
                    h_token,
                    TOKEN_ELEVATION_CLASS,
                    (&raw mut elev).cast::<c_void>(),
                    std::mem::size_of::<TokenElevation>() as u32,
                    &mut ret_len,
                );
                let _ = CloseHandle(h_token);
                if ok != 0 {
                    return elev.token_is_elevated != 0;
                }
            }
            IsUserAnAdmin() != 0
        }
    }

    pub fn read_policy_agent_natt_rule() -> Option<u32> {
        let mut subkey: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\PolicyAgent"
            .encode_utf16()
            .collect();
        subkey.push(0);
        let mut val_name: Vec<u16> = "AssumeUDPEncapsulationContextOnSendRule"
            .encode_utf16()
            .collect();
        val_name.push(0);
        let mut val: u32 = 0;
        let mut cb: u32 = std::mem::size_of::<u32>() as u32;
        // SAFETY: Read-only `RegGetValueW` into stack `u32` with exact byte count.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                val_name.as_ptr(),
                RRF_RT_REG_DWORD,
                null_mut(),
                (&raw mut val).cast::<c_void>(),
                &mut cb,
            )
        };
        if status == 0 { Some(val) } else { None }
    }
}

fn quiet_cmd(program: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        cmd.creation_flags(WIN_CREATE_NO_WINDOW);
    }
    cmd
}

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
        win_ffi::is_current_process_elevated()
    }
}

pub fn query_windows_natt_rule() -> Option<u32> {
    #[cfg(windows)]
    {
        win_ffi::read_policy_agent_natt_rule()
    }
    #[cfg(not(windows))]
    {
        None
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

/// Native 64-bit `x86_64` or `aarch64`. Refuse 32-bit hosts and ISA emulation
/// (Windows-on-ARM x64, macOS Rosetta).
pub fn assert_supported_native_host() -> Result<(), String> {
    if host_matches_binary_isa() {
        Ok(())
    } else {
        Err(format!(
            "VPN Gate Connect desktop requires a native 64-bit {} process (x86_64 or ARM64). 32-bit hardware and ISA emulation (Rosetta / Windows-on-ARM x64) are not supported.",
            cpu_isa_label()
        ))
    }
}

pub fn cpu_isa_label() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

fn host_matches_binary_isa() -> bool {
    #[cfg(windows)]
    {
        #[cfg(target_arch = "x86_64")]
        {
            win_ffi::native_processor_is_amd64()
        }
        #[cfg(target_arch = "aarch64")]
        {
            win_ffi::native_processor_is_arm64()
        }
    }
    #[cfg(target_os = "macos")]
    {
        #[cfg(target_arch = "x86_64")]
        {
            unix_uname_machine_is_x86_64() && !macos_has_arm64_cpu()
        }
        #[cfg(target_arch = "aarch64")]
        {
            unix_uname_machine_is_aarch64() || macos_has_arm64_cpu()
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        #[cfg(target_arch = "x86_64")]
        {
            unix_uname_machine_is_x86_64()
        }
        #[cfg(target_arch = "aarch64")]
        {
            unix_uname_machine_is_aarch64()
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

#[cfg(unix)]
fn unix_uname_machine() -> String {
    // SAFETY: `uname` fills a stack `utsname`; `machine` is a NUL-terminated C string.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) != 0 {
            return String::new();
        }
        std::ffi::CStr::from_ptr(u.machine.as_ptr())
            .to_string_lossy()
            .to_ascii_lowercase()
    }
}

#[cfg(all(unix, target_arch = "x86_64"))]
fn unix_uname_machine_is_x86_64() -> bool {
    machine_is_x86_64(&unix_uname_machine())
}

#[cfg(all(unix, target_arch = "aarch64"))]
fn unix_uname_machine_is_aarch64() -> bool {
    machine_is_aarch64(&unix_uname_machine())
}

pub fn machine_is_x86_64(machine: &str) -> bool {
    matches!(machine, "x86_64" | "amd64")
}

pub fn machine_is_aarch64(machine: &str) -> bool {
    matches!(machine, "aarch64" | "arm64")
}

#[cfg(target_os = "macos")]
fn macos_has_arm64_cpu() -> bool {
    let mut val: i32 = 0;
    let mut size = std::mem::size_of::<i32>() as libc::size_t;
    let Ok(name) = std::ffi::CString::new("hw.optional.arm64") else {
        return true;
    };
    // SAFETY: `sysctlbyname` writes an i32 into `val` when the key exists.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut val).cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    rc == 0 && val == 1
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
        // SAFETY: Win32 `OpenProcess` + `GetExitCodeProcess` checks liveness with zero child process spawns.
        unsafe {
            let h = win_ffi::OpenProcess(win_ffi::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let mut code: u32 = 0;
            let ok = win_ffi::GetExitCodeProcess(h, &mut code);
            let _ = win_ffi::CloseHandle(h);
            ok != 0 && code == win_ffi::STILL_ACTIVE
        }
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
        let _ = quiet_cmd("taskkill")
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

pub fn get_running_openvpn_pid(paths: &AppPaths) -> u32 {
    let Ok(txt) = fs::read_to_string(&paths.ovpn_pid) else {
        return 0;
    };
    let Ok(pid) = txt.trim().parse::<u32>() else {
        return 0;
    };
    if pid != 0 && pid != std::process::id() && pid_matches_cmdline(pid, "openvpn") {
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
        && let Ok(out) = quiet_cmd("powershell")
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
        if let Ok(out) = quiet_cmd("rasdial").output() {
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
    if !paths.active_state.exists()
        || get_running_monitor_pid(paths) > 0
        || get_running_openvpn_pid(paths) > 0
    {
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
    let Ok(out) = quiet_cmd(ovpn_bin).arg("--version").output() else {
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
        ("net.ipv6.conf.lo.disable_ipv6", "0"),
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

/// Checks whether the running Linux kernel supports `/dev/ppp` + `XFRM ESP` (`CONFIG_INET_ESP` & `CONFIG_PPP`),
/// proactively loading modular `xfrm_user`, `esp4`, `ppp_generic`, and `l2tp_ppp` when running as root.
pub fn probe_linux_l2tp_kernel_support() -> std::result::Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    if is_root_or_admin() {
        let modprobe_bin = which_bin("modprobe").or_else(|| {
            ["/sbin/modprobe", "/usr/sbin/modprobe"]
                .into_iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
        });
        if let Some(mp) = modprobe_bin {
            for m in ["xfrm_user", "esp4", "ppp_generic", "l2tp_ppp"] {
                let _ = Command::new(&mp)
                    .arg(m)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    // Inspect `/proc/config.gz` if exposed (common on custom/WSL2/microVM kernels without loadable modules)
    if Path::new("/proc/config.gz").is_file()
        && let Ok(out) = Command::new("gzip")
            .args(["-dc", "/proc/config.gz"])
            .output()
        && out.status.success()
    {
        let cfg_txt = String::from_utf8_lossy(&out.stdout);
        let has_esp =
            cfg_txt.contains("CONFIG_INET_ESP=y") || cfg_txt.contains("CONFIG_INET_ESP=m");
        let has_ppp = cfg_txt.contains("CONFIG_PPP=y") || cfg_txt.contains("CONFIG_PPP=m");
        if !has_esp || !has_ppp {
            return Err(
                "kernel lacks CONFIG_INET_ESP / CONFIG_PPP (OpenVPN Auto fallback active)"
                    .to_string(),
            );
        }
    }

    if is_root_or_admin() && !Path::new("/dev/ppp").exists() {
        return Err("`/dev/ppp` character device unavailable on this kernel".to_string());
    }
    Ok(())
}

/// Locks tunnel DNS on Linux across both `systemd-resolved` (`resolvectl`) and direct `/etc/resolv.conf` distros.
fn apply_linux_tunnel_dns(paths: &AppPaths, dev: &str, dns_servers: &[String]) {
    if !cfg!(target_os = "linux") || dns_servers.is_empty() || !is_root_or_admin() {
        return;
    }

    let mut resolved_handled = false;
    let resolv_path = Path::new("/etc/resolv.conf");
    let is_systemd_symlink = fs::read_link(resolv_path)
        .ok()
        .map(|target| target.to_string_lossy().contains("systemd"))
        .unwrap_or(false);

    if which_bin("resolvectl").is_some() {
        let mut args = vec!["dns".to_string(), dev.to_string()];
        args.extend(dns_servers.iter().cloned());
        let ok_dns = Command::new("resolvectl")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let _ = Command::new("resolvectl")
            .args(["domain", dev, "~."])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if ok_dns && is_systemd_symlink {
            resolved_handled = true;
        }
    }

    if !resolved_handled && resolv_path.exists() && !resolv_path.is_symlink() {
        if !paths.l2tp_resolv_bak.exists() {
            let _ = fs::copy(resolv_path, &paths.l2tp_resolv_bak);
            fix_owner(&paths.l2tp_resolv_bak);
        }
        let mut body =
            String::from("# Managed by vpngate — original backed up to resolv.conf.bak\n");
        for ns in dns_servers {
            let trimmed = ns.trim();
            if !trimmed.is_empty() {
                body.push_str(&format!("nameserver {trimmed}\n"));
            }
        }
        let _ = fs::write(resolv_path, body);
    }
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

/// Deletes leftover VPN Gate L2TP / OpenVPN profile files from the app cache.
fn purge_cached_ovpn_files(paths: &AppPaths, quiet: bool, on_progress: &mut impl FnMut(ProgressEvent)) {
    let Ok(rd) = fs::read_dir(&paths.cache_dir) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let n = name.to_string_lossy();
        let drop_it = n == "openvpn.log"
            || (n.starts_with(NM_PROFILE_PREFIX) && (n.ends_with(".ovpn") || n.ends_with(".log")));
        if drop_it {
            if !quiet {
                on_progress(ProgressEvent::Info(format!(
                    "Removing leftover OpenVPN profile: {n}"
                )));
            }
            let _ = fs::remove_file(ent.path());
        }
    }
}

/// Removes the Windows native L2TP connection object after rasdial disconnect.
fn purge_windows_l2tp_profile(quiet: bool, on_progress: &mut impl FnMut(ProgressEvent)) {
    if !cfg!(target_os = "windows") {
        return;
    }
    if !quiet {
        on_progress(ProgressEvent::Info(format!(
            "Removing Windows L2TP profile '{WIN_VPN_PROFILE_NAME}' ..."
        )));
    }
    let ps = format!(
        "foreach ($scope in @($false, $true)) {{ \
           Get-VpnConnection -Name '{WIN_VPN_PROFILE_NAME}' -AllUserConnection:$scope -ErrorAction SilentlyContinue \
             | Remove-VpnConnection -Force -ErrorAction SilentlyContinue \
         }}"
    );
    let _ = quiet_cmd("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Tears down any active or partial VPN session silently.
pub fn cleanup_existing_vpn(paths: &AppPaths, full_teardown: bool, stop_monitor: bool) {
    cleanup_existing_vpn_with_progress(paths, full_teardown, stop_monitor, true, |_| {});
}

/// Tears down any active or partial VPN session and restores routes, DNS, firewall, and sysctls.
pub fn cleanup_existing_vpn_with_progress(
    paths: &AppPaths,
    full_teardown: bool,
    stop_monitor: bool,
    quiet: bool,
    mut on_progress: impl FnMut(ProgressEvent),
) {
    let _ = paths.ensure_dirs();
    if stop_monitor {
        let mon_pid = get_running_monitor_pid(paths);
        if mon_pid > 0 && !quiet {
            on_progress(ProgressEvent::Info(format!(
                "Stopping Auto-Reconnect Watchdog (PID {mon_pid}) ..."
            )));
        }
        stop_monitor_daemon(paths);
    }
    let _ = fs::remove_file(&paths.active_state);

    if cfg!(target_os = "windows") {
        if let Ok(txt) = fs::read_to_string(&paths.ovpn_pid)
            && let Ok(pid) = txt.trim().parse::<u32>()
        {
            if !quiet {
                on_progress(ProgressEvent::Info(format!(
                    "Stopping OpenVPN process (PID {pid}) ..."
                )));
            }
            terminate_pid(pid, true);
        }
        let _ = fs::remove_file(&paths.ovpn_pid);
        if !quiet {
            on_progress(ProgressEvent::Info(format!(
                "Disconnecting Windows RAS profile '{WIN_VPN_PROFILE_NAME}' ..."
            )));
        }
        let _ = quiet_cmd("rasdial")
            .args([WIN_VPN_PROFILE_NAME, "/DISCONNECT"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        purge_windows_l2tp_profile(quiet, &mut on_progress);
        if let Some(rt) = read_json_opt::<PinnedRouteRecord>(&paths.l2tp_route) {
            let _ = quiet_cmd("route")
                .args(["delete", &rt.server_ip])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = fs::remove_file(&paths.l2tp_route);
        }
        purge_cached_ovpn_files(paths, quiet, &mut on_progress);
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
                let name = parts[1];
                if !quiet {
                    on_progress(ProgressEvent::Info(format!(
                        "Removing NetworkManager VPN profile: {name}"
                    )));
                }
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
        if !quiet {
            on_progress(ProgressEvent::Info(format!(
                "Stopping OpenVPN daemon (PID {pid}) ..."
            )));
        }
        terminate_pid(pid, false);
        std::thread::sleep(Duration::from_millis(400));
    }
    let _ = fs::remove_file(&paths.ovpn_pid);
    purge_cached_ovpn_files(paths, quiet, &mut on_progress);

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
            if !quiet {
                on_progress(ProgressEvent::Info(format!(
                    "Stopping xl2tpd daemon (PID {pid}) ..."
                )));
            }
            terminate_pid(pid, false);
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = Command::new("pkill")
            .args(["-9", "-x", "xl2tpd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if !quiet && (paths.ikev1_pid.exists() || paths.ikev1_state.exists()) {
            on_progress(ProgressEvent::Info(
                "Stopping built-in IKEv1/XFRM daemon & flushing kernel XFRM rules ...".to_string(),
            ));
        }
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
    mut on_progress: impl FnMut(ProgressEvent),
) -> std::result::Result<String, String> {
    probe_linux_l2tp_kernel_support()?;

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

    // Wait up to 9s for Phase 1 + Quick Mode + XFRM SA installation (with live 100ms spinner)
    let total_max = timeout_secs.max(14) + 9;
    let started_all = Instant::now();
    let mut tick = 0usize;
    let ike_deadline = Instant::now() + Duration::from_secs(9);
    let mut ike_ready = false;
    while Instant::now() < ike_deadline {
        if let Some(st) = read_json_opt::<Ikev1StateInfo>(&paths.ikev1_state) {
            if st.status == "ready" {
                ike_ready = true;
                break;
            } else if st.status == "error" {
                on_progress(ProgressEvent::ClearTransient);
                let _ = ike_child.kill();
                stop_ikev1_daemon_and_xfrm(paths);
                return Err(format!("IKEv1 negotiation failed: {}", st.error));
            }
        }
        if ike_child.try_wait().ok().flatten().is_some() {
            break;
        }
        if tick.is_multiple_of(2) {
            on_progress(ProgressEvent::Transient {
                stage: "L2TP/IPsec handshake (IKEv1 Phase 1 & Quick Mode XFRM)".to_string(),
                elapsed_secs: started_all.elapsed().as_secs(),
                max_secs: total_max,
                tick: tick / 2,
            });
        }
        tick += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ike_ready {
        on_progress(ProgressEvent::ClearTransient);
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
        .map_err(|e| {
            on_progress(ProgressEvent::ClearTransient);
            format!("Failed starting xl2tpd: {e}")
        })?;
    if !xl_status.success() {
        on_progress(ProgressEvent::ClearTransient);
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
        let mut ppp_stage = "dialing xl2tpd L2TP/PPP";
        if let Ok(log_txt) = fs::read_to_string(&pppd_log) {
            let low = log_txt.to_ascii_lowercase();
            if low.contains("authentication failed")
                || low.contains("connection terminated")
                || low.contains("modem hangup")
            {
                break;
            }
            if low.contains("chap authentication succeeded") || low.contains("sent [ipcp") {
                ppp_stage = "negotiating PPP IPCP IPv4 lease";
            } else if low.contains("using interface ppp") {
                ppp_stage = "authenticating PPP session";
            }
        }
        if tick.is_multiple_of(2) {
            on_progress(ProgressEvent::Transient {
                stage: format!("L2TP/IPsec handshake ({ppp_stage})"),
                elapsed_secs: started_all.elapsed().as_secs(),
                max_secs: total_max,
                tick: tick / 2,
            });
        }
        tick += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    on_progress(ProgressEvent::ClearTransient);

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

    apply_linux_tunnel_dns(paths, &ppp_dev, dns_servers);

    Ok(ppp_dev)
}

/// Connects Windows 11 Native L2TP/IPsec (`RASMAN`/`IKEEXT`, `PSK = 'vpn'`, zero IKEv2).
pub async fn connect_l2tp_windows(
    paths: &AppPaths,
    server: &VpnServer,
    dns_servers: &[String],
    timeout_secs: u64,
    mut on_progress: impl FnMut(ProgressEvent),
) -> std::result::Result<String, String> {
    let gw = get_default_gateway();
    if !gw.gw.is_empty() {
        let _ = quiet_cmd("route")
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

    let _ = quiet_cmd("rasdial")
        .args([WIN_VPN_PROFILE_NAME, "/DISCONNECT"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let ps_script = format!(
        "$pol = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PolicyAgent'; \
         $cur = (Get-ItemProperty -Path $pol -Name 'AssumeUDPEncapsulationContextOnSendRule' -ErrorAction SilentlyContinue).AssumeUDPEncapsulationContextOnSendRule; \
         if ($cur -ne 2) {{ \
             New-ItemProperty -Path $pol -Name 'AssumeUDPEncapsulationContextOnSendRule' -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null; \
             Restart-Service PolicyAgent, IKEEXT -Force -ErrorAction SilentlyContinue \
         }}; \
         Start-Service PolicyAgent, IKEEXT, RasMan -ErrorAction SilentlyContinue; \
         $ex = Get-VpnConnection -Name '{WIN_VPN_PROFILE_NAME}' -ErrorAction SilentlyContinue; \
         if ($null -ne $ex) {{ Set-VpnConnection -Name '{WIN_VPN_PROFILE_NAME}' -ServerAddress '{}' -TunnelType L2tp -L2tpPsk 'vpn' -AuthenticationMethod Pap,Chap,MSChapv2 -EncryptionLevel Optional -SplitTunneling:$false -RememberCredential -Force | Out-Null }} \
         else {{ Add-VpnConnection -Name '{WIN_VPN_PROFILE_NAME}' -ServerAddress '{}' -TunnelType L2tp -L2tpPsk 'vpn' -AuthenticationMethod Pap,Chap,MSChapv2 -EncryptionLevel Optional -SplitTunneling:$false -RememberCredential -Force | Out-Null }}",
        server.ip, server.ip
    );
    let _ = quiet_cmd("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let eff_max = timeout_secs.max(30);
    let started = Instant::now();
    let mut tick = 0usize;
    let mut ras_cmd = tokio::process::Command::new("rasdial");
    ras_cmd
        .args([WIN_VPN_PROFILE_NAME, "vpn", "vpn"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        ras_cmd.creation_flags(WIN_CREATE_NO_WINDOW);
    }
    let mut child = ras_cmd
        .spawn()
        .map_err(|e| format!("rasdial spawn error: {e}"))?;

    let status_opt = loop {
        if let Ok(Some(st)) = child.try_wait() {
            break Some(st);
        }
        if started.elapsed() >= Duration::from_secs(eff_max) {
            let _ = child.kill().await;
            break None;
        }
        if tick.is_multiple_of(2) {
            on_progress(ProgressEvent::Transient {
                stage: "Windows 11 L2TP/IPsec RAS dial (PSK='vpn', Zero IKEv2)".to_string(),
                elapsed_secs: started.elapsed().as_secs(),
                max_secs: eff_max,
                tick: tick / 2,
            });
        }
        tick += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    on_progress(ProgressEvent::ClearTransient);

    let Some(dial) = status_opt else {
        return Err("Windows rasdial timed out".to_string());
    };
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
        let _ = quiet_cmd("powershell")
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
    mut on_progress: impl FnMut(ProgressEvent),
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

    // Try NetworkManager first on Linux if explicitly requested (`nm`)
    if cfg!(target_os = "linux")
        && engine == "nm"
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

        let started_nm = Instant::now();
        let mut tick_nm = 0usize;
        if let Ok(mut nm_child) = tokio::process::Command::new("nmcli")
            .args([
                "--wait",
                &timeout_secs.to_string(),
                "connection",
                "up",
                &profile_name,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let nm_ok = loop {
                if let Ok(Some(st)) = nm_child.try_wait() {
                    break st.success();
                }
                if started_nm.elapsed() >= Duration::from_secs(timeout_secs + 2) {
                    let _ = nm_child.kill().await;
                    break false;
                }
                if tick_nm.is_multiple_of(2) {
                    on_progress(ProgressEvent::Transient {
                        stage: "OpenVPN handshake (NetworkManager)".to_string(),
                        elapsed_secs: started_nm.elapsed().as_secs(),
                        max_secs: timeout_secs,
                        tick: tick_nm / 2,
                    });
                }
                tick_nm += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            on_progress(ProgressEvent::ClearTransient);
            if nm_ok {
                let dev = get_tun_interfaces()
                    .keys()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "tun0".to_string());
                return Ok((dev, "nmcli-openvpn".to_string()));
            }
        }
        let _ = Command::new("nmcli")
            .args(["connection", "delete", &profile_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Direct OpenVPN daemon with live 100ms `openvpn.log` stage inspection (`PY` parity!)
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
        #[cfg(windows)]
        {
            cmd.creation_flags(WIN_DETACHED_FLAGS);
        }
        let child = cmd.spawn().map_err(|e| format!("openvpn spawn: {e}"))?;
        let _ = fs::write(&paths.ovpn_pid, format!("{}\n", child.id()));
    }

    let eff_timeout = if cfg!(target_os = "windows") {
        timeout_secs.max(38)
    } else {
        timeout_secs.max(15)
    };
    let started = Instant::now();
    let deadline = started + Duration::from_secs(eff_timeout);
    let mut tick = 0usize;

    let live_abort_markers = [
        "Initialization Sequence Completed With Errors",
        "There are no TAP-Windows adapters",
        "All tap-windows6 adapters",
        "All TAP-Windows adapters",
        "All wintun adapters",
        "Server did not request DATA_V2",
        "Blocking DNS failed",
        "ERROR: Exit Event",
        "Exiting due to fatal error",
    ];

    let mut established = false;
    while Instant::now() < deadline {
        let mut stage = "connecting";
        if let Ok(log_txt) = fs::read_to_string(&log_path) {
            if log_txt.contains("Initialization Sequence Completed With Errors") {
                break;
            }
            if log_txt.contains("Initialization Sequence Completed") {
                established = true;
                break;
            }
            if live_abort_markers.iter().any(|m| log_txt.contains(m)) {
                break;
            }
            if log_txt.matches("AUTH_FAILED").count() >= 2 {
                break;
            }
            if log_txt.contains("PUSH: Received control message") || log_txt.contains("open_tun") {
                stage = "configuring TUN adapter & routes";
            } else if log_txt.contains("SENT CONTROL")
                || log_txt.contains("Peer Connection Initiated")
            {
                stage = "requesting VPN IP & routes";
            } else if log_txt.contains("TLS: Initial packet from") || log_txt.contains("VERIFY OK:")
            {
                stage = "TLS handshake";
            } else if log_txt.contains("Attempting to establish TCP connection")
                || log_txt.contains("UDPv4 link remote")
            {
                stage = "contacting remote peer";
            }
        }

        if tick.is_multiple_of(2) {
            on_progress(ProgressEvent::Transient {
                stage: format!("OpenVPN handshake ({stage})"),
                elapsed_secs: started.elapsed().as_secs(),
                max_secs: eff_timeout,
                tick: tick / 2,
            });
        }
        tick += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    on_progress(ProgressEvent::ClearTransient);

    if established {
        let cur = get_tun_interfaces();
        let dev = cur
            .keys()
            .find(|d| !before_tun.contains_key(*d))
            .or_else(|| cur.keys().next())
            .cloned()
            .unwrap_or_else(|| {
                if cfg!(target_os = "windows") {
                    "TAP/Wintun".to_string()
                } else {
                    "tun0".to_string()
                }
            });

        apply_linux_tunnel_dns(paths, &dev, dns_servers);
        return Ok((dev, "openvpn-daemon".to_string()));
    }

    // Kill failed/timed-out OpenVPN child immediately so no background retry loop lingers
    if let Ok(txt) = fs::read_to_string(&paths.ovpn_pid)
        && let Ok(pid) = txt.trim().parse::<u32>()
        && (cfg!(target_os = "windows") || pid_matches_cmdline(pid, "openvpn"))
    {
        terminate_pid(pid, cfg!(target_os = "windows"));
    }
    let _ = fs::remove_file(&paths.ovpn_pid);

    Err("OpenVPN handshake failed or timed out".to_string())
}

/// Verifies end-to-end tunnel routing and confirms public IPv4 egress changed from `initial_ip`.
pub async fn verify_tunnel_egress(initial_ip: &str) -> Option<PublicIpTrace> {
    verify_tunnel_egress_with_progress(initial_ip, |_| {}).await
}

/// Verifies end-to-end tunnel routing with live 100ms spinner progress (`PY` parity).
pub async fn verify_tunnel_egress_with_progress(
    initial_ip: &str,
    mut on_progress: impl FnMut(ProgressEvent),
) -> Option<PublicIpTrace> {
    let max_secs = 22u64;
    let started = Instant::now();
    let mut tick = 0usize;

    let fut = async {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        for attempt in 0..4 {
            if let Some(trace) = get_public_ip_trace(Duration::from_secs(5)).await
                && !trace.ip.is_empty()
                && (initial_ip.is_empty() || trace.ip != initial_ip)
            {
                return Some(trace);
            }
            if attempt < 3 {
                tokio::time::sleep(Duration::from_millis(1300)).await;
            }
        }
        None
    };

    tokio::pin!(fut);
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let _ = interval.tick().await;
    let out = loop {
        tokio::select! {
            res = &mut fut => break res,
            _ = interval.tick() => {
                if tick.is_multiple_of(2) {
                    on_progress(ProgressEvent::Transient {
                        stage: "Tunnel up! Verifying end-to-end internet routing & egress IP".to_string(),
                        elapsed_secs: started.elapsed().as_secs(),
                        max_secs,
                        tick: tick / 2,
                    });
                }
                tick += 1;
            }
        }
    };
    on_progress(ProgressEvent::ClearTransient);
    out
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
    } else if cfg!(target_os = "windows") {
        if get_running_openvpn_pid(paths) == 0 {
            return (false, "OpenVPN daemon process exited".to_string());
        }
    } else if get_tun_interfaces().is_empty() {
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
    let mut cmd = Command::new(self_exe);
    cmd.arg("_monitor")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        cmd.creation_flags(WIN_DETACHED_FLAGS);
    }
    let Ok(child) = cmd.spawn() else {
        return 0;
    };
    let pid = child.id();
    let _ = fs::write(&paths.monitor_pid, format!("{pid}\n"));
    fix_owner(&paths.monitor_pid);
    pid
}

fn append_monitor_log(paths: &AppPaths, msg: &str) {
    let ts = now_unix_secs();
    let tod = ts % 86_400;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    let line = format!("[{hh:02}:{mm:02}:{ss:02} UTC] {msg}\n");
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

/// Attempts connection across ranked `candidates` with plain text log callback.
pub async fn engage_candidates(
    paths: &AppPaths,
    candidates: &[VpnServer],
    cfg: &ConnectSessionConfig,
    mut on_log: impl FnMut(&str),
) -> i32 {
    engage_candidates_with_progress(paths, candidates, cfg, |ev| match ev {
        ProgressEvent::Info(m) | ProgressEvent::Ok(m) | ProgressEvent::Warn(m) => on_log(&m),
        ProgressEvent::AttemptBanner {
            index,
            total,
            hostname,
            ip,
            country_short,
            speed_mbps,
            ..
        } => on_log(&format!(
            "[{index}/{total}] Testing {hostname} ({ip} - {country_short}, {speed_mbps:.1} Mbps) ..."
        )),
        ProgressEvent::Transient { .. } | ProgressEvent::ClearTransient => {}
    })
    .await
}

/// Attempts connection across ranked `candidates` following `L2TP/IPsec -> OVPN UDP -> OVPN TCP`
/// with rich `ProgressEvent` reporting (`PY` branch parity).
///
/// `Ctrl+C` rolls back L2TP/OpenVPN residue and returns [`INTERRUPTED_EXIT`] instead of
/// aborting the process (interactive console returns to the main menu).
pub async fn engage_candidates_with_progress(
    paths: &AppPaths,
    candidates: &[VpnServer],
    cfg: &ConnectSessionConfig,
    mut on_progress: impl FnMut(ProgressEvent),
) -> i32 {
    if candidates.is_empty() {
        return 1;
    }
    if cfg.in_monitor {
        return engage_candidates_body(paths, candidates, cfg, on_progress).await;
    }
    let outcome = tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => None,
        rc = engage_candidates_body(paths, candidates, cfg, &mut on_progress) => Some(rc),
    };
    match outcome {
        Some(rc) => rc,
        None => {
            on_progress(ProgressEvent::ClearTransient);
            on_progress(ProgressEvent::Warn(
                "Interrupted (Ctrl+C) — rolling back VPN Gate L2TP/OpenVPN changes ...".to_string(),
            ));
            cleanup_existing_vpn_with_progress(paths, true, true, false, &mut on_progress);
            on_progress(ProgressEvent::Ok(
                "Rolled back routes, DNS, firewall, and VPN Gate L2TP/OpenVPN profiles.".to_string(),
            ));
            INTERRUPTED_EXIT
        }
    }
}

async fn engage_candidates_body(
    paths: &AppPaths,
    candidates: &[VpnServer],
    cfg: &ConnectSessionConfig,
    mut on_progress: impl FnMut(ProgressEvent),
) -> i32 {
    cleanup_existing_vpn(paths, false, !cfg.in_monitor);

    // Check pre-VPN public IP with live spinner
    let mut ip_tick = 0usize;
    let ip_started = Instant::now();
    let trace_fut = get_public_ip_trace(Duration::from_secs(4));
    tokio::pin!(trace_fut);
    let mut ip_interval = tokio::time::interval(Duration::from_millis(100));
    let _ = ip_interval.tick().await;
    let pre_trace = loop {
        tokio::select! {
            res = &mut trace_fut => break res,
            _ = ip_interval.tick() => {
                if !cfg.in_monitor && ip_tick.is_multiple_of(2) {
                    on_progress(ProgressEvent::Transient {
                        stage: "Checking current public IP before VPN".to_string(),
                        elapsed_secs: ip_started.elapsed().as_secs(),
                        max_secs: 4,
                        tick: ip_tick / 2,
                    });
                }
                ip_tick += 1;
            }
        }
    };
    on_progress(ProgressEvent::ClearTransient);

    let initial_ip = if let Some(ref tr) = pre_trace {
        if !cfg.in_monitor {
            on_progress(ProgressEvent::Info(format!(
                "Current public IP before VPN: {} ({})",
                tr.ip, tr.loc
            )));
        }
        tr.ip.clone()
    } else {
        String::new()
    };

    let start_pos = cfg.start_index.saturating_sub(1);
    let mut ordered: Vec<VpnServer> = candidates.iter().skip(start_pos).cloned().collect();
    if cfg.limit > 0 && ordered.len() > cfg.limit {
        ordered.truncate(cfg.limit);
    }

    let mut cooldowns = load_cooldowns(paths);
    let total = ordered.len();
    let linux_l2tp_err = if cfg!(target_os = "linux") {
        probe_linux_l2tp_kernel_support().err()
    } else {
        None
    };
    let mut warned_l2tp_kernel = false;

    for (idx, srv) in ordered.iter().enumerate() {
        let mut protos = srv.candidate_protocols(cfg.proto_filter);
        if let Some(ref kerr) = linux_l2tp_err
            && protos.contains(&VpnProtocol::L2tpIpsec)
        {
            if !warned_l2tp_kernel {
                warned_l2tp_kernel = true;
                on_progress(ProgressEvent::Warn(format!(
                    "Host Linux L2TP/XFRM unavailable ({kerr}) — skipping L2TP attempts without penalizing servers."
                )));
            }
            protos.retain(|p| *p != VpnProtocol::L2tpIpsec);
        }
        if protos.is_empty() {
            continue;
        }
        on_progress(ProgressEvent::AttemptBanner {
            index: idx + 1,
            total,
            hostname: srv.hostname.clone(),
            ip: srv.ip.clone(),
            country_short: srv.country_short.clone(),
            country_long: srv.country_long.clone(),
            speed_mbps: srv.speed_mbps(),
            ping_ms: srv.ping_ms,
            score: srv.score,
        });

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
                        on_progress(ProgressEvent::Warn(format!(
                            "  -> L2TP pre-flight skipped ({pre:?})"
                        )));
                        cooldowns.mark_failed(&srv.ip, proto);
                        save_cooldowns(paths, &mut cooldowns);
                        continue;
                    }
                    on_progress(ProgressEvent::Info(if cfg!(target_os = "windows") {
                        format!(
                            "  -> Engaging Windows 11 Native L2TP/IPsec (`RASMAN`/`IKEEXT`, PSK='vpn', Zero IKEv2) on {} ...",
                            srv.ip
                        )
                    } else {
                        format!(
                            "  -> Engaging Built-In IKEv1/XFRM (PSK='vpn', Zero IKEv2) + xl2tpd on {} ...",
                            srv.ip
                        )
                    }));
                    let res = if cfg!(target_os = "windows") {
                        connect_l2tp_windows(
                            paths,
                            srv,
                            &cfg.dns_servers,
                            cfg.timeout_secs,
                            &mut on_progress,
                        )
                        .await
                        .map(|d| (d, "win-ras-l2tp".to_string()))
                    } else if cfg!(target_os = "linux") {
                        connect_l2tp_linux_builtin(
                            paths,
                            srv,
                            &cfg.dns_servers,
                            cfg.timeout_secs,
                            &mut on_progress,
                        )
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
                            on_progress(ProgressEvent::Info(format!(
                                "  -> L2TP interface {dev} up! Verifying end-to-end internet routing & egress IP ..."
                            )));
                            if let Some(trace) =
                                verify_tunnel_egress_with_progress(&initial_ip, &mut on_progress)
                                    .await
                            {
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
                                    let mon_pid = spawn_auto_reconnect_monitor(paths);
                                    if mon_pid > 0 {
                                        on_progress(ProgressEvent::Info(format!(
                                            "Auto-Reconnect Monitor armed (PID {mon_pid}, polling every {MONITOR_INTERVAL_SECONDS}s)."
                                        )));
                                    }
                                }
                                return 0;
                            }
                            on_progress(ProgressEvent::Warn(format!(
                                "  -> L2TP ({dev}) came up on {} but failed egress verification.",
                                srv.ip
                            )));
                            cleanup_existing_vpn(paths, false, !cfg.in_monitor);
                        }
                        Err(e) => {
                            on_progress(ProgressEvent::Warn(format!(
                                "  -> L2TP/IPsec negotiation failed on {} ({e}).",
                                srv.ip
                            )));
                            cleanup_existing_vpn(paths, false, !cfg.in_monitor);
                        }
                    }
                    cooldowns.mark_failed(&srv.ip, proto);
                    save_cooldowns(paths, &mut cooldowns);
                }
                VpnProtocol::OpenVpnUdp | VpnProtocol::OpenVpnTcp => {
                    let port = match proto {
                        VpnProtocol::OpenVpnTcp => srv.tcp_port,
                        _ => srv.udp_port,
                    };
                    if proto == VpnProtocol::OpenVpnTcp
                        && srv.tcp_port > 0
                        && let Ok(ip_v4) = srv.ip.parse()
                    {
                        let addr =
                            std::net::SocketAddr::new(std::net::IpAddr::V4(ip_v4), srv.tcp_port);
                        if probe_tcp(addr, Duration::from_millis(2000)).await.is_none() {
                            on_progress(ProgressEvent::Warn(format!(
                                "  -> TCP port {} unreachable; skipping.",
                                srv.tcp_port
                            )));
                            cooldowns.mark_failed(&srv.ip, proto);
                            save_cooldowns(paths, &mut cooldowns);
                            continue;
                        }
                    }
                    let port_tag = if port > 0 {
                        format!("{}:{port}", proto.as_label())
                    } else {
                        proto.as_label().to_string()
                    };
                    on_progress(ProgressEvent::Info(format!(
                        "  -> Engaging {port_tag} on {} ...",
                        srv.ip
                    )));
                    match connect_openvpn_desktop(
                        paths,
                        srv,
                        proto,
                        &cfg.engine,
                        &cfg.dns_servers,
                        cfg.timeout_secs,
                        &mut on_progress,
                    )
                    .await
                    {
                        Ok((dev, backend)) => {
                            on_progress(ProgressEvent::Info(
                                "  -> Tunnel up! Verifying end-to-end internet routing & egress IP ..."
                                    .to_string(),
                            ));
                            if let Some(trace) =
                                verify_tunnel_egress_with_progress(&initial_ip, &mut on_progress)
                                    .await
                            {
                                cooldowns.clear_server(&srv.ip);
                                save_cooldowns(paths, &mut cooldowns);
                                record_active_session(
                                    paths,
                                    srv,
                                    &port_tag,
                                    &backend,
                                    &dev,
                                    &trace,
                                    &initial_ip,
                                    cfg,
                                );
                                if cfg.auto_reconnect && !cfg.in_monitor {
                                    let mon_pid = spawn_auto_reconnect_monitor(paths);
                                    if mon_pid > 0 {
                                        on_progress(ProgressEvent::Info(format!(
                                            "Auto-Reconnect Monitor armed (PID {mon_pid}, polling every {MONITOR_INTERVAL_SECONDS}s)."
                                        )));
                                    }
                                }
                                return 0;
                            }
                            on_progress(ProgressEvent::Warn(
                                "  -> Tunnel connected but failed internet egress verification. Retrying next..."
                                    .to_string(),
                            ));
                            cleanup_existing_vpn(paths, false, !cfg.in_monitor);
                        }
                        Err(e) => {
                            on_progress(ProgressEvent::Warn(format!(
                                "  -> {port_tag} handshake failed ({e})."
                            )));
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

#[cfg(test)]
mod isa_tests {
    use super::{machine_is_aarch64, machine_is_x86_64};

    #[test]
    fn classifies_64bit_machine_names() {
        assert!(machine_is_x86_64("x86_64"));
        assert!(machine_is_x86_64("amd64"));
        assert!(!machine_is_x86_64("aarch64"));
        assert!(machine_is_aarch64("aarch64"));
        assert!(machine_is_aarch64("arm64"));
        assert!(!machine_is_aarch64("x86_64"));
        assert!(!machine_is_x86_64("i686"));
        assert!(!machine_is_aarch64("armv7l"));
    }
}
