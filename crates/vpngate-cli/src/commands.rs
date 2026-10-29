use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::{self, IsTerminal};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use vpngate_core::{
    ActiveSessionState, AppPaths, ConnectSessionConfig, CountrySummary, DiscoveryClient,
    DiscoveryOptions, INTERRUPTED_EXIT, Ikev1StateInfo, MONITOR_INTERVAL_SECONDS, NM_PROFILE_PREFIX,
    OfficialMirrorSite, ProgressEvent, ProtocolFilter, ServerCacheFile, SortBy, VpnServer,
    cleanup_existing_vpn_with_progress, detect_host_os_label, engage_candidates_with_progress,
    filter_by_country, filter_by_protocol, find_openvpn_bin, get_default_gateway,
    get_ppp_interfaces, get_public_ip_trace, get_running_monitor_pid, get_running_openvpn_pid,
    get_servers_cached_with_progress, get_tun_interfaces, is_root_or_admin, load_cached_mirrors,
    load_cooldowns, load_watchdog_pref, normalize_mirror_base_url, now_unix_secs, probe_tcp,
    prune_stale_state_if_dead, query_windows_natt_rule, read_json_opt, run_ikev1_crypto_self_test,
    save_cached_mirrors, save_cooldowns, save_watchdog_pref, sort_servers,
    cached_newer_than_installed, default_repo_slug, fetch_public_url_text, installer_script_urls,
    installed_desktop_version, load_update_cache, record_update_declined, refresh_update_cache,
    resolve_user_home, should_auto_prompt, spawn_auto_reconnect_monitor,
    stop_monitor_daemon, summarize_countries, verify_l2tp_psk_vpn, which_bin,
};

use crate::term_ui::{
    Align, BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW, clear_screen_if_tty, clear_transient_line,
    dynamic_resize_enabled, err, format_duration, format_thousands_u64, get_live_terminal_size,
    info, is_stdout_tty, ok, print_line, prompt_input, render_dynamic_box, render_dynamic_table,
    render_progress_event, request_window_resize, screen_clear_enabled, truncate_plain,
    visible_len, warn, win_vt_enabled,
};

static UAC_ALREADY_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static NO_ELEVATE_REQUESTED: AtomicBool = AtomicBool::new(false);
static SKIP_UPDATE_CHECK: AtomicBool = AtomicBool::new(false);
static UPDATE_PROMPT_DONE: AtomicBool = AtomicBool::new(false);

pub fn set_uac_already_attempted(val: bool) {
    UAC_ALREADY_ATTEMPTED.store(val, Ordering::Relaxed);
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn uac_already_attempted() -> bool {
    UAC_ALREADY_ATTEMPTED.load(Ordering::Relaxed)
}

pub fn set_no_elevate_requested(val: bool) {
    NO_ELEVATE_REQUESTED.store(val, Ordering::Relaxed);
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn no_elevate_requested() -> bool {
    NO_ELEVATE_REQUESTED.load(Ordering::Relaxed)
}

pub fn set_skip_update_check(val: bool) {
    SKIP_UPDATE_CHECK.store(val, Ordering::Relaxed);
}

pub fn skip_update_check() -> bool {
    SKIP_UPDATE_CHECK.load(Ordering::Relaxed)
}

/// Quotes a single command-line argument using standard Win32 `CommandLineToArgvW` rules.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 4);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            out.push_str(&"\\".repeat(backslashes * 2 + 1));
            out.push('"');
            backslashes = 0;
        } else {
            if backslashes > 0 {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
            }
            out.push(ch);
        }
    }
    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }
    out.push('"');
    out
}

#[cfg(windows)]
pub mod win_uac {
    use std::env;
    use std::ffi::c_void;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use super::quote_windows_arg;

    const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
    const SW_SHOWNORMAL: i32 = 1;
    const INFINITE: u32 = 0xFFFF_FFFF;

    #[repr(C)]
    struct ShellExecuteInfoW {
        cb_size: u32,
        f_mask: u32,
        hwnd: *mut c_void,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: *mut c_void,
        lp_id_list: *mut c_void,
        lp_class: *const u16,
        hkey_class: *mut c_void,
        dw_hot_key: u32,
        h_icon_or_monitor: *mut c_void,
        h_process: *mut c_void,
    }

    const _: () = assert!(std::mem::size_of::<ShellExecuteInfoW>() == 112);

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteExW(exec_info: *mut ShellExecuteInfoW) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(process: *mut c_void, exit_code: *mut u32) -> i32;
        fn CloseHandle(object: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    fn to_wide_nul(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    /// Launches `exe` directly with native Win32 `"runas"` UAC elevation (never `wt.exe` AppX alias).
    pub fn run_elevated(exe: &Path, args: &[String], wait: bool) -> Result<i32, u32> {
        let verb_w = to_wide_nul("runas");
        let file_w = to_wide_nul(&exe.display().to_string());
        let params_str = args
            .iter()
            .map(|a| quote_windows_arg(a))
            .collect::<Vec<_>>()
            .join(" ");
        let params_w = to_wide_nul(&params_str);
        let cwd_w = env::current_dir()
            .ok()
            .map(|d| to_wide_nul(&d.display().to_string()));

        let mut sei = ShellExecuteInfoW {
            cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: if wait { SEE_MASK_NOCLOSEPROCESS } else { 0 },
            hwnd: null_mut(),
            lp_verb: verb_w.as_ptr(),
            lp_file: file_w.as_ptr(),
            lp_parameters: if params_str.is_empty() {
                null()
            } else {
                params_w.as_ptr()
            },
            lp_directory: cwd_w.as_ref().map_or(null(), |v| v.as_ptr()),
            n_show: SW_SHOWNORMAL,
            h_inst_app: null_mut(),
            lp_id_list: null_mut(),
            lp_class: null(),
            hkey_class: null_mut(),
            dw_hot_key: 0,
            h_icon_or_monitor: null_mut(),
            h_process: null_mut(),
        };

        // SAFETY: All UTF-16 buffers outlive `ShellExecuteExW`, and `h_process` is closed if returned.
        unsafe {
            if ShellExecuteExW(&mut sei) == 0 {
                return Err(GetLastError());
            }
            if wait && !sei.h_process.is_null() {
                let _ = WaitForSingleObject(sei.h_process, INFINITE);
                let mut exit_code: u32 = 1;
                let _ = GetExitCodeProcess(sei.h_process, &mut exit_code);
                let _ = CloseHandle(sei.h_process);
                return Ok(exit_code as i32);
            }
            if !sei.h_process.is_null() {
                let _ = CloseHandle(sei.h_process);
            }
            Ok(0)
        }
    }
}

fn parse_custom_mirrors(urls: &[String]) -> Vec<OfficialMirrorSite> {
    let mut out = Vec::new();
    for raw in urls {
        if let Some((base_url, portal_url)) = normalize_mirror_base_url(raw)
            && !out
                .iter()
                .any(|m: &OfficialMirrorSite| m.base_url == base_url)
        {
            out.push(OfficialMirrorSite {
                base_url,
                portal_url,
                location: "Custom".to_string(),
                source: "custom".to_string(),
            });
        }
    }
    out
}

async fn trace_public_ip_with_spinner(
    label: &str,
    timeout: Duration,
) -> Option<vpngate_core::PublicIpTrace> {
    let fut = get_public_ip_trace(timeout);
    tokio::pin!(fut);
    let started = Instant::now();
    let max_secs = timeout.as_secs().max(1);
    let mut tick = 0usize;
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let _ = interval.tick().await;
    let res = loop {
        tokio::select! {
            out = &mut fut => break out,
            _ = interval.tick() => {
                if tick.is_multiple_of(2) {
                    render_progress_event(ProgressEvent::Transient {
                        stage: label.to_string(),
                        elapsed_secs: started.elapsed().as_secs(),
                        max_secs,
                        tick: tick / 2,
                    });
                }
                tick += 1;
            }
        }
    };
    clear_transient_line();
    res
}

pub fn elevate_self(paths: &AppPaths, sub_args: &[String]) -> i32 {
    let Ok(self_exe) = env::current_exe() else {
        err("Could not determine current executable path for elevation.");
        return 1;
    };
    #[cfg(unix)]
    {
        let _ = paths;
        let status = Command::new("sudo")
            .arg("-E")
            .arg(self_exe)
            .args(sub_args)
            .status();
        match status {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                err(&format!("Failed launching sudo: {e}"));
                1
            }
        }
    }
    #[cfg(windows)]
    {
        if uac_already_attempted() {
            err(
                "Administrator token was not granted after UAC elevation. \
                 Right-click PowerShell or Windows Terminal -> 'Run as Administrator' and retry.",
            );
            return 1;
        }
        let mut full_args = vec![
            "--uac-elevated".to_string(),
            "--cache-dir".to_string(),
            paths.cache_dir.display().to_string(),
        ];
        full_args.extend_from_slice(sub_args);
        match win_uac::run_elevated(&self_exe, &full_args, true) {
            Ok(code) => code,
            Err(1223) => {
                warn("Windows UAC elevation prompt was cancelled.");
                1
            }
            Err(code) => {
                err(&format!(
                    "Windows UAC elevation failed (Win32 error {code}). \
                     Right-click PowerShell -> 'Run as Administrator' and retry."
                ));
                1
            }
        }
    }
}

#[cfg(windows)]
fn launch_elevated_interactive_console(paths: &AppPaths) -> bool {
    let Ok(self_exe) = env::current_exe() else {
        return false;
    };
    let mut args = vec![
        "--uac-elevated".to_string(),
        "--cache-dir".to_string(),
        paths.cache_dir.display().to_string(),
    ];
    if !dynamic_resize_enabled() {
        args.push("--no-resize".to_string());
    }
    if !screen_clear_enabled() {
        args.push("--no-clear".to_string());
    }
    win_uac::run_elevated(&self_exe, &args, false).is_ok()
}

fn render_established_session_summary(st: &ActiveSessionState) -> io::Result<()> {
    ok(&format!(
        "ESTABLISHED VPN! Server: {BOLD}{}{RESET} ({} - {}) | Protocol: {BOLD}{}{RESET} [{}] | Egress IP: {GREEN}{}{RESET} ({})",
        st.hostname,
        st.country_short,
        st.country_long,
        st.protocol,
        st.backend,
        st.egress_ip,
        st.egress_loc
    ));
    if is_stdout_tty() {
        let box_lines = vec![
            Some(format!("{GREEN}{BOLD}● VPN Tunnel Established{RESET}")),
            None,
            Some(format!(
                "Server    : {BOLD}{}{RESET} ({})",
                st.hostname, st.server_ip
            )),
            Some(format!(
                "Region    : {BOLD}{}{RESET} — {}",
                st.country_short, st.country_long
            )),
            Some(format!(
                "Protocol  : {BOLD}{}{RESET} ({})",
                st.protocol, st.backend
            )),
            Some(format!(
                "Interface : {GREEN}{}{RESET}   |   DNS Locked : {CYAN}{}{RESET}",
                st.device, st.dns
            )),
            Some(format!(
                "Egress IP : {GREEN}{BOLD}{}{RESET} (Cloudflare Loc: {BOLD}{}{RESET})",
                st.egress_ip, st.egress_loc
            )),
        ];
        render_dynamic_box(&box_lines, 3, 64)?;
    }
    Ok(())
}

pub fn print_countries_table(
    rows: &[CountrySummary],
    proto_label: &str,
    indexed: bool,
) -> io::Result<()> {
    if rows.is_empty() {
        warn(&format!(
            "No countries found for protocol filter '{proto_label}'."
        ));
        return Ok(());
    }

    let base_headers = [
        "CODE",
        "COUNTRY / REGION",
        "TOTAL",
        "L2TP/IPSEC",
        "OVPN(UDP)",
        "OVPN(TCP)",
        "MAX SPEED",
        "MIN PING",
    ];
    let mut headers: Vec<&str> = Vec::new();
    let mut aligns: Vec<Align> = Vec::new();
    let mut flex_cols: HashMap<usize, usize> = HashMap::new();
    let mut col_colors: HashMap<usize, &str> = HashMap::new();

    if indexed {
        headers.push("#");
        aligns.push(Align::Right);
        flex_cols.insert(2, 12);
        col_colors.insert(0, CYAN);
        col_colors.insert(1, GREEN);
    } else {
        flex_cols.insert(1, 12);
        col_colors.insert(0, GREEN);
    }
    headers.extend_from_slice(&base_headers);
    aligns.extend_from_slice(&[
        Align::Left,
        Align::Left,
        Align::Right,
        Align::Right,
        Align::Right,
        Align::Right,
        Align::Right,
        Align::Right,
    ]);

    let mut table_rows = Vec::with_capacity(rows.len());
    let mut total_srv = 0usize;
    let mut total_l2tp = 0usize;
    let mut total_ovpn = 0usize;

    for (i, r) in rows.iter().enumerate() {
        total_srv += r.total_servers;
        total_l2tp += r.l2tp_count;
        total_ovpn += r.openvpn_udp_count.max(r.openvpn_tcp_count);
        let ping_s = if r.best_ping_ms < 9999 {
            format!("{} ms", r.best_ping_ms)
        } else {
            "N/A".to_string()
        };
        let mut row = Vec::with_capacity(9);
        if indexed {
            row.push((i + 1).to_string());
        }
        row.push(r.country_short.clone());
        row.push(r.country_long.clone());
        row.push(r.total_servers.to_string());
        row.push(r.l2tp_count.to_string());
        row.push(r.openvpn_udp_count.to_string());
        row.push(r.openvpn_tcp_count.to_string());
        row.push(format!("{:.1} Mbps", r.max_speed_mbps()));
        row.push(ping_s);
        table_rows.push(row);
    }

    let footer = vec![format!(
        "Total: {BOLD}{}{RESET} regions | {BOLD}{total_srv}{RESET} servers (L2TP/IPsec: {BOLD}{total_l2tp}{RESET}, OpenVPN: {BOLD}{total_ovpn}{RESET} | filter: {CYAN}{proto_label}{RESET})",
        rows.len()
    )];
    render_dynamic_table(
        &headers,
        &table_rows,
        &aligns,
        &flex_cols,
        &col_colors,
        &footer,
        3,
    )
}

pub async fn cmd_countries(
    paths: &AppPaths,
    proto_filter: ProtocolFilter,
    force_refresh: bool,
    custom_mirrors: &[String],
) -> io::Result<i32> {
    clear_screen_if_tty();
    let extra = parse_custom_mirrors(custom_mirrors);
    let servers =
        match get_servers_cached_with_progress(paths, force_refresh, &extra, render_progress_event)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                err(&format!("Failed fetching VPN Gate server pool: {e}"));
                return Ok(1);
            }
        };
    let filtered = filter_by_protocol(&servers, proto_filter);
    let rows = summarize_countries(&filtered);
    if rows.is_empty() {
        warn(&format!(
            "No countries found for protocol filter '{}'.",
            proto_filter.as_cli_str()
        ));
        return Ok(1);
    }
    print_countries_table(&rows, proto_filter.as_cli_str(), false)?;
    Ok(0)
}

pub async fn cmd_list(
    paths: &AppPaths,
    country: Option<&str>,
    proto_filter: ProtocolFilter,
    sort_by: SortBy,
    limit: usize,
    force_refresh: bool,
    custom_mirrors: &[String],
) -> io::Result<i32> {
    clear_screen_if_tty();
    let extra = parse_custom_mirrors(custom_mirrors);
    let servers =
        match get_servers_cached_with_progress(paths, force_refresh, &extra, render_progress_event)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                err(&format!("Failed fetching VPN Gate server pool: {e}"));
                return Ok(1);
            }
        };
    let mut matched = filter_by_country(&filter_by_protocol(&servers, proto_filter), country);
    sort_servers(&mut matched, sort_by, proto_filter);

    if matched.is_empty() {
        warn(&format!(
            "No servers matched country='{}' proto='{}'.",
            country.unwrap_or("ALL"),
            proto_filter.as_cli_str()
        ));
        return Ok(1);
    }

    let total_matched = matched.len();
    let shown = if limit > 0 && limit < total_matched {
        &matched[..limit]
    } else {
        &matched[..]
    };

    let headers = [
        "#",
        "CC",
        "COUNTRY",
        "HOSTNAME",
        "IP ADDRESS",
        "PROTOCOLS",
        "SPEED",
        "PING",
        "SCORE",
    ];
    let aligns = [
        Align::Right,
        Align::Left,
        Align::Left,
        Align::Left,
        Align::Left,
        Align::Left,
        Align::Right,
        Align::Right,
        Align::Right,
    ];
    let mut flex_cols = HashMap::new();
    flex_cols.insert(2, 9);
    flex_cols.insert(3, 10);
    flex_cols.insert(5, 10);

    let mut col_colors = HashMap::new();
    col_colors.insert(0, CYAN);
    col_colors.insert(1, GREEN);

    let mut table_rows = Vec::with_capacity(shown.len());
    for (idx, s) in shown.iter().enumerate() {
        let mut protos = Vec::new();
        if s.l2tp {
            protos.push("L2TP".to_string());
        }
        if s.openvpn {
            let mut ports = Vec::new();
            if s.udp_port > 0 {
                ports.push(format!("U:{}", s.udp_port));
            }
            if s.tcp_port > 0 {
                ports.push(format!("T:{}", s.tcp_port));
            }
            protos.push(format!(
                "OVPN({})",
                if ports.is_empty() {
                    "Yes".to_string()
                } else {
                    ports.join(",")
                }
            ));
        }
        let ping_s = if s.ping_ms < 9999 {
            format!("{} ms", s.ping_ms)
        } else {
            "N/A".to_string()
        };
        table_rows.push(vec![
            (idx + 1).to_string(),
            s.country_short.clone(),
            s.country_long.clone(),
            s.hostname.clone(),
            s.ip.clone(),
            protos.join(" "),
            format!("{:.1} Mbps", s.speed_mbps()),
            ping_s,
            format_thousands_u64(s.score),
        ]);
    }

    let footer = vec![format!(
        "Showing {BOLD}{}{RESET} of {BOLD}{total_matched}{RESET} matching servers.",
        shown.len()
    )];
    render_dynamic_table(
        &headers,
        &table_rows,
        &aligns,
        &flex_cols,
        &col_colors,
        &footer,
        3,
    )?;
    Ok(0)
}

pub struct ConnectArgs {
    pub country: String,
    pub proto_filter: ProtocolFilter,
    pub sort_by: SortBy,
    pub limit: usize,
    pub timeout_secs: u64,
    pub engine: String,
    pub dns: String,
    pub start_index: usize,
    pub force_refresh: bool,
    pub auto_reconnect_override: Option<bool>,
    pub custom_mirrors: Vec<String>,
}

pub async fn cmd_connect(paths: &AppPaths, args: &ConnectArgs) -> io::Result<i32> {
    if args.country.trim().is_empty() {
        err(
            "Please specify a target country/region with -c / --country (e.g. -c JP, -c KR, -c all).",
        );
        return Ok(1);
    }
    let auto_reconnect = args
        .auto_reconnect_override
        .unwrap_or_else(|| load_watchdog_pref(paths));

    if !is_root_or_admin() {
        clear_screen_if_tty();
        info(if cfg!(windows) {
            "Elevating privileges to Administrator to configure VPN network interface ..."
        } else {
            "Elevating privileges with sudo to configure VPN network interface ..."
        });
        let mut sub = vec![
            "connect".to_string(),
            "-c".to_string(),
            args.country.clone(),
            "-p".to_string(),
            args.proto_filter.as_cli_str().to_string(),
            "-s".to_string(),
            args.sort_by.as_cli_str().to_string(),
            "-n".to_string(),
            args.limit.to_string(),
            "-t".to_string(),
            args.timeout_secs.to_string(),
            "-e".to_string(),
            args.engine.clone(),
            "--dns".to_string(),
            args.dns.clone(),
            "--start".to_string(),
            args.start_index.to_string(),
        ];
        for m in &args.custom_mirrors {
            sub.push("--mirror".to_string());
            sub.push(m.clone());
        }
        if args.force_refresh {
            sub.push("-r".to_string());
        }
        if !dynamic_resize_enabled() {
            sub.push("--no-resize".to_string());
        }
        if !screen_clear_enabled() {
            sub.push("--no-clear".to_string());
        }
        sub.push(if auto_reconnect {
            "--autoreconnect".to_string()
        } else {
            "--no-autoreconnect".to_string()
        });
        let rc = elevate_self(paths, &sub);
        if cfg!(windows) {
            if rc == 0
                && let Some(st) = read_json_opt::<ActiveSessionState>(&paths.active_state)
            {
                render_established_session_summary(&st)?;
            } else if rc != 0 {
                err("Elevated connection session did not complete or was cancelled.");
            }
        }
        return Ok(rc);
    }

    clear_screen_if_tty();
    let extra = parse_custom_mirrors(&args.custom_mirrors);
    let servers = tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            warn("Interrupted — returning without connecting.");
            return Ok(INTERRUPTED_EXIT);
        }
        res = get_servers_cached_with_progress(
            paths,
            args.force_refresh,
            &extra,
            render_progress_event,
        ) => match res {
            Ok(s) => s,
            Err(e) => {
                err(&format!("Failed fetching VPN Gate server pool: {e}"));
                return Ok(1);
            }
        }
    };
    let mut candidates = filter_by_country(
        &filter_by_protocol(&servers, args.proto_filter),
        Some(&args.country),
    );
    sort_servers(&mut candidates, args.sort_by, args.proto_filter);

    if candidates.is_empty() {
        err(&format!(
            "No VPN Gate servers found for region '{}' with protocol '{}'.",
            args.country,
            args.proto_filter.as_cli_str()
        ));
        info("Tip: Run 'vpngate countries' to see available regions for L2TP and OpenVPN.");
        return Ok(1);
    }

    let dns_servers: Vec<String> = args
        .dns
        .replace(',', " ")
        .split_whitespace()
        .map(ToString::to_string)
        .collect();

    let cfg = ConnectSessionConfig {
        region_label: args.country.clone(),
        proto_filter: args.proto_filter,
        sort_by: args.sort_by,
        limit: args.limit,
        timeout_secs: args.timeout_secs,
        engine: args.engine.clone(),
        dns_servers: if dns_servers.is_empty() {
            vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
        } else {
            dns_servers
        },
        start_index: args.start_index.max(1),
        auto_reconnect,
        in_monitor: false,
    };

    info(&format!(
        "Selected {} candidate server(s) for region '{}' (Order: L2TP/IPsec -> OVPN UDP -> OVPN TCP) ...",
        candidates.len(),
        args.country.to_ascii_uppercase()
    ));

    let rc = engage_candidates_with_progress(paths, &candidates, &cfg, render_progress_event).await;
    if rc == INTERRUPTED_EXIT {
        warn("Connection interrupted. VPN Gate L2TP and OpenVPN profile residue was removed.");
        return Ok(INTERRUPTED_EXIT);
    }
    if rc == 0
        && let Some(st) = read_json_opt::<ActiveSessionState>(&paths.active_state)
    {
        render_established_session_summary(&st)?;
    } else if rc != 0 {
        err("Exhausted candidate servers without establishing a verified tunnel.");
    }
    Ok(rc)
}

pub async fn cmd_disconnect(paths: &AppPaths) -> io::Result<i32> {
    if !is_root_or_admin() {
        clear_screen_if_tty();
        info(if cfg!(windows) {
            "Elevating privileges to Administrator to disconnect VPN ..."
        } else {
            "Elevating privileges with sudo to disconnect VPN ..."
        });
        let mut sub = vec!["disconnect".to_string()];
        if !dynamic_resize_enabled() {
            sub.push("--no-resize".to_string());
        }
        if !screen_clear_enabled() {
            sub.push("--no-clear".to_string());
        }
        let rc = elevate_self(paths, &sub);
        if cfg!(windows) && rc == 0 {
            ok("Disconnected from VPN Gate, removed L2TP/OpenVPN profiles, and restored routes, DNS, and firewall.");
            if let Some(trace) = trace_public_ip_with_spinner(
                "Verifying restored host public egress IP",
                Duration::from_secs(5),
            )
            .await
            {
                info(&format!("Current public IP: {} ({})", trace.ip, trace.loc));
            }
        }
        return Ok(rc);
    }

    clear_screen_if_tty();
    info("Tearing down active VPN tunnel and removing VPN Gate L2TP/OpenVPN profile residue ...");
    cleanup_existing_vpn_with_progress(paths, true, true, false, render_progress_event);
    ok("Disconnected from VPN Gate, removed L2TP/OpenVPN profiles, and restored routes, DNS, and firewall.");
    if let Some(trace) = trace_public_ip_with_spinner(
        "Verifying restored host public egress IP",
        Duration::from_secs(5),
    )
    .await
    {
        info(&format!("Current public IP: {} ({})", trace.ip, trace.loc));
    }
    Ok(0)
}

pub async fn cmd_refresh(paths: &AppPaths, custom_mirrors: &[String]) -> io::Result<i32> {
    clear_screen_if_tty();
    let mut cd = load_cooldowns(paths);
    let cleared = cd.clear_all();
    save_cooldowns(paths, &mut cd);
    if cleared > 0 {
        info(&format!(
            "Cleared {cleared} penalized server cooldown entry/entries."
        ));
    }

    let extra = parse_custom_mirrors(custom_mirrors);
    let servers =
        match get_servers_cached_with_progress(paths, true, &extra, render_progress_event).await {
            Ok(s) => s,
            Err(e) => {
                err(&format!("Server pool refresh failed: {e}"));
                return Ok(1);
            }
        };

    let l2tp_cnt = servers.iter().filter(|s| s.l2tp).count();
    let ovpn_udp_cnt = servers.iter().filter(|s| s.supports_openvpn_udp()).count();
    let ovpn_tcp_cnt = servers.iter().filter(|s| s.supports_openvpn_tcp()).count();
    let regions_cnt: BTreeSet<&str> = servers.iter().map(|s| s.country_short.as_str()).collect();
    let mirrors_cnt = load_cached_mirrors(paths).len();

    let box_lines = vec![
        Some(format!(
            "{GREEN}{BOLD}● Server Pool & Mirror Cache Updated{RESET}"
        )),
        None,
        Some(format!(
            "Total Records   : {BOLD}{}{RESET} unique servers across {BOLD}{}{RESET} regions",
            servers.len(),
            regions_cnt.len()
        )),
        Some(format!(
            "L2TP/IPsec      : {GREEN}{BOLD}{l2tp_cnt}{RESET} cryptographically verified (PSK='vpn', Zero IKEv2)"
        )),
        Some(format!(
            "OpenVPN Pool    : {CYAN}{BOLD}{ovpn_udp_cnt}{RESET} UDP  |  {CYAN}{BOLD}{ovpn_tcp_cnt}{RESET} TCP"
        )),
        Some(format!(
            "Official Mirrors: {BOLD}{mirrors_cnt}{RESET} VPNGate mirror portal(s) cached for firewall failover"
        )),
        Some(format!(
            "Saved Cache     : {DIM}{}{RESET}",
            paths.servers_cache.display()
        )),
    ];
    render_dynamic_box(&box_lines, 2, 72)?;
    Ok(0)
}

pub async fn cmd_mirrors(paths: &AppPaths, custom_mirrors: &[String]) -> io::Result<i32> {
    clear_screen_if_tty();
    let _ = paths.ensure_dirs();
    let mut seeds = parse_custom_mirrors(custom_mirrors);
    for m in load_cached_mirrors(paths) {
        if !seeds.iter().any(|x| x.base_url == m.base_url) {
            seeds.push(m);
        }
    }

    let opts = DiscoveryOptions {
        seed_mirrors: seeds,
        ..DiscoveryOptions::default()
    };
    let client = match DiscoveryClient::new(opts) {
        Ok(c) => c,
        Err(e) => {
            err(&format!("Failed initializing discovery client: {e}"));
            return Ok(1);
        }
    };

    let results = client
        .discover_and_probe_mirror_sites(render_progress_event)
        .await;
    if results.is_empty() {
        return Ok(1);
    }

    let all_mirrors: Vec<OfficialMirrorSite> = results.iter().map(|r| r.mirror.clone()).collect();
    save_cached_mirrors(paths, &all_mirrors);

    let headers = [
        "#",
        "STATUS",
        "OFFICIAL MIRROR PORTAL URL",
        "LOCATION",
        "SOURCE",
        "SERVERS",
        "RTT",
    ];
    let aligns = [
        Align::Right,
        Align::Left,
        Align::Left,
        Align::Left,
        Align::Left,
        Align::Right,
        Align::Right,
    ];
    let mut flex_cols = HashMap::new();
    flex_cols.insert(2, 24);
    flex_cols.insert(3, 8);
    let mut col_colors = HashMap::new();
    col_colors.insert(0, CYAN);

    let mut online_cnt = 0usize;
    let mut rows = Vec::with_capacity(results.len());
    for (i, r) in results.iter().enumerate() {
        if r.reachable {
            online_cnt += 1;
        }
        let st = if r.reachable {
            "ONLINE".to_string()
        } else {
            "OFFLINE".to_string()
        };
        let rtt_s = r
            .rtt_ms
            .map(|ms| format!("{ms} ms"))
            .unwrap_or_else(|| "N/A".to_string());
        let srv_s = if r.servers_count > 0 {
            r.servers_count.to_string()
        } else {
            "-".to_string()
        };
        rows.push(vec![
            (i + 1).to_string(),
            st,
            r.mirror.portal_url.clone(),
            r.mirror.location.clone(),
            r.mirror.source.clone(),
            srv_s,
            rtt_s,
        ]);
    }

    let footer = vec![format!(
        "Official VPNGate Mirror Sites: {GREEN}{BOLD}{online_cnt}{RESET}/{BOLD}{}{RESET} online  |  Cached in {DIM}{}{RESET}",
        results.len(),
        paths.mirrors_cache.display()
    )];
    render_dynamic_table(
        &headers,
        &rows,
        &aligns,
        &flex_cols,
        &col_colors,
        &footer,
        3,
    )?;
    Ok(0)
}

pub async fn cmd_status(paths: &AppPaths) -> io::Result<i32> {
    clear_screen_if_tty();
    let _ = paths.ensure_dirs();
    prune_stale_state_if_dead(paths);

    let trace = trace_public_ip_with_spinner(
        "Querying live tunnel & Cloudflare egress status",
        Duration::from_secs(5),
    )
    .await;

    let mut box_lines: Vec<Option<String>> = vec![
        Some(format!(
            "{CYAN}{BOLD}VPN Gate v{} — Live Connection Status{RESET}",
            env!("CARGO_PKG_VERSION")
        )),
        None,
    ];

    if let Some(st) = read_json_opt::<ActiveSessionState>(&paths.active_state) {
        if st.status == "reconnecting" {
            box_lines.push(Some(format!(
                "Session   : {YELLOW}AUTO-RECONNECTING{RESET} -> Region {BOLD}{}{RESET} (last drop: {})",
                st.region_label, st.last_drop_reason
            )));
        } else {
            let up = format_duration(now_unix_secs().saturating_sub(st.connected_at));
            box_lines.push(Some(format!(
                "Session   : {GREEN}● ACTIVE{RESET} -> {BOLD}{}{RESET} ({})  |  Uptime: {BOLD}{up}{RESET}",
                st.hostname, st.server_ip
            )));
            box_lines.push(Some(format!(
                "Region    : {BOLD}{}{RESET} — {}",
                st.country_short, st.country_long
            )));
            box_lines.push(Some(format!(
                "Protocol  : {BOLD}{}{RESET} ({})  |  DNS: {CYAN}{}{RESET}",
                st.protocol, st.backend, st.dns
            )));
        }
    } else {
        box_lines.push(Some(format!(
            "Session   : {YELLOW}○ Disconnected (no active vpngate session){RESET}"
        )));
    }

    let mon_pid = get_running_monitor_pid(paths);
    let wd_pref = load_watchdog_pref(paths);
    if mon_pid > 0 {
        box_lines.push(Some(format!(
            "Watchdog  : {GREEN}ARMED{RESET} (PID {mon_pid} — health check every {MONITOR_INTERVAL_SECONDS}s)"
        )));
    } else if wd_pref {
        box_lines.push(Some(format!(
            "Watchdog  : {CYAN}Enabled{RESET} (standby — arms on next connect)"
        )));
    } else {
        box_lines.push(Some(format!("Watchdog  : {DIM}Disabled (default){RESET}")));
    }

    if let Ok(log_txt) = fs::read_to_string(&paths.monitor_log)
        && let Some(last) = log_txt.lines().rev().find(|l| !l.trim().is_empty())
    {
        box_lines.push(Some(format!(
            "Last Event: {DIM}{}{RESET}",
            truncate_plain(last.trim(), 66)
        )));
    }

    if which_bin("nmcli").is_some()
        && let Ok(out) = Command::new("nmcli")
            .args([
                "-t",
                "-f",
                "NAME,TYPE,DEVICE",
                "connection",
                "show",
                "--active",
            ])
            .output()
    {
        for ln in String::from_utf8_lossy(&out.stdout).lines() {
            if ln.contains(":vpn:") || ln.starts_with(NM_PROFILE_PREFIX) {
                box_lines.push(Some(format!("NM Tunnel : {GREEN}{ln}{RESET}")));
            }
        }
    }

    let ppp = get_ppp_interfaces();
    if !ppp.is_empty() {
        let desc: Vec<String> = ppp.iter().map(|(k, v)| format!("{k} ({v})")).collect();
        box_lines.push(Some(format!(
            "PPP Link  : {GREEN}{}{RESET}",
            desc.join(", ")
        )));
    }

    if let Some(ike_st) = read_json_opt::<Ikev1StateInfo>(&paths.ikev1_state)
        && ike_st.status == "ready"
    {
        box_lines.push(Some(format!(
            "XFRM SA   : {GREEN}{}/HMAC-SHA1-96{RESET} (ESPinUDP:{}, SPI {}/{})",
            ike_st.esp_alg.to_ascii_uppercase(),
            ike_st.local_port,
            ike_st.spi_in,
            ike_st.spi_out
        )));
    }

    let tun = get_tun_interfaces();
    if !tun.is_empty() {
        let desc: Vec<String> = tun.iter().map(|(k, v)| format!("{k} ({v})")).collect();
        box_lines.push(Some(format!(
            "TUN Link  : {GREEN}{}{RESET}",
            desc.join(", ")
        )));
    } else if cfg!(target_os = "windows") {
        let ovpn_pid = get_running_openvpn_pid(paths);
        if ovpn_pid > 0 {
            box_lines.push(Some(format!(
                "TUN Link  : {GREEN}TAP/Wintun (OpenVPN PID {ovpn_pid}){RESET}"
            )));
        }
    }

    let active_cd = load_cooldowns(paths).active_count();
    if active_cd > 0 {
        box_lines.push(Some(format!(
            "Cooldowns : {YELLOW}{active_cd} failed/dropped server(s) penalized for 30m{RESET}"
        )));
    }

    if let Some(tr) = trace {
        box_lines.push(Some(format!(
            "Egress IP : {GREEN}{BOLD}{}{RESET} (Cloudflare Loc: {BOLD}{}{RESET})",
            tr.ip, tr.loc
        )));
    } else {
        box_lines.push(Some(format!(
            "Egress IP : {RED}Unreachable / settling{RESET}"
        )));
    }

    render_dynamic_box(&box_lines, 3, 66)?;
    Ok(0)
}

pub fn cmd_watchdog(paths: &AppPaths, mode_raw: &str) -> i32 {
    clear_screen_if_tty();
    prune_stale_state_if_dead(paths);
    let wd_pref = load_watchdog_pref(paths);
    let mon_pid = get_running_monitor_pid(paths);
    let mode = match mode_raw.to_ascii_lowercase().as_str() {
        "toggle" => {
            if mon_pid > 0 || wd_pref {
                "off"
            } else {
                "on"
            }
        }
        "on" => "on",
        "off" => "off",
        _ => "status",
    };

    if mode == "status" {
        if mon_pid > 0 {
            ok(&format!(
                "Auto-Reconnect Watchdog is {GREEN}ARMED{RESET} (PID {mon_pid}, polling every {MONITOR_INTERVAL_SECONDS}s)."
            ));
        } else if wd_pref {
            ok(&format!(
                "Auto-Reconnect Watchdog is {CYAN}ENABLED{RESET} (standby — will arm automatically on next VPN connection)."
            ));
        } else {
            info(&format!(
                "Auto-Reconnect Watchdog is {YELLOW}DISABLED{RESET} (default)."
            ));
        }
        return 0;
    }

    let has_active = paths.active_state.exists() || mon_pid > 0;
    if !has_active {
        let enable = mode == "on";
        let _ = save_watchdog_pref(paths, enable);
        if enable {
            ok(&format!(
                "Auto-Reconnect Watchdog {CYAN}ENABLED{RESET} (will arm automatically on your next VPN connection)."
            ));
        } else {
            ok(&format!("Auto-Reconnect Watchdog {YELLOW}DISABLED{RESET}."));
        }
        return 0;
    }

    if !is_root_or_admin() {
        info(&format!(
            "Elevating privileges to {} active session Watchdog ...",
            if mode == "on" { "arm" } else { "stop" }
        ));
        return elevate_self(paths, &["watchdog".to_string(), mode.to_string()]);
    }

    if mode == "off" {
        let _ = save_watchdog_pref(paths, false);
        stop_monitor_daemon(paths);
        if let Some(mut st) = read_json_opt::<ActiveSessionState>(&paths.active_state) {
            st.auto_reconnect = false;
            let _ = vpngate_core::atomic_write_json(&paths.active_state, &st);
        }
        ok(&format!("Auto-Reconnect Watchdog {YELLOW}DISABLED{RESET}."));
        0
    } else {
        let _ = save_watchdog_pref(paths, true);
        if let Some(mut st) = read_json_opt::<ActiveSessionState>(&paths.active_state) {
            st.auto_reconnect = true;
            let _ = vpngate_core::atomic_write_json(&paths.active_state, &st);
            let pid = spawn_auto_reconnect_monitor(paths);
            if pid > 0 {
                ok(&format!(
                    "Auto-Reconnect Watchdog {GREEN}ARMED{RESET} for active session (PID {pid})."
                ));
            } else {
                warn("Watchdog enabled, but could not spawn background monitor process.");
            }
        }
        0
    }
}

pub fn cmd_doctor(paths: &AppPaths) -> io::Result<i32> {
    clear_screen_if_tty();
    let os_label = detect_host_os_label();
    let mut lines: Vec<Option<String>> = vec![
        Some(format!(
            "{CYAN}{BOLD}VPN Gate v{} ({os_label}) — System Readiness & Diagnostics{RESET}",
            env!("CARGO_PKG_VERSION")
        )),
        Some(format!(
            "CPU ISA      : {GREEN}x86_64 native{RESET} — desktop supports x64 hardware only"
        )),
    ];
    if let Some(uc) = load_update_cache(paths) {
        if let Some(remote) = vpngate_core::DesktopVersion::parse(&uc.remote_version) {
            let local = installed_desktop_version();
            if remote > local {
                lines.push(Some(format!(
                    "Desktop Ver  : {YELLOW}UPDATE{RESET} — {local} installed, {GREEN}{}{RESET} on public main (`vpngate update`)",
                    uc.remote_version
                )));
            } else {
                lines.push(Some(format!(
                    "Desktop Ver  : {GREEN}{local}{RESET} — up to date vs public main"
                )));
            }
        } else if !uc.last_error.is_empty() {
            lines.push(Some(format!(
                "Desktop Ver  : {YELLOW}CHECK FAILED{RESET} — retry `{CYAN}vpngate update{RESET}` (anonymous HTTPS, no GitHub login)"
            )));
        } else {
            lines.push(Some(format!(
                "Desktop Ver  : {} — run `{CYAN}vpngate update{RESET}` to scan public main (no GitHub login)",
                env!("CARGO_PKG_VERSION")
            )));
        }
    } else {
        lines.push(Some(format!(
            "Desktop Ver  : {} — run `{CYAN}vpngate update{RESET}` to scan public main (no GitHub login)",
            env!("CARGO_PKG_VERSION")
        )));
    }
    lines.push(None);
    let mut issues = 0usize;

    // 1. Pure-Rust IKEv1 CBC + MODP-1024 + KEYMAT + UDP_ENCAP_ESPINUDP check
    match run_ikev1_crypto_self_test() {
        Ok(()) => lines.push(Some(format!(
            "IKEv1 Crypto : {GREEN}READY{RESET} — Pure-Rust AES-256/128/3DES + MODP-1024 + ESPinUDP verified"
        ))),
        Err(e) => {
            issues += 1;
            lines.push(Some(format!("IKEv1 Crypto : {YELLOW}ISSUE{RESET} — {e}")));
        }
    }

    // 2. Host L2TP/PPP stack & Windows 11 Admin / NAT-T readiness
    if cfg!(target_os = "windows") {
        if is_root_or_admin() {
            lines.push(Some(format!(
                "Admin Rights : {GREEN}ELEVATED{RESET} — Administrator token active"
            )));
        } else {
            lines.push(Some(format!(
                "Admin Rights : {CYAN}STANDARD USER{RESET} — Auto-elevates via UAC when connecting"
            )));
        }
        let natt_note = match query_windows_natt_rule() {
            Some(2) => "NAT-T Rule = 2, Zero IKEv2",
            _ => "NAT-T Rule auto-applied on connect, Zero IKEv2",
        };
        if which_bin("rasdial").is_some() {
            lines.push(Some(format!(
                "L2TP Engine  : {GREEN}READY{RESET} — Windows Native RASMAN/IKEEXT ({natt_note})"
            )));
        } else {
            issues += 1;
            lines.push(Some(format!(
                "L2TP Engine  : {YELLOW}MISSING{RESET} — `rasdial.exe` not found"
            )));
        }
    } else if cfg!(target_os = "linux") {
        let has_xl =
            which_bin("xl2tpd").is_some() || std::path::Path::new("/usr/sbin/xl2tpd").is_file();
        let has_ppp =
            which_bin("pppd").is_some() || std::path::Path::new("/usr/sbin/pppd").is_file();
        let has_ip = which_bin("ip").is_some();
        if !has_xl || !has_ppp || !has_ip {
            issues += 1;
            lines.push(Some(format!(
                "L2TP Engine  : {YELLOW}MISSING{RESET} — Install: `sudo apt install -y xl2tpd ppp iproute2`"
            )));
        } else if let Err(kerr) = vpngate_core::probe_linux_l2tp_kernel_support() {
            lines.push(Some(format!(
                "L2TP Engine  : {YELLOW}SKIPPED{RESET} — {kerr}"
            )));
        } else {
            let fw_note = if which_bin("nft").is_some() {
                "nftables native"
            } else if which_bin("iptables").is_some() {
                "iptables"
            } else {
                "host firewall open"
            };
            lines.push(Some(format!(
                "L2TP Engine  : {GREEN}READY{RESET} — Built-In Rust IKEv1/XFRM + xl2tpd + pppd ({fw_note})"
            )));
        }
    } else {
        lines.push(Some(format!(
            "L2TP Engine  : {GREEN}READY{RESET} — Apple `.mobileconfig` profile generator"
        )));
    }

    // 3. OpenVPN stack
    if let Some(ovpn) = find_openvpn_bin() {
        lines.push(Some(format!(
            "OpenVPN Stack: {GREEN}READY{RESET} — `{}`",
            ovpn.display()
        )));
    } else {
        issues += 1;
        lines.push(Some(format!(
            "OpenVPN Stack: {YELLOW}MISSING{RESET} — Install `openvpn` for OpenVPN UDP/TCP support"
        )));
    }

    // 4. Desktop Window / Console UI
    if cfg!(target_os = "windows") {
        let (cols, rows) = get_live_terminal_size(100, 30);
        let vt_tag = if win_vt_enabled() {
            "VT100 ANSI"
        } else {
            "ASCII Fallback"
        };
        let wt_note = if which_bin("wt").is_some() {
            format!("Windows Terminal (`wt.exe`) + UTF-8 CP65001 ({vt_tag}, {cols}x{rows})")
        } else {
            format!("PowerShell Console UTF-8 CP65001 ({vt_tag}, {cols}x{rows})")
        };
        lines.push(Some(format!(
            "Console UI   : {GREEN}READY{RESET} — {wt_note}"
        )));
    } else if cfg!(target_os = "linux") {
        let self_dir = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
        let launcher_ok = which_bin("vpngate-launcher").is_some()
            || which_bin("vpngate-launcher.py").is_some()
            || std::path::Path::new("/usr/local/bin/vpngate-launcher").is_file()
            || self_dir.as_ref().is_some_and(|d| {
                d.join("vpngate-launcher.py").is_file()
                    || d.parent()
                        .and_then(|p| p.parent())
                        .is_some_and(|r| r.join("vpngate-launcher.py").is_file())
            });
        if launcher_ok {
            lines.push(Some(format!(
                "GNOME Window : {GREEN}READY{RESET} — `vpngate-launcher` dynamic GTK/VTE dark window"
            )));
        } else {
            lines.push(Some(format!(
                "GNOME Window : {YELLOW}CLI ONLY{RESET} — Run `sh ./install-vpngate.sh` to install GNOME launcher"
            )));
        }
    } else {
        lines.push(Some(format!(
            "Console UI   : {GREEN}READY{RESET} — macOS Terminal UTF-8"
        )));
    }

    // 5. Physical default gateway
    let gw = get_default_gateway();
    if !gw.dev.is_empty() {
        let gw_desc = if gw.gw.is_empty() {
            gw.dev
        } else {
            format!("{} via {}", gw.dev, gw.gw)
        };
        lines.push(Some(format!(
            "Host Network : {GREEN}ONLINE{RESET} — Physical interface {BOLD}{gw_desc}{RESET}"
        )));
    } else {
        lines.push(Some(format!(
            "Host Network : {YELLOW}CHECK{RESET} — Tunnel active or physical gateway not detected"
        )));
    }

    // 6. Server + Mirror caches
    let mirrors_cnt = load_cached_mirrors(paths).len();
    if let Some(cache) = read_json_opt::<ServerCacheFile>(&paths.servers_cache)
        && !cache.servers.is_empty()
    {
        let age_m = now_unix_secs().saturating_sub(cache.timestamp) / 60;
        let l2 = cache.servers.iter().filter(|s| s.l2tp).count();
        let ov = cache.servers.iter().filter(|s| s.openvpn).count();
        lines.push(Some(format!(
            "Server Cache : {GREEN}{} servers{RESET} ({l2} L2TP, {ov} OVPN · {age_m}m ago)  |  Mirrors: {BOLD}{mirrors_cnt}{RESET}",
            cache.servers.len()
        )));
    } else {
        lines.push(Some(format!(
            "Server Cache : Empty (populates on first query)  |  Cached Mirrors: {BOLD}{mirrors_cnt}{RESET}"
        )));
    }

    lines.push(None);
    if issues == 0 {
        lines.push(Some(format!(
            "Overall      : {GREEN}{BOLD}ALL CORE SYSTEMS READY{RESET}"
        )));
    } else {
        lines.push(Some(format!(
            "Overall      : {YELLOW}{BOLD}{issues} item(s) need attention{RESET}"
        )));
    }

    render_dynamic_box(&lines, 3, 74)?;
    Ok(if issues == 0 { 0 } else { 1 })
}

pub async fn cmd_probe(ip_raw: &str) -> io::Result<i32> {
    clear_screen_if_tty();
    let Ok(ip) = ip_raw.trim().parse::<Ipv4Addr>() else {
        err(&format!("Invalid IPv4 address: {ip_raw}"));
        return Ok(1);
    };
    info(&format!(
        "Probing {ip} (1-RTT IKEv1 Aggressive Mode PSK='vpn' + TCP/443) ..."
    ));
    let l2tp_res = verify_l2tp_psk_vpn(ip, Duration::from_millis(1500), 2, b"vpn").await;
    let tcp_443 = probe_tcp(
        SocketAddr::new(IpAddr::V4(ip), 443),
        Duration::from_millis(1500),
    )
    .await;

    let l2tp_fmt = if l2tp_res.is_verified() {
        format!("{GREEN}{BOLD}VERIFIED (PSK == 'vpn'){RESET}")
    } else {
        format!("{YELLOW}{l2tp_res:?}{RESET}")
    };
    let tcp_fmt = match tcp_443 {
        Some(rtt) => format!("{GREEN}OPEN ({rtt:.0?}){RESET}"),
        None => format!("{DIM}CLOSED / FILTERED{RESET}"),
    };

    let lines = vec![
        Some(format!("{CYAN}{BOLD}Pre-Flight Server Probe — {ip}{RESET}")),
        None,
        Some(format!("IKEv1 UDP/500 : {l2tp_fmt}")),
        Some(format!("TCP Port 443  : {tcp_fmt}")),
    ];
    render_dynamic_box(&lines, 2, 56)?;
    Ok(0)
}

fn prompt_protocol(allow_all: bool) -> io::Result<Option<ProtocolFilter>> {
    clear_screen_if_tty();
    if allow_all {
        let box_lines = vec![
            Some(format!("{CYAN}{BOLD}Select Protocol Filter{RESET}")),
            None,
            Some(format!(
                " {CYAN}[1]{RESET} All Protocols Combined (L2TP/IPsec + OpenVPN UDP/TCP) {GREEN}[Default]{RESET}"
            )),
            Some(format!(
                " {CYAN}[2]{RESET} L2TP/IPsec Only (Verified PSK='vpn', Zero IKEv2)"
            )),
            Some(format!(" {CYAN}[3]{RESET} OpenVPN UDP Only")),
            Some(format!(" {CYAN}[4]{RESET} OpenVPN TCP Only")),
            Some(format!(" {CYAN}[5]{RESET} OpenVPN Only (UDP + TCP)")),
            None,
            Some(format!(" {CYAN}[0]{RESET} Cancel / Back to Main Menu")),
        ];
        render_dynamic_box(&box_lines, 4, 68)?;
        let Some(ans) = prompt_input(&format!(
            "\nSelect protocol {BOLD}[1-5, Enter=all, 0=Back]{RESET}: "
        )) else {
            return Ok(None);
        };
        return Ok(match ans.to_ascii_lowercase().as_str() {
            "0" | "q" | "back" | "cancel" => None,
            "" | "1" | "all" => Some(ProtocolFilter::Auto),
            "2" | "l2tp" => Some(ProtocolFilter::Only(vpngate_core::VpnProtocol::L2tpIpsec)),
            "3" | "udp" | "openvpn-udp" => {
                Some(ProtocolFilter::Only(vpngate_core::VpnProtocol::OpenVpnUdp))
            }
            "4" | "tcp" | "openvpn-tcp" => {
                Some(ProtocolFilter::Only(vpngate_core::VpnProtocol::OpenVpnTcp))
            }
            "5" | "openvpn" => Some(ProtocolFilter::OpenVpnAny),
            _ => Some(ProtocolFilter::Auto),
        });
    }

    let l2tp_desc = if cfg!(target_os = "windows") {
        "Windows 11 RASMAN/IKEEXT, Zero IKEv2"
    } else {
        "Built-In Rust IKEv1 + Kernel XFRM + xl2tpd"
    };
    let box_lines = vec![
        Some(format!("{CYAN}{BOLD}Select Connection Protocol{RESET}")),
        None,
        Some(format!(
            " {CYAN}[1]{RESET} Auto Hybrid (Try L2TP/IPsec -> OpenVPN UDP -> OpenVPN TCP) {GREEN}[Recommended]{RESET}"
        )),
        Some(format!(" {CYAN}[2]{RESET} L2TP/IPsec Only ({l2tp_desc})")),
        Some(format!(" {CYAN}[3]{RESET} OpenVPN UDP Only")),
        Some(format!(" {CYAN}[4]{RESET} OpenVPN TCP Only")),
        Some(format!(
            " {CYAN}[5]{RESET} OpenVPN Only (UDP -> TCP automatic fallback)"
        )),
        None,
        Some(format!(" {CYAN}[0]{RESET} Cancel / Back to Main Menu")),
    ];
    render_dynamic_box(&box_lines, 4, 74)?;
    let Some(ans) = prompt_input(&format!(
        "\nSelect protocol {BOLD}[1-5, Enter=auto, 0=Back]{RESET}: "
    )) else {
        return Ok(None);
    };
    Ok(match ans.to_ascii_lowercase().as_str() {
        "0" | "q" | "back" | "cancel" => None,
        "" | "1" | "auto" => Some(ProtocolFilter::Auto),
        "2" | "l2tp" => Some(ProtocolFilter::Only(vpngate_core::VpnProtocol::L2tpIpsec)),
        "3" | "udp" | "openvpn-udp" => {
            Some(ProtocolFilter::Only(vpngate_core::VpnProtocol::OpenVpnUdp))
        }
        "4" | "tcp" | "openvpn-tcp" => {
            Some(ProtocolFilter::Only(vpngate_core::VpnProtocol::OpenVpnTcp))
        }
        "5" | "openvpn" => Some(ProtocolFilter::OpenVpnAny),
        _ => Some(ProtocolFilter::Auto),
    })
}

fn prompt_country(servers: &[VpnServer], proto: ProtocolFilter) -> io::Result<Option<String>> {
    clear_screen_if_tty();
    let filtered = filter_by_protocol(servers, proto);
    let rows = summarize_countries(&filtered);
    if rows.is_empty() {
        warn("No countries available for that protocol filter.");
        return Ok(None);
    }
    print_countries_table(&rows, proto.as_cli_str(), true)?;
    print_line(&format!(
        "  {CYAN}[A]{RESET} All Regions / Best Available Worldwide"
    ));
    print_line(&format!("  {CYAN}[0]{RESET} Cancel / Back to Main Menu"));
    loop {
        let Some(ans) = prompt_input(&format!(
            "\nSelect region by {BOLD}Number (1-{}){RESET}, {BOLD}Country Code (e.g. JP){RESET}, {BOLD}A (All){RESET}, or {BOLD}0 (Back){RESET}: ",
            rows.len()
        )) else {
            return Ok(None);
        };
        if ans.is_empty() || matches!(ans.to_ascii_lowercase().as_str(), "0" | "q" | "back") {
            return Ok(None);
        }
        if matches!(ans.to_ascii_lowercase().as_str(), "a" | "all" | "*") {
            return Ok(Some("all".to_string()));
        }
        if let Ok(idx) = ans.parse::<usize>()
            && idx >= 1
            && idx <= rows.len()
        {
            return Ok(Some(rows[idx - 1].country_short.clone()));
        }
        let matched = filter_by_country(&filtered, Some(&ans));
        if let Some(first) = matched.first() {
            return Ok(Some(first.country_short.clone()));
        }
        warn(&format!(
            "Invalid selection '{ans}'. Please enter 1-{}, a country code like JP, or 0 to cancel.",
            rows.len()
        ));
    }
}

fn prompt_sort() -> io::Result<Option<SortBy>> {
    clear_screen_if_tty();
    let box_lines = vec![
        Some(format!(
            "{CYAN}{BOLD}Select Server Priority / Sort Order{RESET}"
        )),
        None,
        Some(format!(
            " {CYAN}[1]{RESET} Highest Score (Overall stability & throughput) {GREEN}[Default]{RESET}"
        )),
        Some(format!(" {CYAN}[2]{RESET} Fastest Line Speed (Mbps)")),
        Some(format!(" {CYAN}[3]{RESET} Lowest Ping Latency (ms)")),
        None,
        Some(format!(" {CYAN}[0]{RESET} Cancel / Back to Main Menu")),
    ];
    render_dynamic_box(&box_lines, 4, 66)?;
    let Some(ans) = prompt_input(&format!(
        "\nSelect sort order {BOLD}[1-3, Enter=1, 0=Back]{RESET}: "
    )) else {
        return Ok(None);
    };
    Ok(match ans.to_ascii_lowercase().as_str() {
        "0" | "q" | "back" | "cancel" => None,
        "" | "1" | "score" | "recommended" => Some(SortBy::Recommended),
        "2" | "speed" => Some(SortBy::Speed),
        "3" | "ping" => Some(SortBy::Ping),
        _ => Some(SortBy::Recommended),
    })
}

fn local_pool_summary_line(paths: &AppPaths) -> String {
    let cd_cnt = load_cooldowns(paths).active_count();
    let mirrors_cnt = load_cached_mirrors(paths).len();
    let cd_tag = if cd_cnt > 0 {
        format!("  |  Cooldowns: {YELLOW}{cd_cnt}{RESET}")
    } else {
        String::new()
    };
    let mir_tag = if mirrors_cnt > 0 {
        format!("  |  Mirrors: {BOLD}{mirrors_cnt}{RESET}")
    } else {
        String::new()
    };
    if let Some(cache) = read_json_opt::<ServerCacheFile>(&paths.servers_cache)
        && !cache.servers.is_empty()
    {
        let l2 = cache.servers.iter().filter(|s| s.l2tp).count();
        let ov = cache.servers.iter().filter(|s| s.openvpn).count();
        let age_m = now_unix_secs().saturating_sub(cache.timestamp) / 60;
        format!(
            "Pool     : {BOLD}{}{RESET} cached ({GREEN}{l2} L2TP{RESET}, {CYAN}{ov} OVPN{RESET} · {age_m}m ago){mir_tag}{cd_tag}",
            cache.servers.len()
        )
    } else {
        format!("Pool     : {DIM}Not fetched yet (auto-loads on selection){RESET}{mir_tag}{cd_tag}")
    }
}

fn pause_for_dashboard(rc: i32) {
    if rc == INTERRUPTED_EXIT {
        return;
    }
    let _ = prompt_input("\nPress Enter to return to Dashboard...");
}

fn is_dev_tree_binary() -> bool {
    env::current_exe()
        .ok()
        .map(|p| p.components().any(|c| c.as_os_str() == "target"))
        .unwrap_or(false)
}

fn canonical_install_binary() -> PathBuf {
    if cfg!(windows) {
        env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| resolve_user_home().join("AppData").join("Local"))
            .join("Programs")
            .join("VPNGate")
            .join("vpngate.exe")
    } else {
        PathBuf::from("/usr/local/bin/vpngate")
    }
}

fn cargo_install_shadow_binary() -> PathBuf {
    if cfg!(windows) {
        resolve_user_home()
            .join(".cargo")
            .join("bin")
            .join("vpngate.exe")
    } else {
        resolve_user_home().join(".cargo").join("bin").join("vpngate")
    }
}

fn remove_shadow_desktop_binaries() {
    if is_dev_tree_binary() {
        return;
    }
    let canonical = canonical_install_binary();
    let cargo_bin = cargo_install_shadow_binary();
    if cargo_bin.is_file() && cargo_bin != canonical {
        match fs::remove_file(&cargo_bin) {
            Ok(()) => ok(&format!(
                "Removed leftover previous binary {}",
                cargo_bin.display()
            )),
            Err(e) => warn(&format!(
                "Could not remove leftover {} ({e})",
                cargo_bin.display()
            )),
        }
    }
}

fn write_upgrade_installer_script(paths: &AppPaths, body: &str) -> io::Result<PathBuf> {
    let _ = paths.ensure_dirs();
    let dest = if cfg!(windows) {
        paths.cache_dir.join("install-vpngate.ps1")
    } else {
        paths.cache_dir.join("install-vpngate.sh")
    };
    let payload = if cfg!(windows) {
        body.to_string()
    } else {
        body.replace('\r', "")
    };
    fs::write(&dest, payload)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms)?;
    }
    Ok(dest)
}

#[cfg(windows)]
fn spawn_windows_upgrade_installer(ps1: &Path) -> io::Result<()> {
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let ps1_disp = ps1.display().to_string().replace('\'', "''");
    let inner = format!(
        "Start-Sleep -Seconds 3; powershell.exe -NoProfile -ExecutionPolicy Bypass -File '{ps1_disp}'"
    );
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &inner,
        ])
        .creation_flags(CREATE_NEW_CONSOLE)
        .stdin(Stdio::null())
        .spawn()?;
    Ok(())
}

async fn run_desktop_installer(paths: &AppPaths) -> io::Result<i32> {
    info("Downloading the public installer (anonymous HTTPS, no GitHub login) ...");
    let slug = default_repo_slug();
    let urls = installer_script_urls(&slug);
    let (body, src) = match fetch_public_url_text(&urls).await {
        Ok(v) => v,
        Err(e) => {
            err(&e);
            return Ok(1);
        }
    };
    info(&format!("Installer source: {src}"));
    let script = write_upgrade_installer_script(paths, &body)?;

    info("Disconnecting any active VPN Gate session so the old binary can be replaced ...");
    let _ = cmd_disconnect(paths).await;
    stop_monitor_daemon(paths);

    #[cfg(windows)]
    {
        remove_shadow_desktop_binaries();
        info("Launching the Windows installer in a new window, then closing this process so vpngate.exe is not locked ...");
        spawn_windows_upgrade_installer(&script)?;
        ok("The installer will replace this copy and remove the previous vpngate.exe.");
        ok("After it finishes, start VPN Gate again from the Start Menu or `vpngate`.");
        return Ok(0);
    }

    #[cfg(not(windows))]
    {
        info("Running the installer (it deletes /usr/local/bin/vpngate, then installs the new build) ...");
        let status = Command::new("sh")
            .arg(&script)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        let rc = status.code().unwrap_or(1);
        if rc != 0 {
            err("Installer did not finish successfully. The previous desktop binary was left in place.");
            return Ok(rc);
        }
        remove_shadow_desktop_binaries();
        ok("Desktop update installed. The old /usr/local/bin/vpngate was replaced.");
        ok("Exit this process and run `vpngate` to use the new version.");
        Ok(0)
    }
}

pub enum UpgradeOffer {
    Continue,
    ExitAfterInstall,
    Failed(i32),
}

pub async fn cmd_upgrade(paths: &AppPaths, assume_yes: bool) -> io::Result<i32> {
    clear_screen_if_tty();
    match offer_desktop_upgrade(paths, true, assume_yes).await? {
        UpgradeOffer::Continue => Ok(0),
        UpgradeOffer::ExitAfterInstall => Ok(0),
        UpgradeOffer::Failed(rc) => Ok(rc),
    }
}

fn desktop_update_status_line(paths: &AppPaths) -> String {
    let local = installed_desktop_version();
    match load_update_cache(paths) {
        Some(cache) if !cache.last_error.is_empty() && cache.remote_version.is_empty() => {
            format!("Update   : {YELLOW}CHECK FAILED{RESET} — run `{BOLD}vpngate update{RESET}` (anonymous HTTPS, no GitHub login)")
        }
        Some(cache) => {
            if let Some(remote) = vpngate_core::DesktopVersion::parse(&cache.remote_version) {
                if remote > local {
                    format!(
                        "Update   : {YELLOW}{BOLD}{} available{RESET} — you have {local}. Installing is strongly recommended.",
                        cache.remote_version
                    )
                } else if remote < local {
                    format!("Update   : {CYAN}{local}{RESET} — newer than public main ({})", cache.remote_version)
                } else {
                    format!("Update   : {GREEN}up to date{RESET} — public main is {local}")
                }
            } else {
                format!("Update   : {DIM}not checked yet{RESET}")
            }
        }
        None => format!("Update   : {DIM}not checked yet{RESET}"),
    }
}

/// Scan public `main` for a newer desktop. `force` ignores the 6h cache (used by `vpngate update`).
pub async fn offer_desktop_upgrade(
    paths: &AppPaths,
    force: bool,
    assume_yes: bool,
) -> io::Result<UpgradeOffer> {
    let installed = installed_desktop_version();
    info("Checking for a newer desktop on public main (anonymous HTTPS, no GitHub login) ...");
    let remote = match refresh_update_cache(paths, force).await {
        Ok(v) => v,
        Err(e) => {
            err(&e);
            warn("Could not see public main. Retry with `vpngate update`.");
            return Ok(UpgradeOffer::Continue);
        }
    };

    if remote.version < installed {
        if force {
            info(&format!(
                "This build ({installed}) is newer than public main ({}).",
                remote.raw
            ));
        }
        return Ok(UpgradeOffer::Continue);
    }
    if remote.version == installed {
        if force {
            ok(&format!(
                "VPN Gate Connect desktop {installed} is up to date."
            ));
        }
        return Ok(UpgradeOffer::Continue);
    }
    if !force {
        if let Some(cache) = load_update_cache(paths)
            && !should_auto_prompt(&cache, &remote.version)
        {
            return Ok(UpgradeOffer::Continue);
        }
    }
    prompt_and_maybe_install(paths, &remote, assume_yes).await
}

async fn prompt_and_maybe_install(
    paths: &AppPaths,
    remote: &vpngate_core::RemoteDesktopVersion,
    assume_yes: bool,
) -> io::Result<UpgradeOffer> {
    let installed = installed_desktop_version();
    print_line("");
    warn("A newer VPN Gate Connect desktop is available — installing it is strongly recommended.");
    print_line(&format!(
        "  Installed : {YELLOW}{installed}{RESET}\n  Latest    : {GREEN}{}{RESET}  ({})",
        remote.raw, remote.source_url
    ));
    print_line(&format!(
        "  {BOLD}Updating replaces this install and removes the old binary.{RESET}"
    ));
    print_line("");

    let accepted = if assume_yes {
        true
    } else if !is_stdout_tty() {
        warn("Non-interactive session: re-run `vpngate update -y` to install.");
        false
    } else {
        match prompt_input("Install this update now? [Y/n]: ") {
            None => false,
            Some(ans) => {
                let t = ans.trim().to_ascii_lowercase();
                !matches!(t.as_str(), "n" | "no" | "q" | "quit" | "0")
            }
        }
    };

    if !accepted {
        record_update_declined(paths, remote);
        info("Skipped. You can install later with `vpngate update`.");
        return Ok(UpgradeOffer::Continue);
    }

    let rc = run_desktop_installer(paths).await?;
    if rc == 0 {
        Ok(UpgradeOffer::ExitAfterInstall)
    } else {
        Ok(UpgradeOffer::Failed(rc))
    }
}

pub async fn interactive_menu(paths: &AppPaths, help_text: &str) -> io::Result<i32> {
    let os_label = detect_host_os_label();

    #[cfg(windows)]
    if !is_root_or_admin() && is_stdout_tty() && !uac_already_attempted() && !no_elevate_requested()
    {
        info("Requesting Administrator privileges via Windows UAC ...");
        if launch_elevated_interactive_console(paths) {
            ok("Opened elevated Administrator VPN Gate console window.");
            return Ok(0);
        }
        warn(
            "UAC elevation was declined - continuing in Read-Only mode (Countries, List, Mirrors, Status, Doctor).",
        );
        tokio::time::sleep(Duration::from_millis(900)).await;
    }

    if is_stdout_tty() && !skip_update_check() {
        info("Checking for a newer desktop on public main (anonymous HTTPS, no GitHub login) ...");
        if let Err(e) = refresh_update_cache(paths, false).await {
            warn(&e);
            warn("Desktop update check failed — the dashboard still works. Retry with `vpngate update`.");
        }
    }

    loop {
        clear_screen_if_tty();
        prune_stale_state_if_dead(paths);

        let mon_pid = get_running_monitor_pid(paths);
        let wd_pref = load_watchdog_pref(paths);
        let wd_str = if mon_pid > 0 {
            format!("{GREEN}ARMED (PID {mon_pid}, {MONITOR_INTERVAL_SECONDS}s){RESET}")
        } else if wd_pref {
            format!("{CYAN}ON (Standby){RESET}")
        } else {
            format!("{DIM}OFF{RESET}")
        };

        let status_line = if let Some(st) = read_json_opt::<ActiveSessionState>(&paths.active_state)
        {
            format!(
                "Tunnel   : {GREEN}● ACTIVE{RESET} -> {BOLD}{}{RESET} ({} · {})  |  Watchdog: {wd_str}",
                st.hostname, st.country_short, st.protocol
            )
        } else {
            let ppp = get_ppp_interfaces();
            let tun = get_tun_interfaces();
            let ovpn_pid = if cfg!(target_os = "windows") {
                get_running_openvpn_pid(paths)
            } else {
                0
            };
            if let Some((dev, ip)) = ppp.iter().next() {
                format!(
                    "Tunnel   : {GREEN}● ACTIVE PPP LINK{RESET} ({dev} -> {ip})  |  Watchdog: {wd_str}"
                )
            } else if let Some((dev, ip)) = tun.iter().next() {
                format!(
                    "Tunnel   : {GREEN}● ACTIVE TUN LINK{RESET} ({dev} -> {ip})  |  Watchdog: {wd_str}"
                )
            } else if ovpn_pid > 0 {
                format!(
                    "Tunnel   : {GREEN}● ACTIVE OPENVPN{RESET} (PID {ovpn_pid})  |  Watchdog: {wd_str}"
                )
            } else {
                format!("Tunnel   : {DIM}○ Disconnected{RESET}  |  Watchdog: {wd_str}")
            }
        };

        let menu_lines = vec![
            Some(format!(
                "{CYAN}{BOLD}VPN Gate Console v{}{RESET}  ·  {os_label} (Auto: L2TP/IPsec -> OVPN UDP -> OVPN TCP)",
                env!("CARGO_PKG_VERSION")
            )),
            Some(status_line),
            Some(local_pool_summary_line(paths)),
            Some(desktop_update_status_line(paths)),
            None,
            Some(format!(
                " {CYAN}[1]{RESET} Quick Connect by Region (Recommended Auto: L2TP -> OVPN UDP -> TCP)"
            )),
            Some(format!(
                " {CYAN}[2]{RESET} Browse & Pick Specific Server in a Country / Region"
            )),
            Some(format!(
                " {CYAN}[3]{RESET} View Unified Countries & Regions Table (L2TP + OpenVPN)"
            )),
            Some(format!(
                " {CYAN}[4]{RESET} Live Tunnel, IPsec SA & Public Egress Status"
            )),
            Some(format!(
                " {CYAN}[5]{RESET} Toggle Auto-Reconnect Watchdog ({})",
                if mon_pid > 0 || wd_pref {
                    "Turn OFF"
                } else {
                    "Turn ON"
                }
            )),
            Some(format!(
                " {CYAN}[6]{RESET} Disconnect Active VPN & Restore Host Network"
            )),
            Some(format!(
                " {CYAN}[7]{RESET} Refresh Server Pool Cache & Clear Server Cooldowns"
            )),
            Some(format!(
                " {CYAN}[8]{RESET} Official VPNGate Mirror Sites (Live Probe & Add Custom Mirror)"
            )),
            Some(format!(
                " {CYAN}[9]{RESET} System Readiness Check (`doctor`) & CLI Reference"
            )),
            None,
            Some(format!(
                " {CYAN}[0]{RESET} Exit Console {DIM}(Active VPN & Watchdog keep running in background){RESET}"
            )),
        ];
        render_dynamic_box(&menu_lines, 5, 76)?;

        if is_stdout_tty()
            && !skip_update_check()
            && !UPDATE_PROMPT_DONE.swap(true, Ordering::Relaxed)
        {
            if let Some(cache) = load_update_cache(paths)
                && let Some(remote) = cached_newer_than_installed(&cache)
                && should_auto_prompt(&cache, &remote.version)
            {
                match prompt_and_maybe_install(paths, &remote, false).await? {
                    UpgradeOffer::ExitAfterInstall => return Ok(0),
                    UpgradeOffer::Continue | UpgradeOffer::Failed(_) => {}
                }
                continue;
            }
        }

        let Some(choice) = prompt_input(&format!("\nSelect an action {BOLD}[0-9]{RESET}: ")) else {
            print_line("");
            if io::stdin().is_terminal() {
                warn("Interrupted — still at the main menu.");
                continue;
            }
            return Ok(0);
        };

        match choice.to_ascii_lowercase().as_str() {
            "0" | "q" | "quit" | "exit" => return Ok(0),
            "1" => {
                clear_screen_if_tty();
                let Ok(servers) =
                    get_servers_cached_with_progress(paths, false, &[], render_progress_event)
                        .await
                else {
                    err("Could not load server pool.");
                    let _ = prompt_input("\nPress Enter to return to Dashboard...");
                    continue;
                };
                let Some(proto) = prompt_protocol(false)? else {
                    continue;
                };
                let Some(country) = prompt_country(&servers, proto)? else {
                    continue;
                };
                let Some(sort_by) = prompt_sort()? else {
                    continue;
                };
                let cargs = ConnectArgs {
                    country,
                    proto_filter: proto,
                    sort_by,
                    limit: 0,
                    timeout_secs: 22,
                    engine: "auto".to_string(),
                    dns: "1.1.1.1 1.0.0.1".to_string(),
                    start_index: 1,
                    force_refresh: false,
                    auto_reconnect_override: None,
                    custom_mirrors: Vec::new(),
                };
                let rc = cmd_connect(paths, &cargs).await?;
                pause_for_dashboard(rc);
            }
            "2" => {
                clear_screen_if_tty();
                let Ok(servers) =
                    get_servers_cached_with_progress(paths, false, &[], render_progress_event)
                        .await
                else {
                    err("Could not load server pool.");
                    let _ = prompt_input("\nPress Enter to return to Dashboard...");
                    continue;
                };
                let Some(proto) = prompt_protocol(false)? else {
                    continue;
                };
                let Some(country) = prompt_country(&servers, proto)? else {
                    continue;
                };
                let Some(sort_by) = prompt_sort()? else {
                    continue;
                };
                let mut candidates =
                    filter_by_country(&filter_by_protocol(&servers, proto), Some(&country));
                sort_servers(&mut candidates, sort_by, proto);
                if candidates.is_empty() {
                    warn("No matching servers found.");
                    let _ = prompt_input("\nPress Enter to return to Dashboard...");
                    continue;
                }
                let _ = cmd_list(paths, Some(&country), proto, sort_by, 35, false, &[]).await?;
                let Some(ans) = prompt_input(&format!(
                    "Enter {BOLD}A{RESET} to auto-test from #1, a {BOLD}Server # (1-{}){RESET} to start from that host, or {BOLD}0{RESET} to cancel: ",
                    candidates.len()
                )) else {
                    continue;
                };
                let start_idx = if ans.eq_ignore_ascii_case("a") {
                    1
                } else if let Ok(n) = ans.parse::<usize>()
                    && n >= 1
                    && n <= candidates.len()
                {
                    n
                } else if ans.is_empty()
                    || matches!(ans.to_ascii_lowercase().as_str(), "0" | "q" | "back")
                {
                    continue;
                } else {
                    warn(&format!("Invalid server selection '{ans}'."));
                    let _ = prompt_input("\nPress Enter to return to Dashboard...");
                    continue;
                };
                let cargs = ConnectArgs {
                    country,
                    proto_filter: proto,
                    sort_by,
                    limit: 0,
                    timeout_secs: 22,
                    engine: "auto".to_string(),
                    dns: "1.1.1.1 1.0.0.1".to_string(),
                    start_index: start_idx,
                    force_refresh: false,
                    auto_reconnect_override: None,
                    custom_mirrors: Vec::new(),
                };
                let rc = cmd_connect(paths, &cargs).await?;
                pause_for_dashboard(rc);
            }
            "3" => {
                let Some(proto) = prompt_protocol(true)? else {
                    continue;
                };
                let _ = cmd_countries(paths, proto, false, &[]).await?;
                let _ = prompt_input("Press Enter to return to Dashboard...");
            }
            "4" => {
                let _ = cmd_status(paths).await?;
                let _ = prompt_input("\nPress Enter to return to Dashboard...");
            }
            "5" => {
                let _ = cmd_watchdog(paths, "toggle");
                let _ = prompt_input("\nPress Enter to return to Dashboard...");
            }
            "6" => {
                let _ = cmd_disconnect(paths).await?;
                let _ = prompt_input("\nPress Enter to return to Dashboard...");
            }
            "7" => {
                let _ = cmd_refresh(paths, &[]).await?;
                let _ = prompt_input("\nPress Enter to return to Dashboard...");
            }
            "8" => {
                let _ = cmd_mirrors(paths, &[]).await?;
                if let Some(ans) = prompt_input(&format!(
                    "Enter a custom Mirror URL (e.g. {CYAN}http://host:port/en/{RESET}) to add & probe, or {BOLD}Enter{RESET} for Dashboard: "
                )) && !ans.is_empty()
                {
                    let _ = cmd_mirrors(paths, &[ans]).await?;
                    let _ = prompt_input("\nPress Enter to return to Dashboard...");
                }
            }
            "9" => {
                let _ = cmd_doctor(paths)?;
                if let Some(ans) = prompt_input(&format!(
                    "\nPress {BOLD}H{RESET} to also view CLI command reference (`--help`), or {BOLD}Enter{RESET} for Dashboard: "
                )) && ans.eq_ignore_ascii_case("h")
                {
                    clear_screen_if_tty();
                    let max_help_w = help_text
                        .lines()
                        .map(visible_len)
                        .max()
                        .unwrap_or(80)
                        .max(80);
                    request_window_resize(max_help_w + 4, (help_text.lines().count() + 5).min(46));
                    print_line(&format!("\n{help_text}"));
                    let _ = prompt_input("\nPress Enter to return to Dashboard...");
                }
            }
            _ => {
                warn(&format!("Invalid option '{choice}'. Please choose 0-9."));
                tokio::time::sleep(Duration::from_millis(800)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::quote_windows_arg;

    #[test]
    fn quotes_windows_command_line_arguments_accurately() {
        assert_eq!(quote_windows_arg("--uac-elevated"), "--uac-elevated");
        assert_eq!(quote_windows_arg(""), "\"\"");
        assert_eq!(
            quote_windows_arg(r"C:\Users\Test User\AppData\Local\vpngate"),
            r#""C:\Users\Test User\AppData\Local\vpngate""#
        );
        assert_eq!(
            quote_windows_arg(r#"C:\Path With Trailing\"#),
            r#""C:\Path With Trailing\\""#
        );
        assert_eq!(quote_windows_arg(r#"a"b"#), r#""a\"b""#);
    }
}
