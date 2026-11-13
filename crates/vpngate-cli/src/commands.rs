use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use vpngate_core::{
    ActiveSessionState, AppPaths, ConnectSessionConfig, CooldownStore, CountrySummary,
    DEFAULT_COOLDOWN_SECS, DiscoveryClient, DiscoveryOptions, INTERRUPTED_EXIT, Ikev1StateInfo,
    MONITOR_INTERVAL_SECONDS, NM_PROFILE_PREFIX, OfficialMirrorSite, PRODUCT_VERSION,
    ProgressEvent, ProtocolFilter, ServerCacheFile, SortBy, cached_newer_than_installed,
    cleanup_existing_vpn_with_progress, default_repo_slug, detect_host_os_label,
    engage_candidates_with_progress, fetch_public_url_text, filter_by_country, filter_by_protocol,
    find_openvpn_bin, fix_owner, get_default_gateway, get_ppp_interfaces, get_public_ip_trace,
    get_running_monitor_pid, get_running_openvpn_pid, get_servers_cached_with_progress,
    get_tun_interfaces, installed_desktop_version, installer_script_urls, is_root_or_admin,
    load_cached_mirrors, load_cooldowns, load_update_cache, load_watchdog_pref,
    normalize_mirror_base_url, now_unix_secs, parse_dns_list, probe_tcp, prune_stale_state_if_dead,
    query_windows_natt_rule, read_json_opt, record_update_declined, refresh_update_cache,
    resolve_user_home, run_ikev1_crypto_self_test, save_cached_mirrors, save_cooldowns,
    save_watchdog_pref, should_auto_prompt, sort_servers, spawn_auto_reconnect_monitor,
    stop_monitor_daemon, summarize_countries, verify_l2tp_psk_vpn, wait_for_cancel_file, which_bin,
};

use crate::term_ui::{
    Align, BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW, clear_transient_line, err, format_duration,
    format_thousands_u64, info, is_stdout_tty, ok, print_line, prompt_input, render_dynamic_box,
    render_dynamic_table, render_progress_event, truncate_plain, warn, work_progress_file,
};

static UAC_ALREADY_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static NO_ELEVATE_REQUESTED: AtomicBool = AtomicBool::new(false);
static SKIP_UPDATE_CHECK: AtomicBool = AtomicBool::new(false);

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
        let mut elevated_args = vec![
            "--cache-dir".to_string(),
            paths.cache_dir.display().to_string(),
        ];
        if let Some(progress_file) = work_progress_file() {
            elevated_args.push("--progress-file".to_string());
            elevated_args.push(progress_file.display().to_string());
        }
        elevated_args.extend_from_slice(sub_args);
        let status = Command::new("sudo")
            .arg("-E")
            .arg(self_exe)
            .args(&elevated_args)
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
            err("Administrator token was not granted after UAC elevation. \
                 Right-click PowerShell or Windows Terminal -> 'Run as Administrator' and retry.");
            return 1;
        }
        let mut full_args = vec![
            "--uac-elevated".to_string(),
            "--cache-dir".to_string(),
            paths.cache_dir.display().to_string(),
        ];
        if let Some(progress_file) = work_progress_file() {
            full_args.push("--progress-file".to_string());
            full_args.push(progress_file.display().to_string());
        }
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
                "Interface : {GREEN}{}{RESET}   |   DNS : {CYAN}{}{RESET}",
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
    pub cancel_file: Option<PathBuf>,
}

pub async fn cmd_connect(paths: &AppPaths, args: &ConnectArgs) -> io::Result<i32> {
    if args.country.trim().is_empty() {
        err(
            "Please specify a target country/region with -c / --country (e.g. -c JP, -c JP,KR, -c all).",
        );
        return Ok(1);
    }
    let auto_reconnect = args
        .auto_reconnect_override
        .unwrap_or_else(|| load_watchdog_pref(paths));

    if !is_root_or_admin() {
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
        if let Some(path) = &args.cancel_file {
            sub.push("--cancel-file".to_string());
            sub.push(path.display().to_string());
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
    let extra = parse_custom_mirrors(&args.custom_mirrors);
    render_progress_event(ProgressEvent::Info(
        "Loading the relay pool and discovering available candidates ...".to_string(),
    ));
    let discovery_result = tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            warn("Interrupted — returning without connecting.");
            return Ok(INTERRUPTED_EXIT);
        }
        _ = wait_for_cancel_file(args.cancel_file.as_deref()) => {
            warn("Connect cancelled — returning without changing the VPN tunnel.");
            return Ok(INTERRUPTED_EXIT);
        }
        res = get_servers_cached_with_progress(
            paths,
            args.force_refresh,
            &extra,
            render_progress_event,
        ) => res,
    };
    let servers = match discovery_result {
        Ok(servers) => servers,
        Err(error) => {
            render_progress_event(ProgressEvent::WorkProgress {
                completed: 1,
                total: 2,
                stage: "Relay-pool discovery finished with an error".to_string(),
            });
            err(&format!("Failed fetching VPN Gate server pool: {error}"));
            render_progress_event(ProgressEvent::WorkProgress {
                completed: 2,
                total: 2,
                stage: "Connect command finished after discovery failure".to_string(),
            });
            return Ok(1);
        }
    };
    let mut candidates = filter_by_country(
        &filter_by_protocol(&servers, args.proto_filter),
        Some(&args.country),
    );
    sort_servers(&mut candidates, args.sort_by, args.proto_filter);

    if candidates.is_empty() {
        render_progress_event(ProgressEvent::WorkProgress {
            completed: 2,
            total: 3,
            stage: "Relay pool filtered; no matching candidates were found".to_string(),
        });
        err(&format!(
            "No VPN Gate servers found for region '{}' with protocol '{}'.",
            args.country,
            args.proto_filter.as_cli_str()
        ));
        info("Tip: Run 'vpngate countries' to see available regions for L2TP and OpenVPN.");
        render_progress_event(ProgressEvent::WorkProgress {
            completed: 3,
            total: 3,
            stage: "Connect command finished without a matching candidate".to_string(),
        });
        return Ok(1);
    }

    let dns_servers = parse_dns_list(&args.dns);

    let cfg = ConnectSessionConfig {
        region_label: args.country.clone(),
        proto_filter: args.proto_filter,
        sort_by: args.sort_by,
        limit: args.limit,
        timeout_secs: args.timeout_secs,
        engine: args.engine.clone(),
        dns_servers,
        start_index: args.start_index.max(1),
        auto_reconnect,
        in_monitor: false,
        cancel_file: args.cancel_file.clone(),
    };

    info(&format!(
        "Selected {} candidate server(s) for region '{}' (Order: L2TP/IPsec -> OVPN UDP -> OVPN TCP) ...",
        candidates.len(),
        args.country.to_ascii_uppercase()
    ));

    // The core plan depends on the filtered candidates' actual protocol slots. Count relay-pool
    // discovery and candidate filtering as two completed units, then reserve one CLI-finalization
    // unit so we never invent a percentage while the total work is still unknown.
    let mut total_work_steps = None;
    let mut core_work_complete = false;
    let rc = engage_candidates_with_progress(paths, &candidates, &cfg, |event| match event {
        ProgressEvent::WorkProgress {
            completed,
            total,
            stage,
        } => {
            let overall_total = total.saturating_add(3);
            total_work_steps = Some(overall_total);
            core_work_complete = completed >= total;
            render_progress_event(ProgressEvent::WorkProgress {
                completed: completed.saturating_add(2).min(overall_total),
                total: overall_total,
                stage,
            });
        }
        event => render_progress_event(event),
    })
    .await;
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
    if core_work_complete && let Some(total) = total_work_steps {
        render_progress_event(ProgressEvent::WorkProgress {
            completed: total,
            total,
            stage: if rc == 0 {
                "Connect finished; tunnel verified".to_string()
            } else {
                "Connect finished; no verified tunnel was established".to_string()
            },
        });
    }
    Ok(rc)
}

pub async fn cmd_disconnect(paths: &AppPaths) -> io::Result<i32> {
    if !is_root_or_admin() {
        info(if cfg!(windows) {
            "Elevating privileges to Administrator to disconnect VPN ..."
        } else {
            "Elevating privileges with sudo to disconnect VPN ..."
        });
        let sub = vec!["disconnect".to_string()];
        let rc = elevate_self(paths, &sub);
        if cfg!(windows) && rc == 0 {
            ok(
                "Disconnected from VPN Gate, removed L2TP/OpenVPN profiles, and restored routes, DNS, and firewall.",
            );
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
    info("Tearing down active VPN tunnel and removing VPN Gate L2TP/OpenVPN profile residue ...");
    cleanup_existing_vpn_with_progress(paths, true, true, false, render_progress_event);
    ok(
        "Disconnected from VPN Gate, removed L2TP/OpenVPN profiles, and restored routes, DNS, and firewall.",
    );
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

fn clear_relay_cooldowns(paths: &AppPaths) -> io::Result<usize> {
    let mut cooldowns = CooldownStore::load_from_path(&paths.failed_servers)
        .unwrap_or_else(|_| CooldownStore::new(DEFAULT_COOLDOWN_SECS));
    let cleared = cooldowns.clear_all();
    cooldowns
        .save_to_path(&paths.failed_servers)
        .map_err(|error| io::Error::other(error.to_string()))?;
    fix_owner(&paths.failed_servers);
    Ok(cleared)
}

pub fn cmd_reset_cooldowns(paths: &AppPaths) -> io::Result<i32> {
    let cleared = clear_relay_cooldowns(paths)?;
    if cleared == 0 {
        info("No active relay cooldown entries needed resetting.");
    } else {
        ok(&format!(
            "Reset {cleared} relay/protocol cooldown entry/entries."
        ));
    }
    Ok(0)
}

pub async fn cmd_refresh(paths: &AppPaths, custom_mirrors: &[String]) -> io::Result<i32> {
    let mut cooldowns = load_cooldowns(paths);
    let cleared = cooldowns.clear_all();
    save_cooldowns(paths, &mut cooldowns);
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
            PRODUCT_VERSION
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
    let os_label = detect_host_os_label();
    let mut lines: Vec<Option<String>> = vec![
        Some(format!(
            "{CYAN}{BOLD}VPN Gate v{} ({os_label}) — System Readiness & Diagnostics{RESET}",
            PRODUCT_VERSION
        )),
        Some(format!(
            "CPU ISA      : {GREEN}{} native{RESET} — 64-bit x86_64 and ARM64 (no 32-bit, no ISA emulation)",
            vpngate_core::cpu_isa_label()
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
                PRODUCT_VERSION
            )));
        }
    } else {
        lines.push(Some(format!(
            "Desktop Ver  : {} — run `{CYAN}vpngate update{RESET}` to scan public main (no GitHub login)",
            PRODUCT_VERSION
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

    // 4. Native GUI companion. The CLI remains usable as a command service without it.
    let gui_name = if cfg!(windows) {
        "vpngate-gui.exe"
    } else {
        "vpngate-gui"
    };
    let gui_sibling = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(gui_name)))
        .filter(|path| path.is_file());
    if let Some(gui) = gui_sibling.or_else(|| which_bin("vpngate-gui")) {
        lines.push(Some(format!(
            "Native GUI   : {GREEN}AVAILABLE{RESET} — `{}`",
            gui.display()
        )));
    } else {
        lines.push(Some(format!(
            "Native GUI   : {DIM}not found{RESET} — install or build `vpngate-gui` (CLI service remains available)"
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
        resolve_user_home()
            .join(".cargo")
            .join("bin")
            .join("vpngate")
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
        info(
            "Launching the Windows installer in a new window, then closing this process so vpngate.exe is not locked ...",
        );
        spawn_windows_upgrade_installer(&script)?;
        ok("The installer will replace this copy and remove the previous vpngate.exe.");
        ok("After it finishes, start VPN Gate again from the Start Menu or `vpngate`.");
        return Ok(0);
    }

    #[cfg(not(windows))]
    {
        info(
            "Running the installer (it deletes /usr/local/bin/vpngate, then installs the new build) ...",
        );
        let status = Command::new("sh")
            .arg(&script)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        let rc = status.code().unwrap_or(1);
        if rc != 0 {
            err(
                "Installer did not finish successfully. The previous desktop binary was left in place.",
            );
            return Ok(rc);
        }
        remove_shadow_desktop_binaries();
        ok("Desktop update installed. The old /usr/local/bin/vpngate was replaced.");
        ok("Close this window and open VPN Gate Connect again to use the new version.");
        if is_stdout_tty() {
            let _ = prompt_input("Press Enter to close...");
        }
        Ok(0)
    }
}

pub enum UpgradeOffer {
    Continue,
    ExitAfterInstall,
    Failed(i32),
}

pub async fn cmd_upgrade(paths: &AppPaths, assume_yes: bool) -> io::Result<i32> {
    match offer_desktop_upgrade(paths, true, assume_yes).await? {
        UpgradeOffer::Continue => Ok(0),
        UpgradeOffer::ExitAfterInstall => Ok(0),
        UpgradeOffer::Failed(rc) => Ok(rc),
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
    if !force
        && let Some(cache) = load_update_cache(paths)
        && !should_auto_prompt(&cache, &remote.version)
    {
        return Ok(UpgradeOffer::Continue);
    }
    prompt_and_maybe_install(paths, &remote, assume_yes).await
}

async fn live_check_desktop_update(paths: &AppPaths) {
    info("Checking for a newer desktop on public main (anonymous HTTPS, no GitHub login) ...");
    if let Err(e) = refresh_update_cache(paths, true).await {
        warn(&e);
        warn("Desktop update check failed — retry with `vpngate update`.");
    }
}

/// `None` if nothing was shown. Snooze is skipped when `respect_snooze` is false (mode 9 / doctor).
async fn maybe_prompt_if_newer(
    paths: &AppPaths,
    respect_snooze: bool,
) -> io::Result<Option<UpgradeOffer>> {
    let Some(cache) = load_update_cache(paths) else {
        return Ok(None);
    };
    let Some(remote) = cached_newer_than_installed(&cache) else {
        return Ok(None);
    };
    if respect_snooze && !should_auto_prompt(&cache, &remote.version) {
        return Ok(None);
    }
    Ok(Some(prompt_and_maybe_install(paths, &remote, false).await?))
}

pub async fn cmd_doctor_with_update(paths: &AppPaths) -> io::Result<(i32, UpgradeOffer)> {
    if is_stdout_tty() && !skip_update_check() {
        live_check_desktop_update(paths).await;
    }
    let rc = cmd_doctor(paths)?;
    let offer = if is_stdout_tty() && !skip_update_check() {
        maybe_prompt_if_newer(paths, false)
            .await?
            .unwrap_or(UpgradeOffer::Continue)
    } else {
        UpgradeOffer::Continue
    };
    Ok((rc, offer))
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{cmd_reset_cooldowns, quote_windows_arg};
    use vpngate_core::{AppPaths, CooldownStore, VpnProtocol, load_cooldowns, now_unix_secs};

    #[test]
    fn cooldown_reset_command_clears_saved_penalties() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let cache_dir = std::env::temp_dir().join(format!(
            "vpngate-cli-cooldown-reset-{}-{nonce}",
            std::process::id()
        ));
        let paths = AppPaths::with_base_dir(cache_dir.clone());
        let mut cooldowns = CooldownStore::new(1800);
        let now = now_unix_secs();
        cooldowns.mark_failed_at("192.0.2.1", VpnProtocol::L2tpIpsec, now);
        cooldowns.mark_failed_at("192.0.2.1", VpnProtocol::OpenVpnUdp, now);
        cooldowns.save_to_path(&paths.failed_servers).unwrap();

        assert_eq!(load_cooldowns(&paths).active_count(), 2);
        assert_eq!(cmd_reset_cooldowns(&paths).unwrap(), 0);
        assert_eq!(load_cooldowns(&paths).active_count(), 0);
        fs::remove_dir_all(cache_dir).unwrap();
    }

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
