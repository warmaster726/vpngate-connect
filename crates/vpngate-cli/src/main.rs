//! `vpngate` — Cross-platform VPN Gate command service for the native desktop GUI.
//! Provides scripted CLI commands backed by the pure-Rust IKEv1/XFRM engine.
//! 64-bit native (`x86_64` and `aarch64`). 32-bit is not supported.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "VPN Gate Connect desktop supports 64-bit x86_64 and aarch64 only. Build with --target x86_64-unknown-linux-gnu / aarch64-unknown-linux-gnu, x86_64-pc-windows-msvc / aarch64-pc-windows-msvc, or x86_64-apple-darwin / aarch64-apple-darwin."
);

mod commands;
mod term_ui;

use std::env;
use std::io;
use std::path::{Path, PathBuf};

use commands::{
    ConnectArgs, UpgradeOffer, cmd_connect, cmd_countries, cmd_disconnect, cmd_doctor_with_update,
    cmd_list, cmd_mirrors, cmd_probe, cmd_refresh, cmd_reset_cooldowns, cmd_status, cmd_upgrade,
    cmd_watchdog, set_no_elevate_requested, set_skip_update_check, set_uac_already_attempted,
};
use term_ui::{err, init_console, print_line, set_work_progress_file};
use vpngate_core::{
    AppPaths, PRODUCT_VERSION, ProtocolFilter, SortBy, assert_supported_native_host,
    run_ikev1_daemon, run_monitor_daemon, tunnel_aid_dns_cli,
};

fn build_help_text() -> String {
    format!(
        r#"vpngate v{PRODUCT_VERSION} — VPN Gate command service

USAGE:
  vpngate [GLOBAL OPTIONS] COMMAND [OPTIONS]
  vpngate --help

COMMANDS:
  countries [-p PROTO] [-r]       List available countries and protocol counts
  list [-c CC] [-p PROTO] [-s SORT] [-n LIMIT] [-r]
                                  List matching relay servers
  connect -c <CC[,CC]|all> [-p PROTO] [-s SORT] [-n LIMIT] [--start N] [-a]
                                  Connect using L2TP/IPsec, then OpenVPN UDP/TCP
  mirrors [--mirror URL]          Discover and live-probe Official VPN Gate mirrors
  status                          Show tunnel, XFRM SA, watchdog, and egress status
  refresh                         Refresh the relay pool and clear cooldowns
  cooldowns reset                 Clear relay cooldowns without refreshing the pool
  watchdog [on|off|status]        Manage the auto-reconnect watchdog
  doctor                          Run crypto, tunnel, OpenVPN, and network diagnostics
  probe <IPv4>                    Run the IKEv1 PSK='vpn' and TCP/443 pre-flight check
  disconnect                      Tear down VPN and restore host DNS/routes/firewall
  update [-y]                     Check for and install a newer desktop version
  upgrade [-y]                    Alias for `update`

COMMAND FLAGS:
  -L, --list-countries            List countries and regions
  -l, --list                      List matching relay servers
  -c, --country <CC>              Region code/name; repeat or comma-separate; `all` is supported
  -p, --proto <PROTO>             auto | l2tp | openvpn-udp | openvpn-tcp | openvpn
  -s, --sort <SORT>               score | speed | ping | recommended
  -n, --limit <N>                 Maximum relays to list/try (0 = all)
  -t, --timeout <SEC>             Per-attempt tunnel timeout (default: 22 seconds)
  -e, --engine <ENG>              auto | nm | daemon
      --dns <IPS>                  Extra DNS merged with connection-pushed resolvers
  -M, --mirrors                   Discover and probe official mirror sites
      --mirror <URL>               Add/use an Official VPN Gate mirror URL
  -r, --refresh                   Force a live relay-pool refresh
  -a, --autoreconnect             Enable the 15-second reconnect watchdog for this session
      --no-autoreconnect           Disable the reconnect watchdog for this session
  -S, --status                    Show connection status
  -D, --doctor                    Run system diagnostics
  -d, --disconnect                Disconnect the active tunnel
  -y, --yes                       Skip the update-install confirmation prompt

GLOBAL OPTIONS:
      --cache-dir <PATH>           Use a specific cache/state directory
      --no-elevate, --read-only    Do not request privilege elevation
      --no-update-check            Skip the update check after `doctor`
      --cancel-file <PATH>         Cancel an in-progress connection when this file appears
      --progress-file <PATH>       Internal GUI progress log in the selected cache directory
  -h, --help                      Show this command reference
  -v, --version                   Show the desktop version

With no command, this reference is printed. The CLI does not launch an interactive dashboard."#
    )
}

async fn dispatch() -> io::Result<i32> {
    let raw_all: Vec<String> = env::args().skip(1).collect();
    init_console(false);
    if let Err(msg) = assert_supported_native_host() {
        err(&msg);
        return Ok(1);
    }

    // Consume global path/elevation/update flags before command dispatch.
    let mut cache_dir_override: Option<PathBuf> = None;
    let mut work_progress_file: Option<PathBuf> = None;
    let mut raw_args: Vec<String> = Vec::with_capacity(raw_all.len());
    let mut idx = 0usize;
    while idx < raw_all.len() {
        match raw_all[idx].as_str() {
            "--cache-dir" => {
                idx += 1;
                match raw_all.get(idx).filter(|dir| !dir.trim().is_empty()) {
                    Some(dir) => cache_dir_override = Some(PathBuf::from(dir)),
                    None => {
                        err("--cache-dir requires a path.");
                        return Ok(2);
                    }
                }
            }
            "--progress-file" => {
                idx += 1;
                match raw_all.get(idx).filter(|path| !path.trim().is_empty()) {
                    Some(path) => work_progress_file = Some(PathBuf::from(path)),
                    None => {
                        err("--progress-file requires a path.");
                        return Ok(2);
                    }
                }
            }
            "--uac-elevated" => set_uac_already_attempted(true),
            "--no-elevate" | "--read-only" => set_no_elevate_requested(true),
            "--no-update-check" => set_skip_update_check(true),
            other => raw_args.push(other.to_string()),
        }
        idx += 1;
    }

    let paths = match cache_dir_override {
        Some(dir) => AppPaths::with_base_dir(dir),
        None => AppPaths::resolve(),
    };
    if let Some(path) = work_progress_file {
        let is_gui_progress_log = path.parent() == Some(paths.cache_dir.as_path())
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("gui-progress-") && name.ends_with(".log"));
        if !is_gui_progress_log {
            err("--progress-file must be a GUI progress log inside the selected cache directory.");
            return Ok(2);
        }
        set_work_progress_file(path);
    }

    // Internal background daemons are still served by this command binary.
    if raw_args.first().map(String::as_str) == Some("_monitor") {
        return Ok(run_monitor_daemon(&paths).await);
    }
    if raw_args.len() >= 3 && raw_args[0] == "_ikev1" {
        return Ok(run_ikev1_daemon(&raw_args[1], Path::new(&raw_args[2])).await);
    }

    dispatch_commands(&paths, &raw_args).await
}

async fn dispatch_commands(paths: &AppPaths, raw_args: &[String]) -> io::Result<i32> {
    let help_text = build_help_text();
    if raw_args.is_empty() {
        print_line(&help_text);
        return Ok(0);
    }

    let mut subcmd = String::new();
    let mut country: Option<String> = None;
    let mut proto_str = "auto".to_string();
    let mut sort_str = "score".to_string();
    let mut limit: Option<usize> = None;
    let mut timeout_secs: u64 = 22;
    let mut engine = "auto".to_string();
    let mut dns = tunnel_aid_dns_cli();
    let mut start_index: usize = 1;
    let mut force_refresh = false;
    let mut auto_reconnect_override: Option<bool> = None;
    let mut custom_mirrors: Vec<String> = Vec::new();
    let mut cancel_file: Option<PathBuf> = None;
    let mut flag_countries = false;
    let mut flag_list = false;
    let mut flag_mirrors = false;
    let mut flag_status = false;
    let mut flag_doctor = false;
    let mut flag_disconnect = false;
    let mut flag_yes = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        match arg.as_str() {
            "-h" | "--help" | "help" => {
                print_line(&help_text);
                return Ok(0);
            }
            "-v" | "-V" | "--version" | "version" => {
                print_line(&format!("vpngate {}", PRODUCT_VERSION));
                return Ok(0);
            }
            "-y" | "--yes" => flag_yes = true,
            "-L" | "--list-countries" => flag_countries = true,
            "-l" | "--list" => flag_list = true,
            "-M" | "--mirrors" => flag_mirrors = true,
            "-r" | "--refresh" => force_refresh = true,
            "-S" | "--status" => flag_status = true,
            "-D" | "--doctor" => flag_doctor = true,
            "-d" | "--disconnect" => flag_disconnect = true,
            "-a" | "--autoreconnect" => auto_reconnect_override = Some(true),
            "--no-autoreconnect" => auto_reconnect_override = Some(false),
            "-c" | "--country" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    match country.as_mut() {
                        Some(existing) => {
                            existing.push(',');
                            existing.push_str(v);
                        }
                        None => country = Some(v.clone()),
                    }
                }
            }
            "-p" | "--proto" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    proto_str = v.clone();
                }
            }
            "-s" | "--sort" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    sort_str = v.clone();
                }
            }
            "-n" | "--limit" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    limit = v.parse::<usize>().ok();
                }
            }
            "-t" | "--timeout" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    timeout_secs = v.parse::<u64>().unwrap_or(22).max(5);
                }
            }
            "-e" | "--engine" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    engine = v.clone();
                }
            }
            "--dns" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    dns = v.clone();
                }
            }
            "--start" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    start_index = v.parse::<usize>().unwrap_or(1).max(1);
                }
            }
            "--mirror" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    custom_mirrors.push(v.clone());
                }
            }
            "--cancel-file" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    cancel_file = Some(PathBuf::from(v));
                } else {
                    err("Missing value for --cancel-file.");
                    return Ok(2);
                }
            }
            other if !other.starts_with('-') && subcmd.is_empty() => {
                subcmd = other.to_ascii_lowercase();
            }
            other if !other.starts_with('-') => {
                positional.push(other.to_string());
            }
            unknown => {
                err(&format!(
                    "Unknown argument '{unknown}'. Run `vpngate --help` for usage."
                ));
                return Ok(2);
            }
        }
        i += 1;
    }

    let proto_filter = ProtocolFilter::from_cli_str(&proto_str).unwrap_or_else(|| {
        err(&format!(
            "Invalid protocol '{proto_str}' (expected auto, l2tp, openvpn-udp, openvpn-tcp, openvpn)."
        ));
        std::process::exit(2);
    });
    let sort_by = SortBy::from_cli_str(&sort_str).unwrap_or(SortBy::Recommended);

    let operation =
        if flag_disconnect || matches!(subcmd.as_str(), "disconnect" | "down" | "stop" | "d") {
            Some("Disconnect")
        } else if flag_doctor || matches!(subcmd.as_str(), "doctor" | "check" | "diag") {
            Some("Diagnostics")
        } else if flag_status || matches!(subcmd.as_str(), "status" | "st") {
            Some("Connection status")
        } else if flag_mirrors || matches!(subcmd.as_str(), "mirrors" | "mirror" | "sites") {
            Some("Discover mirrors")
        } else if matches!(subcmd.as_str(), "watchdog" | "wd") {
            Some("Manage watchdog")
        } else if matches!(subcmd.as_str(), "probe") {
            Some("Probe relay")
        } else if matches!(
            subcmd.as_str(),
            "update" | "upgrade" | "self-update" | "selfupdate"
        ) {
            Some("Update desktop")
        } else if matches!(subcmd.as_str(), "refresh") {
            Some("Refresh relay pool")
        } else if matches!(subcmd.as_str(), "cooldowns") {
            Some("Reset relay cooldowns")
        } else if flag_countries || matches!(subcmd.as_str(), "countries" | "regions" | "c") {
            Some("List countries")
        } else if flag_list || matches!(subcmd.as_str(), "list" | "ls" | "servers") {
            Some("List relays")
        } else if matches!(subcmd.as_str(), "connect" | "up" | "engage") || country.is_some() {
            Some("Connect")
        } else if force_refresh {
            Some("Refresh relay pool")
        } else {
            None
        };
    if operation.is_none() {
        let command = subcmd.trim();
        if command.is_empty() {
            print_line(&help_text);
            return Ok(0);
        }
        err(&format!(
            "Unknown command '{command}'. Run `vpngate --help` for usage."
        ));
        return Ok(2);
    }
    if flag_disconnect || matches!(subcmd.as_str(), "disconnect" | "down" | "stop" | "d") {
        return cmd_disconnect(paths).await;
    }
    if flag_doctor || matches!(subcmd.as_str(), "doctor" | "check" | "diag") {
        let (rc, offer) = cmd_doctor_with_update(paths).await?;
        return Ok(match offer {
            UpgradeOffer::ExitAfterInstall => 0,
            UpgradeOffer::Failed(n) => n,
            UpgradeOffer::Continue => rc,
        });
    }
    if flag_status || matches!(subcmd.as_str(), "status" | "st") {
        return cmd_status(paths).await;
    }
    if flag_mirrors || matches!(subcmd.as_str(), "mirrors" | "mirror" | "sites") {
        return cmd_mirrors(paths, &custom_mirrors).await;
    }
    if matches!(subcmd.as_str(), "watchdog" | "wd") {
        let mode = positional.first().map(String::as_str).unwrap_or("status");
        return Ok(cmd_watchdog(paths, mode));
    }
    if matches!(subcmd.as_str(), "probe") {
        let Some(ip) = positional.first() else {
            err("Usage: vpngate probe <IPv4>");
            return Ok(2);
        };
        return cmd_probe(ip).await;
    }
    if matches!(
        subcmd.as_str(),
        "update" | "upgrade" | "self-update" | "selfupdate"
    ) {
        return cmd_upgrade(paths, flag_yes).await;
    }
    if matches!(subcmd.as_str(), "refresh") {
        return cmd_refresh(paths, &custom_mirrors).await;
    }
    if matches!(subcmd.as_str(), "cooldowns") {
        return match positional.first().map(String::as_str) {
            Some("reset") => cmd_reset_cooldowns(paths),
            _ => {
                err("Usage: vpngate cooldowns reset");
                Ok(2)
            }
        };
    }
    if flag_countries || matches!(subcmd.as_str(), "countries" | "regions" | "c") {
        return cmd_countries(paths, proto_filter, force_refresh, &custom_mirrors).await;
    }
    if flag_list || matches!(subcmd.as_str(), "list" | "ls" | "servers") {
        let target_cc = country.or_else(|| positional.first().cloned());
        return cmd_list(
            paths,
            target_cc.as_deref(),
            proto_filter,
            sort_by,
            limit.unwrap_or(25),
            force_refresh,
            &custom_mirrors,
        )
        .await;
    }
    if matches!(subcmd.as_str(), "connect" | "up" | "engage") || country.is_some() {
        let target_cc = country
            .or_else(|| positional.first().cloned())
            .unwrap_or_default();
        let cargs = ConnectArgs {
            country: target_cc,
            proto_filter,
            sort_by,
            limit: limit.unwrap_or(0),
            timeout_secs,
            engine,
            dns,
            start_index,
            force_refresh,
            auto_reconnect_override,
            custom_mirrors,
            cancel_file,
        };
        return cmd_connect(paths, &cargs).await;
    }
    if force_refresh {
        return cmd_refresh(paths, &custom_mirrors).await;
    }

    err("Unsupported command. Run `vpngate --help` for usage.");
    Ok(2)
}

#[tokio::main]
async fn main() {
    let code = match dispatch().await {
        Ok(c) => c,
        Err(e) => {
            err(&format!("Fatal runtime error: {e}"));
            1
        }
    };
    std::process::exit(code);
}
