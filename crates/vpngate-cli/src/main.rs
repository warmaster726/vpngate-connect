//! `vpngate` — Single-Binary Cross-Platform Desktop CLI & Interactive Console
//! Replicating the Python `v5.3` dual-mode CLI + `[0-9]` Console UX with 100% pure-Rust IKEv1/XFRM.
//! 64-bit native (`x86_64` and `aarch64`). 32-bit is not supported.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "VPN Gate Connect desktop supports 64-bit x86_64 and aarch64 only. Build with --target x86_64-unknown-linux-gnu / aarch64-unknown-linux-gnu, x86_64-pc-windows-msvc / aarch64-pc-windows-msvc, or x86_64-apple-darwin / aarch64-apple-darwin."
);

mod commands;
mod term_ui;

use std::env;
use std::io;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};

use commands::{
    ConnectArgs, UpgradeOffer, cmd_connect, cmd_countries, cmd_disconnect, cmd_doctor_with_update,
    cmd_list, cmd_mirrors, cmd_probe, cmd_refresh, cmd_status, cmd_upgrade, cmd_watchdog,
    interactive_menu, set_no_elevate_requested, set_skip_update_check, set_uac_already_attempted,
};
use term_ui::{err, init_console, print_line, prompt_input, set_dynamic_resize, set_screen_clear};
use vpngate_core::{
    AppPaths, PRODUCT_VERSION, ProtocolFilter, SortBy, assert_supported_native_host,
    run_ikev1_daemon, run_monitor_daemon,
};

fn build_help_text() -> String {
    format!(
        "vpngate v{} — 64-bit SoftEther VPN Gate Client (Auto: L2TP/IPsec -> OVPN UDP -> OVPN TCP)\n\n\
         USAGE:\n\
           vpngate                              Launch Interactive Console Dashboard [0-9]\n\
           vpngate countries [-p PROTO] [-r]    List available countries & protocol counts\n\
           vpngate list [-c CC] [-p PROTO] [-s SORT] [-n LIMIT] [-r]\n\
           vpngate connect -c <CC|all> [-p PROTO] [-s SORT] [-n LIMIT] [--start N] [-a]\n\
           vpngate mirrors [--mirror URL] [--export] [--import FILE]\n\
           vpngate status                       Show active tunnel, XFRM SA, watchdog & egress IP\n\
           vpngate refresh                      Clear 30m server cooldowns & force live pool update\n\
           vpngate watchdog [on|off|status]     Manage 15s Auto-Reconnect Watchdog\n\
           vpngate doctor                       Run crypto, L2TP/XFRM, OpenVPN & network diagnostics\n\
           vpngate probe <IPv4>                 Run 1-RTT IKEv1 PSK='vpn' + TCP/443 pre-flight check\n\
           vpngate disconnect                   Tear down active VPN & restore host DNS/routes/firewall\n\
           vpngate update [-y]                  Scan public main for a newer desktop (no GitHub login) and replace this install\n\
           vpngate upgrade [-y]                 Same as `vpngate update`\n\n\
         SHORTHAND FLAGS (Python v5.3 Compatible):\n\
           -i, --interactive     Launch Interactive Console Dashboard\n\
           -L, --list-countries  Show unified countries & regions table\n\
           -l, --list            List matching relay servers\n\
           -c, --country <CC>    Target country code/name (e.g. JP, KR, US, TW, all)\n\
           -p, --proto <PROTO>   auto (default) | l2tp | openvpn-udp | openvpn-tcp | openvpn\n\
           -s, --sort <SORT>     score (default) | speed | ping\n\
           -n, --limit <N>       Max servers to list or try (0 = all)\n\
           -t, --timeout <SEC>   Per-attempt tunnel timeout in seconds (default: 22)\n\
           -e, --engine <ENG>    auto | nm | daemon\n\
               --dns <IPS>       Locked tunnel DNS servers (default: '1.1.1.1 1.0.0.1')\n\
               --start <N>       1-based server index in sorted list to start connecting from\n\
           -M, --mirrors         Discover & live-probe Official VPNGate Mirror Sites\n\
               --mirror <URL>    Add/use an Official VPNGate Mirror URL (e.g. http://host:port/en/)\n\
               --export          Print last-good mirror URLs as a paste/QR seed\n\
               --import <FILE>   Load a mirror seed file (`-` = stdin)\n\
           -r, --refresh         Force live pool refresh from vpngate.net / mirrors\n\
           -a, --autoreconnect   Enable 15s Auto-Reconnect Watchdog for this session\n\
               --no-autoreconnect Disable Auto-Reconnect Watchdog for this session\n\
           -S, --status          Show live VPN tunnel & public egress IP status\n\
           -D, --doctor          Run system & crypto diagnostics\n\
           -d, --disconnect      Disconnect active VPN Gate tunnel\n\
           -w, --window          Launch inside dedicated GNOME GTK/VTE or Windows Terminal window\n\
               --no-resize       Disable dynamic terminal window resize sequences\n\
               --no-clear        Do not clear previous screen items before command execution\n\
               --no-update-check Skip the dashboard scan for a newer desktop\n\
           -y, --yes             With `update`/`upgrade`, install without an extra confirmation prompt\n\
           -h, --help            Print this help message\n",
        PRODUCT_VERSION
    )
}

fn delegate_to_window_launcher(paths: &AppPaths, raw_args: &[String]) -> i32 {
    let filtered: Vec<String> = raw_args
        .iter()
        .filter(|a| a.as_str() != "-w" && a.as_str() != "--window")
        .cloned()
        .collect();

    #[cfg(windows)]
    {
        let Ok(self_exe) = env::current_exe() else {
            err("Could not determine vpngate executable path.");
            return 1;
        };
        let is_interactive = filtered.is_empty()
            || filtered
                .iter()
                .any(|a| matches!(a.as_str(), "-i" | "--interactive" | "menu" | "interactive"));
        let mut launch_args = vec![
            "--cache-dir".to_string(),
            paths.cache_dir.display().to_string(),
        ];
        launch_args.extend(filtered);
        if !is_interactive {
            launch_args.push("--hold".to_string());
        }

        if !vpngate_core::is_root_or_admin() && !commands::no_elevate_requested() {
            let mut uac_args = vec!["--uac-elevated".to_string()];
            uac_args.extend_from_slice(&launch_args);
            if commands::win_uac::run_elevated(&self_exe, &uac_args, false).is_ok() {
                return 0;
            }
        }

        if let Some(wt) = vpngate_core::which_bin("wt") {
            let mut cmd = std::process::Command::new(wt);
            cmd.args(["--title", "VPN Gate"])
                .arg(self_exe)
                .args(&launch_args);
            return i32::from(cmd.spawn().is_err());
        }

        let ps_bin = vpngate_core::which_bin("pwsh")
            .or_else(|| vpngate_core::which_bin("powershell"))
            .unwrap_or_else(|| PathBuf::from("powershell.exe"));
        let mut quoted = vec![format!(
            "'{}'",
            self_exe.display().to_string().replace('\'', "''")
        )];
        for a in &launch_args {
            quoted.push(format!("'{}'", a.replace('\'', "''")));
        }
        let ps_line = format!("& {}", quoted.join(" "));
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/c", "start", "VPN Gate"])
            .arg(ps_bin)
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &ps_line,
            ])
            .creation_flags(0x0800_0000);
        i32::from(cmd.spawn().is_err())
    }

    #[cfg(not(windows))]
    {
        let _ = paths;
        let self_dir = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
        let mut cands = Vec::new();
        if let Some(d) = self_dir {
            cands.push(d.join("vpngate-launcher"));
        }
        cands.push(PathBuf::from("/usr/local/bin/vpngate-launcher"));
        if let Some(w) = vpngate_core::which_bin("vpngate-launcher") {
            cands.push(w);
        }

        let Some(launcher) = cands.into_iter().find(|p| p.is_file()) else {
            err("Could not find 'vpngate-launcher'. Run `sh ./install-vpngate.sh` first.");
            return 1;
        };

        let mut cmd = std::process::Command::new(launcher);
        if !filtered.is_empty() {
            cmd.arg("--hold");
        }
        cmd.args(&filtered);
        cmd.status().ok().and_then(|s| s.code()).unwrap_or(1)
    }
}

async fn dispatch() -> io::Result<i32> {
    let raw_all: Vec<String> = env::args().skip(1).collect();
    let is_daemon = matches!(
        raw_all.first().map(String::as_str),
        Some("_monitor" | "_ikev1")
    );
    init_console(!is_daemon);
    if let Err(msg) = assert_supported_native_host() {
        err(&msg);
        return Ok(1);
    }

    // Pre-scan global `--cache-dir <DIR>`, `--hold`, and Windows UAC flags before dispatching
    let mut cache_dir_override: Option<PathBuf> = None;
    let mut hold_on_exit = false;
    let mut raw_args: Vec<String> = Vec::with_capacity(raw_all.len());
    let mut idx = 0usize;
    while idx < raw_all.len() {
        match raw_all[idx].as_str() {
            "--cache-dir" => {
                idx += 1;
                if let Some(dir) = raw_all.get(idx)
                    && !dir.trim().is_empty()
                {
                    cache_dir_override = Some(PathBuf::from(dir));
                }
            }
            "--hold" => {
                hold_on_exit = true;
            }
            "--uac-elevated" => {
                set_uac_already_attempted(true);
            }
            "--no-elevate" | "--read-only" => {
                set_no_elevate_requested(true);
            }
            "--no-update-check" => {
                set_skip_update_check(true);
            }
            other => raw_args.push(other.to_string()),
        }
        idx += 1;
    }

    let paths = match cache_dir_override {
        Some(dir) => AppPaths::with_base_dir(dir),
        None => AppPaths::resolve(),
    };

    // Internal background daemons (exact match with Python v5.3 architecture)
    if raw_args.first().map(String::as_str) == Some("_monitor") {
        return Ok(run_monitor_daemon(&paths).await);
    }
    if raw_args.len() >= 3 && raw_args[0] == "_ikev1" {
        return Ok(run_ikev1_daemon(&raw_args[1], Path::new(&raw_args[2])).await);
    }
    if raw_args.iter().any(|a| a == "-w" || a == "--window") {
        return Ok(delegate_to_window_launcher(&paths, &raw_args));
    }

    let rc = dispatch_commands(&paths, &raw_args).await?;
    if hold_on_exit && term_ui::is_stdout_tty() {
        let _ = prompt_input("\nPress Enter to close this window...");
    }
    Ok(rc)
}

async fn dispatch_commands(paths: &AppPaths, raw_args: &[String]) -> io::Result<i32> {
    let help_text = build_help_text();
    if raw_args.is_empty() {
        return interactive_menu(paths, &help_text).await;
    }

    let mut subcmd = String::new();
    let mut country: Option<String> = None;
    let mut proto_str = "auto".to_string();
    let mut sort_str = "score".to_string();
    let mut limit: Option<usize> = None;
    let mut timeout_secs: u64 = 22;
    let mut engine = "auto".to_string();
    let mut dns = "1.1.1.1 1.0.0.1".to_string();
    let mut start_index: usize = 1;
    let mut force_refresh = false;
    let mut auto_reconnect_override: Option<bool> = None;
    let mut custom_mirrors: Vec<String> = Vec::new();
    let mut export_seed = false;
    let mut import_path: Option<String> = None;
    let mut flag_interactive = false;
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
            "--no-resize" => set_dynamic_resize(false),
            "--no-clear" => set_screen_clear(false),
            "-y" | "--yes" => flag_yes = true,
            "-i" | "--interactive" => flag_interactive = true,
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
                    country = Some(v.clone());
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
            "--export" => {
                export_seed = true;
            }
            "--import" => {
                i += 1;
                if let Some(v) = raw_args.get(i) {
                    import_path = Some(v.clone());
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

    if flag_interactive || matches!(subcmd.as_str(), "menu" | "interactive") {
        return interactive_menu(paths, &help_text).await;
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
        return cmd_mirrors(paths, &custom_mirrors, export_seed, import_path.as_deref()).await;
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
        };
        return cmd_connect(paths, &cargs).await;
    }
    if force_refresh {
        return cmd_refresh(paths, &custom_mirrors).await;
    }

    interactive_menu(paths, &help_text).await
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
