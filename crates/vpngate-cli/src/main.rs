mod commands;
mod term_ui;

use std::env;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use vpngate_core::{
    AppPaths, ProtocolFilter, SortBy, detect_host_os_label, run_ikev1_daemon, run_monitor_daemon,
};

use crate::commands::{
    ConnectArgs, cmd_connect, cmd_countries, cmd_disconnect, cmd_doctor, cmd_list, cmd_probe,
    cmd_refresh, cmd_status, cmd_watchdog, interactive_menu,
};
use crate::term_ui::{err, set_dynamic_resize};

fn help_reference() -> String {
    format!(
        "vpngate v{} ({}) — Unified Cross-Platform Encrypted L2TP/IPsec (Zero IKEv2) & OpenVPN Client\n\
         Priority Cascade: Auto -> L2TP/IPsec (PSK='vpn') -> OpenVPN UDP -> OpenVPN TCP\n\n\
         USAGE:\n\
           vpngate                         Launch interactive [0-8] Console Dashboard\n\
           vpngate countries [-p PROTO]    List available countries/regions & protocol counts\n\
           vpngate list [-c CC] [-p PROTO] List ranked servers matching filters\n\
           vpngate connect -c CC [OPTIONS] Recursively test & connect to best verified server\n\
           vpngate disconnect              Disconnect active tunnel & restore host network\n\
           vpngate status                  Show active VPN session, XFRM SA & public egress IP\n\
           vpngate doctor                  Run system readiness & pure-Rust IKEv1 diagnostics\n\
           vpngate watchdog [on|off|status] Inspect or toggle Auto-Reconnect Watchdog\n\
           vpngate refresh                 Force live server pool refresh & clear cooldowns\n\
           vpngate probe <IPV4>            Run 1-RTT IKEv1 PSK='vpn' + TCP-443 pre-flight check\n\n\
         SHORTHAND FLAGS:\n\
           -i, --interactive     Launch interactive [0-8] Console Dashboard\n\
           -L, --list-countries  List available countries/regions table\n\
           -l, --list-servers    List servers matching -c / -p / -s filters\n\
           -c, --country <CC>    Target country ISO2 (e.g. JP, KR, US, HK, all) or name\n\
           -p, --proto <PROTO>   auto | all | l2tp | openvpn-udp | openvpn-tcp | openvpn\n\
           -s, --sort <SORT>     recommended | score | speed | ping\n\
           -n, --limit <N>       Max servers to list or test (0 = all)\n\
           -t, --timeout <SEC>   Per-server handshake timeout in seconds (default: 22)\n\
           -e, --engine <ENG>    auto | builtin | nm | openvpn\n\
               --dns <IPS>       Tunnel DNS servers (default: \"1.1.1.1 1.0.0.1\")\n\
               --start <IDX>     1-based server index to start testing from (default: 1)\n\
           -a, --autoreconnect   Enable background Auto-Reconnect Watchdog\n\
               --no-autoreconnect Disable background Auto-Reconnect Watchdog\n\
           -r, --refresh         Force live server pool refresh\n\
           -S, --status          Show active VPN status & public IP\n\
           -D, --doctor          Run system & crypto diagnostics\n\
           -d, --disconnect      Disconnect active VPN Gate tunnel\n\
           -w, --window          Launch inside dedicated GNOME GTK/VTE or Windows Terminal window\n\
               --no-resize       Disable dynamic terminal window resize sequences\n\
           -h, --help            Print this help reference\n\
           -V, --version         Print version",
        env!("CARGO_PKG_VERSION"),
        detect_host_os_label()
    )
}

#[derive(Default)]
struct ParsedFlags {
    interactive: bool,
    list_countries: bool,
    list_servers: bool,
    status: bool,
    doctor: bool,
    disconnect: bool,
    refresh: bool,
    help: bool,
    version: bool,
    country: Option<String>,
    proto: Option<String>,
    sort: Option<String>,
    limit: Option<usize>,
    timeout: Option<u64>,
    engine: Option<String>,
    dns: Option<String>,
    start: Option<usize>,
    autoreconnect: Option<bool>,
    positionals: Vec<String>,
}

fn parse_flags(args: &[String]) -> Result<ParsedFlags, String> {
    let mut out = ParsedFlags::default();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-h" | "--help" => out.help = true,
            "-V" | "--version" => out.version = true,
            "-i" | "--interactive" => out.interactive = true,
            "-L" | "--list-countries" => out.list_countries = true,
            "-l" | "--list-servers" => out.list_servers = true,
            "-S" | "--status" => out.status = true,
            "-D" | "--doctor" => out.doctor = true,
            "-d" | "--disconnect" => out.disconnect = true,
            "-r" | "--refresh" => out.refresh = true,
            "-a" | "--autoreconnect" => out.autoreconnect = Some(true),
            "--no-autoreconnect" => out.autoreconnect = Some(false),
            "--no-resize" => set_dynamic_resize(false),
            "-c" | "--country" => {
                i += 1;
                out.country = Some(args.get(i).ok_or("Missing value for -c/--country")?.clone());
            }
            "-p" | "--proto" => {
                i += 1;
                out.proto = Some(args.get(i).ok_or("Missing value for -p/--proto")?.clone());
            }
            "-s" | "--sort" => {
                i += 1;
                out.sort = Some(args.get(i).ok_or("Missing value for -s/--sort")?.clone());
            }
            "-n" | "--limit" => {
                i += 1;
                let v = args.get(i).ok_or("Missing value for -n/--limit")?;
                out.limit = Some(v.parse().map_err(|_| format!("Invalid --limit: {v}"))?);
            }
            "-t" | "--timeout" => {
                i += 1;
                let v = args.get(i).ok_or("Missing value for -t/--timeout")?;
                out.timeout = Some(v.parse().map_err(|_| format!("Invalid --timeout: {v}"))?);
            }
            "-e" | "--engine" => {
                i += 1;
                out.engine = Some(args.get(i).ok_or("Missing value for -e/--engine")?.clone());
            }
            "--dns" => {
                i += 1;
                out.dns = Some(args.get(i).ok_or("Missing value for --dns")?.clone());
            }
            "--start" => {
                i += 1;
                let v = args.get(i).ok_or("Missing value for --start")?;
                out.start = Some(v.parse().map_err(|_| format!("Invalid --start: {v}"))?);
            }
            other if other.starts_with('-') => {
                return Err(format!("Unknown flag '{other}'. Run `vpngate --help`."));
            }
            pos => out.positionals.push(pos.to_string()),
        }
        i += 1;
    }
    Ok(out)
}

fn delegate_to_window_launcher(raw_args: &[String]) -> i32 {
    let filtered: Vec<String> = raw_args
        .iter()
        .filter(|a| a.as_str() != "-w" && a.as_str() != "--window")
        .cloned()
        .collect();

    if cfg!(target_os = "windows") {
        let Ok(self_exe) = env::current_exe() else {
            err("Could not determine vpngate executable path.");
            return 1;
        };
        if let Some(wt) = vpngate_core::which_bin("wt") {
            let mut cmd = std::process::Command::new(wt);
            cmd.args(["--title", "VPN Gate"])
                .arg(self_exe)
                .args(&filtered);
            return i32::from(cmd.spawn().is_err());
        }
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/c", "start", "VPN Gate"])
            .arg(self_exe)
            .args(&filtered);
        return i32::from(cmd.spawn().is_err());
    }

    let self_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
    let mut cands = Vec::new();
    if let Some(d) = self_dir {
        cands.push(d.join("vpngate-launcher"));
        cands.push(d.join("vpngate-launcher.py"));
        // Also support running from target/{debug,release}/vpngate inside repo root
        if let Some(repo_root) = d.parent().and_then(|p| p.parent()) {
            cands.push(repo_root.join("vpngate-launcher.py"));
        }
    }
    cands.push(std::path::PathBuf::from("/usr/local/bin/vpngate-launcher"));
    cands.push(std::path::PathBuf::from(
        "/usr/local/bin/vpngate-launcher.py",
    ));
    if let Some(w) = vpngate_core::which_bin("vpngate-launcher")
        .or_else(|| vpngate_core::which_bin("vpngate-launcher.py"))
    {
        cands.push(w);
    }

    let Some(launcher) = cands.into_iter().find(|p| p.is_file()) else {
        err("Could not find 'vpngate-launcher'. Run `sh ./install-vpngate.sh` first.");
        return 1;
    };

    let mut cmd = std::process::Command::new("python3");
    cmd.arg(launcher);
    if !filtered.is_empty() {
        cmd.arg("--hold");
    }
    cmd.args(&filtered);
    cmd.status().ok().and_then(|s| s.code()).unwrap_or(1)
}

async fn dispatch() -> io::Result<i32> {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let paths = AppPaths::resolve();

    // Internal background daemons (exact match with Python v5.3 architecture)
    if raw_args.first().map(String::as_str) == Some("_monitor") {
        return Ok(run_monitor_daemon(&paths).await);
    }
    if raw_args.len() >= 3 && raw_args[0] == "_ikev1" {
        return Ok(run_ikev1_daemon(&raw_args[1], Path::new(&raw_args[2])).await);
    }
    if raw_args.iter().any(|a| a == "-w" || a == "--window") {
        return Ok(delegate_to_window_launcher(&raw_args));
    }

    let help_txt = help_reference();
    if raw_args.is_empty() {
        return interactive_menu(&paths, &help_txt).await;
    }

    let flags = match parse_flags(&raw_args) {
        Ok(f) => f,
        Err(msg) => {
            err(&msg);
            return Ok(2);
        }
    };

    if flags.help {
        println!("{help_txt}");
        return Ok(0);
    }
    if flags.version {
        println!("vpngate {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }

    let pfilter = match flags.proto.as_deref() {
        Some(p) => match ProtocolFilter::from_cli_str(p) {
            Some(pf) => pf,
            None => {
                err(&format!("Invalid protocol '{p}'."));
                return Ok(2);
            }
        },
        None => ProtocolFilter::Auto,
    };
    let sby = match flags.sort.as_deref() {
        Some(s) => match SortBy::from_cli_str(s) {
            Some(sb) => sb,
            None => {
                err(&format!("Invalid sort '{s}'."));
                return Ok(2);
            }
        },
        None => SortBy::Recommended,
    };

    if let Some(sub) = flags.positionals.first().map(String::as_str) {
        match sub {
            "menu" | "interactive" => return interactive_menu(&paths, &help_txt).await,
            "countries" | "regions" | "c" => {
                return cmd_countries(&paths, pfilter, flags.refresh).await;
            }
            "list" | "ls" | "servers" => {
                let country = flags
                    .country
                    .as_deref()
                    .or_else(|| flags.positionals.get(1).map(String::as_str));
                let lim = flags.limit.unwrap_or(25);
                return cmd_list(&paths, country, pfilter, sby, lim, flags.refresh).await;
            }
            "connect" | "up" | "engage" => {
                let country = flags
                    .country
                    .clone()
                    .or_else(|| flags.positionals.get(1).cloned())
                    .unwrap_or_default();
                let cargs = ConnectArgs {
                    country,
                    proto_filter: pfilter,
                    sort_by: sby,
                    limit: flags.limit.unwrap_or(0),
                    timeout_secs: flags.timeout.unwrap_or(22),
                    engine: flags.engine.unwrap_or_else(|| "auto".to_string()),
                    dns: flags.dns.unwrap_or_else(|| "1.1.1.1 1.0.0.1".to_string()),
                    start_index: flags.start.unwrap_or(1),
                    force_refresh: flags.refresh,
                    auto_reconnect_override: flags.autoreconnect,
                };
                return cmd_connect(&paths, &cargs).await;
            }
            "refresh" | "update" => return cmd_refresh(&paths).await,
            "status" | "st" => return cmd_status(&paths).await,
            "doctor" | "check" | "diag" => return cmd_doctor(&paths),
            "watchdog" | "wd" => {
                let mode = flags
                    .positionals
                    .get(1)
                    .map(String::as_str)
                    .unwrap_or("status");
                return Ok(cmd_watchdog(&paths, mode));
            }
            "disconnect" | "down" | "stop" | "d" => return cmd_disconnect(&paths).await,
            "probe" => {
                let Some(ip) = flags.positionals.get(1) else {
                    err("Usage: vpngate probe <IPV4>");
                    return Ok(2);
                };
                return cmd_probe(ip).await;
            }
            other => {
                err(&format!("Unknown command '{other}'. Run `vpngate --help`."));
                return Ok(2);
            }
        }
    }

    // Top-level shorthand flag dispatch (matching Python v5.3)
    if flags.interactive {
        if flags.refresh {
            let _ = cmd_refresh(&paths).await?;
        }
        return interactive_menu(&paths, &help_txt).await;
    }
    if flags.disconnect {
        return cmd_disconnect(&paths).await;
    }
    if flags.doctor {
        return cmd_doctor(&paths);
    }
    if flags.status {
        return cmd_status(&paths).await;
    }
    if flags.list_countries {
        return cmd_countries(&paths, pfilter, flags.refresh).await;
    }
    if flags.list_servers {
        return cmd_list(
            &paths,
            flags.country.as_deref(),
            pfilter,
            sby,
            flags.limit.unwrap_or(25),
            flags.refresh,
        )
        .await;
    }
    if let Some(country) = flags.country {
        let cargs = ConnectArgs {
            country,
            proto_filter: pfilter,
            sort_by: sby,
            limit: flags.limit.unwrap_or(0),
            timeout_secs: flags.timeout.unwrap_or(22),
            engine: flags.engine.unwrap_or_else(|| "auto".to_string()),
            dns: flags.dns.unwrap_or_else(|| "1.1.1.1 1.0.0.1".to_string()),
            start_index: flags.start.unwrap_or(1),
            force_refresh: flags.refresh,
            auto_reconnect_override: flags.autoreconnect,
        };
        return cmd_connect(&paths, &cargs).await;
    }
    if flags.refresh {
        return cmd_refresh(&paths).await;
    }

    interactive_menu(&paths, &help_txt).await
}

#[tokio::main]
async fn main() -> ExitCode {
    match dispatch().await {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code.clamp(1, 255) as u8),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            err(&format!("I/O error: {e}"));
            ExitCode::FAILURE
        }
    }
}
