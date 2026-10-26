use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use vpngate_core::{
    DiscoveryClient, DiscoveryOptions, ProtocolFilter, SortBy, TargetPlatform, filter_by_country,
    probe_tcp, sort_servers, summarize_countries, verify_l2tp_psk_vpn,
};

fn write_line(out: &mut impl Write, args: std::fmt::Arguments<'_>) -> io::Result<()> {
    writeln!(out, "{args}")
}

fn print_usage(out: &mut impl Write) -> io::Result<()> {
    write_line(
        out,
        format_args!(
            "vpngate-connect v{} (host: {})",
            env!("CARGO_PKG_VERSION"),
            TargetPlatform::current().as_str()
        ),
    )?;
    write_line(out, format_args!(""))?;
    write_line(out, format_args!("Usage:"))?;
    write_line(
        out,
        format_args!(
            "  vpngate countries          Fetch live pool and summarize countries & protocols"
        ),
    )?;
    write_line(
        out,
        format_args!(
            "  vpngate list [COUNTRY]     List ranked live servers (optional ISO2 or name, e.g. JP)"
        ),
    )?;
    write_line(
        out,
        format_args!(
            "  vpngate probe <IPV4>       Run 1-RTT IKEv1 PSK='vpn' + TCP-443 pre-flight check"
        ),
    )
}

async fn run_cli() -> Result<ExitCode, io::Error> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut stdout = io::stdout().lock();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage(&mut stdout)?;
        return Ok(ExitCode::SUCCESS);
    };

    match cmd {
        "countries" => {
            let client = match DiscoveryClient::new(DiscoveryOptions::default()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error initializing HTTP client: {e}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            eprintln!("Fetching live VPN Gate relays...");
            let servers = match client.fetch_servers().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Discovery failed: {e}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let summaries = summarize_countries(&servers);
            write_line(
                &mut stdout,
                format_args!(
                    "{:<4} {:<24} {:>7} {:>6} {:>8} {:>8} {:>10}",
                    "ISO", "COUNTRY", "SERVERS", "L2TP", "OVPN-UDP", "OVPN-TCP", "MAX MBPS"
                ),
            )?;
            write_line(&mut stdout, format_args!("{}", "-".repeat(73)))?;
            for c in summaries {
                write_line(
                    &mut stdout,
                    format_args!(
                        "{:<4} {:<24} {:>7} {:>6} {:>8} {:>8} {:>10.1}",
                        c.country_short,
                        c.country_long,
                        c.total_servers,
                        c.l2tp_count,
                        c.openvpn_udp_count,
                        c.openvpn_tcp_count,
                        c.max_speed_mbps()
                    ),
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        "list" => {
            let country_arg = args.get(1).map(String::as_str);
            let client = match DiscoveryClient::new(DiscoveryOptions::default()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error initializing HTTP client: {e}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let pool = match client.fetch_servers().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Discovery failed: {e}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let mut filtered = filter_by_country(&pool, country_arg);
            sort_servers(&mut filtered, SortBy::Recommended, ProtocolFilter::Auto);

            write_line(
                &mut stdout,
                format_args!(
                    "{:<16} {:<4} {:<18} {:>9} {:>7}  PROTOCOLS",
                    "IP", "ISO", "HOST", "MBPS", "PING"
                ),
            )?;
            write_line(&mut stdout, format_args!("{}", "-".repeat(76)))?;
            for srv in filtered.into_iter().take(50) {
                let mut protos = Vec::new();
                if srv.l2tp {
                    protos.push("L2TP".to_string());
                }
                if srv.supports_openvpn_udp() {
                    protos.push(format!("UDP:{}", srv.udp_port));
                }
                if srv.supports_openvpn_tcp() {
                    protos.push(format!("TCP:{}", srv.tcp_port));
                }
                let ping_disp = if srv.ping_ms >= 9999 {
                    "-".to_string()
                } else {
                    format!("{}ms", srv.ping_ms)
                };
                write_line(
                    &mut stdout,
                    format_args!(
                        "{:<16} {:<4} {:<18} {:>9.1} {:>7}  {}",
                        srv.ip,
                        srv.country_short,
                        srv.hostname.chars().take(18).collect::<String>(),
                        srv.speed_mbps(),
                        ping_disp,
                        protos.join(", ")
                    ),
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        "probe" => {
            let Some(ip_raw) = args.get(1) else {
                eprintln!("Usage: vpngate probe <IPV4>");
                return Ok(ExitCode::FAILURE);
            };
            let Ok(ip) = ip_raw.parse::<Ipv4Addr>() else {
                eprintln!("Invalid IPv4 address: {ip_raw}");
                return Ok(ExitCode::FAILURE);
            };
            write_line(
                &mut stdout,
                format_args!("Probing {ip} (IKEv1 UDP/500 PSK='vpn' + TCP/443)..."),
            )?;
            let l2tp_res = verify_l2tp_psk_vpn(ip, Duration::from_millis(1500), 2, b"vpn").await;
            let tcp_443 = probe_tcp(
                SocketAddr::new(IpAddr::V4(ip), 443),
                Duration::from_millis(1500),
            )
            .await;

            write_line(
                &mut stdout,
                format_args!("  IKEv1 L2TP/IPsec (PSK='vpn'): {l2tp_res:?}"),
            )?;
            match tcp_443 {
                Some(rtt) => write_line(
                    &mut stdout,
                    format_args!("  TCP 443 Reachability        : OPEN ({rtt:.0?})"),
                )?,
                None => write_line(
                    &mut stdout,
                    format_args!("  TCP 443 Reachability        : CLOSED / FILTERED"),
                )?,
            }
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            print_usage(&mut stdout)?;
            Ok(ExitCode::FAILURE)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run_cli().await {
        Ok(code) => code,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("I/O error: {e}");
            ExitCode::FAILURE
        }
    }
}
