use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::country::normalize_country_pair;
use crate::doh::is_poisoned_ipv4;
use crate::server::VpnServer;

/// Official SoftEther VPN Gate Mirror Site portal (`http://<host>:<port>/en/`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialMirrorSite {
    /// Base origin without trailing slash, e.g. `http://150.40.105.11:4917`.
    pub base_url: String,
    /// Full `/en/` server list page URL, e.g. `http://150.40.105.11:4917/en/`.
    pub portal_url: String,
    /// Geographic mirror location label reported by VPN Gate (`Croatia`, `Japan`, `France`, etc.).
    pub location: String,
    /// Discovery origin (`sites.aspx`, `mirror-portal`, `daily-feed`, `wayback`, `cached`, `custom`).
    pub source: String,
}

/// Normalizes a raw mirror URL (`http://150.40.105.11:4917/en/` or `150.40.105.11:4917`)
/// into `(base_url, portal_url)`, excluding primary `vpngate.net` itself.
pub fn normalize_mirror_base_url(raw: &str) -> Option<(String, String)> {
    let trimmed = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '.');
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = reqwest::Url::parse(&with_scheme).ok()?;
    let host = parsed.host_str()?;
    let host_low = host.to_ascii_lowercase();
    if matches!(
        host_low.as_str(),
        "www.vpngate.net"
            | "vpngate.net"
            | "www.tsukuba.ac.jp"
            | "tsukuba.ac.jp"
            | "www.softether.org"
            | "softether.org"
            | "icondrawer.com"
            | "www.win10pcap.org"
            | "web.archive.org"
    ) || host_low.ends_with(".tsukuba.ac.jp")
        || host_low.ends_with(".archive.org")
    {
        return None;
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>()
        && is_poisoned_ipv4(v4)
    {
        return None;
    }
    let scheme = parsed.scheme();
    let base = match parsed.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    let portal = format!("{base}/en/");
    Some((base, portal))
}

/// Parses Official VPN Gate Mirror Sites from `sites.aspx` HTML or daily mirror email text.
pub fn parse_vpngate_mirror_sites_html(html: &str, source_label: &str) -> Vec<OfficialMirrorSite> {
    static RE_URL: OnceLock<Regex> = OnceLock::new();
    static RE_LOC: OnceLock<Regex> = OnceLock::new();

    if html.is_empty() {
        return Vec::new();
    }

    let re_url = RE_URL.get_or_init(|| {
        Regex::new(r#"(?i)(https?://[a-z0-9.\-]+:\d+(?:/en/?|/?))"#)
            .expect("valid mirror url regex")
    });
    let re_loc = RE_LOC.get_or_init(|| {
        Regex::new(r"(?i)\(\s*(?:Mirror\s+)?location:\s*([^)<\r\n]+)").expect("valid loc regex")
    });

    let mut out = Vec::new();
    let mut seen = BTreeMap::<String, usize>::new();

    let mut push_item = |raw_url: &str, raw_loc: Option<&str>| {
        let Some((base_url, portal_url)) = normalize_mirror_base_url(raw_url) else {
            return;
        };
        let loc_clean = raw_loc
            .map(|s| {
                let s = s.replace("&nbsp;", " ");
                let before_local = s.split("(LOCAL").next().unwrap_or(&s);
                before_local.trim().trim_end_matches(')').trim().to_string()
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Unknown".to_string());

        if let Some(&idx) = seen.get(&base_url) {
            let existing: &mut OfficialMirrorSite = &mut out[idx];
            if existing.location == "Unknown" && loc_clean != "Unknown" {
                existing.location = loc_clean;
            }
        } else {
            seen.insert(base_url.clone(), out.len());
            out.push(OfficialMirrorSite {
                base_url,
                portal_url,
                location: loc_clean,
                source: source_label.to_string(),
            });
        }
    };

    let normalized = html.replace("<li", "\n<li").replace("<br", "\n<br");
    for line in normalized.lines() {
        let loc_opt = re_loc
            .captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str());
        for cap in re_url.captures_iter(line) {
            push_item(&cap[1], loc_opt);
        }
    }

    out
}

fn parse_u64_clean(s: &str, default: u64) -> u64 {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    cleaned.parse::<u64>().unwrap_or(default)
}

fn parse_u32_clean(s: &str, default: u32) -> u32 {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    cleaned.parse::<u32>().unwrap_or(default)
}

fn valid_public_ipv4_str(s: &str) -> Option<String> {
    let v4 = s.trim().parse::<Ipv4Addr>().ok()?;
    if is_poisoned_ipv4(v4) {
        return None;
    }
    Some(v4.to_string())
}

fn extract_ovpn_transport_and_ports(b64: &str) -> (bool, u16, u16) {
    static RE_PROTO: OnceLock<Regex> = OnceLock::new();
    static RE_REMOTE: OnceLock<Regex> = OnceLock::new();

    if b64.is_empty() {
        return (false, 0, 0);
    }
    let Ok(bytes) = BASE64_STD.decode(b64.trim()) else {
        return (false, 0, 0);
    };
    let text = String::from_utf8_lossy(&bytes);
    if !text.contains("<ca>") {
        return (false, 0, 0);
    }

    let re_proto = RE_PROTO.get_or_init(|| Regex::new(r"(?m)^proto\s+(\w+)").expect("valid regex"));
    let re_remote =
        RE_REMOTE.get_or_init(|| Regex::new(r"(?m)^remote\s+\S+\s+(\d+)").expect("valid regex"));

    let mut tcp_port = 0u16;
    let mut udp_port = 0u16;
    if let (Some(cp), Some(cr)) = (re_proto.captures(&text), re_remote.captures(&text))
        && let Ok(port) = cr[1].parse::<u16>()
    {
        if cp[1].to_ascii_lowercase().starts_with("tcp") {
            tcp_port = port;
        } else {
            udp_port = port;
        }
    }
    (true, tcp_port, udp_port)
}

/// Parses official VPN Gate `/api/iphone/` & mirror CSV feeds into `servers_by_ip`.
pub fn parse_vpngate_csv_into(csv_raw: &str, servers_by_ip: &mut BTreeMap<String, VpnServer>) {
    for raw_line in csv_raw.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('*') || trimmed.starts_with('#') {
            continue;
        }
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_reader(trimmed.as_bytes());

        let Some(Ok(row)) = rdr.records().next() else {
            continue;
        };
        if row.len() < 15 {
            continue;
        }

        let Some(ip) = valid_public_ipv4_str(&row[1]) else {
            continue;
        };

        let b64 = row[14].trim().to_string();
        let (ovpn_ok, tcp_port, udp_port) = extract_ovpn_transport_and_ports(&b64);

        let score = parse_u64_clean(&row[2], 0);
        let mut ping_ms = parse_u32_clean(&row[3], 9999);
        if ping_ms == 0 {
            ping_ms = 9999;
        }
        let speed_bps = parse_u64_clean(&row[4], 0);
        let sessions = parse_u32_clean(&row[7], 0);
        let uptime_ms = parse_u64_clean(&row[8], 0);
        let (country_long, country_short) = normalize_country_pair(&row[5], &row[6]);
        let hostname = {
            let h = row[0].trim();
            if h.is_empty() {
                ip.clone()
            } else {
                h.to_string()
            }
        };
        let operator = row[12].trim().to_string();

        if let Some(existing) = servers_by_ip.get_mut(&ip) {
            if ovpn_ok {
                existing.openvpn = true;
                if existing.ovpn_b64.is_empty() || score >= existing.score {
                    existing.ovpn_b64 = b64;
                }
            }
            if tcp_port > 0 {
                existing.tcp_port = tcp_port;
            }
            if udp_port > 0 {
                existing.udp_port = udp_port;
            }
            if score > existing.score {
                existing.score = score;
            }
            if ping_ms > 0 && ping_ms < existing.ping_ms {
                existing.ping_ms = ping_ms;
            }
            if speed_bps > existing.speed_bps {
                existing.speed_bps = speed_bps;
            }
            if existing.country_short == "XX" && country_short != "XX" {
                existing.country_short = country_short;
                existing.country_long = country_long;
            }
        } else {
            servers_by_ip.insert(
                ip.clone(),
                VpnServer {
                    hostname,
                    ip,
                    score,
                    ping_ms,
                    speed_bps,
                    country_long,
                    country_short,
                    sessions,
                    uptime_ms,
                    operator,
                    l2tp: false,
                    openvpn: ovpn_ok,
                    tcp_port,
                    udp_port,
                    ovpn_b64: if ovpn_ok { b64 } else { String::new() },
                    ovpn_dl_query: String::new(),
                },
            );
        }
    }
}

/// Parses rolling `sdise/vpngate` candidate CSV (`Country,Hostname,IP,Speed_Mbps,TCP_Port`).
/// Leaves `l2tp = false` and `openvpn = false` until live pre-flight verification succeeds.
pub fn parse_sdise_csv_into(csv_raw: &str, target_by_ip: &mut BTreeMap<String, VpnServer>) {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_raw.as_bytes());

    for rec in rdr.records().flatten() {
        if rec.len() < 4 || rec[0].trim().eq_ignore_ascii_case("country") {
            continue;
        }
        let Some(ip) = valid_public_ipv4_str(&rec[2]) else {
            continue;
        };
        if target_by_ip.contains_key(&ip) {
            continue;
        }

        let (country_long, country_short) = normalize_country_pair(&rec[0], "");
        let raw_host = rec[1].trim();
        let host = raw_host
            .strip_suffix(".opengw.net")
            .or_else(|| raw_host.strip_suffix(".OPENGW.NET"))
            .unwrap_or(raw_host)
            .trim();
        let hostname = if host.is_empty() {
            ip.clone()
        } else {
            host.to_string()
        };
        let speed_bps = rec[3]
            .trim()
            .parse::<f64>()
            .map(|mbps| (mbps.max(0.0) * 1_000_000.0) as u64)
            .unwrap_or(0);

        target_by_ip.insert(
            ip.clone(),
            VpnServer {
                hostname,
                ip,
                score: (speed_bps / 500).max(100_000),
                ping_ms: 9999,
                speed_bps,
                country_long,
                country_short,
                sessions: 0,
                uptime_ms: 0,
                operator: "VPNGate Volunteer".to_string(),
                l2tp: false,
                openvpn: false,
                tcp_port: 0,
                udp_port: 0,
                ovpn_b64: String::new(),
                ovpn_dl_query: String::new(),
            },
        );
    }
}

/// Parses VPN Gate HTML server table rows (`www.vpngate.net/en/` & Wayback snapshots),
/// extracting L2TP support (`howto_l2tp.aspx`), OpenVPN TCP/UDP ports (`do_openvpn.aspx`), and stats.
pub fn parse_vpngate_html_into(html_raw: &str, servers_by_ip: &mut BTreeMap<String, VpnServer>) {
    static RE_IP: OnceLock<Regex> = OnceLock::new();
    static RE_OVPN: OnceLock<Regex> = OnceLock::new();
    static RE_TCP: OnceLock<Regex> = OnceLock::new();
    static RE_UDP: OnceLock<Regex> = OnceLock::new();
    static RE_FLAG: OnceLock<Regex> = OnceLock::new();
    static RE_CNAME: OnceLock<Regex> = OnceLock::new();
    static RE_HOST: OnceLock<Regex> = OnceLock::new();
    static RE_SCORE: OnceLock<Regex> = OnceLock::new();
    static RE_PING: OnceLock<Regex> = OnceLock::new();
    static RE_SPEED: OnceLock<Regex> = OnceLock::new();
    static RE_SESS: OnceLock<Regex> = OnceLock::new();

    if html_raw.is_empty() {
        return;
    }

    let re_ip = RE_IP.get_or_init(|| Regex::new(r">(\d{1,3}(?:\.\d{1,3}){3})<").expect("regex"));
    let re_ovpn =
        RE_OVPN.get_or_init(|| Regex::new(r#"do_openvpn\.aspx\?([^'"]+)"#).expect("regex"));
    let re_tcp = RE_TCP.get_or_init(|| Regex::new(r"(?:^|&)tcp=(\d+)").expect("regex"));
    let re_udp = RE_UDP.get_or_init(|| Regex::new(r"(?:^|&)udp=(\d+)").expect("regex"));
    let re_flag = RE_FLAG
        .get_or_init(|| Regex::new(r"\.\./images/flags/([A-Z]{2})\.png'\s+width='32'").expect("r"));
    let re_cname = RE_CNAME.get_or_init(|| {
        Regex::new(r"(?i)width='32'\s+height='32'\s*/>\s*<br>\s*([^<]+)</td>").expect("r")
    });
    let re_host = RE_HOST.get_or_init(|| {
        Regex::new(r"<b><span[^>]*>([^<]+?)(?:\.opengw\.net)?</span></b>").expect("r")
    });
    let re_score =
        RE_SCORE.get_or_init(|| Regex::new(r"<b><span[^>]*>([\d,]+)</span></b></td>").expect("r"));
    let re_ping = RE_PING.get_or_init(|| Regex::new(r"(?i)Ping:\s*<b>(\d+)\s*ms</b>").expect("r"));
    let re_speed = RE_SPEED
        .get_or_init(|| Regex::new(r"(?i)<b><span[^>]*>([\d,.]+)\s*Mbps</span></b>").expect("r"));
    let re_sess = RE_SESS
        .get_or_init(|| Regex::new(r"(?i)<b><span[^>]*>(\d+)\s*sessions</span></b>").expect("r"));

    for chunk in html_raw.split("<tr>") {
        if !chunk.contains("vg_table_row_") || !chunk.contains("width='32' height='32'") {
            continue;
        }
        let Some(ip_cap) = re_ip.captures(chunk) else {
            continue;
        };
        let Some(ip) = valid_public_ipv4_str(&ip_cap[1]) else {
            continue;
        };

        let has_l2tp = chunk.contains("howto_l2tp.aspx");
        let mut tcp_port = 0u16;
        let mut udp_port = 0u16;
        let mut ovpn_qs = String::new();
        if let Some(oc) = re_ovpn.captures(chunk) {
            ovpn_qs = oc[1].to_string();
            if let Some(mt) = re_tcp.captures(&ovpn_qs) {
                tcp_port = mt[1].parse::<u16>().unwrap_or(0);
            }
            if let Some(mu) = re_udp.captures(&ovpn_qs) {
                udp_port = mu[1].parse::<u16>().unwrap_or(0);
            }
        }

        let raw_cname = re_cname
            .captures(chunk)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("");
        let raw_flag = re_flag
            .captures(chunk)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("");
        let (country_long, country_short) = normalize_country_pair(raw_cname, raw_flag);

        let hostname = re_host
            .captures(chunk)
            .map(|c| c[1].trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| ip.clone());

        let parsed_score = re_score
            .captures_iter(chunk)
            .last()
            .map(|c| parse_u64_clean(&c[1], 0))
            .unwrap_or(0);

        let parsed_ping = re_ping
            .captures(chunk)
            .map(|c| parse_u32_clean(&c[1], 9999))
            .unwrap_or(9999);

        let speed_bps = re_speed
            .captures(chunk)
            .and_then(|c| c[1].replace(',', "").parse::<f64>().ok())
            .map(|mbps| (mbps * 1_000_000.0) as u64)
            .unwrap_or(0);

        let sessions = re_sess
            .captures(chunk)
            .map(|c| parse_u32_clean(&c[1], 0))
            .unwrap_or(0);

        if let Some(existing) = servers_by_ip.get_mut(&ip) {
            if has_l2tp {
                existing.l2tp = true;
            }
            if tcp_port > 0 {
                existing.tcp_port = tcp_port;
            }
            if udp_port > 0 {
                existing.udp_port = udp_port;
            }
            if !ovpn_qs.is_empty() {
                existing.ovpn_dl_query = ovpn_qs;
                existing.openvpn = true;
            }
            if parsed_score > existing.score {
                existing.score = parsed_score;
            }
            if parsed_ping > 0 && parsed_ping < existing.ping_ms {
                existing.ping_ms = parsed_ping;
            }
            if speed_bps > existing.speed_bps {
                existing.speed_bps = speed_bps;
            }
            if existing.country_short == "XX" && country_short != "XX" {
                existing.country_short = country_short;
                existing.country_long = country_long;
            }
        } else {
            let has_ovpn = !ovpn_qs.is_empty();
            servers_by_ip.insert(
                ip.clone(),
                VpnServer {
                    hostname,
                    ip,
                    score: parsed_score,
                    ping_ms: parsed_ping,
                    speed_bps,
                    country_long,
                    country_short,
                    sessions,
                    uptime_ms: 0,
                    operator: "VPNGate Volunteer".to_string(),
                    l2tp: has_l2tp,
                    openvpn: has_ovpn,
                    tcp_port,
                    udp_port,
                    ovpn_b64: String::new(),
                    ovpn_dl_query: ovpn_qs,
                },
            );
        }
    }
}

/// Extracts ASP.NET hidden `__VIEWSTATE*` / `__EVENTVALIDATION` form inputs for protocol-filtered POSTs.
pub fn extract_aspnet_fields(html: &str) -> HashMap<String, String> {
    static RE_HIDDEN: OnceLock<Regex> = OnceLock::new();
    let re = RE_HIDDEN.get_or_init(|| {
        Regex::new(r#"<input[^>]*type=["']hidden["'][^>]*name=["']([^"']+)["'][^>]*value=["']([^"']*)["']"#)
            .expect("regex")
    });
    let mut map = HashMap::new();
    for cap in re.captures_iter(html) {
        map.insert(cap[1].to_string(), cap[2].to_string());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csv_and_extracts_ovpn_ports() {
        let ovpn_sample =
            "client\ndev tun\nproto udp\nremote 219.100.37.10 1195\n<ca>\nCERT\n</ca>\n";
        let b64 = BASE64_STD.encode(ovpn_sample);
        let csv_data = format!(
            "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n\
             vpn123,219.100.37.10,2500000,12,450000000,Japan,JP,42,86400000,1000,999999,2weeks,Tsukuba,,{b64}\n"
        );

        let mut map = BTreeMap::new();
        parse_vpngate_csv_into(&csv_data, &mut map);
        let srv = map.get("219.100.37.10").expect("server parsed");
        assert_eq!(srv.country_short, "JP");
        assert!(srv.openvpn);
        assert_eq!(srv.udp_port, 1195);
        assert_eq!(srv.ping_ms, 12);
    }

    #[test]
    fn parses_html_row_and_sdise_csv() {
        let html = r#"
        <table>
        <tr><td class='vg_table_row_1'><img src='../images/flags/KR.png' width='32' height='32' /><br>Korea Republic of</td>
        <td class='vg_table_row_1'><b><span>public-vpn-77.opengw.net</span></b><br><span>211.200.10.25</span></td>
        <td class='vg_table_row_1'><b><span>55 VPN sessions</span></b></td>
        <td class='vg_table_row_1'><b><span>612.4 Mbps</span></b><br>Ping: <b>8 ms</b></td>
        <td class='vg_table_row_1'><a href='do_openvpn.aspx?fqdn=x&ip=211.200.10.25&tcp=443&udp=1195'>OpenVPN</a></td>
        <td class='vg_table_row_1'><a href='howto_l2tp.aspx'>L2TP/IPsec</a></td>
        <td class='vg_table_row_1'><b><span>1,890,500</span></b></td></tr>
        </table>"#;

        let mut map = BTreeMap::new();
        parse_vpngate_html_into(html, &mut map);
        let kr = map.get("211.200.10.25").expect("HTML server parsed");
        assert_eq!(kr.country_short, "KR");
        assert!(kr.l2tp);
        assert_eq!(kr.tcp_port, 443);
        assert_eq!(kr.udp_port, 1195);
        assert_eq!(kr.score, 1_890_500);

        let sdise =
            "Country,Hostname,IP,Speed,Port\nJapan,vpn999.opengw.net,219.100.37.55,320.5,443\n";
        parse_sdise_csv_into(sdise, &mut map);
        let cand = map.get("219.100.37.55").expect("sdise candidate parsed");
        assert_eq!(cand.hostname, "vpn999");
        assert!(!cand.l2tp);
        assert!(!cand.openvpn);
    }

    #[test]
    fn parses_official_vpngate_mirror_sites_html() {
        let sample = r#"
        <ul>
          <li><b><a href='http://150.40.105.11:4917/en/' target='_blank'>http://150.40.105.11:4917/en/</a></b>&nbsp;(Mirror location: Croatia (LOCAL Name: Hrvatska))</li>
          <li><b><a href='http://ns374305.ip-178-32-222.eu:18609/en/'>http://ns374305.ip-178-32-222.eu:18609/en/</a></b> (Mirror location: France)</li>
          <li><a href='https://www.vpngate.net/en/'>https://www.vpngate.net/en/</a></li>
        </ul>
        "#;
        let mirrors = parse_vpngate_mirror_sites_html(sample, "sites.aspx");
        assert_eq!(mirrors.len(), 2);
        assert_eq!(mirrors[0].base_url, "http://150.40.105.11:4917");
        assert_eq!(mirrors[0].portal_url, "http://150.40.105.11:4917/en/");
        assert_eq!(mirrors[0].location, "Croatia");
        assert_eq!(
            mirrors[1].base_url,
            "http://ns374305.ip-178-32-222.eu:18609"
        );
        assert_eq!(mirrors[1].location, "France");
    }
}
