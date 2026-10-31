//! Static installer bodies, VPN Gate CSV export, and mirror-seed text.
//! Compiled on native (tests) and wasm (Worker routes).

use crate::model::{Mirror, Server, APP_VERSION};

pub const INSTALL_SH: &str = include_str!("../../install-vpngate.sh");
pub const INSTALL_PS1: &str = include_str!("../../install-vpngate.ps1");
pub const DESKTOP_VERSION: &str = include_str!("../../assets/desktop-version.txt");
pub const BUNDLED_MIRROR_SEED: &str = include_str!("../../assets/mirror-seed.txt");
pub const REPO_SLUG: &str = "warmaster726/vpngate-connect";

fn csv_escape(s: &str) -> String {
    if s.bytes()
        .any(|b| b == b',' || b == b'"' || b == b'\n' || b == b'\r')
    {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Official `/api/iphone/` CSV so the desktop HTTPS-CSV stage can treat this Worker as a feed.
pub fn servers_to_vpngate_csv(
    servers: &[Server],
    ovpn_by_ip: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut out = String::from(
        "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n",
    );
    for s in servers {
        let b64 = ovpn_by_ip
            .get(&s.ip)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .unwrap_or(s.ovpn_b64.as_str());
        let line = [
            csv_escape(&s.hostname),
            s.ip.clone(),
            s.score.to_string(),
            s.ping_ms.to_string(),
            s.speed_bps.to_string(),
            csv_escape(&s.country_long),
            csv_escape(&s.country_short),
            s.sessions.to_string(),
            s.uptime_ms.to_string(),
            "0".into(),
            "0".into(),
            "2".into(),
            csv_escape(&s.operator),
            String::new(),
            b64.to_string(),
        ];
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

pub fn format_mirror_seed(mirrors: &[Mirror]) -> String {
    let mut out = format!(
        "# VPN Gate Connect mirror seed (Worker {APP_VERSION})\n# Tsukuba daily mail: https://www.vpngate.net/en/mail.aspx\n# Paste into `vpngate mirrors --import -` or this console's Mirrors tab.\n"
    );
    let mut n = 0usize;
    for m in mirrors {
        let url = m.portal_url.trim();
        if url.is_empty() {
            continue;
        }
        out.push_str(url);
        if !url.ends_with('\n') {
            out.push('\n');
        }
        n += 1;
    }
    if n == 0 {
        out.push_str(BUNDLED_MIRROR_SEED);
    }
    out
}

pub fn is_safe_git_ref(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty() || s.len() > 64 || s.contains("..") {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '/')
}

pub fn is_safe_dns_name(raw: &str) -> bool {
    let s = raw.trim().trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !s.starts_with('-')
        && !s.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Server;

    #[test]
    fn csv_starts_with_official_header_and_escapes_commas() {
        let srv = Server {
            hostname: "host".into(),
            ip: "219.100.37.10".into(),
            score: 1,
            ping_ms: 10,
            speed_bps: 1000,
            country_long: "Japan, JP".into(),
            country_short: "JP".into(),
            sessions: 1,
            uptime_ms: 0,
            operator: "Tsukuba".into(),
            l2tp: true,
            openvpn: true,
            tcp_port: 443,
            udp_port: 1195,
            ovpn_b64: "Y2xpZW50".into(),
            has_ovpn_cert: true,
            verify_state: None,
            verified_port: None,
            verified_rtt_ms: None,
            unlocked: Vec::new(),
            locked: Vec::new(),
            dead_until: 0,
        };
        let csv = servers_to_vpngate_csv(&[srv], &serde_json::Map::new());
        assert!(csv.contains("*vpn_servers"));
        assert!(csv.contains("#HostName"));
        assert!(csv.contains("\"Japan, JP\""));
        assert!(csv.contains("219.100.37.10"));
        assert!(csv.contains("Y2xpZW50"));
    }

    #[test]
    fn git_ref_and_dns_name_filters() {
        assert!(is_safe_git_ref("main"));
        assert!(is_safe_git_ref("refs/heads/main"));
        assert!(!is_safe_git_ref("../etc/passwd"));
        assert!(is_safe_dns_name("www.vpngate.net"));
        assert!(!is_safe_dns_name("a b.com"));
        assert!(!is_safe_dns_name("-bad.example"));
    }

    #[test]
    fn installer_bodies_are_embedded() {
        assert!(INSTALL_SH.contains("install-vpngate.sh"));
        assert!(INSTALL_PS1.contains("vpngate.exe") || INSTALL_PS1.contains("VPNGate"));
        assert!(!DESKTOP_VERSION.trim().is_empty());
        assert!(BUNDLED_MIRROR_SEED.contains("http://"));
    }
}
