//! Tunnel DNS: keep whatever the VPN connection pushes, then add Cloudflare + Google.

use std::collections::HashSet;
use std::net::IpAddr;

/// Cloudflare + Google recursive DNS (IPv4 and IPv6) added beside connection-pushed resolvers.
pub const TUNNEL_AID_DNS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
];

pub fn tunnel_aid_dns() -> Vec<String> {
    TUNNEL_AID_DNS.iter().map(|s| (*s).to_string()).collect()
}

pub fn tunnel_aid_dns_cli() -> String {
    TUNNEL_AID_DNS.join(" ")
}

pub fn is_ipv6_dns(addr: &str) -> bool {
    matches!(addr.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
}

pub fn looks_like_dns_addr(raw: &str) -> bool {
    raw.trim().parse::<IpAddr>().is_ok()
}

/// Split a user `--dns` / query string. Empty → Cloudflare + Google aid list.
pub fn parse_dns_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for part in raw.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let t = part.trim();
        if t.is_empty() || !looks_like_dns_addr(t) {
            continue;
        }
        if seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    if out.is_empty() {
        tunnel_aid_dns()
    } else {
        out
    }
}

/// Connection-pushed resolvers first, then aid (Cloudflare/Google or `--dns`), unique.
pub fn merge_connection_and_aid_dns(connection: &[String], aid: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for src in [connection, aid] {
        for s in src {
            let t = s.trim();
            if t.is_empty() || !looks_like_dns_addr(t) {
                continue;
            }
            if seen.insert(t.to_string()) {
                out.push(t.to_string());
            }
        }
    }
    if out.is_empty() {
        tunnel_aid_dns()
    } else {
        out
    }
}

pub fn ovpn_dhcp_option_line(addr: &str) -> String {
    if is_ipv6_dns(addr) {
        format!("dhcp-option DNS6 {addr}")
    } else {
        format!("dhcp-option DNS {addr}")
    }
}

/// Pull `dhcp-option DNS` / `DNS6` out of an `.ovpn` body or OpenVPN PUSH_REPLY log.
pub fn parse_dhcp_option_dns(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for segment in text.split(|c: char| c == ',' || c == '\n' || c == '\r') {
        let s = segment.trim().trim_matches('"');
        if s.is_empty() {
            continue;
        }
        let low = s.to_ascii_lowercase();
        for prefix in ["dhcp-option dns6 ", "dhcp-option dns "] {
            if let Some(rest) = low.strip_prefix(prefix) {
                let addr = s[s.len() - rest.len()..].trim();
                if looks_like_dns_addr(addr) && seen.insert(addr.to_string()) {
                    out.push(addr.to_string());
                }
            }
        }
    }
    out
}

pub fn parse_nameserver_file(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let t = line.trim();
        let low = t.to_ascii_lowercase();
        if let Some(rest) = low.strip_prefix("nameserver ") {
            let addr = t[t.len() - rest.len()..].trim();
            if looks_like_dns_addr(addr) && seen.insert(addr.to_string()) {
                out.push(addr.to_string());
            }
        }
    }
    out
}

pub fn parse_resolvectl_dns_output(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for tok in text.split_whitespace() {
        let t = tok.trim_matches(|c: char| c == '(' || c == ')' || c == ',');
        if looks_like_dns_addr(t) && seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aid_list_is_cloudflare_and_google_v4_v6() {
        let d = tunnel_aid_dns();
        assert!(d.contains(&"1.1.1.1".into()));
        assert!(d.contains(&"1.0.0.1".into()));
        assert!(d.contains(&"8.8.8.8".into()));
        assert!(d.contains(&"8.8.4.4".into()));
        assert!(d.contains(&"2606:4700:4700::1111".into()));
        assert!(d.contains(&"2606:4700:4700::1001".into()));
        assert!(d.contains(&"2001:4860:4860::8888".into()));
        assert!(d.contains(&"2001:4860:4860::8844".into()));
        assert_eq!(d.len(), 8);
    }

    #[test]
    fn merge_keeps_connection_dns_ahead_of_aid() {
        let conn = vec!["10.8.0.1".into(), "1.1.1.1".into()];
        let aid = tunnel_aid_dns();
        let m = merge_connection_and_aid_dns(&conn, &aid);
        assert_eq!(m[0], "10.8.0.1");
        assert_eq!(m[1], "1.1.1.1");
        assert!(m.contains(&"8.8.8.8".into()));
        assert!(m.contains(&"2001:4860:4860::8888".into()));
        assert_eq!(m.iter().filter(|s| *s == "1.1.1.1").count(), 1);
    }

    #[test]
    fn empty_user_list_becomes_aid() {
        assert_eq!(parse_dns_list(""), tunnel_aid_dns());
        assert_eq!(parse_dns_list("  , ; "), tunnel_aid_dns());
    }

    #[test]
    fn parses_push_reply_and_nameservers() {
        let log = "PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,dhcp-option DNS 10.8.0.1,dhcp-option DNS6 2001:db8::1,ping 10'";
        let d = parse_dhcp_option_dns(log);
        assert_eq!(d, vec!["10.8.0.1".to_string(), "2001:db8::1".to_string()]);
        let ns = parse_nameserver_file("# pppd\nnameserver 10.211.1.1\nnameserver 1.1.1.1\n");
        assert_eq!(ns, vec!["10.211.1.1".to_string(), "1.1.1.1".to_string()]);
        let rv = parse_resolvectl_dns_output("Link 19 (ppp0): 10.211.1.1 2606:4700:4700::1111\n");
        assert_eq!(
            rv,
            vec!["10.211.1.1".to_string(), "2606:4700:4700::1111".to_string()]
        );
    }
}
