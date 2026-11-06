use serde::{Deserialize, Serialize};

use crate::protocol::{ProtocolFilter, SortBy, VpnProtocol};

/// Unified VPN Gate relay server record shared across the core engine and CLI/TUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnServer {
    pub hostname: String,
    pub ip: String,
    pub score: u64,
    pub ping_ms: u32,
    pub speed_bps: u64,
    pub country_long: String,
    pub country_short: String,
    pub sessions: u32,
    pub uptime_ms: u64,
    pub operator: String,
    pub l2tp: bool,
    pub openvpn: bool,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub ovpn_b64: String,
    pub ovpn_dl_query: String,
}

impl VpnServer {
    pub fn speed_mbps(&self) -> f64 {
        (self.speed_bps as f64) / 1_000_000.0
    }

    pub fn supports_openvpn_udp(&self) -> bool {
        self.openvpn && (self.udp_port > 0 || (!self.ovpn_b64.is_empty() && self.tcp_port == 0))
    }

    pub fn supports_openvpn_tcp(&self) -> bool {
        self.openvpn && (self.tcp_port > 0 || (!self.ovpn_b64.is_empty() && self.udp_port == 0))
    }

    pub fn supports_protocol(&self, proto: VpnProtocol) -> bool {
        match proto {
            VpnProtocol::L2tpIpsec => self.l2tp,
            VpnProtocol::OpenVpnUdp => self.supports_openvpn_udp(),
            VpnProtocol::OpenVpnTcp => self.supports_openvpn_tcp(),
        }
    }

    pub fn has_any_protocol(&self) -> bool {
        self.l2tp || self.openvpn
    }

    /// Lower tier number = higher `Auto` connection priority (`0`: L2TP, `1`: OVPN-UDP, `2`: OVPN-TCP).
    pub fn auto_priority_tier(&self) -> u8 {
        if self.l2tp {
            0
        } else if self.supports_openvpn_udp() {
            1
        } else if self.supports_openvpn_tcp() {
            2
        } else {
            3
        }
    }

    /// Returns the ordered list of transports to attempt on this server under `filter`.
    pub fn candidate_protocols(&self, filter: ProtocolFilter) -> Vec<VpnProtocol> {
        match filter {
            ProtocolFilter::Only(p) => {
                if self.supports_protocol(p) {
                    vec![p]
                } else {
                    Vec::new()
                }
            }
            ProtocolFilter::OpenVpnAny => [VpnProtocol::OpenVpnUdp, VpnProtocol::OpenVpnTcp]
                .into_iter()
                .filter(|p| self.supports_protocol(*p))
                .collect(),
            ProtocolFilter::Auto => VpnProtocol::AUTO_ORDER
                .into_iter()
                .filter(|p| self.supports_protocol(*p))
                .collect(),
        }
    }
}

fn is_all_country_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "all" | "any" | "*" | "worldwide"
    )
}

fn is_iso2_token(token: &str) -> bool {
    token.len() == 2 && token.chars().all(|c| c.is_ascii_alphabetic())
}

/// Splits `-c JP,KR` / `JP KR` (ISO codes) while leaving `United States` as one name.
pub fn split_country_query(raw: &str) -> Vec<String> {
    let q = raw.trim();
    if q.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<String> = q
        .split(|c: char| c == ',' || c == ';' || c == '/')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() == 1 {
        let ws: Vec<&str> = parts[0].split_whitespace().collect();
        if ws.len() > 1
            && ws
                .iter()
                .all(|t| is_all_country_token(t) || is_iso2_token(t))
        {
            parts = ws.iter().map(|s| (*s).to_string()).collect();
        }
    }
    parts
}

fn country_token_matches(server: &VpnServer, token: &str) -> bool {
    let q = token.trim();
    if q.is_empty() || is_all_country_token(q) {
        return true;
    }
    let q_up = q.to_ascii_uppercase();
    if is_iso2_token(q) {
        let iso = if q_up == "UK" { "GB" } else { q_up.as_str() };
        return server.country_short.eq_ignore_ascii_case(iso);
    }
    let q_low = q.to_ascii_lowercase();
    server.country_short.eq_ignore_ascii_case(&q_up)
        || server.country_long.to_ascii_lowercase().contains(&q_low)
}

/// Filters servers by country. `query` may be one code/name, `all`, or several
/// (`JP,KR` / `JP KR` / `UK,JP`). Each 2-letter token is a strict ISO match
/// (`UK` → `GB`) so `-c US` never hits `Russian Federation` or `Australia`.
pub fn filter_by_country(servers: &[VpnServer], query: Option<&str>) -> Vec<VpnServer> {
    let Some(q_raw) = query else {
        return servers.to_vec();
    };
    let parts = split_country_query(q_raw);
    if parts.is_empty() || parts.iter().any(|t| is_all_country_token(t)) {
        return servers.to_vec();
    }
    servers
        .iter()
        .filter(|s| parts.iter().any(|t| country_token_matches(s, t)))
        .cloned()
        .collect()
}

/// Filters servers supporting the requested `ProtocolFilter`.
pub fn filter_by_protocol(servers: &[VpnServer], filter: ProtocolFilter) -> Vec<VpnServer> {
    servers
        .iter()
        .filter(|s| match filter {
            ProtocolFilter::Auto => s.has_any_protocol(),
            ProtocolFilter::OpenVpnAny => s.openvpn,
            ProtocolFilter::Only(p) => s.supports_protocol(p),
        })
        .cloned()
        .collect()
}

/// Sorts servers in-place according to `sort_by` and `filter`.
pub fn sort_servers(servers: &mut [VpnServer], sort_by: SortBy, filter: ProtocolFilter) {
    servers.sort_by(|a, b| {
        let tier_cmp = match filter {
            ProtocolFilter::Auto => a.auto_priority_tier().cmp(&b.auto_priority_tier()),
            ProtocolFilter::OpenVpnAny => {
                let ta = u8::from(!a.supports_openvpn_udp());
                let tb = u8::from(!b.supports_openvpn_udp());
                ta.cmp(&tb)
            }
            ProtocolFilter::Only(_) => std::cmp::Ordering::Equal,
        };

        let eff_ping_a = if a.ping_ms == 0 { u32::MAX } else { a.ping_ms };
        let eff_ping_b = if b.ping_ms == 0 { u32::MAX } else { b.ping_ms };

        match sort_by {
            SortBy::Recommended => tier_cmp
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| b.speed_bps.cmp(&a.speed_bps))
                .then_with(|| eff_ping_a.cmp(&eff_ping_b)),
            SortBy::Speed => b
                .speed_bps
                .cmp(&a.speed_bps)
                .then(tier_cmp)
                .then_with(|| b.score.cmp(&a.score)),
            SortBy::Ping => eff_ping_a
                .cmp(&eff_ping_b)
                .then(tier_cmp)
                .then_with(|| b.speed_bps.cmp(&a.speed_bps)),
            SortBy::Score => tier_cmp
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| b.speed_bps.cmp(&a.speed_bps)),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy(ip: &str, l2tp: bool, udp: u16, tcp: u16, score: u64) -> VpnServer {
        VpnServer {
            hostname: ip.to_string(),
            ip: ip.to_string(),
            score,
            ping_ms: 20,
            speed_bps: 100_000_000,
            country_long: "Japan".to_string(),
            country_short: "JP".to_string(),
            sessions: 10,
            uptime_ms: 1000,
            operator: "Test".to_string(),
            l2tp,
            openvpn: udp > 0 || tcp > 0,
            tcp_port: tcp,
            udp_port: udp,
            ovpn_b64: String::new(),
            ovpn_dl_query: String::new(),
        }
    }

    #[test]
    fn auto_sort_prioritizes_l2tp_then_udp_then_tcp() {
        let mut pool = vec![
            dummy("1.1.1.3", false, 0, 443, 9_000_000),
            dummy("1.1.1.2", false, 1195, 0, 5_000_000),
            dummy("1.1.1.1", true, 0, 0, 1_000_000),
        ];
        sort_servers(&mut pool, SortBy::Recommended, ProtocolFilter::Auto);
        assert_eq!(pool[0].ip, "1.1.1.1");
        assert_eq!(pool[1].ip, "1.1.1.2");
        assert_eq!(pool[2].ip, "1.1.1.3");
    }

    #[test]
    fn iso_two_letter_country_filter_never_matches_substring_false_positives() {
        let mut ru = dummy("2.2.2.1", false, 1194, 443, 500_000);
        ru.country_short = "RU".to_string();
        ru.country_long = "Russian Federation".to_string();

        let mut au = dummy("2.2.2.2", false, 1194, 443, 500_000);
        au.country_short = "AU".to_string();
        au.country_long = "Australia".to_string();

        let mut us = dummy("2.2.2.3", true, 1194, 443, 500_000);
        us.country_short = "US".to_string();
        us.country_long = "United States".to_string();

        let mut gb = dummy("2.2.2.4", false, 1194, 443, 500_000);
        gb.country_short = "GB".to_string();
        gb.country_long = "United Kingdom".to_string();

        let pool = vec![ru, au, us, gb];
        let us_only = filter_by_country(&pool, Some("US"));
        assert_eq!(us_only.len(), 1);
        assert_eq!(us_only[0].country_short, "US");

        let uk_alias = filter_by_country(&pool, Some("UK"));
        assert_eq!(uk_alias.len(), 1);
        assert_eq!(uk_alias[0].country_short, "GB");

        let us_and_gb = filter_by_country(&pool, Some("US,UK"));
        assert_eq!(us_and_gb.len(), 2);
        assert!(us_and_gb.iter().any(|s| s.country_short == "US"));
        assert!(us_and_gb.iter().any(|s| s.country_short == "GB"));

        let spaced = filter_by_country(&pool, Some("US GB"));
        assert_eq!(spaced.len(), 2);

        let united = filter_by_country(&pool, Some("United States"));
        assert_eq!(united.len(), 1);
        assert_eq!(united[0].country_short, "US");

        let all_mix = filter_by_country(&pool, Some("JP,all"));
        assert_eq!(all_mix.len(), pool.len());
    }
}
