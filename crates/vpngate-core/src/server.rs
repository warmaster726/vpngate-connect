use serde::{Deserialize, Serialize};

use crate::protocol::{ProtocolFilter, SortBy, VpnProtocol};

/// Unified VPN Gate relay server record shared across CLI/TUI and Flutter FFI.
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

/// Filters servers by 2-letter ISO code or case-insensitive country substring.
pub fn filter_by_country(servers: &[VpnServer], query: Option<&str>) -> Vec<VpnServer> {
    let Some(q_raw) = query else {
        return servers.to_vec();
    };
    let q = q_raw.trim();
    if q.is_empty() || q.eq_ignore_ascii_case("all") || q.eq_ignore_ascii_case("any") {
        return servers.to_vec();
    }
    let q_up = q.to_ascii_uppercase();
    let q_low = q.to_ascii_lowercase();

    servers
        .iter()
        .filter(|s| {
            if q.len() == 2 && s.country_short.eq_ignore_ascii_case(&q_up) {
                return true;
            }
            s.country_long.to_ascii_lowercase().contains(&q_low)
        })
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

        match sort_by {
            SortBy::Recommended => tier_cmp
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| b.speed_bps.cmp(&a.speed_bps))
                .then_with(|| a.ping_ms.cmp(&b.ping_ms)),
            SortBy::Speed => tier_cmp
                .then_with(|| b.speed_bps.cmp(&a.speed_bps))
                .then_with(|| b.score.cmp(&a.score)),
            SortBy::Ping => tier_cmp
                .then_with(|| a.ping_ms.cmp(&b.ping_ms))
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
}
