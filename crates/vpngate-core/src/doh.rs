use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Deserialize;

use crate::error::{CoreError, Result};

/// Returns `true` if `ip` is a bogon, private, loopback, carrier-grade NAT, or ISP-poisoned sinkhole IP.
pub fn is_poisoned_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // RFC 6598 Carrier-Grade NAT 100.64.0.0/10
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        // RFC 2544 benchmarking 198.18.0.0/15
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        // Reserved 240.0.0.0/4
        || octets[0] >= 240
}

pub fn is_poisoned_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_poisoned_ipv4(v4),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback() || v6.is_multicast(),
    }
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

/// Resolves unpoisoned public IPv4 `A` records via Cloudflare DoH (`1.1.1.1:443` / `1.0.0.1:443`)
/// using direct IP-pinned TLS (`cloudflare-dns.com` SNI), completely immune to local UDP-53 poisoning.
pub async fn resolve_ipv4_via_cloudflare_doh(
    host: &str,
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>> {
    if let Ok(literal) = host.trim().parse::<Ipv4Addr>() {
        if !is_poisoned_ipv4(literal) {
            return Ok(vec![literal]);
        }
        return Err(CoreError::DohResolutionFailed {
            host: host.to_string(),
        });
    }

    for resolver_ip in [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)] {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .resolve(
                "cloudflare-dns.com",
                SocketAddr::new(IpAddr::V4(resolver_ip), 443),
            )
            .build()?;

        let resp = client
            .get("https://cloudflare-dns.com/dns-query")
            .query(&[("name", host), ("type", "A")])
            .header("Accept", "application/dns-json")
            .send()
            .await;

        let Ok(http_resp) = resp else {
            continue;
        };
        let Ok(parsed) = http_resp.json::<DohResponse>().await else {
            continue;
        };

        let mut valid = Vec::new();
        for ans in parsed.answer {
            if ans.record_type == 1
                && let Ok(v4) = ans.data.trim().parse::<Ipv4Addr>()
                && !is_poisoned_ipv4(v4)
                && !valid.contains(&v4)
            {
                valid.push(v4);
            }
        }
        if !valid.is_empty() {
            return Ok(valid);
        }
    }

    Err(CoreError::DohResolutionFailed {
        host: host.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_poisoned_and_valid_ipv4() {
        assert!(is_poisoned_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_poisoned_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_poisoned_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_poisoned_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_poisoned_ipv4(Ipv4Addr::new(219, 100, 37, 10)));
        assert!(!is_poisoned_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
