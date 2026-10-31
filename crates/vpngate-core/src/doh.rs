use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Deserialize;

use crate::edge::edge_path_urls;
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

struct DohUpstream {
    /// TLS SNI / Host header. Empty = URL host, no IP pin.
    sni: &'static str,
    url: &'static str,
    ips: &'static [Ipv4Addr],
}

/// IP-pinned DoH mesh. UDP/53 is never used. Poisoned A records are dropped.
const PINNED_DOH: &[DohUpstream] = &[
    DohUpstream {
        sni: "cloudflare-dns.com",
        url: "https://cloudflare-dns.com/dns-query",
        ips: &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
    },
    DohUpstream {
        sni: "dns.google",
        url: "https://dns.google/dns-query",
        ips: &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
    },
    DohUpstream {
        sni: "dns.quad9.net",
        url: "https://dns.quad9.net/dns-query",
        ips: &[Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
    },
];

/// Resolves unpoisoned public IPv4 `A` records via Cloudflare DoH (`1.1.1.1:443`).
/// Prefer [`resolve_ipv4_via_doh`], which also tries Google, Quad9, and the Worker.
pub async fn resolve_ipv4_via_cloudflare_doh(
    host: &str,
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>> {
    resolve_ipv4_via_doh(host, timeout).await
}

/// Resolves unpoisoned public IPv4 `A` records via a DoH mesh:
/// Cloudflare `1.1.1.1` / `1.0.0.1`, Google `8.8.8.8` / `8.8.4.4`,
/// Quad9 `9.9.9.9` / `149.112.112.112`, then the Cloudflare Worker `/dns-query`.
/// Each public resolver is IP-pinned (SNI) so local UDP-53 poisoning cannot divert the query.
pub async fn resolve_ipv4_via_doh(host: &str, timeout: Duration) -> Result<Vec<Ipv4Addr>> {
    if let Ok(literal) = host.trim().parse::<Ipv4Addr>() {
        if !is_poisoned_ipv4(literal) {
            return Ok(vec![literal]);
        }
        return Err(CoreError::DohResolutionFailed {
            host: host.to_string(),
        });
    }

    for upstream in PINNED_DOH {
        if let Some(valid) = query_doh_upstream(upstream, host, timeout).await {
            return Ok(valid);
        }
    }

    for url in edge_path_urls("/dns-query") {
        if let Some(valid) = query_doh_url(&url, None, None, host, timeout).await {
            return Ok(valid);
        }
    }

    Err(CoreError::DohResolutionFailed {
        host: host.to_string(),
    })
}

async fn query_doh_upstream(
    upstream: &DohUpstream,
    host: &str,
    timeout: Duration,
) -> Option<Vec<Ipv4Addr>> {
    if upstream.ips.is_empty() {
        return query_doh_url(upstream.url, None, None, host, timeout).await;
    }
    for &ip in upstream.ips {
        let pin = SocketAddr::new(IpAddr::V4(ip), 443);
        if let Some(valid) =
            query_doh_url(upstream.url, Some(upstream.sni), Some(pin), host, timeout).await
        {
            return Some(valid);
        }
    }
    None
}

async fn query_doh_url(
    url: &str,
    sni: Option<&str>,
    pin: Option<SocketAddr>,
    host: &str,
    timeout: Duration,
) -> Option<Vec<Ipv4Addr>> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let (Some(name), Some(addr)) = (sni, pin) {
        builder = builder.resolve(name, addr);
    }
    let client = builder.build().ok()?;
    let resp = client
        .get(url)
        .query(&[("name", host), ("type", "A")])
        .header("Accept", "application/dns-json")
        .send()
        .await
        .ok()?;
    let parsed = resp.json::<DohResponse>().await.ok()?;
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
    if valid.is_empty() { None } else { Some(valid) }
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
        assert!(!is_poisoned_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_poisoned_ipv4(Ipv4Addr::new(9, 9, 9, 9)));
    }
}
