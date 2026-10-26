use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::doh::resolve_ipv4_via_cloudflare_doh;
use crate::error::Result;
use crate::ikev1::{sweep_ikev1_sa_responders, verify_l2tp_psk_vpn};
use crate::parser::{parse_sdise_csv_into, parse_vpngate_csv_into, parse_vpngate_html_into};
use crate::server::VpnServer;

pub const OFFICIAL_CSV_URLS: &[&str] = &[
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
];

pub const OFFICIAL_HTML_URLS: &[&str] =
    &["https://www.vpngate.net/en/", "http://www.vpngate.net/en/"];

pub const MIRROR_CSV_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-mirror/main/data/servers.csv",
    "https://raw.githubusercontent.com/funcra/vpngate-mirror/main/api/iphone.csv",
    "https://raw.githubusercontent.com/sinspired/VpnGate-mirrors/main/vpngate.csv",
    "https://cdn.jsdelivr.net/gh/cjsl99/vpngate@main/iphone.csv",
    "https://cdn.jsdelivr.net/gh/NetLops/VPNGate-Mirror@main/vpngate.csv",
];

pub const SDISE_CSV_URL: &str = "https://raw.githubusercontent.com/sdise/vpngate/main/servers.csv";

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) VPNGateConnect-Rust/0.1";

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub request_timeout: Duration,
    /// Cryptographically verify live `PSK == "vpn"` L2TP/IPsec capability on candidate servers.
    pub probe_l2tp_candidates: bool,
    /// Maximum servers to run through 1-RTT Aggressive Mode `PSK == "vpn"` verification when HTML is blocked.
    pub max_l2tp_probe_candidates: usize,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(12),
            probe_l2tp_candidates: true,
            max_l2tp_probe_candidates: 96,
        }
    }
}

/// Multi-source censorship-resilient VPN Gate server discovery client.
pub struct DiscoveryClient {
    http: reqwest::Client,
    opts: DiscoveryOptions,
}

impl DiscoveryClient {
    pub fn new(opts: DiscoveryOptions) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(opts.request_timeout)
            .build()?;
        Ok(Self { http, opts })
    }

    async fn fetch_text_with_doh_fallback(&self, url: &str) -> Option<String> {
        if let Ok(resp) = self.http.get(url).send().await
            && resp.status().is_success()
            && let Ok(text) = resp.text().await
            && text.len() > 256
        {
            return Some(text);
        }

        // Fallback: resolve hostname via Cloudflare DoH (1.1.1.1:443) to bypass ISP DNS poisoning
        let parsed = reqwest::Url::parse(url).ok()?;
        let host = parsed.host_str()?;
        let port = parsed.port_or_known_default()?;
        let ips = resolve_ipv4_via_cloudflare_doh(host, Duration::from_secs(5))
            .await
            .ok()?;

        for ip in ips.into_iter().take(2) {
            let Ok(pinned_client) = reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .timeout(self.opts.request_timeout)
                .resolve(host, SocketAddr::new(IpAddr::V4(ip), port))
                .build()
            else {
                continue;
            };
            if let Ok(resp) = pinned_client.get(url).send().await
                && resp.status().is_success()
                && let Ok(text) = resp.text().await
                && text.len() > 256
            {
                return Some(text);
            }
        }
        None
    }

    /// Fetches, merges, and optionally verifies the live VPN Gate relay pool across all feeds.
    pub async fn fetch_servers(&self) -> Result<Vec<VpnServer>> {
        let mut servers_by_ip: BTreeMap<String, VpnServer> = BTreeMap::new();

        // 1. Official CSV API -> fallback to HTTPS GitHub/jsDelivr CSV mirrors
        let mut got_csv = false;
        for &url in OFFICIAL_CSV_URLS {
            if let Some(body) = self.fetch_text_with_doh_fallback(url).await
                && body.contains("*vpn_servers")
            {
                parse_vpngate_csv_into(&body, &mut servers_by_ip);
                got_csv = !servers_by_ip.is_empty();
                if got_csv {
                    break;
                }
            }
        }
        if !got_csv {
            for &url in MIRROR_CSV_URLS {
                if let Some(body) = self.fetch_text_with_doh_fallback(url).await {
                    let before = servers_by_ip.len();
                    parse_vpngate_csv_into(&body, &mut servers_by_ip);
                    if servers_by_ip.len() > before {
                        break;
                    }
                }
            }
        }

        // 2. Official HTML Server Table (adds L2TP flags + dual TCP/UDP OpenVPN ports)
        let mut got_html = false;
        for &url in OFFICIAL_HTML_URLS {
            if let Some(html) = self.fetch_text_with_doh_fallback(url).await
                && html.contains("vg_table_row_")
            {
                parse_vpngate_html_into(&html, &mut servers_by_ip);
                got_html = true;
                break;
            }
        }

        // 3. If HTML was unreachable or yielded zero L2TP flags, pull `sdise` candidates & run live IKEv1 sweep
        let has_any_l2tp = servers_by_ip.values().any(|s| s.l2tp);
        if self.opts.probe_l2tp_candidates && (!got_html || !has_any_l2tp) {
            let mut candidates: BTreeMap<String, VpnServer> = servers_by_ip.clone();
            if let Some(sdise_csv) = self.fetch_text_with_doh_fallback(SDISE_CSV_URL).await {
                parse_sdise_csv_into(&sdise_csv, &mut candidates);
            }

            let candidate_ips: Vec<Ipv4Addr> = candidates
                .keys()
                .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                .collect();

            // Stage A: Fast multi-socket Main Mode SA+NAT-T responder sweep
            let sa_responders =
                sweep_ikev1_sa_responders(&candidate_ips, Duration::from_millis(1600)).await;

            // Stage B: 1-RTT Aggressive Mode cryptographic `PSK == "vpn"` verification
            let sem = Arc::new(Semaphore::new(32));
            let mut tasks = Vec::new();
            for ip in sa_responders
                .into_iter()
                .take(self.opts.max_l2tp_probe_candidates)
            {
                let permit_pool = Arc::clone(&sem);
                tasks.push(tokio::spawn(async move {
                    let _permit = permit_pool.acquire().await.ok()?;
                    let res = verify_l2tp_psk_vpn(ip, Duration::from_millis(1200), 1, b"vpn").await;
                    res.is_verified().then_some(ip.to_string())
                }));
            }

            for handle in tasks {
                if let Ok(Some(verified_ip)) = handle.await {
                    if let Some(existing) = servers_by_ip.get_mut(&verified_ip) {
                        existing.l2tp = true;
                    } else if let Some(mut recovered) = candidates.remove(&verified_ip) {
                        recovered.l2tp = true;
                        servers_by_ip.insert(verified_ip, recovered);
                    }
                }
            }
        }

        Ok(servers_by_ip
            .into_values()
            .filter(|s| s.has_any_protocol())
            .collect())
    }
}
