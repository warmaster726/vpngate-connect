use std::collections::{BTreeMap, HashMap};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::doh::resolve_ipv4_via_cloudflare_doh;
use crate::error::{CoreError, Result};
use crate::ikev1::{probe_tcp, sweep_ikev1_sa_responders, verify_l2tp_psk_vpn};
use crate::parser::{
    OfficialMirrorSite, extract_aspnet_fields, normalize_mirror_base_url, parse_sdise_csv_into,
    parse_vpngate_csv_into, parse_vpngate_html_into, parse_vpngate_mirror_sites_html,
};
use crate::server::VpnServer;

/// Live command execution progress events (exact parity with Python `v5.3` console UX).
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// Transient in-place spinner/counter line (`\r[*] [|] <stage> [Xs/Ys] - Press Ctrl+C to interrupt`).
    Transient {
        stage: String,
        elapsed_secs: u64,
        max_secs: u64,
        tick: usize,
    },
    /// Clears any active transient spinner line immediately.
    ClearTransient,
    /// Permanent `[*] ...` informational step line.
    Info(String),
    /// Permanent `[+] ...` completion step line.
    Ok(String),
    /// Permanent `[!] ...` warning or failover notice.
    Warn(String),
    /// Candidate connection attempt header (`[Attempt i/N] Testing ...`).
    AttemptBanner {
        index: usize,
        total: usize,
        hostname: String,
        ip: String,
        country_short: String,
        country_long: String,
        speed_mbps: f64,
        ping_ms: u32,
        score: u64,
    },
}

pub const OFFICIAL_CSV_URLS: &[&str] = &[
    "http://www.vpngate.net/api/iphone/",
    "https://www.vpngate.net/api/iphone/",
];

pub const OFFICIAL_HTML_URLS: &[&str] =
    &["https://www.vpngate.net/en/", "http://www.vpngate.net/en/"];

pub const OFFICIAL_MIRROR_SITES_URLS: &[&str] = &[
    "https://www.vpngate.net/en/sites.aspx",
    "http://www.vpngate.net/en/sites.aspx",
    "https://www.vpngate.net/ja/sites.aspx",
    "https://www.vpngate.net/cn/sites.aspx",
];

/// Community daily official mirror URL relays (`sites.aspx` daily e-mail mirrors).
pub const DAILY_MIRROR_JSON_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/kusrabyzarc/vpngate-daily-mirrors/main/mirrors.json",
    "https://cdn.jsdelivr.net/gh/kusrabyzarc/vpngate-daily-mirrors@latest/mirrors.json",
];

pub const WAYBACK_MIRROR_SITES_CDX_URL: &str = "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/sites.aspx&output=json&limit=-3&filter=statuscode:200&collapse=timestamp:8";

/// Exact `PY` branch HTTPS CSV mirrors + CDN fallbacks.
pub const MIRROR_CSV_URLS: &[&str] = &[
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
    "https://raw.githubusercontent.com/funcra/vg-mirror/main/servers.csv",
    "https://raw.githubusercontent.com/sinspired/VpngateAPI/main/servers.csv",
    "https://raw.githubusercontent.com/cjsl99/VpngateAPI/main/servers.csv",
    "https://raw.githubusercontent.com/NetLops/vpngate-mirror/main/vpngate.csv",
    "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-mirror/main/data/servers.csv",
    "https://raw.githubusercontent.com/funcra/vpngate-mirror/main/api/iphone.csv",
];

pub const SDISE_CSV_URL: &str = "https://raw.githubusercontent.com/sdise/vpngate/main/vpngate.csv";
pub const FUNCRA_HISTORY_BASE_URL: &str =
    "https://raw.githubusercontent.com/funcra/vg-mirror/main/servers_history";

pub const WAYBACK_CDX_URLS: &[&str] = &[
    "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/&output=json&limit=-6&filter=statuscode:200&collapse=timestamp:8",
    "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/ja/&output=json&limit=-4&filter=statuscode:200&collapse=timestamp:8",
];

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) VPNGate-CLI/0.1";

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub request_timeout: Duration,
    /// Cryptographically verify live `PSK == "vpn"` L2TP/IPsec capability on candidate servers.
    pub probe_l2tp_candidates: bool,
    /// Maximum servers to run through 1-RTT Aggressive Mode `PSK == "vpn"` verification when HTML is blocked.
    pub max_l2tp_probe_candidates: usize,
    /// Previously cached or custom Official VPNGate Mirror Sites (`http://<host>:<port>`).
    pub seed_mirrors: Vec<OfficialMirrorSite>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            probe_l2tp_candidates: true,
            max_l2tp_probe_candidates: 128,
            seed_mirrors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryOutcome {
    pub servers: Vec<VpnServer>,
    pub official_mirrors: Vec<OfficialMirrorSite>,
}

#[derive(Debug, Clone)]
pub struct MirrorProbeResult {
    pub mirror: OfficialMirrorSite,
    pub reachable: bool,
    pub rtt_ms: Option<u64>,
    pub servers_count: usize,
}

#[derive(Debug, Deserialize)]
struct DailyMirrorJsonRow {
    #[serde(alias = "IP", alias = "ip")]
    ip: String,
    #[serde(alias = "PORT", alias = "port")]
    port: u16,
    #[serde(default, alias = "LOCATION", alias = "location")]
    location: String,
}

#[derive(Debug, Deserialize)]
struct FuncraHistEntry {
    file: String,
}

/// Runs an async future while emitting 100ms transient progress updates on a single task.
async fn await_with_spinner<T, F>(
    fut: F,
    stage: &str,
    max_secs: u64,
    on_progress: &mut impl FnMut(ProgressEvent),
) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(fut);
    let started = Instant::now();
    let mut tick = 0usize;
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    // First tick fires immediately
    let _ = interval.tick().await;

    let out = loop {
        tokio::select! {
            res = &mut fut => break res,
            _ = interval.tick() => {
                if tick.is_multiple_of(2) {
                    on_progress(ProgressEvent::Transient {
                        stage: stage.to_string(),
                        elapsed_secs: started.elapsed().as_secs(),
                        max_secs,
                        tick: tick / 2,
                    });
                }
                tick += 1;
            }
        }
    };
    on_progress(ProgressEvent::ClearTransient);
    out
}

fn collect_env_custom_mirrors() -> Vec<OfficialMirrorSite> {
    let mut out = Vec::new();
    if let Ok(raw) = env::var("VPNGATE_MIRRORS") {
        for part in raw.split([',', ' ', ';']) {
            if let Some((base_url, portal_url)) = normalize_mirror_base_url(part) {
                out.push(OfficialMirrorSite {
                    base_url,
                    portal_url,
                    location: "Custom".to_string(),
                    source: "custom".to_string(),
                });
            }
        }
    }
    out
}

fn merge_mirror_lists(lists: Vec<Vec<OfficialMirrorSite>>) -> Vec<OfficialMirrorSite> {
    let mut out = Vec::new();
    let mut seen = BTreeMap::<String, usize>::new();
    for list in lists {
        for m in list {
            if let Some(&idx) = seen.get(&m.base_url) {
                let existing: &mut OfficialMirrorSite = &mut out[idx];
                if existing.location == "Unknown" && m.location != "Unknown" {
                    existing.location = m.location;
                }
            } else {
                seen.insert(m.base_url.clone(), out.len());
                out.push(m);
            }
        }
    }
    out
}

/// Multi-source censorship-resilient VPN Gate server & Official Mirror Site discovery client.
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

    async fn get_with_cookie_and_doh(
        &self,
        url: &str,
        timeout: Duration,
    ) -> Option<(String, String)> {
        let extract_cookie = |resp: &reqwest::Response| -> String {
            resp.headers()
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .filter_map(|s| s.split(';').next())
                .collect::<Vec<_>>()
                .join("; ")
        };

        if let Ok(resp) = self.http.get(url).timeout(timeout).send().await
            && resp.status().is_success()
        {
            let cookie = extract_cookie(&resp);
            if let Ok(text) = resp.text().await
                && text.len() > 64
            {
                return Some((text, cookie));
            }
        }

        // Fallback: resolve hostname via IP-pinned Cloudflare DoH (1.1.1.1:443)
        let parsed = reqwest::Url::parse(url).ok()?;
        let host = parsed.host_str()?;
        if host.parse::<Ipv4Addr>().is_ok() {
            return None;
        }
        let port = parsed.port_or_known_default()?;
        let ips = resolve_ipv4_via_cloudflare_doh(host, Duration::from_secs(4))
            .await
            .ok()?;

        for ip in ips.into_iter().take(2) {
            let Ok(pinned) = reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .timeout(timeout)
                .resolve(host, SocketAddr::new(IpAddr::V4(ip), port))
                .build()
            else {
                continue;
            };
            if let Ok(resp) = pinned.get(url).send().await
                && resp.status().is_success()
            {
                let cookie = extract_cookie(&resp);
                if let Ok(text) = resp.text().await
                    && text.len() > 64
                {
                    return Some((text, cookie));
                }
            }
        }
        None
    }

    async fn fetch_text_with_doh(&self, url: &str, timeout: Duration) -> Option<String> {
        self.get_with_cookie_and_doh(url, timeout)
            .await
            .map(|(t, _)| t)
    }

    /// Posts ASP.NET `C_L2TP=on` or `C_OpenVPN=on` protocol filter (works on `vpngate.net` AND Official Mirror Portals!).
    async fn post_protocol_filter(
        &self,
        portal_url: &str,
        asp_fields: &HashMap<String, String>,
        cookie: &str,
        checkbox_name: &str,
        timeout: Duration,
    ) -> Option<String> {
        let mut form = asp_fields.clone();
        form.insert(checkbox_name.to_string(), "on".to_string());
        form.insert("Button3".to_string(), "Refresh Servers List".to_string());

        let mut req = self
            .http
            .post(portal_url)
            .timeout(timeout)
            .header(reqwest::header::REFERER, portal_url)
            .form(&form);
        if !cookie.is_empty() {
            req = req.header(reqwest::header::COOKIE, cookie);
        }
        let resp = req.send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.text().await.ok()?;
        (body.len() > 256).then_some(body)
    }

    async fn try_primary_csv(&self) -> Option<String> {
        for &url in OFFICIAL_CSV_URLS {
            if let Some(body) = self
                .fetch_text_with_doh(url, Duration::from_millis(3200))
                .await
                && (body.contains("*vpn_servers") || body.contains("#HostName"))
            {
                return Some(body);
            }
        }
        None
    }

    async fn try_primary_html(&self) -> Option<(String, String, String)> {
        for &url in OFFICIAL_HTML_URLS {
            if let Some((html, cookie)) = self
                .get_with_cookie_and_doh(url, Duration::from_millis(3200))
                .await
                && html.contains("vg_table_row_")
            {
                return Some((url.to_string(), html, cookie));
            }
        }
        None
    }

    async fn try_primary_mirror_sites(&self) -> Vec<OfficialMirrorSite> {
        for &url in OFFICIAL_MIRROR_SITES_URLS {
            if let Some(html) = self
                .fetch_text_with_doh(url, Duration::from_millis(3200))
                .await
            {
                let parsed = parse_vpngate_mirror_sites_html(&html, "sites.aspx");
                if !parsed.is_empty() {
                    return parsed;
                }
            }
        }
        Vec::new()
    }

    async fn fetch_fallback_official_mirror_sites(&self) -> Vec<OfficialMirrorSite> {
        let fut_daily = async {
            for &url in DAILY_MIRROR_JSON_URLS {
                if let Some(raw) = self
                    .fetch_text_with_doh(url, Duration::from_millis(3500))
                    .await
                    && let Ok(rows) = serde_json::from_str::<Vec<DailyMirrorJsonRow>>(&raw)
                {
                    let mut list = Vec::new();
                    for r in rows {
                        let raw_u = format!("http://{}:{}/en/", r.ip.trim(), r.port);
                        if let Some((base_url, portal_url)) = normalize_mirror_base_url(&raw_u) {
                            list.push(OfficialMirrorSite {
                                base_url,
                                portal_url,
                                location: if r.location.trim().is_empty() {
                                    "Mirror".to_string()
                                } else {
                                    r.location.trim().to_string()
                                },
                                source: "daily-mirror-feed".to_string(),
                            });
                        }
                    }
                    if !list.is_empty() {
                        return list;
                    }
                }
            }
            Vec::new()
        };

        let fut_wb = async {
            let Some(cdx_raw) = self
                .fetch_text_with_doh(WAYBACK_MIRROR_SITES_CDX_URL, Duration::from_millis(3000))
                .await
            else {
                return Vec::new();
            };
            let Ok(rows) = serde_json::from_str::<Vec<Vec<String>>>(&cdx_raw) else {
                return Vec::new();
            };
            for r in rows.into_iter().skip(1).rev() {
                if r.len() >= 3 {
                    let snap_url = format!("https://web.archive.org/web/{}id_/{}", r[1], r[2]);
                    if let Some(html) = self
                        .fetch_text_with_doh(&snap_url, Duration::from_millis(3500))
                        .await
                    {
                        let parsed = parse_vpngate_mirror_sites_html(&html, "wayback-sites");
                        if !parsed.is_empty() {
                            return parsed;
                        }
                    }
                }
            }
            Vec::new()
        };

        let (daily, wb) = tokio::join!(fut_daily, fut_wb);
        merge_mirror_lists(vec![daily, wb])
    }

    /// Queries an Official VPNGate Mirror Portal (`<base>/api/iphone/`, `<base>/en/` + ASP.NET POSTs + `<base>/en/sites.aspx`).
    async fn fetch_from_official_mirror_portal(
        &self,
        mirror: &OfficialMirrorSite,
    ) -> Option<(String, String, String, String, Vec<OfficialMirrorSite>)> {
        let csv_url = format!("{}/api/iphone/", mirror.base_url);
        let en_url = mirror.portal_url.clone();
        let sites_url = format!("{}/en/sites.aspx", mirror.base_url);

        let (csv_opt, en_opt, sites_opt) = tokio::join!(
            self.fetch_text_with_doh(&csv_url, Duration::from_millis(4200)),
            self.get_with_cookie_and_doh(&en_url, Duration::from_millis(4200)),
            self.fetch_text_with_doh(&sites_url, Duration::from_millis(3500)),
        );

        let csv_body = csv_opt
            .filter(|b| b.contains("*vpn_servers") || b.contains("#HostName"))
            .unwrap_or_default();
        let (base_html, cookie) = en_opt
            .filter(|(h, _)| h.contains("vg_table_row_"))
            .unwrap_or_default();

        if csv_body.is_empty() && base_html.is_empty() {
            return None;
        }

        let mut l2tp_html = String::new();
        let mut ovpn_html = String::new();
        if !base_html.is_empty() {
            let asp = extract_aspnet_fields(&base_html);
            if asp.contains_key("__VIEWSTATE") {
                let (l2, ov) = tokio::join!(
                    self.post_protocol_filter(
                        &en_url,
                        &asp,
                        &cookie,
                        "C_L2TP",
                        Duration::from_millis(4500),
                    ),
                    self.post_protocol_filter(
                        &en_url,
                        &asp,
                        &cookie,
                        "C_OpenVPN",
                        Duration::from_millis(4500),
                    ),
                );
                l2tp_html = l2.unwrap_or_default();
                ovpn_html = ov.unwrap_or_default();
            }
        }

        let extra_mirrors = sites_opt
            .map(|h| parse_vpngate_mirror_sites_html(&h, "mirror-sites.aspx"))
            .unwrap_or_default();

        Some((csv_body, base_html, l2tp_html, ovpn_html, extra_mirrors))
    }

    /// Harvests dedicated-L2TP candidate servers from Internet Archive Wayback `www.vpngate.net/{en,ja}/` (`PY` parity).
    async fn fetch_wayback_l2tp_candidates(&self) -> BTreeMap<String, VpnServer> {
        let mut cdx_futs = Vec::new();
        for &u in WAYBACK_CDX_URLS {
            cdx_futs.push(self.fetch_text_with_doh(u, Duration::from_millis(2800)));
        }
        let mut snap_urls = Vec::new();
        let mut seen_ts = std::collections::HashSet::new();
        for fut in cdx_futs {
            if let Some(raw) = fut.await
                && let Ok(rows) = serde_json::from_str::<Vec<Vec<String>>>(&raw)
            {
                for r in rows.into_iter().skip(1) {
                    if r.len() >= 3 && seen_ts.insert(r[1].clone()) {
                        snap_urls.push(format!("https://web.archive.org/web/{}id_/{}", r[1], r[2]));
                    }
                }
            }
        }
        if snap_urls.is_empty() {
            return BTreeMap::new();
        }
        let start = snap_urls.len().saturating_sub(6);
        let mut candidates = BTreeMap::new();
        let mut tasks = Vec::new();
        for u in &snap_urls[start..] {
            tasks.push(self.fetch_text_with_doh(u, Duration::from_millis(4200)));
        }
        for t in tasks {
            if let Some(snap_html) = t.await {
                let mut parsed = BTreeMap::new();
                parse_vpngate_html_into(&snap_html, &mut parsed);
                for (ip, mut srv) in parsed {
                    if srv.l2tp {
                        srv.openvpn = false;
                        srv.l2tp = false;
                        srv.ovpn_b64.clear();
                        srv.ovpn_dl_query.clear();
                        candidates.insert(ip, srv);
                    }
                }
            }
        }
        candidates
    }

    /// Harvests recent `funcra/vg-mirror/servers_history` snapshots as L2TP probe candidates (`PY` parity).
    async fn fetch_funcra_history_l2tp_candidates(&self) -> BTreeMap<String, VpnServer> {
        let info_url = format!("{FUNCRA_HISTORY_BASE_URL}/info.json");
        let Some(raw_info) = self
            .fetch_text_with_doh(&info_url, Duration::from_millis(2500))
            .await
        else {
            return BTreeMap::new();
        };
        let Ok(entries) = serde_json::from_str::<Vec<FuncraHistEntry>>(&raw_info) else {
            return BTreeMap::new();
        };
        let start = entries.len().saturating_sub(6);
        let mut out = BTreeMap::new();
        for e in &entries[start..] {
            let u = format!("{FUNCRA_HISTORY_BASE_URL}/{}", e.file);
            if let Some(csv_raw) = self
                .fetch_text_with_doh(&u, Duration::from_millis(3500))
                .await
            {
                let mut parsed = BTreeMap::new();
                parse_vpngate_csv_into(&csv_raw, &mut parsed);
                for (ip, mut srv) in parsed {
                    srv.openvpn = false;
                    srv.l2tp = false;
                    srv.ovpn_b64.clear();
                    out.entry(ip).or_insert(srv);
                }
            }
        }
        out
    }

    /// Discovers and live-probes Official VPNGate Mirror Sites (`vpngate mirrors` command).
    pub async fn discover_and_probe_mirror_sites(
        &self,
        mut on_progress: impl FnMut(ProgressEvent),
    ) -> Vec<MirrorProbeResult> {
        on_progress(ProgressEvent::Info(
            "Discovering Official VPNGate Mirror Sites (sites.aspx + daily mirror feeds + cache) ..."
                .to_string(),
        ));

        let discover_fut = async {
            let (primary_sites, fallback_sites) = tokio::join!(
                self.try_primary_mirror_sites(),
                self.fetch_fallback_official_mirror_sites(),
            );
            merge_mirror_lists(vec![
                collect_env_custom_mirrors(),
                primary_sites,
                self.opts.seed_mirrors.clone(),
                fallback_sites,
            ])
        };

        let mirrors = await_with_spinner(
            discover_fut,
            "Querying VPNGate Mirror Sites directory",
            6,
            &mut on_progress,
        )
        .await;

        if mirrors.is_empty() {
            on_progress(ProgressEvent::Warn(
                "No Official VPNGate Mirror Sites found from directory or cache.".to_string(),
            ));
            return Vec::new();
        }

        on_progress(ProgressEvent::Info(format!(
            "Probing {} Official VPNGate Mirror Site(s) for live reachability & server feeds ...",
            mirrors.len()
        )));

        let probe_all = async {
            let mut results = Vec::with_capacity(mirrors.len());
            let mut handles = Vec::new();
            for m in mirrors {
                let client = self.http.clone();
                handles.push(tokio::spawn(async move {
                    let t0 = Instant::now();
                    let mut reachable = false;
                    let mut rtt_ms = None;
                    let mut servers_count = 0usize;

                    let api_url = format!("{}/api/iphone/", m.base_url);
                    if let Ok(resp) = client
                        .get(&api_url)
                        .timeout(Duration::from_millis(3800))
                        .send()
                        .await
                        && resp.status().is_success()
                        && let Ok(body) = resp.text().await
                        && (body.contains("*vpn_servers") || body.contains("#HostName"))
                    {
                        let mut map = BTreeMap::new();
                        parse_vpngate_csv_into(&body, &mut map);
                        reachable = true;
                        servers_count = map.len();
                        rtt_ms = Some(t0.elapsed().as_millis().max(1) as u64);
                    } else if let Ok(resp) = client
                        .get(&m.portal_url)
                        .timeout(Duration::from_millis(3800))
                        .send()
                        .await
                        && resp.status().is_success()
                        && let Ok(html) = resp.text().await
                        && html.contains("vg_table_row_")
                    {
                        let mut map = BTreeMap::new();
                        parse_vpngate_html_into(&html, &mut map);
                        reachable = true;
                        servers_count = map.len();
                        rtt_ms = Some(t0.elapsed().as_millis().max(1) as u64);
                    } else if let Ok(parsed) = reqwest::Url::parse(&m.base_url)
                        && let Some(host) = parsed.host_str()
                        && let Some(port) = parsed.port_or_known_default()
                        && let Ok(v4) = host.parse::<Ipv4Addr>()
                    {
                        let _ = probe_tcp(
                            SocketAddr::new(IpAddr::V4(v4), port),
                            Duration::from_millis(1500),
                        )
                        .await;
                    }

                    MirrorProbeResult {
                        mirror: m,
                        reachable,
                        rtt_ms,
                        servers_count,
                    }
                }));
            }
            for h in handles {
                if let Ok(r) = h.await {
                    results.push(r);
                }
            }
            results.sort_by_key(|r| (!r.reachable, r.rtt_ms.unwrap_or(99_999)));
            results
        };

        let results = await_with_spinner(
            probe_all,
            "Testing Official VPNGate Mirror portals",
            5,
            &mut on_progress,
        )
        .await;

        let online_cnt = results.iter().filter(|r| r.reachable).count();
        on_progress(ProgressEvent::Ok(format!(
            "Mirror probe finished: {online_cnt}/{} Official VPNGate Mirror Site(s) online.",
            results.len()
        )));
        results
    }

    /// Silent convenience wrapper around `fetch_servers_with_progress`.
    pub async fn fetch_servers(&self) -> Result<Vec<VpnServer>> {
        let out = self.fetch_servers_with_progress(|_| {}).await?;
        Ok(out.servers)
    }

    /// Full multi-stage server + Official Mirror discovery with live `PY`-style progress events.
    pub async fn fetch_servers_with_progress(
        &self,
        mut on_progress: impl FnMut(ProgressEvent),
    ) -> Result<DiscoveryOutcome> {
        let mut servers_by_ip: BTreeMap<String, VpnServer> = BTreeMap::new();
        let mut extra_l2tp_candidates: BTreeMap<String, VpnServer> = BTreeMap::new();
        let env_mirrors = collect_env_custom_mirrors();

        // =========================================================================
        // Stage 1: Primary vpngate.net (`/api/iphone/` CSV + `/en/` HTML + `/en/sites.aspx` mirrors)
        // =========================================================================
        on_progress(ProgressEvent::Info(
            "Querying primary vpngate.net + Official Mirror Sites list (3.5s fast-failover cap) ..."
                .to_string(),
        ));

        // Enforce strict 3.6s cap on Stage 1 just like PY `deadline_sec=3.5`
        let (primary_csv, primary_html_opt, primary_mirrors) = await_with_spinner(
            async {
                tokio::time::timeout(Duration::from_millis(3600), async {
                    tokio::join!(
                        self.try_primary_csv(),
                        self.try_primary_html(),
                        self.try_primary_mirror_sites(),
                    )
                })
                .await
                .unwrap_or((None, None, Vec::new()))
            },
            "Contacting primary vpngate.net (CSV + HTML + sites.aspx)",
            4,
            &mut on_progress,
        )
        .await;

        let mut harvested_mirrors = merge_mirror_lists(vec![
            env_mirrors.clone(),
            primary_mirrors.clone(),
            self.opts.seed_mirrors.clone(),
        ]);

        if !primary_mirrors.is_empty() {
            on_progress(ProgressEvent::Ok(format!(
                "Harvested {} Official VPNGate Mirror Site(s) from sites.aspx.",
                primary_mirrors.len()
            )));
        }

        let mut l2tp_html = String::new();
        let mut ovpn_html = String::new();
        let mut base_html = String::new();

        if let Some((portal_url, html, cookie)) = primary_html_opt {
            base_html = html;
            let asp_fields = extract_aspnet_fields(&base_html);
            if asp_fields.contains_key("__VIEWSTATE") {
                on_progress(ProgressEvent::Info(
                    "Primary vpngate.net online! Fetching separate C_L2TP=on and C_OpenVPN=on tables ..."
                        .to_string(),
                ));
                let (l2, ov) = await_with_spinner(
                    async {
                        tokio::time::timeout(Duration::from_millis(5500), async {
                            tokio::join!(
                                self.post_protocol_filter(
                                    &portal_url,
                                    &asp_fields,
                                    &cookie,
                                    "C_L2TP",
                                    Duration::from_secs(5),
                                ),
                                self.post_protocol_filter(
                                    &portal_url,
                                    &asp_fields,
                                    &cookie,
                                    "C_OpenVPN",
                                    Duration::from_secs(5),
                                ),
                            )
                        })
                        .await
                        .unwrap_or((None, None))
                    },
                    "Fetching C_L2TP=on & C_OpenVPN=on protocol tables",
                    6,
                    &mut on_progress,
                )
                .await;
                l2tp_html = l2.unwrap_or_default();
                ovpn_html = ov.unwrap_or_default();
            }
        }

        if let Some(ref csv_raw) = primary_csv {
            parse_vpngate_csv_into(csv_raw, &mut servers_by_ip);
        }
        if !ovpn_html.is_empty() || !l2tp_html.is_empty() || !base_html.is_empty() {
            parse_vpngate_html_into(&ovpn_html, &mut servers_by_ip);
            parse_vpngate_html_into(&l2tp_html, &mut servers_by_ip);
            parse_vpngate_html_into(&base_html, &mut servers_by_ip);
        }

        // =========================================================================
        // Stage 1b: Official VPNGate Mirror Portals (`http://<mirror>:<port>/en/` & `/api/iphone/`)
        // Used automatically when primary `vpngate.net` is blocked/incomplete OR custom mirrors set!
        // =========================================================================
        if servers_by_ip.is_empty() || l2tp_html.is_empty() || !env_mirrors.is_empty() {
            if harvested_mirrors.is_empty() {
                let fb_mirrors = await_with_spinner(
                    self.fetch_fallback_official_mirror_sites(),
                    "Fetching daily Official VPNGate Mirror URLs",
                    5,
                    &mut on_progress,
                )
                .await;
                harvested_mirrors = merge_mirror_lists(vec![harvested_mirrors, fb_mirrors]);
            }

            if !harvested_mirrors.is_empty() && (servers_by_ip.is_empty() || l2tp_html.is_empty()) {
                let probe_slice: Vec<OfficialMirrorSite> =
                    harvested_mirrors.iter().take(5).cloned().collect();
                on_progress(ProgressEvent::Info(format!(
                    "Querying {} Official VPNGate Mirror Portal(s) ({}) ...",
                    probe_slice.len(),
                    probe_slice
                        .iter()
                        .map(|m| format!("{} [{}]", m.base_url, m.location))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));

                let portal_res = await_with_spinner(
                    async {
                        let mut out = Vec::new();
                        for m in &probe_slice {
                            if let Some(res) = self.fetch_from_official_mirror_portal(m).await {
                                out.push((m.clone(), res));
                                break;
                            }
                        }
                        out
                    },
                    "Fetching server lists from Official VPNGate Mirror Portals",
                    6,
                    &mut on_progress,
                )
                .await;

                for (m, (m_csv, m_base, m_l2tp, m_ovpn, m_sites)) in portal_res {
                    if !m_csv.is_empty() {
                        parse_vpngate_csv_into(&m_csv, &mut servers_by_ip);
                    }
                    parse_vpngate_html_into(&m_ovpn, &mut servers_by_ip);
                    parse_vpngate_html_into(&m_l2tp, &mut servers_by_ip);
                    parse_vpngate_html_into(&m_base, &mut servers_by_ip);
                    if !m_l2tp.is_empty() && l2tp_html.is_empty() {
                        l2tp_html = m_l2tp;
                    }
                    if !m_sites.is_empty() {
                        harvested_mirrors = merge_mirror_lists(vec![harvested_mirrors, m_sites]);
                    }
                    on_progress(ProgressEvent::Ok(format!(
                        "Official VPNGate Mirror {} ({}) online — merged live relay pool.",
                        m.portal_url, m.location
                    )));
                }
            }
        }

        // =========================================================================
        // Stage 2: HTTPS Multi-Mirror CSV + Wayback & funcra Dedicated-L2TP Archive Enrichment (`PY` parity)
        // =========================================================================
        if servers_by_ip.len() < 200 || primary_csv.is_none() || l2tp_html.is_empty() {
            if servers_by_ip.is_empty() {
                on_progress(ProgressEvent::Warn(
                    "Primary vpngate.net unreachable — switching automatically to HTTPS mirror & L2TP archive pools ..."
                        .to_string(),
                ));
            } else {
                on_progress(ProgressEvent::Info(
                    "Enriching server pool from HTTPS mirrors & archive feeds ...".to_string(),
                ));
            }

            let need_l2tp_archives = l2tp_html.is_empty();
            let (mirror_bodies, sdise_opt, wb_map, fh_map) = await_with_spinner(
                async {
                    tokio::time::timeout(Duration::from_millis(13_500), async {
                        let csv_fut = async {
                            let mut futs = Vec::new();
                            for &u in MIRROR_CSV_URLS {
                                futs.push(self.fetch_text_with_doh(u, Duration::from_secs(9)));
                            }
                            let mut bodies = Vec::new();
                            for f in futs {
                                if let Some(b) = f.await {
                                    bodies.push(b);
                                }
                            }
                            bodies
                        };
                        let sdise_fut =
                            self.fetch_text_with_doh(SDISE_CSV_URL, Duration::from_secs(8));
                        let wb_fut = async {
                            if need_l2tp_archives {
                                self.fetch_wayback_l2tp_candidates().await
                            } else {
                                BTreeMap::new()
                            }
                        };
                        let fh_fut = async {
                            if need_l2tp_archives {
                                self.fetch_funcra_history_l2tp_candidates().await
                            } else {
                                BTreeMap::new()
                            }
                        };
                        tokio::join!(csv_fut, sdise_fut, wb_fut, fh_fut)
                    })
                    .await
                    .unwrap_or_else(|_| (Vec::new(), None, BTreeMap::new(), BTreeMap::new()))
                },
                "Downloading HTTPS mirror CSVs & L2TP archive candidates",
                13,
                &mut on_progress,
            )
            .await;

            let mut mirror_hits = 0usize;
            for body in mirror_bodies {
                if body.contains("*vpn_servers") || body.contains("#HostName") {
                    parse_vpngate_csv_into(&body, &mut servers_by_ip);
                    mirror_hits += 1;
                }
            }
            if let Some(sdise_raw) = sdise_opt {
                parse_sdise_csv_into(&sdise_raw, &mut extra_l2tp_candidates);
            }
            let mut merged_extra = BTreeMap::new();
            for map in [wb_map, fh_map, extra_l2tp_candidates] {
                for (k, v) in map {
                    merged_extra.entry(k).or_insert(v);
                }
            }
            extra_l2tp_candidates = merged_extra;

            if mirror_hits > 0 {
                on_progress(ProgressEvent::Ok(format!(
                    "Loaded {} fresh OpenVPN servers from {mirror_hits} HTTPS mirror feeds.",
                    servers_by_ip.len()
                )));
            }
        }

        if servers_by_ip.is_empty() && extra_l2tp_candidates.is_empty() {
            return Err(CoreError::NoMatchingServers);
        }

        // =========================================================================
        // Stage 3: Live Cryptographic IKEv1 `PSK == "vpn"` Verification (`PY` parity)
        // =========================================================================
        if self.opts.probe_l2tp_candidates {
            let listed_l2tp_cnt = servers_by_ip.values().filter(|s| s.l2tp).count();
            if l2tp_html.is_empty() || listed_l2tp_cnt == 0 {
                let mut all_ips = Vec::new();
                let mut seen_ip = std::collections::HashSet::new();
                for ip_s in servers_by_ip.keys().chain(extra_l2tp_candidates.keys()) {
                    if let Ok(v4) = ip_s.parse::<Ipv4Addr>()
                        && seen_ip.insert(v4)
                    {
                        all_ips.push(v4);
                    }
                }

                on_progress(ProgressEvent::Info(format!(
                    "Probing {} candidate hosts via NAT-T + PSK='vpn' cryptographic IKEv1 verifier ...",
                    all_ips.len()
                )));

                let verified_ips = await_with_spinner(
                    async {
                        let sa_responders =
                            sweep_ikev1_sa_responders(&all_ips, Duration::from_millis(1600)).await;
                        let sem = Arc::new(Semaphore::new(32));
                        let mut handles = Vec::new();
                        for ip in sa_responders
                            .into_iter()
                            .take(self.opts.max_l2tp_probe_candidates)
                        {
                            let p = Arc::clone(&sem);
                            handles.push(tokio::spawn(async move {
                                let _g = p.acquire().await.ok()?;
                                let r =
                                    verify_l2tp_psk_vpn(ip, Duration::from_millis(1200), 1, b"vpn")
                                        .await;
                                r.is_verified().then_some(ip.to_string())
                            }));
                        }
                        let mut ok_set = std::collections::HashSet::new();
                        for h in handles {
                            if let Ok(Some(ip_s)) = h.await {
                                ok_set.insert(ip_s);
                            }
                        }
                        ok_set
                    },
                    "Verifying live IKEv1 Aggressive Mode PSK='vpn' responders",
                    4,
                    &mut on_progress,
                )
                .await;

                for verified_ip in verified_ips {
                    if let Some(existing) = servers_by_ip.get_mut(&verified_ip) {
                        existing.l2tp = true;
                        if let Some(wb) = extra_l2tp_candidates.get(&verified_ip)
                            && existing.hostname.starts_with("vg-")
                            && !wb.hostname.is_empty()
                        {
                            existing.hostname = wb.hostname.clone();
                        }
                    } else if let Some(mut promoted) = extra_l2tp_candidates.remove(&verified_ip) {
                        promoted.l2tp = true;
                        servers_by_ip.insert(verified_ip, promoted);
                    }
                }
            } else {
                let listed_ips: Vec<Ipv4Addr> = servers_by_ip
                    .iter()
                    .filter(|(_, s)| s.l2tp)
                    .filter_map(|(ip_s, _)| ip_s.parse::<Ipv4Addr>().ok())
                    .collect();

                on_progress(ProgressEvent::Info(format!(
                    "Verifying {} listed L2TP/IPsec hosts (PSK='vpn', pruning dead/private-PSK nodes) ...",
                    listed_ips.len()
                )));

                let verified_set = await_with_spinner(
                    async {
                        let sa_responders =
                            sweep_ikev1_sa_responders(&listed_ips, Duration::from_millis(1400))
                                .await;
                        let sem = Arc::new(Semaphore::new(32));
                        let mut handles = Vec::new();
                        for ip in sa_responders {
                            let p = Arc::clone(&sem);
                            handles.push(tokio::spawn(async move {
                                let _g = p.acquire().await.ok()?;
                                let r =
                                    verify_l2tp_psk_vpn(ip, Duration::from_millis(1200), 1, b"vpn")
                                        .await;
                                r.is_verified().then_some(ip.to_string())
                            }));
                        }
                        let mut ok_set = std::collections::HashSet::new();
                        for h in handles {
                            if let Ok(Some(ip_s)) = h.await {
                                ok_set.insert(ip_s);
                            }
                        }
                        ok_set
                    },
                    "Cryptographically verifying listed PSK='vpn' L2TP/IPsec servers",
                    3,
                    &mut on_progress,
                )
                .await;

                for s in servers_by_ip.values_mut() {
                    if s.l2tp {
                        s.l2tp = verified_set.contains(&s.ip);
                    }
                }
            }
        }

        let servers: Vec<VpnServer> = servers_by_ip
            .into_values()
            .filter(|s| s.has_any_protocol())
            .collect();
        if servers.is_empty() {
            return Err(CoreError::NoMatchingServers);
        }

        let l2tp_cnt = servers.iter().filter(|s| s.l2tp).count();
        let ovpn_cnt = servers.iter().filter(|s| s.openvpn).count();
        on_progress(ProgressEvent::Ok(format!(
            "Server pool ready: {} unique servers ({ovpn_cnt} OpenVPN, {l2tp_cnt} verified PSK='vpn' L2TP/IPsec).",
            servers.len()
        )));

        Ok(DiscoveryOutcome {
            servers,
            official_mirrors: harvested_mirrors,
        })
    }
}
