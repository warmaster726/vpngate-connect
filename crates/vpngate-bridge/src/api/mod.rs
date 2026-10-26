use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpngate_core::{
    AppPaths, CountrySummary, DiscoveryClient, DiscoveryOptions, L2tpVerifyOutcome,
    MirrorProbeResult, OfficialMirrorSite, OpenVpnCompat, OvpnPatchOptions, ProgressEvent,
    ProtocolFilter, PublicIpTrace, ServerCacheFile, SortBy, TargetPlatform, UserspaceL2tpConfig,
    UserspaceL2tpHandle, UserspaceL2tpStats, VpnProtocol, VpnServer, build_apple_l2tp_mobileconfig,
    build_patched_ovpn, filter_by_country, filter_by_protocol, get_public_ip_trace,
    get_servers_cached_with_progress, load_cached_mirrors, load_cooldowns, load_watchdog_pref,
    normalize_mirror_base_url, now_unix_secs, probe_tcp, read_json_opt, run_ikev1_crypto_self_test,
    save_cached_mirrors, save_cooldowns, save_watchdog_pref, sort_servers,
    spawn_userspace_l2tp_session, summarize_countries, verify_l2tp_psk_vpn,
};

const MAX_PROGRESS_BUFFER: usize = 256;

struct BridgeState {
    rt: tokio::runtime::Runtime,
    storage_dir: Mutex<Option<PathBuf>>,
    progress: Mutex<VecDeque<ProgressEvent>>,
    l2tp_session: Mutex<Option<UserspaceL2tpHandle>>,
}

impl BridgeState {
    fn get() -> &'static Self {
        static STATE: OnceLock<BridgeState> = OnceLock::new();
        STATE.get_or_init(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .expect("Failed to initialize vpngate-bridge Tokio runtime");
            Self {
                rt,
                storage_dir: Mutex::new(None),
                progress: Mutex::new(VecDeque::with_capacity(MAX_PROGRESS_BUFFER)),
                l2tp_session: Mutex::new(None),
            }
        })
    }

    fn paths(&self) -> AppPaths {
        if let Ok(guard) = self.storage_dir.lock()
            && let Some(dir) = guard.as_ref()
        {
            return AppPaths::with_base_dir(dir.clone());
        }
        AppPaths::resolve()
    }

    fn push_event(&self, ev: ProgressEvent) {
        if let Ok(mut q) = self.progress.lock() {
            if matches!(ev, ProgressEvent::Transient { .. })
                && matches!(q.back(), Some(ProgressEvent::Transient { .. }))
            {
                let _ = q.pop_back();
            }
            if q.len() >= MAX_PROGRESS_BUFFER {
                let _ = q.pop_front();
            }
            q.push_back(ev);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoverRequest {
    #[serde(default)]
    pub force_refresh: bool,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default = "default_proto_auto")]
    pub protocol: String,
    #[serde(default = "default_sort_recommended")]
    pub sort_by: String,
    #[serde(default)]
    pub mirror_urls: Vec<String>,
}

fn default_proto_auto() -> String {
    "auto".to_string()
}

fn default_sort_recommended() -> String {
    "recommended".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverResponse {
    pub servers: Vec<VpnServer>,
    pub countries: Vec<CountrySummary>,
    pub cached_mirrors: Vec<OfficialMirrorSite>,
    pub total_pool: usize,
    pub cache_age_secs: Option<u64>,
    pub active_cooldowns: usize,
    pub watchdog_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPlanRequest {
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default = "default_proto_auto")]
    pub protocol: String,
    #[serde(default = "default_sort_recommended")]
    pub sort_by: String,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
    #[serde(default)]
    pub is_ios: bool,
    #[serde(default)]
    pub force_refresh: bool,
    #[serde(default)]
    pub mirror_urls: Vec<String>,
    #[serde(default)]
    pub pinned_ip: Option<String>,
}

fn default_max_candidates() -> usize {
    12
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAttempt {
    pub server: VpnServer,
    /// `"l2tp"`, `"udp"`, or `"tcp"`.
    pub protocol: String,
    pub protocol_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareAttemptRequest {
    pub server: VpnServer,
    /// `"l2tp"`, `"udp"`, or `"tcp"`.
    pub protocol: String,
    #[serde(default)]
    pub is_ios: bool,
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedAttempt {
    pub server: VpnServer,
    pub protocol: String,
    pub endpoint_ip: String,
    pub endpoint_port: u16,
    pub dns_servers: Vec<String>,
    pub ovpn_config: Option<String>,
    pub apple_mobileconfig: Option<String>,
}

fn parse_proto_filter(raw: &str) -> ProtocolFilter {
    ProtocolFilter::from_cli_str(raw).unwrap_or(ProtocolFilter::Auto)
}

fn parse_sort_key(raw: &str) -> SortBy {
    SortBy::from_cli_str(raw).unwrap_or(SortBy::Recommended)
}

fn parse_extra_mirrors(raw_urls: &[String]) -> Vec<OfficialMirrorSite> {
    let mut out = Vec::new();
    for raw in raw_urls {
        for token in raw.split([',', ' ', ';']) {
            if let Some((base_url, portal_url)) = normalize_mirror_base_url(token) {
                out.push(OfficialMirrorSite {
                    base_url,
                    portal_url,
                    location: "User Mirror".to_string(),
                    source: "custom".to_string(),
                });
            }
        }
    }
    out
}

/// Configures the persistent sandbox directory (`servers_cache.json`, `mirrors_cache.json`, `failed_servers.json`).
pub fn init_storage_dir(dir: String) -> Result<String, String> {
    let trimmed = dir.trim();
    if trimmed.is_empty() {
        return Err("Storage directory cannot be empty".to_string());
    }
    let pb = PathBuf::from(trimmed);
    let paths = AppPaths::with_base_dir(pb.clone());
    paths.ensure_dirs().map_err(|e| e.to_string())?;
    let mut guard = BridgeState::get()
        .storage_dir
        .lock()
        .map_err(|_| "Storage mutex poisoned".to_string())?;
    *guard = Some(pb.clone());
    Ok(pb.display().to_string())
}

/// Drains buffered live `ProgressEvent`s for Flutter's real-time console overlay.
pub fn drain_progress_events() -> Vec<ProgressEvent> {
    let Ok(mut q) = BridgeState::get().progress.lock() else {
        return Vec::new();
    };
    q.drain(..).collect()
}

/// Returns the detected host OS identifier (`android`, `ios`, `linux`, `macos`, `windows`) + IKEv1 crypto self-test status.
pub fn host_platform_name() -> String {
    TargetPlatform::current().as_str().to_string()
}

/// Runs diagnostics on the embedded `vpngate-core` engine (crypto self-test, cache age, mirror count, cooldowns).
pub fn run_bridge_diagnostics() -> Result<serde_json::Value, String> {
    run_ikev1_crypto_self_test()?;
    let st = BridgeState::get();
    let paths = st.paths();
    let mirrors = load_cached_mirrors(&paths);
    let cd = load_cooldowns(&paths);
    let active_cd = cd.active_count();
    let cache_info = read_json_opt::<ServerCacheFile>(&paths.servers_cache);
    Ok(serde_json::json!({
        "platform": host_platform_name(),
        "ikev1_crypto_self_test": "PASS",
        "userspace_l2tp_engine": "READY (IKEv1 + ESPinUDP + L2TPv2 + PPP/IPCP)",
        "storage_dir": paths.cache_dir.display().to_string(),
        "cached_servers": cache_info.as_ref().map(|c| c.servers.len()).unwrap_or(0),
        "cached_mirrors": mirrors.len(),
        "active_cooldowns": active_cd,
        "watchdog_enabled": load_watchdog_pref(&paths),
    }))
}

/// Fetches, filters, and ranks the VPN Gate server pool using the full anti-censorship + Official Mirror cascade.
pub fn discover_servers_sync(req: DiscoverRequest) -> Result<DiscoverResponse, String> {
    let st = BridgeState::get();
    let paths = st.paths();
    let extra_mirrors = parse_extra_mirrors(&req.mirror_urls);

    let pool = st
        .rt
        .block_on(get_servers_cached_with_progress(
            &paths,
            req.force_refresh,
            &extra_mirrors,
            |ev| st.push_event(ev),
        ))
        .map_err(|e| e.to_string())?;

    let total_pool = pool.len();
    let countries = summarize_countries(&pool);
    let proto_filter = parse_proto_filter(&req.protocol);
    let sort_key = parse_sort_key(&req.sort_by);

    let by_country = filter_by_country(&pool, req.country.as_deref());
    let mut filtered = filter_by_protocol(&by_country, proto_filter);
    sort_servers(&mut filtered, sort_key, proto_filter);

    let cache_age_secs = read_json_opt::<ServerCacheFile>(&paths.servers_cache)
        .map(|c| now_unix_secs().saturating_sub(c.timestamp));
    let mut cd = load_cooldowns(&paths);
    let active_cooldowns = cd.active_count();
    save_cooldowns(&paths, &mut cd);

    Ok(DiscoverResponse {
        servers: filtered,
        countries,
        cached_mirrors: load_cached_mirrors(&paths),
        total_pool,
        cache_age_secs,
        active_cooldowns,
        watchdog_enabled: load_watchdog_pref(&paths),
    })
}

/// Discovers and live-probes Official VPN Gate Mirror Sites (`sites.aspx` + daily feed + cache) and caches reachable mirrors.
pub fn probe_official_mirrors_sync(
    extra_urls: Vec<String>,
) -> Result<Vec<MirrorProbeResult>, String> {
    let st = BridgeState::get();
    let paths = st.paths();
    let mut seeds = parse_extra_mirrors(&extra_urls);
    for m in load_cached_mirrors(&paths) {
        if !seeds.iter().any(|x| x.base_url == m.base_url) {
            seeds.push(m);
        }
    }
    let opts = DiscoveryOptions {
        seed_mirrors: seeds,
        ..DiscoveryOptions::default()
    };
    let client = DiscoveryClient::new(opts).map_err(|e| e.to_string())?;
    let results = st
        .rt
        .block_on(client.discover_and_probe_mirror_sites(|ev| st.push_event(ev)));
    let reachable: Vec<OfficialMirrorSite> = results
        .iter()
        .filter(|r| r.reachable)
        .map(|r| r.mirror.clone())
        .collect();
    if !reachable.is_empty() {
        save_cached_mirrors(&paths, &reachable);
    }
    Ok(results)
}

/// Builds the ordered `Auto` (or single-protocol) failover queue matching Desktop `Auto`:
/// `L2TP/IPsec (PSK='vpn') -> OpenVPN UDP -> OpenVPN TCP`, skipping relays currently in 30m cooldown.
pub fn build_connect_plan_sync(req: ConnectPlanRequest) -> Result<Vec<PlannedAttempt>, String> {
    let st = BridgeState::get();
    let paths = st.paths();
    let extra_mirrors = parse_extra_mirrors(&req.mirror_urls);
    let pool = st
        .rt
        .block_on(get_servers_cached_with_progress(
            &paths,
            req.force_refresh,
            &extra_mirrors,
            |ev| st.push_event(ev),
        ))
        .map_err(|e| e.to_string())?;

    let proto_filter = parse_proto_filter(&req.protocol);
    let sort_key = parse_sort_key(&req.sort_by);

    let mut candidates = if let Some(pin) = req
        .pinned_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        pool.into_iter().filter(|s| s.ip == pin).collect::<Vec<_>>()
    } else {
        let c = filter_by_country(&pool, req.country.as_deref());
        filter_by_protocol(&c, proto_filter)
    };
    sort_servers(&mut candidates, sort_key, proto_filter);

    let cd = load_cooldowns(&paths);
    let max_servers = req.max_candidates.clamp(1, 32);
    let mut plan = Vec::new();

    for srv in candidates.into_iter().take(max_servers) {
        let protos: Vec<(VpnProtocol, &str, &str)> = match proto_filter {
            ProtocolFilter::Only(VpnProtocol::L2tpIpsec) => {
                if srv.l2tp {
                    vec![(VpnProtocol::L2tpIpsec, "l2tp", "L2TP/IPsec (PSK='vpn')")]
                } else {
                    Vec::new()
                }
            }
            ProtocolFilter::Only(VpnProtocol::OpenVpnUdp) => {
                if srv.supports_openvpn_udp() {
                    vec![(VpnProtocol::OpenVpnUdp, "udp", "OpenVPN UDP")]
                } else {
                    Vec::new()
                }
            }
            ProtocolFilter::Only(VpnProtocol::OpenVpnTcp) => {
                if srv.supports_openvpn_tcp() {
                    vec![(VpnProtocol::OpenVpnTcp, "tcp", "OpenVPN TCP")]
                } else {
                    Vec::new()
                }
            }
            ProtocolFilter::OpenVpnAny => {
                let mut v = Vec::new();
                if srv.supports_openvpn_udp() {
                    v.push((VpnProtocol::OpenVpnUdp, "udp", "OpenVPN UDP"));
                }
                if srv.supports_openvpn_tcp() {
                    v.push((VpnProtocol::OpenVpnTcp, "tcp", "OpenVPN TCP"));
                }
                v
            }
            ProtocolFilter::Auto => {
                let mut v = Vec::new();
                if !req.is_ios && srv.l2tp {
                    v.push((
                        VpnProtocol::L2tpIpsec,
                        "l2tp",
                        "L2TP/IPsec (User-Space ESP/L2TP)",
                    ));
                }
                if srv.supports_openvpn_udp() {
                    v.push((VpnProtocol::OpenVpnUdp, "udp", "OpenVPN UDP"));
                }
                if srv.supports_openvpn_tcp() {
                    v.push((VpnProtocol::OpenVpnTcp, "tcp", "OpenVPN TCP"));
                }
                v
            }
        };

        for (vp, p_code, p_label) in protos {
            if cd.is_on_cooldown(&srv.ip, vp) {
                continue;
            }
            plan.push(PlannedAttempt {
                server: srv.clone(),
                protocol: p_code.to_string(),
                protocol_label: p_label.to_string(),
            });
        }
    }

    if plan.is_empty() {
        return Err(
            "No matching VPN Gate relays available (clear 30m cooldowns or refresh server pool)"
                .to_string(),
        );
    }
    Ok(plan)
}

/// Runs fast pre-flight verification (`1-RTT IKEv1 PSK='vpn'` for L2TP, TCP handshake probe for TCP)
/// and produces the mobile tunnel configuration (`.ovpn` `MobileCore3` or `.mobileconfig`).
pub fn prepare_attempt_sync(req: PrepareAttemptRequest) -> Result<PreparedAttempt, String> {
    let st = BridgeState::get();
    let paths = st.paths();
    let proto = req.protocol.trim().to_ascii_lowercase();
    let ip_v4: Ipv4Addr = req
        .server
        .ip
        .trim()
        .parse()
        .map_err(|_| format!("Invalid relay IPv4 address: {}", req.server.ip))?;

    let dns_servers = if req.dns_servers.is_empty() {
        vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
    } else {
        req.dns_servers.clone()
    };

    match proto.as_str() {
        "l2tp" => {
            st.push_event(ProgressEvent::Info(format!(
                "Pre-flight 1-RTT IKEv1 Aggressive Mode PSK='vpn' check on {}:500 ...",
                req.server.ip
            )));
            let outcome = st.rt.block_on(verify_l2tp_psk_vpn(
                ip_v4,
                Duration::from_millis(1600),
                2,
                b"vpn",
            ));
            if outcome != L2tpVerifyOutcome::VerifiedPskVpn {
                let mut cd = load_cooldowns(&paths);
                cd.mark_failed(&req.server.ip, VpnProtocol::L2tpIpsec);
                save_cooldowns(&paths, &mut cd);
                let msg = format!(
                    "L2TP pre-flight rejected {} ({:?}) — cooled down 30m",
                    req.server.ip, outcome
                );
                st.push_event(ProgressEvent::Warn(msg.clone()));
                return Err(msg);
            }
            st.push_event(ProgressEvent::Ok(format!(
                "Verified SoftEther IKEv1 PSK='vpn' on {}!",
                req.server.ip
            )));
            let mobileconfig = build_apple_l2tp_mobileconfig(&req.server);
            Ok(PreparedAttempt {
                server: req.server.clone(),
                protocol: "l2tp".to_string(),
                endpoint_ip: req.server.ip,
                endpoint_port: 4500,
                dns_servers,
                ovpn_config: None,
                apple_mobileconfig: Some(mobileconfig),
            })
        }
        "udp" | "tcp" => {
            let use_tcp = proto == "tcp";
            let port = if use_tcp {
                if req.server.tcp_port > 0 {
                    req.server.tcp_port
                } else {
                    443
                }
            } else if req.server.udp_port > 0 {
                req.server.udp_port
            } else {
                1194
            };

            if use_tcp {
                st.push_event(ProgressEvent::Info(format!(
                    "Probing OpenVPN TCP {}:{} ...",
                    req.server.ip, port
                )));
                let reachable = st
                    .rt
                    .block_on(probe_tcp(
                        SocketAddr::new(IpAddr::V4(ip_v4), port),
                        Duration::from_millis(1800),
                    ))
                    .is_some();
                if !reachable {
                    let mut cd = load_cooldowns(&paths);
                    cd.mark_failed(&req.server.ip, VpnProtocol::OpenVpnTcp);
                    save_cooldowns(&paths, &mut cd);
                    let msg = format!(
                        "OpenVPN TCP {}:{} unreachable — cooled down 30m",
                        req.server.ip, port
                    );
                    st.push_event(ProgressEvent::Warn(msg.clone()));
                    return Err(msg);
                }
            }

            let opts = OvpnPatchOptions {
                platform: if req.is_ios {
                    TargetPlatform::Ios
                } else {
                    TargetPlatform::Android
                },
                compat: OpenVpnCompat::MobileCore3,
                transport: if use_tcp {
                    VpnProtocol::OpenVpnTcp
                } else {
                    VpnProtocol::OpenVpnUdp
                },
                dns_servers: dns_servers.clone(),
                ..Default::default()
            };
            let ovpn = build_patched_ovpn(&req.server, &opts).map_err(|e| e.to_string())?;
            Ok(PreparedAttempt {
                server: req.server,
                protocol: proto,
                endpoint_ip: ip_v4.to_string(),
                endpoint_port: port,
                dns_servers,
                ovpn_config: Some(ovpn),
                apple_mobileconfig: None,
            })
        }
        other => Err(format!("Unsupported mobile protocol '{other}'")),
    }
}

/// Marks `(ip, protocol)` as failed for 30 minutes in `failed_servers.json`.
pub fn record_attempt_failure_sync(ip: String, protocol: String) -> usize {
    let paths = BridgeState::get().paths();
    let mut cd = load_cooldowns(&paths);
    let vp = VpnProtocol::from_cli_str(&protocol).unwrap_or(VpnProtocol::OpenVpnUdp);
    cd.mark_failed(ip.trim(), vp);
    let count = cd.active_count();
    save_cooldowns(&paths, &mut cd);
    count
}

/// Clears all 30-minute server/protocol cooldowns.
pub fn clear_cooldowns_sync() -> Result<(), String> {
    let paths = BridgeState::get().paths();
    let mut cd = load_cooldowns(&paths);
    let _ = cd.clear_all();
    save_cooldowns(&paths, &mut cd);
    Ok(())
}

/// Persists the 15-second auto-reconnect watchdog preference.
pub fn set_watchdog_enabled_sync(enabled: bool) -> Result<bool, String> {
    let paths = BridgeState::get().paths();
    save_watchdog_pref(&paths, enabled).map_err(|e| e.to_string())?;
    Ok(enabled)
}

/// Queries live egress IPv4 & country code (`1.1.1.1/cdn-cgi/trace` -> fallbacks).
pub fn check_public_ip_sync(timeout_ms: u64) -> Result<PublicIpTrace, String> {
    let st = BridgeState::get();
    st.rt
        .block_on(get_public_ip_trace(Duration::from_millis(
            timeout_ms.clamp(1200, 10_000),
        )))
        .ok_or_else(|| "Public IP trace timed out".to_string())
}

/// Starts or replaces the active user-space L2TP/IPsec (`IKEv1 + ESPinUDP + L2TPv2 + PPP/IPCP`) session.
pub fn start_userspace_l2tp_with_callbacks(
    server_ip: &str,
    dns_servers: &[String],
    timeout_secs: u64,
    protect_fd: Option<&dyn Fn(i32) -> bool>,
    establish_tun: &mut dyn FnMut(&UserspaceL2tpConfig) -> Result<i32, String>,
) -> Result<UserspaceL2tpConfig, String> {
    stop_userspace_l2tp_sync();
    let st = BridgeState::get();
    let ip: Ipv4Addr = server_ip
        .trim()
        .parse()
        .map_err(|_| format!("Invalid L2TP server IPv4: {server_ip}"))?;

    st.push_event(ProgressEvent::Info(format!(
        "Negotiating user-space IKEv1 + ESP-in-UDP + L2TPv2/PPP with {ip}:4500 ..."
    )));

    let handle =
        spawn_userspace_l2tp_session(ip, dns_servers, timeout_secs, protect_fd, establish_tun)?;
    let cfg = handle.config.clone();
    st.push_event(ProgressEvent::Ok(format!(
        "User-space L2TP/IPsec UP -> {} (ESP {}, MTU {})",
        cfg.assigned_ip, cfg.esp_cipher, cfg.mtu
    )));

    if let Ok(mut guard) = st.l2tp_session.lock() {
        *guard = Some(handle);
    }
    Ok(cfg)
}

/// Returns live traffic & state statistics for the user-space L2TP/IPsec engine.
pub fn get_userspace_l2tp_stats_sync() -> UserspaceL2tpStats {
    if let Ok(guard) = BridgeState::get().l2tp_session.lock()
        && let Some(h) = guard.as_ref()
    {
        return h.stats();
    }
    UserspaceL2tpStats {
        active: false,
        server_ip: String::new(),
        assigned_ip: String::new(),
        esp_cipher: String::new(),
        tx_bytes: 0,
        rx_bytes: 0,
        error: String::new(),
    }
}

/// Stops any active user-space L2TP/IPsec tunnel cleanly (`StopCCN` + `Delete-SA` + close `tun_fd`).
pub fn stop_userspace_l2tp_sync() {
    if let Ok(mut guard) = BridgeState::get().l2tp_session.lock()
        && let Some(mut h) = guard.take()
    {
        h.stop();
    }
}

// --- Preserved async/helper Rust API ---

/// Fetches and sorts the live VPN Gate server pool for Rust callers.
pub async fn fetch_ranked_servers(
    country_filter: Option<String>,
) -> Result<Vec<VpnServer>, String> {
    let client = DiscoveryClient::new(DiscoveryOptions::default()).map_err(|e| e.to_string())?;
    let pool = client.fetch_servers().await.map_err(|e| e.to_string())?;
    let mut filtered = filter_by_country(&pool, country_filter.as_deref());
    sort_servers(&mut filtered, SortBy::Recommended, ProtocolFilter::Auto);
    Ok(filtered)
}

/// Summarizes country counts and protocol availability from a fetched server slice.
pub fn build_country_summaries(servers: Vec<VpnServer>) -> Vec<CountrySummary> {
    summarize_countries(&servers)
}

/// Generates a mobile-ready patched `.ovpn` profile (`MobileCore3` for Android `ics-openvpn` & iOS `Partout`/`OpenVPN3`).
pub fn generate_mobile_ovpn_profile(
    server: VpnServer,
    use_tcp: bool,
    is_ios: bool,
) -> Result<String, String> {
    let opts = OvpnPatchOptions {
        platform: if is_ios {
            TargetPlatform::Ios
        } else {
            TargetPlatform::Android
        },
        compat: OpenVpnCompat::MobileCore3,
        transport: if use_tcp {
            VpnProtocol::OpenVpnTcp
        } else {
            VpnProtocol::OpenVpnUdp
        },
        ..Default::default()
    };
    build_patched_ovpn(&server, &opts).map_err(|e| e.to_string())
}

/// Generates an Apple `.mobileconfig` XML profile for native iOS/macOS L2TP/IPsec (`PSK = "vpn"`).
pub fn generate_apple_l2tp_profile(server: VpnServer) -> String {
    build_apple_l2tp_mobileconfig(&server)
}

/// Runs a 1-RTT IKEv1 Aggressive Mode `PSK == "vpn"` pre-flight check against `ip`.
pub async fn verify_server_l2tp_psk(ip: String) -> Result<L2tpVerifyOutcome, String> {
    let parsed: Ipv4Addr = ip
        .trim()
        .parse()
        .map_err(|_| format!("Invalid IPv4 address: {ip}"))?;
    Ok(verify_l2tp_psk_vpn(parsed, Duration::from_millis(1500), 2, b"vpn").await)
}
