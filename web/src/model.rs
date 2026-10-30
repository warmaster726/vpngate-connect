use serde::{Deserialize, Serialize};

pub const APP_VERSION: &str = "0.3.4";
pub const POOL_CACHE_TTL_MS: u64 = 180_000;
pub const POOL_CACHE_KEY_URL: &str = "https://vpngate-edge-cache.internal/v1/pool-snapshot";
pub const VERIFY_MEM_CACHE_URL: &str = "https://vpngate-edge-cache.internal/v1/verify-memory";
pub const VERIFY_IP_CACHE_PREFIX: &str = "https://vpngate-edge-cache.internal/v1/verify-ip/";
pub const HANDSHAKE_TIMEOUT_MS: u64 = 17_600;
pub const DEAD_PENALTY_MS: u64 = 15 * 60 * 1000;
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) VPNGate-WebWorker/0.3";
pub const MAX_OFFICIAL_MIRROR_CSV: usize = 12;
pub const VERIFY_OK_TTL_MS: u64 = 180_000;
pub const VERIFY_FAIL_TTL_MS: u64 = DEAD_PENALTY_MS;

pub const OFFICIAL_CSV_URLS: &[&str] = &[
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
];
pub const OFFICIAL_HTML_URLS: &[&str] = &[
    "https://www.vpngate.net/en/",
    "http://www.vpngate.net/en/",
];
pub const OFFICIAL_MIRROR_SITES_URLS: &[&str] = &[
    "https://www.vpngate.net/en/sites.aspx",
    "http://www.vpngate.net/en/sites.aspx",
    "https://www.vpngate.net/ja/sites.aspx",
    "https://www.vpngate.net/cn/sites.aspx",
];
pub const DAILY_MIRROR_JSON_URLS: &[&str] = &[
    "https://cdn.jsdelivr.net/gh/kusrabyzarc/vpngate-daily-mirrors@latest/mirrors.json",
    "https://raw.githubusercontent.com/kusrabyzarc/vpngate-daily-mirrors/main/mirrors.json",
];
pub const WAYBACK_MIRROR_SITES_CDX_URL: &str =
    "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/sites.aspx&output=json&limit=-2&filter=statuscode:200&collapse=timestamp:8";
pub const WAYBACK_PORTAL_CDX_URLS: &[&str] = &[
    "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/en/&output=json&limit=-6&filter=statuscode:200&collapse=timestamp:8",
    "https://web.archive.org/cdx/search/cdx?url=www.vpngate.net/ja/&output=json&limit=-4&filter=statuscode:200&collapse=timestamp:8",
];
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub hostname: String,
    pub ip: String,
    pub score: u64,
    pub ping_ms: u64,
    pub speed_bps: u64,
    pub country_long: String,
    pub country_short: String,
    pub sessions: u64,
    pub uptime_ms: u64,
    pub operator: String,
    pub l2tp: bool,
    pub openvpn: bool,
    pub tcp_port: u16,
    pub udp_port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ovpn_b64: String,
    #[serde(default)]
    pub has_ovpn_cert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_rtt_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlocked: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locked: Vec<LockedKind>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dead_until: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedKind {
    pub kind: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mirror {
    pub base_url: String,
    pub portal_url: String,
    pub location: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountrySummary {
    pub country_short: String,
    pub country_long: String,
    pub total_servers: u64,
    pub l2tp_count: u64,
    pub openvpn_udp_count: u64,
    pub openvpn_tcp_count: u64,
    pub max_speed_bps: u64,
    pub best_ping_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub level: String,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counts {
    pub total: usize,
    pub l2tp: usize,
    pub openvpn: usize,
    pub countries: usize,
    pub mirrors: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicPayload {
    pub ok: bool,
    pub version: String,
    pub generated_at: u64,
    pub counts: Counts,
    pub logs: Vec<LogLine>,
    pub countries: Vec<CountrySummary>,
    pub servers: Vec<Server>,
    pub mirrors: Vec<Mirror>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSnapshot {
    pub generated_at: u64,
    pub donor_ovpn_b64: String,
    pub ovpn_by_ip: serde_json::Map<String, serde_json::Value>,
    pub public_payload: PublicPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerifyRec {
    pub ok: bool,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub tcp_handshake: bool,
    #[serde(default)]
    pub host_up: bool,
    #[serde(default)]
    pub tcp_open: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlocked: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locked: Vec<LockedKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub ts: u64,
}

impl Server {
    pub fn has_ovpn_cert(&self) -> bool {
        self.has_ovpn_cert || self.ovpn_b64.len() > 40
    }

    pub fn supports_openvpn_udp(&self) -> bool {
        self.openvpn && (self.udp_port > 0 || (self.has_ovpn_cert() && self.tcp_port == 0))
    }

    pub fn supports_openvpn_tcp(&self) -> bool {
        self.openvpn && (self.tcp_port > 0 || (self.has_ovpn_cert() && self.udp_port == 0))
    }
}
