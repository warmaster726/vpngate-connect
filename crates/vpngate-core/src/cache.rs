use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cooldown::CooldownStore;
use crate::discovery::{DiscoveryClient, DiscoveryOptions, ProgressEvent};
use crate::error::Result;
use crate::parser::OfficialMirrorSite;
use crate::server::VpnServer;

pub const CACHE_TTL_SECONDS: u64 = 600;
pub const MONITOR_INTERVAL_SECONDS: u64 = 15;

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Resolves the real interactive user's home directory even when invoked via `sudo`.
pub fn resolve_user_home() -> PathBuf {
    #[cfg(unix)]
    {
        if let Ok(sudo_user) = env::var("SUDO_USER") {
            let trimmed = sudo_user.trim();
            if !trimmed.is_empty()
                && trimmed != "root"
                && let Ok(passwd) = fs::read_to_string("/etc/passwd")
            {
                for line in passwd.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 6 && parts[0] == trimmed && !parts[5].is_empty() {
                        return PathBuf::from(parts[5]);
                    }
                }
            }
        }
        if let Ok(home) = env::var("HOME")
            && !home.trim().is_empty()
        {
            return PathBuf::from(home);
        }
        PathBuf::from("/tmp")
    }
    #[cfg(windows)]
    {
        if let Ok(up) = env::var("USERPROFILE")
            && !up.trim().is_empty()
        {
            return PathBuf::from(up);
        }
        PathBuf::from(r"C:\Users\Public")
    }
}

/// Restores ownership of files written under `sudo` back to `SUDO_UID:SUDO_GID`.
pub fn fix_owner(path: &Path) {
    #[cfg(unix)]
    {
        if let (Ok(uid_s), Ok(gid_s)) = (env::var("SUDO_UID"), env::var("SUDO_GID"))
            && let (Ok(uid), Ok(gid)) = (uid_s.parse::<u32>(), gid_s.parse::<u32>())
            && let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        {
            // SAFETY: `c_path` is a valid NUL-terminated path buffer.
            unsafe {
                let _ = libc::chown(c_path.as_ptr(), uid, gid);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Canonical workspace/runtime file layout matching Python `v5.3`.
#[derive(Debug, Clone)]
pub struct AppPaths {
    pub cache_dir: PathBuf,
    pub servers_cache: PathBuf,
    pub mirrors_cache: PathBuf,
    pub failed_servers: PathBuf,
    pub active_state: PathBuf,
    pub watchdog_pref: PathBuf,
    pub ikev1_state: PathBuf,
    pub ikev1_pid: PathBuf,
    pub ovpn_pid: PathBuf,
    pub monitor_pid: PathBuf,
    pub monitor_log: PathBuf,
    pub sysctl_backup: PathBuf,
    pub l2tp_route: PathBuf,
    pub l2tp_resolv_bak: PathBuf,
    pub l2tp_run_dir: PathBuf,
}

impl AppPaths {
    pub fn resolve() -> Self {
        let cache_dir = if let Ok(override_dir) = env::var("VPNGATE_CACHE_DIR")
            && !override_dir.trim().is_empty()
        {
            PathBuf::from(override_dir)
        } else if cfg!(target_os = "windows") {
            env::var("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|_| resolve_user_home().join("AppData").join("Local"))
                .join("vpngate")
        } else if cfg!(target_os = "macos") {
            resolve_user_home()
                .join("Library")
                .join("Caches")
                .join("vpngate")
        } else {
            resolve_user_home().join(".cache").join("vpngate")
        };

        let l2tp_run_dir = if cfg!(target_os = "linux") {
            PathBuf::from("/run/vpngate-l2tp")
        } else {
            cache_dir.join("l2tp-run")
        };

        Self {
            servers_cache: cache_dir.join("servers_cache.json"),
            mirrors_cache: cache_dir.join("mirrors_cache.json"),
            failed_servers: cache_dir.join("failed_servers.json"),
            active_state: cache_dir.join("active_state.json"),
            watchdog_pref: cache_dir.join("watchdog_pref.json"),
            ikev1_state: cache_dir.join("ikev1_state.json"),
            ikev1_pid: cache_dir.join("ikev1.pid"),
            ovpn_pid: cache_dir.join("openvpn.pid"),
            monitor_pid: cache_dir.join("monitor.pid"),
            monitor_log: cache_dir.join("monitor.log"),
            sysctl_backup: cache_dir.join("sysctl_backup.json"),
            l2tp_route: cache_dir.join("l2tp_route.json"),
            l2tp_resolv_bak: cache_dir.join("resolv.conf.bak"),
            l2tp_run_dir,
            cache_dir,
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.cache_dir)?;
        fix_owner(&self.cache_dir);
        Ok(())
    }
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        fix_owner(parent);
    }
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_string_pretty(value)?;
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    fix_owner(path);
    Ok(())
}

pub fn read_json_opt<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCacheFile {
    pub timestamp: u64,
    pub servers: Vec<VpnServer>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MirrorCacheFile {
    pub timestamp: u64,
    pub mirrors: Vec<OfficialMirrorSite>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchdogPrefFile {
    pub enabled: bool,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSessionState {
    pub status: String,
    pub profile_name: String,
    pub protocol: String,
    pub backend: String,
    pub device: String,
    pub hostname: String,
    pub server_ip: String,
    pub egress_ip: String,
    pub egress_loc: String,
    pub pre_vpn_ip: String,
    pub country_short: String,
    pub country_long: String,
    pub region_label: String,
    pub proto_choice: String,
    pub sort_key: String,
    pub engine: String,
    pub dns: String,
    pub timeout: u64,
    pub auto_reconnect: bool,
    pub connected_at: u64,
    #[serde(default)]
    pub last_drop_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ikev1StateInfo {
    pub status: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub local_ip: String,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default)]
    pub server_ip: String,
    #[serde(default)]
    pub p1_alg: String,
    #[serde(default)]
    pub esp_alg: String,
    #[serde(default)]
    pub spi_in: String,
    #[serde(default)]
    pub spi_out: String,
    #[serde(default)]
    pub established_at: u64,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIpTrace {
    pub ip: String,
    pub loc: String,
}

pub fn load_watchdog_pref(paths: &AppPaths) -> bool {
    read_json_opt::<WatchdogPrefFile>(&paths.watchdog_pref)
        .map(|p| p.enabled)
        .unwrap_or(false)
}

pub fn save_watchdog_pref(paths: &AppPaths, enabled: bool) -> Result<()> {
    let payload = WatchdogPrefFile {
        enabled,
        updated_at: now_unix_secs(),
    };
    atomic_write_json(&paths.watchdog_pref, &payload)
}

pub fn load_cooldowns(paths: &AppPaths) -> CooldownStore {
    CooldownStore::load_from_path(&paths.failed_servers).unwrap_or_default()
}

pub fn save_cooldowns(paths: &AppPaths, store: &mut CooldownStore) {
    let _ = store.save_to_path(&paths.failed_servers);
    fix_owner(&paths.failed_servers);
}

pub fn load_cached_mirrors(paths: &AppPaths) -> Vec<OfficialMirrorSite> {
    read_json_opt::<MirrorCacheFile>(&paths.mirrors_cache)
        .map(|f| f.mirrors)
        .unwrap_or_default()
}

pub fn save_cached_mirrors(paths: &AppPaths, mirrors: &[OfficialMirrorSite]) {
    if mirrors.is_empty() {
        return;
    }
    let payload = MirrorCacheFile {
        timestamp: now_unix_secs(),
        mirrors: mirrors.to_vec(),
    };
    let _ = atomic_write_json(&paths.mirrors_cache, &payload);
}

///Silent convenience wrapper around `get_servers_cached_with_progress`.
pub async fn get_servers_cached(paths: &AppPaths, force_refresh: bool) -> Result<Vec<VpnServer>> {
    get_servers_cached_with_progress(paths, force_refresh, &[], |_| {}).await
}

/// Returns cached server pool when fresher than `CACHE_TTL_SECONDS` (`10m`), or fetches live
/// with step-by-step `ProgressEvent` reporting and persists both servers & Official Mirror Sites.
pub async fn get_servers_cached_with_progress(
    paths: &AppPaths,
    force_refresh: bool,
    extra_mirrors: &[OfficialMirrorSite],
    mut on_progress: impl FnMut(ProgressEvent),
) -> Result<Vec<VpnServer>> {
    paths.ensure_dirs()?;
    let now = now_unix_secs();

    if !force_refresh
        && extra_mirrors.is_empty()
        && let Some(cached) = read_json_opt::<ServerCacheFile>(&paths.servers_cache)
        && !cached.servers.is_empty()
        && now.saturating_sub(cached.timestamp) < CACHE_TTL_SECONDS
    {
        return Ok(cached.servers);
    }

    let mut seeds = extra_mirrors.to_vec();
    for mut m in load_cached_mirrors(paths) {
        if m.source == "sites.aspx" {
            m.source = "cached".to_string();
        }
        if !seeds.iter().any(|x| x.base_url == m.base_url) {
            seeds.push(m);
        }
    }

    let opts = DiscoveryOptions {
        seed_mirrors: seeds,
        ..DiscoveryOptions::default()
    };
    let client = DiscoveryClient::new(opts)?;

    match client.fetch_servers_with_progress(&mut on_progress).await {
        Ok(outcome) if !outcome.servers.is_empty() => {
            if !outcome.official_mirrors.is_empty() {
                save_cached_mirrors(paths, &outcome.official_mirrors);
            }
            let file_obj = ServerCacheFile {
                timestamp: now,
                servers: outcome.servers.clone(),
            };
            let _ = atomic_write_json(&paths.servers_cache, &file_obj);
            Ok(outcome.servers)
        }
        Ok(_) => Err(crate::error::CoreError::NoMatchingServers),
        Err(e) => {
            if !force_refresh
                && let Some(stale) = read_json_opt::<ServerCacheFile>(&paths.servers_cache)
                && !stale.servers.is_empty()
            {
                on_progress(ProgressEvent::Warn(format!(
                    "Live refresh failed ({e}); falling back to cached server pool ({} servers).",
                    stale.servers.len()
                )));
                return Ok(stale.servers);
            }
            Err(e)
        }
    }
}

/// Queries public IPv4 egress IP & Cloudflare POP country code (`1.1.1.1/cdn-cgi/trace` -> fallbacks).
pub async fn get_public_ip_trace(timeout: Duration) -> Option<PublicIpTrace> {
    let client = reqwest::Client::builder().timeout(timeout).build().ok()?;

    for url in [
        "https://1.1.1.1/cdn-cgi/trace",
        "https://1.0.0.1/cdn-cgi/trace",
    ] {
        if let Ok(resp) = client.get(url).send().await
            && let Ok(text) = resp.text().await
        {
            let mut ip = String::new();
            let mut loc = String::new();
            for line in text.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    match k.trim() {
                        "ip" => ip = v.trim().to_string(),
                        "loc" => loc = v.trim().to_string(),
                        _ => {}
                    }
                }
            }
            if !ip.is_empty() {
                return Some(PublicIpTrace { ip, loc });
            }
        }
    }

    if let Ok(resp) = client.get("http://checkip.amazonaws.com").send().await
        && let Ok(text) = resp.text().await
    {
        let cand = text.trim();
        if cand.parse::<std::net::Ipv4Addr>().is_ok() {
            return Some(PublicIpTrace {
                ip: cand.to_string(),
                loc: "??".to_string(),
            });
        }
    }

    None
}
