//! Public, anonymous desktop update check.
//!
//! Uses only unauthenticated HTTPS (`raw.githubusercontent.com` and the jsDelivr GitHub CDN).
//! No GitHub API, no `gh`, no tokens, no 2FA.

use std::cmp::Ordering;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cache::{AppPaths, atomic_write_json, now_unix_secs, read_json_opt};
use crate::doh::resolve_ipv4_via_cloudflare_doh;

/// Skip auto-prompt for this long after the user declines a given remote version.
pub const UPDATE_DECLINE_SNOOZE_SECS: u64 = 24 * 3600;
/// Re-use a successful scan for this long on the interactive dashboard.
pub const UPDATE_CACHE_TTL_SECS: u64 = 6 * 3600;

const FETCH_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl DesktopVersion {
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim().trim_start_matches('v').trim();
        let mut it = s.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        let patch = it.next()?.parse().ok()?;
        if it.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    pub fn as_str(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for DesktopVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DesktopVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

impl std::fmt::Display for DesktopVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone)]
pub struct RemoteDesktopVersion {
    pub version: DesktopVersion,
    pub raw: String,
    pub source_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateCheckCache {
    pub checked_at: u64,
    #[serde(default)]
    pub remote_version: String,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub declined_version: String,
    #[serde(default)]
    pub declined_at: u64,
}

pub fn installed_desktop_version() -> DesktopVersion {
    DesktopVersion::parse(env!("CARGO_PKG_VERSION")).unwrap_or(DesktopVersion {
        major: 0,
        minor: 0,
        patch: 0,
    })
}

pub fn default_repo_slug() -> String {
    env::var("VPNGATE_REPO")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| {
            let mut parts = s.split('/');
            matches!(
                (parts.next(), parts.next(), parts.next()),
                (Some(o), Some(r), None)
                    if !o.is_empty()
                        && !r.is_empty()
                        && o.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                        && r.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            )
        })
        .unwrap_or_else(|| "warmaster726/vpngate-connect".to_string())
}

pub fn cargo_toml_check_urls(slug: &str) -> Vec<String> {
    vec![
        format!("https://raw.githubusercontent.com/{slug}/main/Cargo.toml"),
        format!("https://cdn.jsdelivr.net/gh/{slug}@main/Cargo.toml"),
    ]
}

pub fn installer_script_urls(slug: &str) -> Vec<String> {
    if cfg!(windows) {
        vec![
            format!("https://raw.githubusercontent.com/{slug}/main/install-vpngate.ps1"),
            format!("https://cdn.jsdelivr.net/gh/{slug}@main/install-vpngate.ps1"),
        ]
    } else {
        vec![
            format!("https://raw.githubusercontent.com/{slug}/main/install-vpngate.sh"),
            format!("https://cdn.jsdelivr.net/gh/{slug}@main/install-vpngate.sh"),
        ]
    }
}

/// Parse `[workspace.package] version = "x.y.z"` (patch may exceed 9).
pub fn parse_workspace_package_version(toml: &str) -> Option<String> {
    let idx = toml.find("[workspace.package]")?;
    for line in toml[idx..].lines().skip(1) {
        let t = line.trim();
        if t.starts_with('[') {
            break;
        }
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        let Some(rest) = t.strip_prefix("version") else {
            continue;
        };
        let rest = rest.trim().trim_start_matches('=').trim();
        let ver = rest.trim_matches('"').trim_matches('\'').trim();
        if DesktopVersion::parse(ver).is_some() {
            return Some(ver.to_string());
        }
    }
    None
}

fn user_agent() -> String {
    format!(
        "VPNGate-CLI/{} (+https://github.com/warmaster726/vpngate-connect)",
        env!("CARGO_PKG_VERSION")
    )
}

async fn fetch_public_text(url: &str) -> Option<String> {
    let ua = user_agent();
    let client = reqwest::Client::builder()
        .user_agent(&ua)
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .ok()?;
    if let Ok(resp) = client.get(url).send().await
        && resp.status().is_success()
        && let Ok(text) = resp.text().await
        && text.len() > 16
    {
        return Some(text);
    }

    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    let port = parsed.port_or_known_default()?;
    let ips = resolve_ipv4_via_cloudflare_doh(host, Duration::from_secs(4))
        .await
        .ok()?;
    for ip in ips.into_iter().take(2) {
        let Ok(pinned) = reqwest::Client::builder()
            .user_agent(&ua)
            .timeout(FETCH_TIMEOUT)
            .resolve(host, SocketAddr::new(IpAddr::V4(ip), port))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
        else {
            continue;
        };
        if let Ok(resp) = pinned.get(url).send().await
            && resp.status().is_success()
            && let Ok(text) = resp.text().await
            && text.len() > 16
        {
            return Some(text);
        }
    }
    None
}

pub async fn fetch_public_url_text(urls: &[String]) -> Result<(String, String), String> {
    for url in urls {
        if let Some(text) = fetch_public_text(url).await {
            return Ok((text, url.clone()));
        }
    }
    Err(
        "Could not read the public desktop version (raw.githubusercontent.com / jsDelivr). No GitHub login is used."
            .to_string(),
    )
}

pub async fn check_remote_desktop_version() -> Result<RemoteDesktopVersion, String> {
    let slug = default_repo_slug();
    let urls = cargo_toml_check_urls(&slug);
    let (toml, source_url) = fetch_public_url_text(&urls).await?;
    let raw = parse_workspace_package_version(&toml).ok_or_else(|| {
        format!("Public Cargo.toml from {source_url} did not contain [workspace.package] version")
    })?;
    let version = DesktopVersion::parse(&raw).ok_or_else(|| format!("Invalid version '{raw}'"))?;
    Ok(RemoteDesktopVersion {
        version,
        raw,
        source_url,
    })
}

pub fn load_update_cache(paths: &AppPaths) -> Option<UpdateCheckCache> {
    read_json_opt::<UpdateCheckCache>(&paths.update_check)
}

pub fn save_update_cache(paths: &AppPaths, cache: &UpdateCheckCache) {
    let _ = atomic_write_json(&paths.update_check, cache);
}

pub fn record_update_scan(paths: &AppPaths, remote: &RemoteDesktopVersion) -> UpdateCheckCache {
    let mut cache = load_update_cache(paths).unwrap_or_default();
    cache.checked_at = now_unix_secs();
    cache.remote_version = remote.raw.clone();
    cache.source_url = remote.source_url.clone();
    save_update_cache(paths, &cache);
    cache
}

pub fn record_update_declined(paths: &AppPaths, remote: &RemoteDesktopVersion) {
    let mut cache = load_update_cache(paths).unwrap_or_default();
    cache.declined_version = remote.raw.clone();
    cache.declined_at = now_unix_secs();
    cache.checked_at = now_unix_secs();
    cache.remote_version = remote.raw.clone();
    cache.source_url = remote.source_url.clone();
    save_update_cache(paths, &cache);
}

pub fn cache_is_fresh(cache: &UpdateCheckCache) -> bool {
    now_unix_secs().saturating_sub(cache.checked_at) < UPDATE_CACHE_TTL_SECS
}

/// Auto-prompt on the dashboard unless this remote version was declined recently.
pub fn should_auto_prompt(cache: &UpdateCheckCache, remote: &DesktopVersion) -> bool {
    if cache.declined_version != remote.as_str() {
        return true;
    }
    now_unix_secs().saturating_sub(cache.declined_at) >= UPDATE_DECLINE_SNOOZE_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_may_exceed_nine() {
        let a = DesktopVersion::parse("0.2.9").unwrap();
        let b = DesktopVersion::parse("0.2.10").unwrap();
        let c = DesktopVersion::parse("0.2.17").unwrap();
        assert!(a < b);
        assert!(b < c);
        assert!(c > a);
    }

    #[test]
    fn parses_workspace_package_version() {
        let toml = r#"
[workspace]
resolver = "2"

[workspace.package]
# Product version for the desktop crates. Patch may exceed 9 (0.2.10, 0.2.15, …).
version = "0.2.18"
edition = "2024"
"#;
        assert_eq!(
            parse_workspace_package_version(toml).as_deref(),
            Some("0.2.18")
        );
    }
}
