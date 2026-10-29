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

const FETCH_TIMEOUT: Duration = Duration::from_secs(12);
const OVERALL_CHECK_TIMEOUT: Duration = Duration::from_secs(20);

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
    #[serde(default)]
    pub last_error: String,
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
    version_check_urls(slug)
        .into_iter()
        .filter(|u| u.ends_with("Cargo.toml"))
        .collect()
}

/// Anonymous HTTPS endpoints only (no GitHub API, no tokens, no 2FA).
pub fn version_check_urls(slug: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for file in ["assets/desktop-version.txt", "Cargo.toml"] {
        urls.push(format!(
            "https://raw.githubusercontent.com/{slug}/main/{file}"
        ));
        urls.push(format!(
            "https://raw.githubusercontent.com/{slug}/refs/heads/main/{file}"
        ));
        urls.push(format!("https://cdn.jsdelivr.net/gh/{slug}@main/{file}"));
        urls.push(format!(
            "https://fastly.jsdelivr.net/gh/{slug}@main/{file}"
        ));
        urls.push(format!(
            "https://github.com/{slug}/raw/main/{file}"
        ));
    }
    urls
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

/// Parse a tiny `desktop-version.txt` (`0.2.20`) or `[workspace.package] version`.
pub fn parse_version_payload(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || looks_like_html(trimmed) {
        return None;
    }
    if let Some(line) = trimmed.lines().next() {
        let line = line.trim().trim_start_matches('v');
        if DesktopVersion::parse(line).is_some() {
            return Some(line.to_string());
        }
    }
    parse_workspace_package_version(text)
}

fn looks_like_html(text: &str) -> bool {
    let t = text.trim_start().to_ascii_lowercase();
    t.starts_with("<!doctype") || t.starts_with("<html") || t.starts_with("<head")
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

fn user_agents() -> [String; 2] {
    [
        format!(
            "VPNGate-CLI/{} (+https://github.com/warmaster726/vpngate-connect)",
            env!("CARGO_PKG_VERSION")
        ),
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
    ]
}

fn acceptable_body(text: &str) -> bool {
    let t = text.trim();
    t.len() >= 5 && !looks_like_html(t)
}

async fn send_get(
    url: &str,
    ua: &str,
    http1_only: bool,
    pinned: Option<(String, SocketAddr)>,
) -> Option<String> {
    let mut builder = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(5));
    if http1_only {
        builder = builder.http1_only();
    }
    if let Some((host, addr)) = pinned {
        builder = builder.resolve(&host, addr);
    }
    let client = builder.build().ok()?;
    let resp = client
        .get(url)
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    if acceptable_body(&text) {
        Some(text)
    } else {
        None
    }
}

async fn fetch_public_text(url: &str) -> Option<String> {
    for ua in user_agents() {
        for http1 in [false, true] {
            if let Some(text) = send_get(url, &ua, http1, None).await {
                return Some(text);
            }
        }
    }

    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    let port = parsed.port_or_known_default()?;
    let ips = resolve_ipv4_via_cloudflare_doh(&host, Duration::from_secs(4))
        .await
        .ok()?;
    let ua = user_agents()[0].clone();
    for ip in ips.into_iter().take(2) {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        if let Some(text) = send_get(url, &ua, true, Some((host.clone(), addr))).await {
            return Some(text);
        }
    }
    None
}

/// Prefer URL order (GitHub raw first). Do not race CDNs for installer bodies.
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

/// Keep the highest SemVer. A stale CDN (jsDelivr still on 0.2.20) must not hide GitHub 0.3.x.
pub fn pick_highest_version(hits: &[(String, String)]) -> Option<RemoteDesktopVersion> {
    let mut best: Option<RemoteDesktopVersion> = None;
    for (raw, source_url) in hits {
        let Some(version) = DesktopVersion::parse(raw) else {
            continue;
        };
        let cand = RemoteDesktopVersion {
            version,
            raw: raw.clone(),
            source_url: source_url.clone(),
        };
        if best
            .as_ref()
            .is_none_or(|b| cand.version > b.version)
        {
            best = Some(cand);
        }
    }
    best
}

const VERSION_GRACE_AFTER_FIRST: Duration = Duration::from_secs(3);

async fn collect_public_versions(urls: &[String]) -> Vec<(String, String)> {
    let mut set = tokio::task::JoinSet::new();
    for url in urls.iter().cloned() {
        set.spawn(async move {
            let text = fetch_public_text(&url).await?;
            let raw = parse_version_payload(&text)?;
            Some((raw, url))
        });
    }
    let overall = tokio::time::sleep(OVERALL_CHECK_TIMEOUT);
    tokio::pin!(overall);
    let grace = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(grace);
    let mut grace_armed = false;
    let mut hits = Vec::new();
    loop {
        if set.is_empty() {
            break;
        }
        tokio::select! {
            _ = &mut overall => break,
            _ = &mut grace, if grace_armed => break,
            joined = set.join_next() => {
                match joined {
                    Some(Ok(Some(pair))) => {
                        hits.push(pair);
                        if !grace_armed {
                            grace.as_mut().reset(
                                tokio::time::Instant::now() + VERSION_GRACE_AFTER_FIRST,
                            );
                            grace_armed = true;
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        }
    }
    hits
}

pub async fn check_remote_desktop_version() -> Result<RemoteDesktopVersion, String> {
    let slug = default_repo_slug();
    let urls = version_check_urls(&slug);
    let hits = collect_public_versions(&urls).await;
    pick_highest_version(&hits).ok_or_else(|| {
        "Could not read the public desktop version (raw.githubusercontent.com / jsDelivr). No GitHub login is used."
            .to_string()
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
    cache.last_error.clear();
    save_update_cache(paths, &cache);
    cache
}

pub fn record_update_failure(paths: &AppPaths, error: &str) {
    let mut cache = load_update_cache(paths).unwrap_or_default();
    cache.checked_at = now_unix_secs();
    cache.last_error = error.to_string();
    save_update_cache(paths, &cache);
}

pub fn cached_remote_version(cache: &UpdateCheckCache) -> Option<RemoteDesktopVersion> {
    let version = DesktopVersion::parse(&cache.remote_version)?;
    Some(RemoteDesktopVersion {
        version,
        raw: cache.remote_version.clone(),
        source_url: cache.source_url.clone(),
    })
}

pub fn cached_newer_than_installed(cache: &UpdateCheckCache) -> Option<RemoteDesktopVersion> {
    let remote = cached_remote_version(cache)?;
    if remote.version > installed_desktop_version() {
        Some(remote)
    } else {
        None
    }
}

/// Live-scan unless a successful result is still within the TTL.
pub async fn refresh_update_cache(
    paths: &AppPaths,
    force: bool,
) -> Result<RemoteDesktopVersion, String> {
    if !force && let Some(cache) = load_update_cache(paths) {
        let age = now_unix_secs().saturating_sub(cache.checked_at);
        let usable = cache.last_error.is_empty() && cache_is_fresh(&cache);
        let retry_failed = !cache.last_error.is_empty() && age < 30;
        if usable {
            if let Some(remote) = cached_remote_version(&cache) {
                return Ok(remote);
            }
        } else if retry_failed {
            return Err(cache.last_error);
        }
    }
    match check_remote_desktop_version().await {
        Ok(remote) => {
            record_update_scan(paths, &remote);
            Ok(remote)
        }
        Err(err) => {
            record_update_failure(paths, &err);
            Err(err)
        }
    }
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
        let d = DesktopVersion::parse("0.2.20").unwrap();
        let e = DesktopVersion::parse("0.3.0").unwrap();
        assert!(a < b);
        assert!(b < c);
        assert!(c > a);
        assert!(e > d);
        assert!(d > c);
    }

    #[test]
    fn highest_version_ignores_stale_cdn_hits() {
        let hits = vec![
            (
                "0.2.20".to_string(),
                "https://cdn.jsdelivr.net/gh/example@main/assets/desktop-version.txt".to_string(),
            ),
            (
                "0.2.19".to_string(),
                "https://cdn.jsdelivr.net/gh/example@main/Cargo.toml".to_string(),
            ),
            (
                "0.3.0".to_string(),
                "https://raw.githubusercontent.com/example/main/assets/desktop-version.txt"
                    .to_string(),
            ),
        ];
        let best = pick_highest_version(&hits).unwrap();
        assert_eq!(best.raw, "0.3.0");
        assert!(best.source_url.contains("raw.githubusercontent.com"));
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
        assert_eq!(
            parse_version_payload("0.2.20\n").as_deref(),
            Some("0.2.20")
        );
        assert!(parse_version_payload("<html>404</html>").is_none());
        assert!(parse_version_payload("<!DOCTYPE html>").is_none());
    }

    #[test]
    fn version_urls_include_plain_text_and_cargo_toml() {
        let urls = version_check_urls("warmaster726/vpngate-connect");
        assert!(
            urls.iter()
                .any(|u| u.ends_with("/assets/desktop-version.txt"))
        );
        assert!(urls.iter().any(|u| u.ends_with("/Cargo.toml")));
        assert!(
            urls.iter()
                .any(|u| u.contains("raw.githubusercontent.com") && u.contains("/main/"))
        );
        assert!(urls.iter().any(|u| u.contains("cdn.jsdelivr.net")));
        assert!(urls.iter().any(|u| u.contains("fastly.jsdelivr.net")));
    }
}
