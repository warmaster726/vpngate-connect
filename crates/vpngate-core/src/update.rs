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
use crate::doh::resolve_ipv4_via_doh;
use crate::edge::{edge_path_urls, is_edge_url};

/// Skip auto-prompt for this long after the user declines a given remote version.
pub const UPDATE_DECLINE_SNOOZE_SECS: u64 = 24 * 3600;
/// Re-use a successful scan for this long on the interactive dashboard.
pub const UPDATE_CACHE_TTL_SECS: u64 = 6 * 3600;

const FETCH_TIMEOUT: Duration = Duration::from_secs(12);
const GITHUB_CHECK_TIMEOUT: Duration = Duration::from_secs(12);
const CDN_CHECK_TIMEOUT: Duration = Duration::from_secs(8);

/// Public desktop label. Cargo crate version stays SemVer (`0.3.5`); a trailing
/// letter (`0.3.5a`) would be a revision *after* that patch, used for update prompts.
pub const PRODUCT_VERSION: &str = "0.3.5";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DesktopVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// `0` = plain `x.y.z`; `b'a'`..=`b'z'` = `x.y.za` (newer than `x.y.z`).
    pub letter: u8,
}

impl DesktopVersion {
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim().trim_start_matches('v').trim();
        let mut it = s.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        let patch_raw = it.next()?;
        if it.next().is_some() {
            return None;
        }
        let (patch, letter) = parse_patch_and_letter(patch_raw)?;
        Some(Self {
            major,
            minor,
            patch,
            letter,
        })
    }

    pub fn as_str(&self) -> String {
        self.to_string()
    }
}

fn parse_patch_and_letter(raw: &str) -> Option<(u64, u8)> {
    let digits = raw
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit())
        .last()
        .map(|(i, _)| i + 1)
        .unwrap_or(0);
    if digits == 0 {
        return None;
    }
    let patch: u64 = raw[..digits].parse().ok()?;
    let rest = raw[digits..].strip_prefix('-').unwrap_or(&raw[digits..]);
    if rest.is_empty() {
        return Some((patch, 0));
    }
    let mut chars = rest.chars();
    let c = chars.next()?;
    if chars.next().is_some() || !c.is_ascii_alphabetic() {
        return None;
    }
    Some((patch, c.to_ascii_lowercase() as u8))
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
            .then(self.letter.cmp(&other.letter))
    }
}

impl std::fmt::Display for DesktopVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if self.letter != 0 {
            write!(f, "{}", self.letter as char)?;
        }
        Ok(())
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
    DesktopVersion::parse(PRODUCT_VERSION)
        .or_else(|| DesktopVersion::parse(env!("CARGO_PKG_VERSION")))
        .unwrap_or_default()
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

pub fn is_github_version_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.contains("raw.githubusercontent.com/") || (u.contains("github.com/") && u.contains("/raw/"))
}

/// Anonymous HTTPS endpoints only (no GitHub API, no tokens, no 2FA).
/// GitHub raw is authoritative; the Cloudflare Worker then jsDelivr/Fastly are fallbacks.
pub fn version_check_urls(slug: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for file in ["assets/desktop-version.txt", "Cargo.toml"] {
        urls.push(format!(
            "https://raw.githubusercontent.com/{slug}/main/{file}"
        ));
        urls.push(format!(
            "https://raw.githubusercontent.com/{slug}/refs/heads/main/{file}"
        ));
        urls.push(format!("https://github.com/{slug}/raw/main/{file}"));
    }
    urls.extend(edge_path_urls("/desktop-version.txt"));
    for file in ["assets/desktop-version.txt", "Cargo.toml"] {
        urls.push(format!("https://cdn.jsdelivr.net/gh/{slug}@main/{file}"));
        urls.push(format!("https://fastly.jsdelivr.net/gh/{slug}@main/{file}"));
    }
    urls
}

fn push_unique(urls: &mut Vec<String>, url: String) {
    if !urls.iter().any(|u| u == &url) {
        urls.push(url);
    }
}

/// Worker-first, then jsDelivr, then GitHub raw (installer fetch when GitHub is blocked).
pub fn installer_script_urls(slug: &str) -> Vec<String> {
    let mut urls = Vec::new();
    if cfg!(windows) {
        for path in ["/install.ps1", "/install-vpngate.ps1"] {
            for u in edge_path_urls(path) {
                push_unique(&mut urls, u);
            }
        }
        push_unique(
            &mut urls,
            format!("https://cdn.jsdelivr.net/gh/{slug}@main/install-vpngate.ps1"),
        );
        push_unique(
            &mut urls,
            format!("https://fastly.jsdelivr.net/gh/{slug}@main/install-vpngate.ps1"),
        );
        push_unique(
            &mut urls,
            format!("https://raw.githubusercontent.com/{slug}/main/install-vpngate.ps1"),
        );
    } else {
        for path in ["/install.sh", "/install-vpngate.sh"] {
            for u in edge_path_urls(path) {
                push_unique(&mut urls, u);
            }
        }
        push_unique(
            &mut urls,
            format!("https://cdn.jsdelivr.net/gh/{slug}@main/install-vpngate.sh"),
        );
        push_unique(
            &mut urls,
            format!("https://fastly.jsdelivr.net/gh/{slug}@main/install-vpngate.sh"),
        );
        push_unique(
            &mut urls,
            format!("https://raw.githubusercontent.com/{slug}/main/install-vpngate.sh"),
        );
    }
    urls
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
    let ips = resolve_ipv4_via_doh(&host, Duration::from_secs(4))
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

/// Keep the highest SemVer. Used for CDN fallbacks that may be stale relative to each other.
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
        if best.as_ref().is_none_or(|b| cand.version > b.version) {
            best = Some(cand);
        }
    }
    best
}

async fn first_parsed_version(urls: &[String], timeout: Duration) -> Option<RemoteDesktopVersion> {
    let mut set = tokio::task::JoinSet::new();
    for url in urls.iter().cloned() {
        set.spawn(async move {
            let text = fetch_public_text(&url).await?;
            let raw = parse_version_payload(&text)?;
            let version = DesktopVersion::parse(&raw)?;
            Some(RemoteDesktopVersion {
                version,
                raw,
                source_url: url,
            })
        });
    }
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return None,
            joined = set.join_next() => {
                match joined {
                    Some(Ok(Some(remote))) => return Some(remote),
                    Some(_) => continue,
                    None => return None,
                }
            }
        }
    }
}

async fn collect_public_versions(urls: &[String], timeout: Duration) -> Vec<(String, String)> {
    let mut set = tokio::task::JoinSet::new();
    for url in urls.iter().cloned() {
        set.spawn(async move {
            let text = fetch_public_text(&url).await?;
            let raw = parse_version_payload(&text)?;
            Some((raw, url))
        });
    }
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut hits = Vec::new();
    loop {
        if set.is_empty() {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            joined = set.join_next() => {
                match joined {
                    Some(Ok(Some(pair))) => hits.push(pair),
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
    let github: Vec<String> = urls
        .iter()
        .cloned()
        .filter(|u| is_github_version_url(u))
        .collect();
    let edge: Vec<String> = urls
        .iter()
        .cloned()
        .filter(|u| is_edge_url(u) && !is_github_version_url(u))
        .collect();
    let cdn: Vec<String> = urls
        .iter()
        .cloned()
        .filter(|u| !is_github_version_url(u) && !is_edge_url(u))
        .collect();

    // GitHub raw is the source of truth for public main. Do not let a stale
    // jsDelivr/Fastly copy (still on 0.2.20) win a race against 0.3.x.
    if let Some(remote) = first_parsed_version(&github, GITHUB_CHECK_TIMEOUT).await {
        return Ok(remote);
    }
    if let Some(remote) = first_parsed_version(&edge, CDN_CHECK_TIMEOUT).await {
        return Ok(remote);
    }
    let hits = collect_public_versions(&cdn, CDN_CHECK_TIMEOUT).await;
    pick_highest_version(&hits).ok_or_else(|| {
        "Could not read the public desktop version (GitHub raw / Cloudflare Worker / jsDelivr). No GitHub login is used."
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
    fn letter_revision_is_newer_than_the_plain_patch() {
        let plain = DesktopVersion::parse("0.3.4").unwrap();
        let a = DesktopVersion::parse("0.3.4a").unwrap();
        let a2 = DesktopVersion::parse("v0.3.4a").unwrap();
        let b = DesktopVersion::parse("0.3.4b").unwrap();
        let next = DesktopVersion::parse("0.3.5").unwrap();
        assert!(plain < a);
        assert_eq!(a, a2);
        assert!(a < b);
        assert!(a < next);
        assert_eq!(a.to_string(), "0.3.4a");
        assert_eq!(plain.to_string(), "0.3.4");
        assert_eq!(parse_version_payload("0.3.4a\n").as_deref(), Some("0.3.4a"));
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
        assert_eq!(parse_version_payload("0.2.20\n").as_deref(), Some("0.2.20"));
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
        assert!(is_github_version_url(
            "https://raw.githubusercontent.com/warmaster726/vpngate-connect/main/Cargo.toml"
        ));
        assert!(is_github_version_url(
            "https://github.com/warmaster726/vpngate-connect/raw/main/assets/desktop-version.txt"
        ));
        assert!(!is_github_version_url(
            "https://cdn.jsdelivr.net/gh/warmaster726/vpngate-connect@main/Cargo.toml"
        ));
        let github: Vec<_> = urls.iter().filter(|u| is_github_version_url(u)).collect();
        let cdn: Vec<_> = urls.iter().filter(|u| !is_github_version_url(u)).collect();
        assert!(!github.is_empty());
        assert!(!cdn.is_empty());
        assert!(github.iter().all(|u| !u.contains("jsdelivr")));
    }
}
