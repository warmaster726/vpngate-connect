use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::protocol::VpnProtocol;

/// Default cooldown window (30 minutes) applied to failed `(ip, protocol)` pairs.
pub const DEFAULT_COOLDOWN_SECS: u64 = 1800;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Persistent + in-memory failure penalty store shared by Desktop and Mobile runtimes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CooldownStore {
    entries: BTreeMap<String, u64>,
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
}

const fn default_ttl() -> u64 {
    DEFAULT_COOLDOWN_SECS
}

impl CooldownStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            ttl_secs,
        }
    }

    fn key(ip: &str, proto: VpnProtocol) -> String {
        format!("{}:{}", ip.trim(), proto.cooldown_bucket())
    }

    pub fn mark_failed(&mut self, ip: &str, proto: VpnProtocol) {
        self.mark_failed_at(ip, proto, now_unix_secs());
    }

    pub fn mark_failed_at(&mut self, ip: &str, proto: VpnProtocol, unix_secs: u64) {
        self.entries.insert(Self::key(ip, proto), unix_secs);
    }

    pub fn clear_server(&mut self, ip: &str) {
        let prefix = format!("{}:", ip.trim());
        self.entries.retain(|k, _| !k.starts_with(&prefix));
    }

    pub fn clear_all(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        count
    }

    pub fn active_count(&self) -> usize {
        let now = now_unix_secs();
        self.entries
            .values()
            .filter(|&&ts| now.saturating_sub(ts) < self.ttl_secs)
            .count()
    }

    pub fn is_on_cooldown(&self, ip: &str, proto: VpnProtocol) -> bool {
        self.is_on_cooldown_at(ip, proto, now_unix_secs())
    }

    pub fn is_on_cooldown_at(&self, ip: &str, proto: VpnProtocol, now_secs: u64) -> bool {
        let Some(&failed_at) = self.entries.get(&Self::key(ip, proto)) else {
            return false;
        };
        now_secs.saturating_sub(failed_at) < self.ttl_secs
    }

    pub fn prune_expired(&mut self) {
        let now = now_unix_secs();
        let ttl = self.ttl_secs;
        self.entries
            .retain(|_, &mut ts| now.saturating_sub(ts) < ttl);
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new(DEFAULT_COOLDOWN_SECS));
        }
        let raw = std::fs::read_to_string(path)?;
        let mut store: Self = serde_json::from_str(&raw)?;
        store.prune_expired();
        Ok(store)
    }

    pub fn save_to_path(&mut self, path: &Path) -> Result<()> {
        self.prune_expired();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_and_expires_per_protocol_cooldowns() {
        let mut store = CooldownStore::new(1800);
        store.mark_failed_at("219.100.37.10", VpnProtocol::L2tpIpsec, 1_000);

        assert!(store.is_on_cooldown_at("219.100.37.10", VpnProtocol::L2tpIpsec, 2_000));
        assert!(!store.is_on_cooldown_at("219.100.37.10", VpnProtocol::OpenVpnUdp, 2_000));
        assert!(!store.is_on_cooldown_at("219.100.37.10", VpnProtocol::L2tpIpsec, 2_801));
    }
}
