//! OS-backed singleton guard for the native desktop GUI.
//!
//! Unlike operation-control leases, this lock is held only for the lifetime of the
//! GUI process. Short-lived CLI command-service workers do not acquire it.

#[cfg(unix)]
use std::fs;
use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use crate::cache::AppPaths;

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug)]
pub enum InteractiveInstanceError {
    AlreadyRunning,
    Io(io::Error),
}

impl std::fmt::Display for InteractiveInstanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning => write!(f, "another VPN Gate Connect window is already running"),
            Self::Io(error) => write!(f, "could not acquire the frontend instance lock: {error}"),
        }
    }
}

impl std::error::Error for InteractiveInstanceError {}

impl From<io::Error> for InteractiveInstanceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Keeps the OS file lock until the owning frontend exits.
pub struct InteractiveInstanceGuard {
    _lock_file: File,
}

impl std::fmt::Debug for InteractiveInstanceGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractiveInstanceGuard")
            .finish_non_exhaustive()
    }
}

/// Acquire the single interactive-frontend slot for this user's VPN Gate cache.
///
/// The operating-system lock is automatically released on normal drop, process
/// exit, or crash; the small lock file itself is intentionally left in place.
pub fn acquire_interactive_instance(
    paths: &AppPaths,
) -> Result<InteractiveInstanceGuard, InteractiveInstanceError> {
    paths
        .ensure_dirs()
        .map_err(|error| InteractiveInstanceError::Io(io::Error::other(error.to_string())))?;

    let path = lock_path(paths);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }

    let file = options.open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE_MODE));
    }

    match file.try_lock() {
        Ok(()) => {
            // Empty any token written by older GTK/VTE launcher versions.
            file.set_len(0)?;
            file.sync_data()?;
            Ok(InteractiveInstanceGuard { _lock_file: file })
        }
        Err(TryLockError::WouldBlock) => Err(InteractiveInstanceError::AlreadyRunning),
        Err(TryLockError::Error(error)) => Err(InteractiveInstanceError::Io(error)),
    }
}

/// Acquire the per-user singleton slot and, when a custom cache is selected, that
/// cache's slot too. Locking the stable default path makes different cache overrides
/// contend across GUI launches.
pub fn acquire_interactive_instances(
    selected_paths: &AppPaths,
    default_cache_dir: &Path,
) -> Result<Vec<InteractiveInstanceGuard>, InteractiveInstanceError> {
    let default_paths = AppPaths::with_base_dir(default_cache_dir.to_path_buf());
    let mut lock_paths = vec![default_paths.clone()];
    if selected_paths.cache_dir != default_paths.cache_dir {
        lock_paths.push(selected_paths.clone());
    }

    let mut guards = Vec::with_capacity(lock_paths.len());
    for paths in &lock_paths {
        guards.push(acquire_interactive_instance(paths)?);
    }
    Ok(guards)
}

fn lock_path(paths: &AppPaths) -> PathBuf {
    paths.cache_dir.join("interactive-frontend.lock")
}

#[cfg(test)]
mod tests {
    use super::{
        InteractiveInstanceError, acquire_interactive_instance, acquire_interactive_instances,
    };
    use crate::cache::AppPaths;

    #[test]
    fn allows_only_one_live_frontend_and_releases_after_drop() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let cache =
            std::env::temp_dir().join(format!("vpngate-instance-{}-{nonce}", std::process::id()));
        let paths = AppPaths::with_base_dir(cache.clone());

        let first = acquire_interactive_instance(&paths).expect("first frontend acquires lock");
        assert!(matches!(
            acquire_interactive_instance(&paths),
            Err(InteractiveInstanceError::AlreadyRunning)
        ));

        drop(first);
        let second = acquire_interactive_instance(&paths).expect("lock is released on drop");
        drop(second);
        std::fs::remove_dir_all(cache).expect("temporary cache cleanup");
    }

    #[test]
    fn different_cache_overrides_still_share_the_default_slot() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "vpngate-custom-cache-instance-{}-{nonce}",
            std::process::id()
        ));
        let default_cache = root.join("default");
        let first_paths = AppPaths::with_base_dir(root.join("custom-a"));
        let second_paths = AppPaths::with_base_dir(root.join("custom-b"));

        let first = acquire_interactive_instances(&first_paths, &default_cache)
            .expect("first frontend acquires default and custom cache locks");
        assert!(matches!(
            acquire_interactive_instances(&second_paths, &default_cache),
            Err(InteractiveInstanceError::AlreadyRunning)
        ));
        drop(first);
        let second = acquire_interactive_instances(&second_paths, &default_cache)
            .expect("second cache can start after the first frontend exits");
        drop(second);
        std::fs::remove_dir_all(root).expect("temporary cache cleanup");
    }

    #[test]
    fn child_process_cannot_acquire_parent_frontend_lock() {
        let Ok(cache) = std::env::var("VPNGATE_TEST_INSTANCE_CACHE") else {
            return;
        };
        let paths = AppPaths::with_base_dir(cache.into());
        assert!(matches!(
            acquire_interactive_instance(&paths),
            Err(InteractiveInstanceError::AlreadyRunning)
        ));
    }

    #[test]
    fn frontend_lock_blocks_a_separate_process() {
        use std::process::Command;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let cache = std::env::temp_dir().join(format!(
            "vpngate-cross-process-instance-{}-{nonce}",
            std::process::id()
        ));
        let paths = AppPaths::with_base_dir(cache.clone());
        let guard = acquire_interactive_instance(&paths).expect("parent frontend lock");
        let child = Command::new(std::env::current_exe().expect("test executable path"))
            .args([
                "--exact",
                "interactive_instance::tests::child_process_cannot_acquire_parent_frontend_lock",
            ])
            .env("VPNGATE_TEST_INSTANCE_CACHE", &cache)
            .output()
            .expect("spawn child lock probe");
        assert!(
            child.status.success(),
            "child lock probe failed: {}",
            String::from_utf8_lossy(&child.stderr)
        );
        drop(guard);
        std::fs::remove_dir_all(cache).expect("temporary cache cleanup");
    }
}
