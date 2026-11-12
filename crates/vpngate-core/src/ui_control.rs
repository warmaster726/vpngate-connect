//! Shared cross-process control lease used by the native GUI and the legacy CLI/GTK UI.
//!
//! The lease is intentionally stored in the normal VPN Gate cache directory so every
//! frontend using the same user profile observes the same owner and active operation.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::cache::{AppPaths, fix_owner, now_unix_secs};
use crate::desktop_tunnel::is_pid_alive;

/// Increment when the private GUI-to-desktop-service control handshake changes.
pub const UI_CONTROL_PROTOCOL_VERSION: u32 = 1;

#[cfg(unix)]
const CONTROL_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiControlSnapshot {
    pub owner: String,
    pub operation: String,
    pub phase: String,
    pub owner_pid: u32,
    pub executor_pid: u32,
    pub started_at: u64,
    pub updated_at: u64,
    pub cancel_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlRecord {
    token: String,
    #[serde(flatten)]
    snapshot: UiControlSnapshot,
}

#[derive(Debug)]
pub enum UiControlError {
    Busy(UiControlSnapshot),
    InvalidToken,
    Io(io::Error),
}

impl std::fmt::Display for UiControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy(s) => write!(
                f,
                "{} is controlling {} ({})",
                s.owner, s.operation, s.phase
            ),
            Self::InvalidToken => write!(f, "the shared UI control token is invalid or expired"),
            Self::Io(e) => write!(f, "shared UI control lock: {e}"),
        }
    }
}

impl std::error::Error for UiControlError {}

impl From<io::Error> for UiControlError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// A lease owned by a frontend process. Dropping it releases the lock unless an
/// executor child is still running, in which case that child releases it on exit.
pub struct UiControlLease {
    paths: AppPaths,
    token: String,
    owner_pid: u32,
}

impl std::fmt::Debug for UiControlLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UiControlLease")
            .field("owner_pid", &self.owner_pid)
            .finish_non_exhaustive()
    }
}

impl UiControlLease {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn set_phase(&self, phase: impl Into<String>) -> bool {
        update_record(&self.paths, &self.token, |record| {
            record.snapshot.phase = phase.into();
            record.snapshot.updated_at = now_unix_secs();
        })
    }

    /// Ask the executing connect operation to stop and perform its normal rollback.
    pub fn request_cancel(&self) -> bool {
        update_record(&self.paths, &self.token, |record| {
            record.snapshot.cancel_requested = true;
            record.snapshot.phase = "Stopping and rolling back".to_string();
            record.snapshot.updated_at = now_unix_secs();
        })
    }
}

impl Drop for UiControlLease {
    fn drop(&mut self) {
        let path = control_path(&self.paths);
        let Ok(_lock) = acquire_control_file_lock(&path) else {
            return;
        };
        let Some(record) = read_record_unlocked(&path) else {
            return;
        };
        if record.token != self.token || record.snapshot.owner_pid != self.owner_pid {
            return;
        }
        if record.snapshot.executor_pid != 0
            && record.snapshot.executor_pid != std::process::id()
            && is_pid_alive(record.snapshot.executor_pid)
        {
            // The GUI/terminal may be closing while an already-started CLI child
            // still owns a connection operation. Leave the lease for that child.
            return;
        }
        remove_if_token_unlocked(&path, &self.token);
    }
}

/// Guard held by a CLI child that was started by a frontend which owns the lease.
/// It keeps the lock alive if the frontend closes during the operation.
pub struct UiControlExecutorGuard {
    paths: AppPaths,
    token: String,
    executor_pid: u32,
}

impl std::fmt::Debug for UiControlExecutorGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UiControlExecutorGuard")
            .field("executor_pid", &self.executor_pid)
            .finish_non_exhaustive()
    }
}

impl Drop for UiControlExecutorGuard {
    fn drop(&mut self) {
        let path = control_path(&self.paths);
        let Ok(_lock) = acquire_control_file_lock(&path) else {
            return;
        };
        let Some(mut record) = read_record_unlocked(&path) else {
            return;
        };
        if record.token != self.token || record.snapshot.executor_pid != self.executor_pid {
            return;
        }
        record.snapshot.executor_pid = 0;
        record.snapshot.updated_at = now_unix_secs();
        if !is_pid_alive(record.snapshot.owner_pid) {
            remove_if_token_unlocked(&path, &self.token);
        } else {
            let _ = write_record_atomic(&path, &record);
        }
    }
}

/// Owns a new lease, or joins the lease held by a GUI/terminal parent through a
/// private token. The returned guard must stay alive for the complete operation.
pub enum UiControlAccess {
    Owner(UiControlLease),
    Executor(UiControlExecutorGuard),
}

/// Acquire the exclusive controller lease. An active, live owner is never
/// displaced; stale records are cleared and retried once.
pub fn acquire_ui_control(
    paths: &AppPaths,
    owner: &str,
    operation: &str,
) -> Result<UiControlLease, UiControlError> {
    paths
        .ensure_dirs()
        .map_err(|e| UiControlError::Io(io::Error::other(e.to_string())))?;
    let path = control_path(paths);
    let _lock = acquire_control_file_lock(&path)?;
    let token = new_token();
    let now = now_unix_secs();
    let record = ControlRecord {
        token: token.clone(),
        snapshot: UiControlSnapshot {
            owner: owner.to_string(),
            operation: operation.to_string(),
            phase: "Starting".to_string(),
            owner_pid: std::process::id(),
            executor_pid: 0,
            started_at: now,
            updated_at: now,
            cancel_requested: false,
        },
    };

    for attempt in 0..2 {
        match create_exclusive(&path, &record) {
            Ok(()) => {
                return Ok(UiControlLease {
                    paths: paths.clone(),
                    token,
                    owner_pid: std::process::id(),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if let Some(existing) = read_record_unlocked(&path) {
                    if is_record_stale(&existing) {
                        remove_if_token_unlocked(&path, &existing.token);
                        if attempt == 0 {
                            continue;
                        }
                    } else {
                        return Err(UiControlError::Busy(existing.snapshot));
                    }
                } else if file_is_old(&path) {
                    let _ = fs::remove_file(&path);
                    if attempt == 0 {
                        continue;
                    }
                } else {
                    return Err(UiControlError::Busy(starting_snapshot()));
                }
            }
            Err(e) => return Err(UiControlError::Io(e)),
        }
    }

    match read_record_unlocked(&path) {
        Some(existing) => Err(UiControlError::Busy(existing.snapshot)),
        None => Err(UiControlError::Busy(starting_snapshot())),
    }
}

/// Join a frontend-owned lease from its child CLI process.
pub fn join_ui_control(
    paths: &AppPaths,
    token: &str,
) -> Result<UiControlExecutorGuard, UiControlError> {
    let executor_pid = std::process::id();
    let mut joined = false;
    let updated = update_record(paths, token, |record| {
        record.snapshot.executor_pid = executor_pid;
        record.snapshot.updated_at = now_unix_secs();
        joined = true;
    });
    if !updated || !joined {
        return Err(UiControlError::InvalidToken);
    }
    Ok(UiControlExecutorGuard {
        paths: paths.clone(),
        token: token.to_string(),
        executor_pid,
    })
}

/// Read the active controller, clearing the record if both owner and executor died.
pub fn ui_control_status(paths: &AppPaths) -> Option<UiControlSnapshot> {
    let path = control_path(paths);
    let _lock = acquire_control_file_lock(&path).ok()?;
    let record = read_record_unlocked(&path)?;
    if is_record_stale(&record) {
        remove_if_token_unlocked(&path, &record.token);
        None
    } else {
        Some(record.snapshot)
    }
}

/// Private token used by the current owner/executor for privilege hand-off and
/// cooperative cancellation. It is never included in the public snapshot.
pub fn ui_control_token_for_process(paths: &AppPaths) -> Option<String> {
    let record = read_record(&control_path(paths))?;
    let pid = std::process::id();
    (record.snapshot.owner_pid == pid || record.snapshot.executor_pid == pid)
        .then_some(record.token)
}

pub fn ui_control_cancel_requested(paths: &AppPaths, token: &str) -> bool {
    read_record(&control_path(paths))
        .is_some_and(|record| record.token == token && record.snapshot.cancel_requested)
}

/// Wait until the active frontend requests cancellation. Used only inside a
/// cancellable connection flow; cleanup remains in the normal connect rollback path.
pub async fn wait_for_ui_control_cancel(paths: &AppPaths) {
    let token = ui_control_token_for_process(paths).unwrap_or_default();
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if !token.is_empty() && ui_control_cancel_requested(paths, &token) {
            return;
        }
    }
}

/// Update a short, user-visible operation stage without exposing the lock token.
pub fn report_ui_control_phase(paths: &AppPaths, phase: impl Into<String>) {
    if let Some(token) = ui_control_token_for_process(paths) {
        let phase = phase.into();
        let _ = update_record(paths, &token, |record| {
            record.snapshot.phase = phase;
            record.snapshot.updated_at = now_unix_secs();
        });
    }
}

fn control_path(paths: &AppPaths) -> PathBuf {
    paths.ui_control.clone()
}

/// All control-record reads and writes share this OS-backed lock. It prevents
/// simultaneous progress updates from overwriting a cancellation request and
/// keeps readers from observing the Windows replacement fallback mid-write.
fn acquire_control_file_lock(path: &Path) -> io::Result<fs::File> {
    let lock_path = path.with_extension("json.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(CONTROL_FILE_MODE);
    }
    let file = options.open(&lock_path)?;
    set_private_permissions(&lock_path);
    fix_owner(&lock_path);
    file.lock()?;
    Ok(file)
}

fn new_token() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_record(path: &Path) -> Option<ControlRecord> {
    let _lock = acquire_control_file_lock(path).ok()?;
    read_record_unlocked(path)
}

fn read_record_unlocked(path: &Path) -> Option<ControlRecord> {
    let raw = fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn is_record_stale(record: &ControlRecord) -> bool {
    !is_pid_alive(record.snapshot.owner_pid)
        && (record.snapshot.executor_pid == 0 || !is_pid_alive(record.snapshot.executor_pid))
}

fn starting_snapshot() -> UiControlSnapshot {
    UiControlSnapshot {
        owner: "Another UI".to_string(),
        operation: "Starting".to_string(),
        phase: "Acquiring control".to_string(),
        owner_pid: 0,
        executor_pid: 0,
        started_at: now_unix_secs(),
        updated_at: now_unix_secs(),
        cancel_requested: false,
    }
}

fn file_is_old(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age > Duration::from_secs(2))
}

fn create_exclusive(path: &Path, record: &ControlRecord) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(CONTROL_FILE_MODE);
    }
    let mut file = options.open(path)?;
    let data = serde_json::to_vec(record).map_err(io::Error::other)?;
    if let Err(error) = file.write_all(&data).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    set_private_permissions(path);
    fix_owner(path);
    Ok(())
}

fn update_record(paths: &AppPaths, token: &str, update: impl FnOnce(&mut ControlRecord)) -> bool {
    let path = control_path(paths);
    let Ok(_lock) = acquire_control_file_lock(&path) else {
        return false;
    };
    let Some(mut record) = read_record_unlocked(&path) else {
        return false;
    };
    if record.token != token {
        return false;
    }
    update(&mut record);
    write_record_atomic(&path, &record).is_ok()
}

fn write_record_atomic(path: &Path, record: &ControlRecord) -> io::Result<()> {
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let data = serde_json::to_vec(record).map_err(io::Error::other)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(CONTROL_FILE_MODE);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(&data)?;
    file.sync_all()?;
    drop(file);
    set_private_permissions(&tmp);
    fix_owner(&tmp);
    if let Err(error) = fs::rename(&tmp, path) {
        #[cfg(windows)]
        {
            let _ = error;
            if let Err(write_error) = fs::write(path, &data) {
                let _ = fs::remove_file(&tmp);
                return Err(write_error);
            }
            let _ = fs::remove_file(&tmp);
        }
        #[cfg(not(windows))]
        {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
    }
    set_private_permissions(path);
    fix_owner(path);
    Ok(())
}

fn set_private_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(CONTROL_FILE_MODE));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn remove_if_token_unlocked(path: &Path, token: &str) {
    if read_record_unlocked(path).is_some_and(|record| record.token == token) {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        UiControlError, acquire_ui_control, join_ui_control, ui_control_cancel_requested,
        ui_control_status,
    };
    use crate::cache::AppPaths;
    use std::fs;
    use std::sync::Barrier;

    fn temp_paths(label: &str) -> AppPaths {
        let dir = std::env::temp_dir().join(format!(
            "vpngate-control-{}-{}-{label}",
            std::process::id(),
            crate::cache::now_unix_secs()
        ));
        AppPaths::with_base_dir(dir)
    }

    #[test]
    fn controller_lease_is_exclusive_and_released_on_drop() {
        let paths = temp_paths("exclusive");
        let lease = acquire_ui_control(&paths, "GUI", "Connect").unwrap();
        assert_eq!(ui_control_status(&paths).unwrap().operation, "Connect");
        assert!(matches!(
            acquire_ui_control(&paths, "CLI", "Disconnect"),
            Err(UiControlError::Busy(_))
        ));
        drop(lease);
        assert!(ui_control_status(&paths).is_none());
        let _ = fs::remove_dir_all(paths.cache_dir);
    }

    #[test]
    fn owner_can_request_cooperative_cancellation() {
        let paths = temp_paths("cancel");
        let lease = acquire_ui_control(&paths, "GUI", "Connect").unwrap();
        assert!(!ui_control_cancel_requested(&paths, lease.token()));
        assert!(lease.request_cancel());
        assert!(ui_control_cancel_requested(&paths, lease.token()));
        assert_eq!(
            ui_control_status(&paths).unwrap().phase,
            "Stopping and rolling back"
        );
        drop(lease);
        let _ = fs::remove_dir_all(paths.cache_dir);
    }

    #[test]
    fn child_joins_frontend_lease_and_guard_cleans_up_on_release() {
        let paths = temp_paths("join");
        let lease = acquire_ui_control(&paths, "GUI", "Connect").unwrap();
        let guard = join_ui_control(&paths, lease.token()).unwrap();
        assert_eq!(
            ui_control_status(&paths).unwrap().executor_pid,
            std::process::id()
        );
        drop(guard);
        drop(lease);
        assert!(ui_control_status(&paths).is_none());
        let _ = fs::remove_dir_all(paths.cache_dir);
    }

    #[test]
    fn concurrent_progress_updates_preserve_cancellation() {
        let paths = temp_paths("concurrent-cancel");
        let lease = acquire_ui_control(&paths, "GUI", "Connect").unwrap();
        let barrier = Barrier::new(5);

        std::thread::scope(|scope| {
            for worker in 0..4 {
                let barrier = &barrier;
                let lease = &lease;
                scope.spawn(move || {
                    barrier.wait();
                    for tick in 0..100 {
                        lease.set_phase(format!("worker {worker} progress {tick}"));
                    }
                });
            }
            barrier.wait();
            assert!(lease.request_cancel());
        });

        assert!(ui_control_cancel_requested(&paths, lease.token()));
        drop(lease);
        let _ = fs::remove_dir_all(paths.cache_dir);
    }

    #[test]
    fn invalid_join_token_is_rejected() {
        let paths = temp_paths("invalid");
        let _lease = acquire_ui_control(&paths, "GUI", "Status").unwrap();
        assert!(join_ui_control(&paths, "not-the-token").is_err());
        let _ = fs::remove_dir_all(paths.cache_dir);
    }
}
