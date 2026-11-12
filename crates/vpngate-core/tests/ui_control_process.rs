use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use vpngate_core::{
    AppPaths, acquire_ui_control, join_ui_control, ui_control_status, wait_for_ui_control_cancel,
};

const CHILD_MODE_ENV: &str = "VPNGATE_UI_TEST_CHILD";
const CHILD_DIR_ENV: &str = "VPNGATE_UI_TEST_DIR";
const CHILD_TOKEN_ENV: &str = "VPNGATE_UI_TEST_TOKEN";

/// This test is re-executed as a separate OS process by the controller test below.
#[test]
fn helper_child_waits_for_cancellation() {
    if std::env::var(CHILD_MODE_ENV).as_deref() != Ok("wait") {
        return;
    }

    let base_dir = std::env::var_os(CHILD_DIR_ENV).expect("test directory passed to child");
    let token = std::env::var(CHILD_TOKEN_ENV).expect("control token passed to child");
    let paths = AppPaths::with_base_dir(base_dir.into());
    let _executor = join_ui_control(&paths, &token).expect("child joins the controller lease");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("test runtime");
    runtime.block_on(wait_for_ui_control_cancel(&paths));
}

#[test]
fn separate_cli_process_joins_and_observes_controller_cancellation() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let base_dir = std::env::temp_dir().join(format!(
        "vpngate-ui-control-process-{}-{unique}",
        std::process::id()
    ));
    let paths = AppPaths::with_base_dir(base_dir.clone());
    let lease = acquire_ui_control(&paths, "GUI", "Connect").expect("controller lease");
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "helper_child_waits_for_cancellation",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "wait")
        .env(CHILD_DIR_ENV, &base_dir)
        .env(CHILD_TOKEN_ENV, lease.token())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn CLI executor test process");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("poll child process") {
            panic!("executor exited before cancellation: {status}");
        }
        if ui_control_status(&paths).is_some_and(|state| state.executor_pid == child.id()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child did not join the lease in time"
        );
        thread::sleep(Duration::from_millis(10));
    }

    assert!(lease.request_cancel(), "send shared cancellation request");
    let deadline = Instant::now() + Duration::from_secs(10);
    let child_status = loop {
        if let Some(status) = child.try_wait().expect("poll cancelled child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not stop after shared cancellation");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(
        child_status.success(),
        "cancellation helper failed: {child_status}"
    );
    assert!(
        ui_control_status(&paths)
            .is_some_and(|state| { state.cancel_requested && state.executor_pid == 0 })
    );

    drop(lease);
    assert!(ui_control_status(&paths).is_none());
    let _ = std::fs::remove_dir_all(base_dir);
}
