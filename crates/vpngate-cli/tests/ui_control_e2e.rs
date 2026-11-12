use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use vpngate_core::{AppPaths, UI_CONTROL_PROTOCOL_VERSION, acquire_ui_control, ui_control_status};

#[test]
fn reports_shared_ui_control_protocol_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_vpngate"))
        .arg("--ui-control-protocol-version")
        .output()
        .expect("query shared UI control protocol");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        UI_CONTROL_PROTOCOL_VERSION.to_string()
    );
}

#[test]
fn delegated_cli_command_joins_gui_lease_and_other_cli_is_observe_only() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let cache_dir = std::env::temp_dir().join(format!(
        "vpngate-cli-control-e2e-{}-{unique}",
        std::process::id()
    ));
    let paths = AppPaths::with_base_dir(cache_dir.clone());
    let lease = acquire_ui_control(&paths, "GUI", "Watchdog status").expect("GUI lease");
    let binary = env!("CARGO_BIN_EXE_vpngate");

    let delegated = Command::new(binary)
        .arg("--cache-dir")
        .arg(&cache_dir)
        .arg("--ui-control-token")
        .arg(lease.token())
        .args(["watchdog", "status"])
        .output()
        .expect("run delegated CLI operation");
    assert_eq!(
        delegated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&delegated.stderr)
    );
    assert!(
        ui_control_status(&paths)
            .is_some_and(|state| { state.owner == "GUI" && state.executor_pid == 0 })
    );

    let competing = Command::new(binary)
        .arg("--cache-dir")
        .arg(&cache_dir)
        .args(["watchdog", "status"])
        .output()
        .expect("run competing CLI operation");
    assert_eq!(competing.status.code(), Some(75));
    assert!(String::from_utf8_lossy(&competing.stderr).contains("Observe-only"));

    drop(lease);
    assert!(ui_control_status(&paths).is_none());
    let _ = std::fs::remove_dir_all(cache_dir);
}
