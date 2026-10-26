//! Zero-codegen C-ABI (`extern "C"`) exported by `libvpngate_bridge.{so,a,dylib,dll}`
//! for Flutter (`dart:ffi`), Android `VpnService` (`JNI`), and iOS `NEPacketTunnelProvider`.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::Serialize;
use serde_json::Value;

use crate::api::{
    ConnectPlanRequest, DiscoverRequest, PrepareAttemptRequest, build_connect_plan_sync,
    check_public_ip_sync, clear_cooldowns_sync, discover_servers_sync, drain_progress_events,
    generate_apple_l2tp_profile, generate_mobile_ovpn_profile, get_userspace_l2tp_stats_sync,
    host_platform_name, init_storage_dir, prepare_attempt_sync, probe_official_mirrors_sync,
    record_attempt_failure_sync, run_bridge_diagnostics, set_watchdog_enabled_sync,
    start_userspace_l2tp_with_callbacks, stop_userspace_l2tp_sync,
};
use vpngate_core::VpnServer;

/// Callback invoked synchronously on every outbound UDP socket FD (`500`/`4500`)
/// so Android `VpnService.protect(fd)` exempts tunnel carrier packets from routing loops.
pub type ProtectFdCallback = extern "C" fn(ctx: *mut c_void, fd: c_int) -> bool;

/// Callback invoked synchronously once user-space `IKEv1 + ESP + L2TP + PPP/IPCP` negotiates
/// an IPv4 address, returning a detached `TUN` file descriptor (`>= 0`) or `-1` on error/probe.
pub type EstablishTunCallback = extern "C" fn(
    ctx: *mut c_void,
    assigned_ip: *const c_char,
    peer_ip: *const c_char,
    dns1: *const c_char,
    dns2: *const c_char,
    mtu: c_int,
) -> c_int;

#[derive(Serialize)]
struct RpcEnvelope<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn into_c_json<T: Serialize>(res: Result<T, String>) -> *mut c_char {
    let env = match res {
        Ok(data) => RpcEnvelope {
            ok: true,
            data: Some(data),
            error: None,
        },
        Err(err) => RpcEnvelope {
            ok: false,
            data: None,
            error: Some(err),
        },
    };
    let s = serde_json::to_string(&env)
        .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"JSON serialization error: {e}"}}"#));
    CString::new(s.replace('\0', ""))
        .unwrap_or_else(|_| CString::new(r#"{"ok":false,"error":"CString NUL error"}"#).unwrap())
        .into_raw()
}

unsafe fn opt_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn dispatch_rpc(method: &str, params_raw: &str) -> Result<Value, String> {
    let params: Value = if params_raw.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(params_raw).map_err(|e| format!("Invalid JSON params: {e}"))?
    };

    match method.trim() {
        "ping" | "platform" => Ok(serde_json::json!({
            "platform": host_platform_name(),
            "version": env!("CARGO_PKG_VERSION"),
        })),
        "init_storage" => {
            let dir = params
                .get("dir")
                .and_then(Value::as_str)
                .ok_or("Missing 'dir' string parameter")?
                .to_string();
            let resolved = init_storage_dir(dir)?;
            Ok(serde_json::json!({ "storage_dir": resolved }))
        }
        "diagnostics" | "doctor" => run_bridge_diagnostics(),
        "discover_servers" => {
            let req: DiscoverRequest = serde_json::from_value(params)
                .map_err(|e| format!("Invalid DiscoverRequest: {e}"))?;
            let resp = discover_servers_sync(req)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "probe_mirrors" => {
            let urls: Vec<String> = params
                .get("mirror_urls")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let res = probe_official_mirrors_sync(urls)?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "build_connect_plan" => {
            let req: ConnectPlanRequest = serde_json::from_value(params)
                .map_err(|e| format!("Invalid ConnectPlanRequest: {e}"))?;
            let plan = build_connect_plan_sync(req)?;
            serde_json::to_value(plan).map_err(|e| e.to_string())
        }
        "prepare_attempt" => {
            let req: PrepareAttemptRequest = serde_json::from_value(params)
                .map_err(|e| format!("Invalid PrepareAttemptRequest: {e}"))?;
            let prep = prepare_attempt_sync(req)?;
            serde_json::to_value(prep).map_err(|e| e.to_string())
        }
        "record_failure" => {
            let ip = params
                .get("ip")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let proto = params
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("auto")
                .to_string();
            let active = record_attempt_failure_sync(ip, proto);
            Ok(serde_json::json!({ "active_cooldowns": active }))
        }
        "clear_cooldowns" => {
            clear_cooldowns_sync()?;
            Ok(serde_json::json!({ "cleared": true }))
        }
        "set_watchdog" => {
            let enabled = params
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let saved = set_watchdog_enabled_sync(enabled)?;
            Ok(serde_json::json!({ "watchdog_enabled": saved }))
        }
        "check_public_ip" => {
            let timeout_ms = params
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(3500);
            let trace = check_public_ip_sync(timeout_ms)?;
            serde_json::to_value(trace).map_err(|e| e.to_string())
        }
        "generate_ovpn" => {
            let srv_val = params
                .get("server")
                .cloned()
                .ok_or_else(|| "Missing 'server'".to_string())?;
            let srv: VpnServer = serde_json::from_value(srv_val).map_err(|e| e.to_string())?;
            let use_tcp = params
                .get("use_tcp")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let is_ios = params
                .get("is_ios")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let ovpn = generate_mobile_ovpn_profile(srv, use_tcp, is_ios)?;
            Ok(serde_json::json!({ "ovpn": ovpn }))
        }
        "generate_apple_mobileconfig" => {
            let srv_val = params
                .get("server")
                .cloned()
                .ok_or_else(|| "Missing 'server'".to_string())?;
            let srv: VpnServer = serde_json::from_value(srv_val).map_err(|e| e.to_string())?;
            let xml = generate_apple_l2tp_profile(srv);
            Ok(serde_json::json!({ "mobileconfig": xml }))
        }
        "l2tp_status" => {
            let st = get_userspace_l2tp_stats_sync();
            serde_json::to_value(st).map_err(|e| e.to_string())
        }
        "l2tp_stop" => {
            stop_userspace_l2tp_sync();
            Ok(serde_json::json!({ "stopped": true }))
        }
        other => Err(format!("Unknown vpngate-bridge RPC method: '{other}'")),
    }
}

/// Primary Zero-Codegen JSON RPC entry point for Flutter (`dart:ffi` `Isolate.run`).
/// Caller must free the returned string via `vpngate_free_string`.
///
/// # Safety
/// `method` and `params_json` must each be either null or a valid pointer to a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpngate_json_call(
    method: *const c_char,
    params_json: *const c_char,
) -> *mut c_char {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let m = unsafe { opt_cstr(method) };
        let p = unsafe { opt_cstr(params_json) };
        dispatch_rpc(&m, &p)
    }));
    match outcome {
        Ok(res) => into_c_json(res),
        Err(_) => into_c_json::<Value>(Err("Panic inside vpngate_json_call".to_string())),
    }
}

/// Non-blocking drain of buffered `ProgressEvent`s for real-time Flutter progress rendering.
/// Caller must free the returned string via `vpngate_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn vpngate_drain_progress_json() -> *mut c_char {
    let outcome = catch_unwind(|| Ok(drain_progress_events()));
    match outcome {
        Ok(res) => into_c_json(res),
        Err(_) => into_c_json::<Vec<vpngate_core::ProgressEvent>>(Ok(Vec::new())),
    }
}

/// Starts user-space `IKEv1 + ESP-in-UDP + L2TPv2 + PPP/IPCP` with synchronous `protect_cb`
/// and `establish_cb` hooks (used by Android `VpnGateVpnService` JNI and Linux `TUN` tests).
/// Caller must free the returned JSON string via `vpngate_free_string`.
///
/// # Safety
/// `server_ip` and `dns_csv` must each be either null or a valid pointer to a NUL-terminated C string,
/// and `cb_ctx` must remain valid for synchronous calls during the handshake before this function returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpngate_l2tp_start_with_callbacks(
    server_ip: *const c_char,
    dns_csv: *const c_char,
    timeout_secs: c_int,
    cb_ctx: *mut c_void,
    protect_cb: Option<ProtectFdCallback>,
    establish_cb: Option<EstablishTunCallback>,
) -> *mut c_char {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let ip = unsafe { opt_cstr(server_ip) };
        let dns_raw = unsafe { opt_cstr(dns_csv) };
        let dns_list: Vec<String> = dns_raw
            .split([',', ' ', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();

        let protect_closure = |fd: i32| -> bool {
            if let Some(cb) = protect_cb {
                cb(cb_ctx, fd as c_int)
            } else {
                true
            }
        };

        let mut establish_closure =
            |cfg: &vpngate_core::UserspaceL2tpConfig| -> Result<i32, String> {
                let Some(cb) = establish_cb else {
                    return Ok(-1);
                };
                let assigned = CString::new(cfg.assigned_ip.as_str()).map_err(|e| e.to_string())?;
                let peer = CString::new(cfg.peer_ip.as_str()).map_err(|e| e.to_string())?;
                let d1 = CString::new(cfg.dns_primary.as_str()).map_err(|e| e.to_string())?;
                let d2 = CString::new(cfg.dns_secondary.as_str()).map_err(|e| e.to_string())?;
                let fd = cb(
                    cb_ctx,
                    assigned.as_ptr(),
                    peer.as_ptr(),
                    d1.as_ptr(),
                    d2.as_ptr(),
                    c_int::from(cfg.mtu),
                );
                if fd == -2 {
                    return Err(
                        "Android VpnService.Builder.establish() returned null TUN interface"
                            .to_string(),
                    );
                }
                Ok(fd)
            };

        start_userspace_l2tp_with_callbacks(
            &ip,
            &dns_list,
            timeout_secs.max(15) as u64,
            Some(&protect_closure),
            &mut establish_closure,
        )
    }));

    match outcome {
        Ok(res) => into_c_json(res),
        Err(_) => into_c_json::<vpngate_core::UserspaceL2tpConfig>(Err(
            "Panic inside vpngate_l2tp_start_with_callbacks".to_string(),
        )),
    }
}

/// Returns live JSON statistics for the active user-space L2TP/IPsec session.
#[unsafe(no_mangle)]
pub extern "C" fn vpngate_l2tp_status_json() -> *mut c_char {
    into_c_json::<vpngate_core::UserspaceL2tpStats>(Ok(get_userspace_l2tp_stats_sync()))
}

/// Stops any active user-space L2TP/IPsec session cleanly (`StopCCN` + `Delete-SA` + close `tun_fd`).
#[unsafe(no_mangle)]
pub extern "C" fn vpngate_l2tp_stop() {
    let _ = catch_unwind(stop_userspace_l2tp_sync);
}

/// Frees a C string previously returned by `vpngate_*` FFI functions.
///
/// # Safety
/// `ptr` must be either null or a pointer previously returned by `vpngate_json_call`,
/// `vpngate_drain_progress_json`, `vpngate_l2tp_start_with_callbacks`, or `vpngate_l2tp_status_json`,
/// and must not be freed more than once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpngate_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_json_call_diagnostics_and_memory_roundtrip() {
        let method = CString::new("diagnostics").unwrap();
        let params = CString::new("{}").unwrap();
        let raw_ptr = unsafe { vpngate_json_call(method.as_ptr(), params.as_ptr()) };
        assert!(!raw_ptr.is_null());
        let json_str = unsafe { CStr::from_ptr(raw_ptr) }
            .to_str()
            .expect("valid UTF-8")
            .to_string();
        unsafe { vpngate_free_string(raw_ptr) };

        let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON envelope");
        assert_eq!(parsed.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            parsed
                .pointer("/data/ikev1_crypto_self_test")
                .and_then(Value::as_str),
            Some("PASS")
        );
    }
}
