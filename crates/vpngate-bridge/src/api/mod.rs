use vpngate_core::{VpnProtocol, host_platform};

/// Lightweight health check callable from Flutter (`Android` / `iOS`) via `flutter_rust_bridge`.
pub fn bridge_runtime_summary() -> String {
    let cascade: Vec<&str> = VpnProtocol::AUTO_ORDER
        .iter()
        .map(|p| p.as_label())
        .collect();
    format!(
        "vpngate-core {} on {} [{}]",
        env!("CARGO_PKG_VERSION"),
        host_platform(),
        cascade.join(" -> ")
    )
}
