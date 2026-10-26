use vpngate_core::{VpnProtocol, host_platform};

fn main() {
    let order: Vec<&str> = VpnProtocol::AUTO_ORDER
        .iter()
        .map(|p| p.as_label())
        .collect();

    println!(
        "vpngate-connect v{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        host_platform(),
        std::env::consts::ARCH
    );
    println!("Auto protocol priority: {}", order.join(" -> "));
}
