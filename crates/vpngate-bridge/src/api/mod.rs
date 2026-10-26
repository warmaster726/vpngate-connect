use std::net::Ipv4Addr;
use std::time::Duration;

use vpngate_core::{
    CountrySummary, DiscoveryClient, DiscoveryOptions, L2tpVerifyOutcome, OpenVpnCompat,
    OvpnPatchOptions, ProtocolFilter, SortBy, TargetPlatform, VpnProtocol, VpnServer,
    build_apple_l2tp_mobileconfig, build_patched_ovpn, filter_by_country, sort_servers,
    summarize_countries, verify_l2tp_psk_vpn,
};

/// Returns the detected host OS identifier for the Flutter UI shell.
pub fn host_platform_name() -> String {
    TargetPlatform::current().as_str().to_string()
}

/// Fetches and sorts the live VPN Gate server pool for Flutter Desktop & Mobile views.
pub async fn fetch_ranked_servers(
    country_filter: Option<String>,
) -> Result<Vec<VpnServer>, String> {
    let client = DiscoveryClient::new(DiscoveryOptions::default()).map_err(|e| e.to_string())?;
    let pool = client.fetch_servers().await.map_err(|e| e.to_string())?;
    let mut filtered = filter_by_country(&pool, country_filter.as_deref());
    sort_servers(&mut filtered, SortBy::Recommended, ProtocolFilter::Auto);
    Ok(filtered)
}

/// Summarizes country counts and protocol availability from a fetched server slice.
pub fn build_country_summaries(servers: Vec<VpnServer>) -> Vec<CountrySummary> {
    summarize_countries(&servers)
}

/// Generates a mobile-ready patched `.ovpn` profile (`Android ics-openvpn` or `iOS Partout`).
pub fn generate_mobile_ovpn_profile(
    server: VpnServer,
    use_tcp: bool,
    is_ios: bool,
) -> Result<String, String> {
    let opts = OvpnPatchOptions {
        platform: if is_ios {
            TargetPlatform::Ios
        } else {
            TargetPlatform::Android
        },
        compat: if is_ios {
            OpenVpnCompat::MobileCore3
        } else {
            OpenVpnCompat::OpenVpn26
        },
        transport: if use_tcp {
            VpnProtocol::OpenVpnTcp
        } else {
            VpnProtocol::OpenVpnUdp
        },
        ..Default::default()
    };
    build_patched_ovpn(&server, &opts).map_err(|e| e.to_string())
}

/// Generates an Apple `.mobileconfig` XML profile for native iOS/macOS L2TP/IPsec (`PSK = "vpn"`).
pub fn generate_apple_l2tp_profile(server: VpnServer) -> String {
    build_apple_l2tp_mobileconfig(&server)
}

/// Runs a 1-RTT IKEv1 Aggressive Mode `PSK == "vpn"` pre-flight check against `ip`.
pub async fn verify_server_l2tp_psk(ip: String) -> Result<L2tpVerifyOutcome, String> {
    let parsed: Ipv4Addr = ip
        .trim()
        .parse()
        .map_err(|_| format!("Invalid IPv4 address: {ip}"))?;
    Ok(verify_l2tp_psk_vpn(parsed, Duration::from_millis(1500), 2, b"vpn").await)
}
