//! `vpngate-core`: Shared cross-platform engine for Windows, macOS, Linux, Android, and iOS.
//!
//! Planned core subsystems:
//! - `discovery`: Dual-feed mirror fetching, Wayback fallback, and Cloudflare DoH (`1.1.1.1`).
//! - `probe`: Concurrent TCP and UDP `500` IKEv1 (`PSK = "vpn"`) pre-flight liveness checks.
//! - `profile`: SoftEther `.ovpn` cipher/TLS patcher and Apple `.mobileconfig` L2TP generator.
//! - `tunnel`: Portable `TUN` packet abstraction + user-space `IKEv1 / ESPinUDP / L2TP / PPP` engine.

/// Supported tunnel transport priority order (`Auto`: `L2tpIpsec -> OpenVpnUdp -> OpenVpnTcp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProtocol {
    L2tpIpsec,
    OpenVpnUdp,
    OpenVpnTcp,
}

impl VpnProtocol {
    /// Default `Auto` connection cascade matching `vpngate-connect` design.
    pub const AUTO_ORDER: [Self; 3] = [Self::L2tpIpsec, Self::OpenVpnUdp, Self::OpenVpnTcp];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::L2tpIpsec => "L2TP/IPsec",
            Self::OpenVpnUdp => "OpenVPN UDP",
            Self::OpenVpnTcp => "OpenVPN TCP",
        }
    }
}

/// Returns the active host operating system family detected at compile time.
pub const fn host_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_priority_starts_with_l2tp() {
        assert_eq!(VpnProtocol::AUTO_ORDER[0], VpnProtocol::L2tpIpsec);
        assert_eq!(VpnProtocol::AUTO_ORDER[1], VpnProtocol::OpenVpnUdp);
        assert_eq!(VpnProtocol::AUTO_ORDER[2], VpnProtocol::OpenVpnTcp);
    }
}
