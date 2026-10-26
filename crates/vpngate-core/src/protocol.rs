use serde::{Deserialize, Serialize};

/// Supported tunnel transport protocols in recommended `Auto` priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpnProtocol {
    L2tpIpsec,
    OpenVpnUdp,
    OpenVpnTcp,
}

impl VpnProtocol {
    /// Default `Auto` connection cascade: `L2TP/IPsec -> OpenVPN UDP -> OpenVPN TCP`.
    pub const AUTO_ORDER: [Self; 3] = [Self::L2tpIpsec, Self::OpenVpnUdp, Self::OpenVpnTcp];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::L2tpIpsec => "L2TP/IPsec",
            Self::OpenVpnUdp => "OpenVPN UDP",
            Self::OpenVpnTcp => "OpenVPN TCP",
        }
    }

    pub const fn cooldown_bucket(self) -> &'static str {
        match self {
            Self::L2tpIpsec => "l2tp",
            Self::OpenVpnUdp => "openvpn-udp",
            Self::OpenVpnTcp => "openvpn-tcp",
        }
    }

    pub fn from_cli_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "l2tp" | "l2tp-ipsec" | "ipsec" => Some(Self::L2tpIpsec),
            "openvpn-udp" | "ovpn-udp" | "udp" => Some(Self::OpenVpnUdp),
            "openvpn-tcp" | "ovpn-tcp" | "tcp" => Some(Self::OpenVpnTcp),
            _ => None,
        }
    }
}

/// Server pool filter mode (`Auto` includes all supported protocols).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolFilter {
    #[default]
    Auto,
    Only(VpnProtocol),
}

/// Server ranking strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SortBy {
    #[default]
    Recommended,
    Speed,
    Ping,
    Score,
}

/// Target operating system family for profile generation & tunnel runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetPlatform {
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
}

impl TargetPlatform {
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "android") {
            Self::Android
        } else if cfg!(target_os = "ios") {
            Self::Ios
        } else {
            Self::Linux
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

/// OpenVPN engine compatibility target for `.ovpn` profile patching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OpenVpnCompat {
    /// OpenVPN `>= 2.6` (Linux, macOS Tunnelblick, Windows Community 2.6+, Android `ics-openvpn`).
    #[default]
    OpenVpn26,
    /// OpenVPN `2.5.5 - 2.5.x` with `tls-cert-profile insecure`.
    OpenVpn25,
    /// Legacy OpenVPN `2.4.x` (`ncp-ciphers` + `cipher AES-128-CBC`).
    OpenVpn24,
    /// Mobile `OpenVPN 3 Core` / iOS `Partout` (`Passepartout` / `OpenVPN Connect`).
    MobileCore3,
}

/// Windows virtual network adapter selection for OpenVPN 2.5/2.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WindowsOvpnDriver {
    #[default]
    TapWindows6,
    WinTun,
}
