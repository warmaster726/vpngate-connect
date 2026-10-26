//! `vpngate-core` — Shared cross-platform networking, anti-censorship discovery,
//! SoftEther IKEv1 cryptographic pre-flight verification, and tunnel profile generator
//! for Windows, macOS, Linux, Android, and iOS.

pub mod cooldown;
pub mod country;
pub mod discovery;
pub mod doh;
pub mod error;
pub mod ikev1;
pub mod parser;
pub mod profile;
pub mod protocol;
pub mod server;

pub use cooldown::{CooldownStore, DEFAULT_COOLDOWN_SECS};
pub use country::{
    CountrySummary, lookup_country_long, normalize_country_pair, summarize_countries,
};
pub use discovery::{DiscoveryClient, DiscoveryOptions};
pub use doh::{is_poisoned_ip, is_poisoned_ipv4, resolve_ipv4_via_cloudflare_doh};
pub use error::{CoreError, Result};
pub use ikev1::{L2tpVerifyOutcome, probe_tcp, sweep_ikev1_sa_responders, verify_l2tp_psk_vpn};
pub use parser::{parse_sdise_csv_into, parse_vpngate_csv_into, parse_vpngate_html_into};
pub use profile::{OvpnPatchOptions, build_apple_l2tp_mobileconfig, build_patched_ovpn};
pub use protocol::{
    OpenVpnCompat, ProtocolFilter, SortBy, TargetPlatform, VpnProtocol, WindowsOvpnDriver,
};
pub use server::{VpnServer, filter_by_country, filter_by_protocol, sort_servers};
