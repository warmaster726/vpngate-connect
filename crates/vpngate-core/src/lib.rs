//! `vpngate-core` — Shared cross-platform networking, anti-censorship discovery,
//! SoftEther IKEv1 cryptographic pre-flight verification, desktop tunnel drivers,
//! and tunnel profile generator for Windows, macOS, Linux, Android, and iOS.

pub mod cache;
pub mod cooldown;
pub mod country;
pub mod desktop_tunnel;
pub mod discovery;
pub mod doh;
pub mod error;
pub mod ikev1;
pub mod ikev1_daemon;
pub mod parser;
pub mod profile;
pub mod protocol;
pub mod server;

pub use cache::{
    ActiveSessionState, AppPaths, CACHE_TTL_SECONDS, Ikev1StateInfo, MONITOR_INTERVAL_SECONDS,
    PublicIpTrace, ServerCacheFile, atomic_write_json, fix_owner, get_public_ip_trace,
    get_servers_cached, load_cooldowns, load_watchdog_pref, now_unix_secs, read_json_opt,
    save_cooldowns, save_watchdog_pref,
};
pub use cooldown::{CooldownStore, DEFAULT_COOLDOWN_SECS};
pub use country::{
    CountrySummary, lookup_country_long, normalize_country_pair, summarize_countries,
};
pub use desktop_tunnel::{
    ConnectSessionConfig, GatewayInfo, NM_PROFILE_PREFIX, WIN_VPN_PROFILE_NAME,
    cleanup_existing_vpn, detect_host_os_label, engage_candidates, find_openvpn_bin,
    get_default_gateway, get_ppp_interfaces, get_running_monitor_pid, get_tun_interfaces,
    is_root_or_admin, prune_stale_state_if_dead, run_monitor_daemon, spawn_auto_reconnect_monitor,
    stop_monitor_daemon, which_bin,
};
pub use discovery::{DiscoveryClient, DiscoveryOptions};
pub use doh::{is_poisoned_ip, is_poisoned_ipv4, resolve_ipv4_via_cloudflare_doh};
pub use error::{CoreError, Result};
pub use ikev1::{L2tpVerifyOutcome, probe_tcp, sweep_ikev1_sa_responders, verify_l2tp_psk_vpn};
pub use ikev1_daemon::{run_ikev1_crypto_self_test, run_ikev1_daemon};
pub use parser::{parse_sdise_csv_into, parse_vpngate_csv_into, parse_vpngate_html_into};
pub use profile::{OvpnPatchOptions, build_apple_l2tp_mobileconfig, build_patched_ovpn};
pub use protocol::{
    OpenVpnCompat, ProtocolFilter, SortBy, TargetPlatform, VpnProtocol, WindowsOvpnDriver,
};
pub use server::{VpnServer, filter_by_country, filter_by_protocol, sort_servers};
