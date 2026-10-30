//! `vpngate-core` — Shared cross-platform networking, anti-censorship discovery,
//! SoftEther IKEv1 cryptographic pre-flight verification, desktop tunnel drivers,
//! and multi-platform profile generator (`.ovpn` & Apple `.mobileconfig`).
//!
//! Desktop builds are **64-bit native** (`x86_64` or `aarch64`). 32-bit is not supported.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "VPN Gate Connect desktop supports 64-bit x86_64 and aarch64 only. Build with --target x86_64-unknown-linux-gnu / aarch64-unknown-linux-gnu, x86_64-pc-windows-msvc / aarch64-pc-windows-msvc, or x86_64-apple-darwin / aarch64-apple-darwin."
);

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
pub mod update;

pub use cache::{
    ActiveSessionState, AppPaths, CACHE_TTL_SECONDS, Ikev1StateInfo, MONITOR_INTERVAL_SECONDS,
    MirrorCacheFile, PublicIpTrace, ServerCacheFile, atomic_write_json, fix_owner,
    get_public_ip_trace, get_servers_cached, get_servers_cached_with_progress, load_cached_mirrors,
    load_cooldowns, load_watchdog_pref, now_unix_secs, read_json_opt, resolve_user_home,
    save_cached_mirrors, save_cooldowns, save_watchdog_pref,
};
pub use cooldown::{CooldownStore, DEFAULT_COOLDOWN_SECS};
pub use country::{
    CountrySummary, lookup_country_long, normalize_country_pair, summarize_countries,
};
pub use desktop_tunnel::{
    ConnectSessionConfig, GatewayInfo, INTERRUPTED_EXIT, NM_PROFILE_PREFIX, WIN_VPN_PROFILE_NAME,
    assert_supported_native_host, cleanup_existing_vpn, cleanup_existing_vpn_with_progress,
    cpu_isa_label, detect_host_os_label,
    engage_candidates, engage_candidates_with_progress, find_openvpn_bin, get_default_gateway,
    get_ppp_interfaces, get_running_monitor_pid, get_running_openvpn_pid, get_tun_interfaces,
    is_root_or_admin, probe_linux_l2tp_kernel_support, prune_stale_state_if_dead,
    query_windows_natt_rule, run_monitor_daemon, spawn_auto_reconnect_monitor,
    stop_monitor_daemon, which_bin,
};
pub use discovery::{
    DiscoveryClient, DiscoveryOptions, DiscoveryOutcome, MirrorProbeResult, ProgressEvent,
};
pub use doh::{is_poisoned_ip, is_poisoned_ipv4, resolve_ipv4_via_cloudflare_doh};
pub use error::{CoreError, Result};
pub use ikev1::{L2tpVerifyOutcome, probe_tcp, sweep_ikev1_sa_responders, verify_l2tp_psk_vpn};
pub use ikev1_daemon::{run_ikev1_crypto_self_test, run_ikev1_daemon};
pub use parser::{
    OfficialMirrorSite, normalize_mirror_base_url, parse_sdise_csv_into, parse_vpngate_csv_into,
    parse_vpngate_html_into, parse_vpngate_mirror_sites_html,
};
pub use profile::{OvpnPatchOptions, build_apple_l2tp_mobileconfig, build_patched_ovpn};
pub use protocol::{
    OpenVpnCompat, ProtocolFilter, SortBy, TargetPlatform, VpnProtocol, WindowsOvpnDriver,
};
pub use server::{VpnServer, filter_by_country, filter_by_protocol, sort_servers};
pub use update::{
    DesktopVersion, RemoteDesktopVersion, UpdateCheckCache, cache_is_fresh,
    cached_newer_than_installed, cached_remote_version, cargo_toml_check_urls,
    check_remote_desktop_version, default_repo_slug, fetch_public_url_text,
    installer_script_urls, installed_desktop_version, load_update_cache,
    parse_version_payload, parse_workspace_package_version, record_update_declined,
    record_update_failure, record_update_scan, refresh_update_cache, should_auto_prompt,
    version_check_urls,
};
