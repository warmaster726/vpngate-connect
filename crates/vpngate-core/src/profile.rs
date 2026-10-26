use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use regex::Regex;

use crate::error::{CoreError, Result};
use crate::protocol::{OpenVpnCompat, TargetPlatform, VpnProtocol, WindowsOvpnDriver};
use crate::server::VpnServer;

/// Options controlling cross-platform `.ovpn` patching across Desktop and Mobile engines.
#[derive(Debug, Clone)]
pub struct OvpnPatchOptions {
    pub platform: TargetPlatform,
    pub compat: OpenVpnCompat,
    pub transport: VpnProtocol,
    pub windows_driver: WindowsOvpnDriver,
    pub dns_servers: Vec<String>,
}

impl Default for OvpnPatchOptions {
    fn default() -> Self {
        Self {
            platform: TargetPlatform::current(),
            compat: OpenVpnCompat::OpenVpn26,
            transport: VpnProtocol::OpenVpnUdp,
            windows_driver: WindowsOvpnDriver::TapWindows6,
            dns_servers: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
        }
    }
}

/// Decodes and patches a raw VPN Gate `.ovpn` config for zero-prompt cross-platform compatibility
/// across Linux, Windows, macOS, Android (`ics-openvpn`), and iOS (`Partout` / `OpenVPN3`).
pub fn build_patched_ovpn(server: &VpnServer, opts: &OvpnPatchOptions) -> Result<String> {
    if server.ovpn_b64.trim().is_empty() {
        return Err(CoreError::MissingOpenVpnConfig {
            ip: server.ip.clone(),
        });
    }
    let decoded = BASE64_STD.decode(server.ovpn_b64.trim())?;
    let raw_text = String::from_utf8_lossy(&decoded);
    Ok(patch_ovpn_text(&raw_text, server, opts))
}

pub fn patch_ovpn_text(raw_text: &str, server: &VpnServer, opts: &OvpnPatchOptions) -> String {
    static RE_PROTO: OnceLock<Regex> = OnceLock::new();
    static RE_REMOTE: OnceLock<Regex> = OnceLock::new();

    let re_proto = RE_PROTO.get_or_init(|| Regex::new(r"^proto\s+").expect("regex"));
    let re_remote = RE_REMOTE.get_or_init(|| Regex::new(r"^remote\s+\S+\s+(\d+)").expect("regex"));

    let want_tcp = matches!(opts.transport, VpnProtocol::OpenVpnTcp);
    let mut lines_out = Vec::new();
    let mut in_xml_tag = false;

    for raw_ln in raw_text.replace("\r\n", "\n").lines() {
        let stripped = raw_ln.trim();
        if stripped.starts_with('<') && !stripped.starts_with("</") {
            in_xml_tag = true;
        }
        if !in_xml_tag {
            let low = stripped.to_ascii_lowercase();
            // Strip legacy / conflicting cipher & interactive auth directives
            if low.starts_with("cipher ")
                || low.starts_with("data-ciphers")
                || low.starts_with("ncp-")
                || low.starts_with("auth-user-pass")
                || low.starts_with("register-dns")
                || low.starts_with("block-outside-dns")
                || low.starts_with("windows-driver")
            {
                continue;
            }
            if re_proto.is_match(stripped) {
                lines_out.push(if want_tcp {
                    "proto tcp-client".to_string()
                } else {
                    "proto udp".to_string()
                });
                continue;
            }
            if let Some(cap) = re_remote.captures(stripped) {
                let fallback_port = cap[1].parse::<u16>().unwrap_or(443);
                let chosen_port = if want_tcp && server.tcp_port > 0 {
                    server.tcp_port
                } else if !want_tcp && server.udp_port > 0 {
                    server.udp_port
                } else {
                    fallback_port
                };
                lines_out.push(format!("remote {} {}", server.ip, chosen_port));
                continue;
            }
        }
        lines_out.push(raw_ln.to_string());
        if stripped.starts_with("</") {
            in_xml_tag = false;
        }
    }

    lines_out.push(String::new());
    lines_out.push("# --- Patched by vpngate-core ---".to_string());

    match opts.compat {
        OpenVpnCompat::OpenVpn26 => {
            lines_out.push(
                "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC"
                    .to_string(),
            );
            lines_out.push("data-ciphers-fallback AES-128-CBC".to_string());
            lines_out.push("disable-dco".to_string());
            lines_out.push("tls-cert-profile insecure".to_string());
        }
        OpenVpnCompat::OpenVpn25 => {
            lines_out
                .push("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC".to_string());
            lines_out.push("data-ciphers-fallback AES-128-CBC".to_string());
            lines_out.push("tls-cert-profile insecure".to_string());
        }
        OpenVpnCompat::OpenVpn24 => {
            lines_out.push("ncp-ciphers AES-256-GCM:AES-128-GCM".to_string());
            lines_out.push("cipher AES-128-CBC".to_string());
        }
        OpenVpnCompat::MobileCore3 => {
            // OpenVPN3 / Partout negotiates AES-CBC & AES-GCM cleanly without DCO flags
            lines_out.push("cipher AES-128-CBC".to_string());
            lines_out
                .push("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC".to_string());
        }
    }

    lines_out.push("connect-retry-max 2".to_string());
    lines_out.push("resolv-retry 10".to_string());
    lines_out.push("hand-window 20".to_string());
    lines_out.push("keepalive 10 30".to_string());

    for dns in &opts.dns_servers {
        lines_out.push(format!("dhcp-option DNS {dns}"));
    }

    if opts.platform == TargetPlatform::Windows {
        let drv = match opts.windows_driver {
            WindowsOvpnDriver::TapWindows6 => "tap-windows6",
            WindowsOvpnDriver::WinTun => "wintun",
        };
        lines_out.push(format!("windows-driver {drv}"));
        lines_out.push("block-outside-dns".to_string());
    }

    lines_out.push(String::new());
    lines_out.join("\n")
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Generates an Apple Configuration Profile (`.mobileconfig`) for one-tap native L2TP/IPsec
/// setup on **iOS / iPadOS** and **macOS** (`PSK = "vpn"`, `User = "vpn"`, `Pass = "vpn"`).
pub fn build_apple_l2tp_mobileconfig(server: &VpnServer) -> String {
    let profile_name = format!(
        "VPN Gate — {} ({})",
        xml_escape(&server.country_long),
        xml_escape(&server.ip)
    );
    let ip_esc = xml_escape(&server.ip);
    let octets: Vec<u8> = server
        .ip
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();
    let suffix = if octets.len() == 4 {
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            octets[0], octets[1], octets[2], octets[3]
        )
    } else {
        "00000001".to_string()
    };
    let payload_uuid = format!("56504e47-4154-4500-8001-0000{suffix}");
    let root_uuid = format!("56504e47-4154-4500-8000-0000{suffix}");
    let shared_secret_b64 = BASE64_STD.encode(b"vpn");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNS</key>
            <dict>
                <key>ServerAddresses</key>
                <array>
                    <string>1.1.1.1</string>
                    <string>1.0.0.1</string>
                </array>
            </dict>
            <key>IPSec</key>
            <dict>
                <key>AuthenticationMethod</key>
                <string>SharedSecret</string>
                <key>SharedSecret</key>
                <data>{shared_secret_b64}</data>
            </dict>
            <key>IPv4</key>
            <dict>
                <key>OverridePrimary</key>
                <integer>1</integer>
            </dict>
            <key>PPP</key>
            <dict>
                <key>AuthName</key>
                <string>vpn</string>
                <key>AuthPassword</key>
                <string>vpn</string>
                <key>CommRemoteAddress</key>
                <string>{ip_esc}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures VPN Gate L2TP over IPsec tunnel</string>
            <key>PayloadDisplayName</key>
            <string>{profile_name}</string>
            <key>PayloadIdentifier</key>
            <string>net.vpngate.connect.l2tp.{ip_esc}</string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>UserDefinedName</key>
            <string>{profile_name}</string>
            <key>VPNType</key>
            <string>L2TP</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>{profile_name}</string>
    <key>PayloadIdentifier</key>
    <string>net.vpngate.connect.profile.{ip_esc}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{root_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server() -> VpnServer {
        let raw_ovpn = "client\ndev tun\nproto udp\nremote 10.0.0.1 1194\ncipher AES-128-CBC\nauth-user-pass\n<ca>\nCERTDATA\n</ca>\n";
        VpnServer {
            hostname: "vpn-jp".to_string(),
            ip: "219.100.37.10".to_string(),
            score: 1_000_000,
            ping_ms: 15,
            speed_bps: 300_000_000,
            country_long: "Japan".to_string(),
            country_short: "JP".to_string(),
            sessions: 20,
            uptime_ms: 50000,
            operator: "Tsukuba".to_string(),
            l2tp: true,
            openvpn: true,
            tcp_port: 443,
            udp_port: 1195,
            ovpn_b64: BASE64_STD.encode(raw_ovpn),
            ovpn_dl_query: String::new(),
        }
    }

    #[test]
    fn patches_ovpn_for_tcp_and_strips_auth_prompt() {
        let srv = sample_server();
        let opts = OvpnPatchOptions {
            platform: TargetPlatform::Linux,
            compat: OpenVpnCompat::OpenVpn26,
            transport: VpnProtocol::OpenVpnTcp,
            ..Default::default()
        };
        let patched = build_patched_ovpn(&srv, &opts).expect("patched");
        assert!(patched.contains("proto tcp-client"));
        assert!(patched.contains("remote 219.100.37.10 443"));
        assert!(!patched.contains("auth-user-pass"));
        assert!(patched.contains("disable-dco"));
        assert!(patched.contains("dhcp-option DNS 1.1.1.1"));
    }

    #[test]
    fn generates_valid_apple_mobileconfig() {
        let srv = sample_server();
        let xml = build_apple_l2tp_mobileconfig(&srv);
        assert!(xml.contains("<string>com.apple.vpn.managed</string>"));
        assert!(xml.contains("<string>219.100.37.10</string>"));
        assert!(xml.contains("<string>1.1.1.1</string>"));
    }
}
