use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;

use crate::parse::{parse_ipv4_octets, valid_public_ipv4};
use crate::model::Server;

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn sanitize_dns_list(raw_dns: Option<&str>) -> Vec<String> {
    let src = raw_dns.unwrap_or("1.1.1.1,1.0.0.1");
    let parts: Vec<String> = src
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter_map(valid_public_ipv4)
        .take(4)
        .collect();
    if parts.is_empty() {
        vec!["1.1.1.1".into(), "1.0.0.1".into()]
    } else {
        parts
    }
}

pub fn build_apple_l2tp_mobileconfig(server: &Server, dns_servers: &[String]) -> String {
    let country_long = if server.country_long.is_empty() {
        "Relay"
    } else {
        &server.country_long
    };
    let profile_name = format!(
        "VPN Gate — {} ({})",
        xml_escape(country_long),
        xml_escape(&server.ip)
    );
    let ip_esc = xml_escape(&server.ip);
    let suffix = parse_ipv4_octets(&server.ip)
        .map(|o| format!("{:02x}{:02x}{:02x}{:02x}", o[0], o[1], o[2], o[3]))
        .unwrap_or_else(|| "00000001".into());
    let payload_uuid = format!("56504e47-4154-4500-8001-0000{suffix}");
    let root_uuid = format!("56504e47-4154-4500-8000-0000{suffix}");
    let shared_secret_b64 = BASE64_STD.encode("vpn");
    let dns_xml: String = dns_servers
        .iter()
        .map(|d| format!("                    <string>{}</string>", xml_escape(d)))
        .collect::<Vec<_>>()
        .join("\n");

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
{dns_xml}
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

pub struct OvpnOpts<'a> {
    pub transport: &'a str,
    pub compat: &'a str,
    pub dns_servers: &'a [String],
    pub windows_driver: &'a str,
}

pub fn patch_ovpn_text(raw_text: &str, server: &Server, opts: &OvpnOpts<'_>) -> String {
    let want_tcp = opts.transport == "tcp";
    let mut lines_out = Vec::new();
    let mut in_xml_tag = false;
    for raw_ln in raw_text.replace("\r\n", "\n").split('\n') {
        let stripped = raw_ln.trim();
        if stripped.starts_with('<') && !stripped.starts_with("</") {
            in_xml_tag = true;
        }
        if !in_xml_tag {
            let low = stripped.to_ascii_lowercase();
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
            if low.starts_with("proto ") {
                lines_out.push(if want_tcp {
                    "proto tcp-client".to_string()
                } else {
                    "proto udp".to_string()
                });
                continue;
            }
            if low.starts_with("remote ") {
                let fallback = stripped
                    .split_whitespace()
                    .nth(2)
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(443);
                let chosen = if want_tcp && server.tcp_port > 0 {
                    server.tcp_port
                } else if !want_tcp && server.udp_port > 0 {
                    server.udp_port
                } else {
                    fallback
                };
                lines_out.push(format!("remote {} {chosen}", server.ip));
                continue;
            }
        }
        lines_out.push(raw_ln.to_string());
        if stripped.starts_with("</") {
            in_xml_tag = false;
        }
    }
    lines_out.push(String::new());
    lines_out.push("# --- Patched by vpngate-core ---".into());
    match opts.compat {
        "ovpn26" => {
            lines_out.push(
                "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC"
                    .into(),
            );
            lines_out.push("data-ciphers-fallback AES-128-CBC".into());
            lines_out.push("disable-dco".into());
            lines_out.push("tls-cert-profile insecure".into());
        }
        "ovpn25" => {
            lines_out.push("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC".into());
            lines_out.push("data-ciphers-fallback AES-128-CBC".into());
            lines_out.push("tls-cert-profile insecure".into());
        }
        "ovpn24" => {
            lines_out.push("ncp-ciphers AES-256-GCM:AES-128-GCM".into());
            lines_out.push("cipher AES-128-CBC".into());
        }
        _ => {
            lines_out.push("cipher AES-128-CBC".into());
            lines_out.push("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC".into());
        }
    }
    lines_out.push("connect-retry-max 2".into());
    lines_out.push("resolv-retry 10".into());
    lines_out.push("hand-window 20".into());
    lines_out.push("keepalive 10 30".into());
    for dns in opts.dns_servers {
        lines_out.push(format!("dhcp-option DNS {dns}"));
    }
    if opts.windows_driver == "tap-windows6" || opts.windows_driver == "wintun" {
        lines_out.push(format!("windows-driver {}", opts.windows_driver));
        lines_out.push("block-outside-dns".into());
    }
    lines_out.push(String::new());
    lines_out.join("\n")
}

pub fn build_patched_ovpn(server: &Server, donor_b64: &str, opts: &OvpnOpts<'_>) -> Option<String> {
    let b64 = if !server.ovpn_b64.is_empty() {
        server.ovpn_b64.as_str()
    } else {
        donor_b64
    };
    if b64.is_empty() {
        return None;
    }
    let mut padded = b64.trim().as_bytes().to_vec();
    while padded.len() % 4 != 0 {
        padded.push(b'=');
    }
    let decoded = BASE64_STD.decode(&padded).ok()?;
    let raw = String::from_utf8_lossy(&decoded);
    if !raw.contains("<ca>") {
        return None;
    }
    Some(patch_ovpn_text(&raw, server, opts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobileconfig_contains_psk_and_managed_vpn() {
        let srv = Server {
            hostname: "jp".into(),
            ip: "219.100.37.10".into(),
            score: 1,
            ping_ms: 20,
            speed_bps: 1,
            country_long: "Japan".into(),
            country_short: "JP".into(),
            sessions: 0,
            uptime_ms: 0,
            operator: "op".into(),
            l2tp: true,
            openvpn: true,
            tcp_port: 443,
            udp_port: 1195,
            ovpn_b64: String::new(),
            has_ovpn_cert: false,
            verify_state: None,
            verified_port: None,
            verified_rtt_ms: None,
            unlocked: Vec::new(),
            locked: Vec::new(),
            dead_until: 0,
        };
        let xml = build_apple_l2tp_mobileconfig(&srv, &["1.1.1.1".into(), "1.0.0.1".into()]);
        assert!(xml.contains("com.apple.vpn.managed"));
        assert!(xml.contains("dnBu")); // base64("vpn")
        let patched = patch_ovpn_text(
            "client\ndev tun\nproto udp\nremote 10.0.0.1 1194\ncipher AES-128-CBC\nauth-user-pass\n<ca>\nCERT\n</ca>\n",
            &srv,
            &OvpnOpts {
                transport: "udp",
                compat: "mobile3",
                dns_servers: &["1.1.1.1".into(), "1.0.0.1".into()],
                windows_driver: "",
            },
        );
        assert!(patched.contains("remote 219.100.37.10 1195"));
        assert!(!patched.contains("auth-user-pass"));
    }
}
