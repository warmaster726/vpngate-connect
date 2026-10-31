//! Isolated Cloudflare Worker — VPN Gate Connect profile console.
//! Browser UI is HTML/CSS/JS; edge logic is Rust (`workers-rs`).

mod bootstrap;
mod country;
mod model;
mod parse;
mod portal;
mod profile;
mod timeutil;

#[cfg(target_arch = "wasm32")]
mod discover;
#[cfg(target_arch = "wasm32")]
mod fetchutil;
#[cfg(target_arch = "wasm32")]
mod verify;

#[cfg(target_arch = "wasm32")]
use worker::*;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
async fn main(req: Request, _env: Env, ctx: Context) -> Result<Response> {
    edge::handle(req, ctx).await
}

#[cfg(target_arch = "wasm32")]
mod edge {
    use super::*;
    use crate::bootstrap::{
        format_mirror_seed, is_safe_dns_name, is_safe_git_ref, servers_to_vpngate_csv,
        DESKTOP_VERSION, INSTALL_PS1, INSTALL_SH, REPO_SLUG,
    };
    use crate::discover::{fetch_text, get_pool_snapshot, probe_mirrors};
    use crate::model::{Server, APP_VERSION, HANDSHAKE_TIMEOUT_MS, USER_AGENT};
    use crate::parse::valid_public_ipv4;
    use crate::portal::{render_portal_html, ICON_SVG};
    use crate::profile::{
        build_apple_l2tp_mobileconfig, build_patched_ovpn, patch_ovpn_text, sanitize_dns_list,
        OvpnOpts,
    };
    use crate::timeutil::now_ms;
    use crate::verify::{
        assert_verified_for_profile, decorate_servers, ensure_verify_memory,
        probe_openvpn_handshake, recursive_verify_relays, remember_probe,
    };
    use serde_json::{json, Value};

    fn json_response(payload: &Value, status: u16) -> Result<Response> {
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/json; charset=utf-8")?;
        headers.set("X-Content-Type-Options", "nosniff")?;
        headers.set("Referrer-Policy", "no-referrer")?;
        headers.set("Cache-Control", "no-store")?;
        Ok(Response::from_json(payload)?
            .with_status(status)
            .with_headers(headers))
    }

    fn param(url: &Url, key: &str) -> String {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    }

    fn text_response(body: &str, content_type: &str, cache: &str) -> Result<Response> {
        let mut headers = Headers::new();
        headers.set("Content-Type", content_type)?;
        headers.set("X-Content-Type-Options", "nosniff")?;
        headers.set("Cache-Control", cache)?;
        Ok(Response::ok(body)?.with_headers(headers))
    }

    async fn fetch_bytes(url: &str, extra: &[(&str, &str)]) -> Option<(u16, Vec<u8>)> {
        let mut headers = Headers::new();
        let _ = headers.set("User-Agent", USER_AGENT);
        for (k, v) in extra {
            let _ = headers.set(*k, *v);
        }
        let mut init = RequestInit::new();
        init.method = Method::Get;
        init.headers = headers;
        let req = Request::new_with_init(url, &init).ok()?;
        let mut resp = Fetch::Request(req).send().await.ok()?;
        let status = resp.status_code();
        let bytes = resp.bytes().await.ok()?;
        Some((status, bytes))
    }

    async fn proxy_github_archive(kind: &str, branch: &str) -> Result<Response> {
        let (url, ctype, fname) = if kind == "zip" {
            (
                format!("https://codeload.github.com/{REPO_SLUG}/zip/refs/heads/{branch}"),
                "application/zip",
                "vpngate-connect.zip",
            )
        } else {
            (
                format!("https://codeload.github.com/{REPO_SLUG}/tar.gz/refs/heads/{branch}"),
                "application/gzip",
                "vpngate-connect.tar.gz",
            )
        };
        let Some((status, bytes)) = fetch_bytes(&url, &[]).await else {
            return json_response(
                &json!({"ok": false, "error": "Upstream source archive unreachable."}),
                502,
            );
        };
        if !(200..300).contains(&status) || bytes.len() < 64 {
            return json_response(
                &json!({"ok": false, "error": "Upstream source archive unavailable.", "status": status}),
                502,
            );
        }
        let mut headers = Headers::new();
        headers.set("Content-Type", ctype)?;
        headers.set(
            "Content-Disposition",
            &format!("attachment; filename=\"{fname}\""),
        )?;
        headers.set("Cache-Control", "public, max-age=300")?;
        Ok(Response::from_bytes(bytes)?.with_headers(headers))
    }

    pub async fn handle(req: Request, ctx: Context) -> Result<Response> {
        ensure_verify_memory(&ctx).await;
        let url = req.url()?;
        let path = url.path().to_string();
        match req.method() {
            Method::Get | Method::Head => {}
            _ => {
                return json_response(&json!({"ok": false, "error": "Method Not Allowed"}), 405);
            }
        }

        if path == "/install.sh" || path == "/install-vpngate.sh" {
            return text_response(
                INSTALL_SH,
                "text/x-shellscript; charset=utf-8",
                "public, max-age=300",
            );
        }
        if path == "/install.ps1" || path == "/install-vpngate.ps1" {
            return text_response(
                INSTALL_PS1,
                "text/plain; charset=utf-8",
                "public, max-age=300",
            );
        }
        if path == "/desktop-version.txt" {
            return text_response(
                DESKTOP_VERSION.trim(),
                "text/plain; charset=utf-8",
                "public, max-age=60",
            );
        }
        if path == "/edge.json" {
            let origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));
            return json_response(
                &json!({
                    "ok": true,
                    "version": APP_VERSION,
                    "desktop_version": DESKTOP_VERSION.trim(),
                    "origin": origin,
                    "workers_dev_only": true,
                    "endpoints": {
                        "install_sh": "/install.sh",
                        "install_ps1": "/install.ps1",
                        "desktop_version": "/desktop-version.txt",
                        "api_servers": "/api/servers",
                        "api_csv": "/api.csv",
                        "dns_query": "/dns-query",
                        "src_tar": "/src.tar.gz",
                        "src_zip": "/src.zip",
                        "seed": "/seed.txt"
                    },
                    "binaries": {
                        "hosted": false,
                        "reason": "Cloudflare Workers script limits are about 1 MB (free) / 10 MB (paid). Desktop tarballs exceed that, so this Worker proxies source (/src.tar.gz) and install scripts instead of prebuilt binaries."
                    }
                }),
                200,
            );
        }
        if path == "/artifact" || path == "/artifact/" || path.starts_with("/artifact/") {
            return json_response(
                &json!({
                    "ok": false,
                    "error": "Desktop binaries are not hosted on Cloudflare Workers (size limit ~1 MB free / ~10 MB paid).",
                    "use": ["/install.sh", "/src.tar.gz"]
                }),
                404,
            );
        }
        if path == "/src.tar.gz" || path == "/src.zip" {
            let branch_raw = param(&url, "branch");
            let branch = if branch_raw.is_empty() {
                "main"
            } else if is_safe_git_ref(&branch_raw) {
                branch_raw.as_str()
            } else {
                return json_response(&json!({"ok": false, "error": "Invalid branch."}), 400);
            };
            let kind = if path.ends_with(".zip") { "zip" } else { "tar" };
            return proxy_github_archive(kind, branch).await;
        }
        if path == "/dns-query" {
            let name = param(&url, "name");
            if !is_safe_dns_name(&name) {
                return json_response(
                    &json!({"ok": false, "error": "Valid DNS 'name' is required."}),
                    400,
                );
            }
            let qtype_raw = param(&url, "type");
            let qtype = if qtype_raw.is_empty() {
                "A"
            } else {
                qtype_raw.as_str()
            };
            if !qtype.chars().all(|c| c.is_ascii_alphanumeric()) || qtype.len() > 8 {
                return json_response(&json!({"ok": false, "error": "Invalid DNS type."}), 400);
            }
            let upstream = format!("https://cloudflare-dns.com/dns-query?name={name}&type={qtype}");
            let Some((status, bytes)) =
                fetch_bytes(&upstream, &[("Accept", "application/dns-json")]).await
            else {
                return json_response(
                    &json!({"ok": false, "error": "DoH upstream unreachable."}),
                    502,
                );
            };
            if !(200..300).contains(&status) {
                return json_response(
                    &json!({"ok": false, "error": "DoH upstream failed.", "status": status}),
                    502,
                );
            }
            let body = String::from_utf8_lossy(&bytes).into_owned();
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/dns-json")?;
            headers.set("Cache-Control", "no-store")?;
            return Ok(Response::ok(body)?.with_headers(headers));
        }
        if path == "/seed.txt" || path == "/mirrors.txt" {
            let snap = get_pool_snapshot(&ctx, false, "").await;
            let body = format_mirror_seed(&snap.public_payload.mirrors);
            return text_response(&body, "text/plain; charset=utf-8", "no-store");
        }
        if path == "/api.csv" || path == "/api/iphone" || path == "/api/iphone/" {
            let snap = get_pool_snapshot(&ctx, false, "").await;
            let csv = servers_to_vpngate_csv(&snap.public_payload.servers, &snap.ovpn_by_ip);
            return text_response(&csv, "text/csv; charset=utf-8", "no-store");
        }

        if path == "/manifest.webmanifest" {
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/manifest+json; charset=utf-8")?;
            headers.set("X-Content-Type-Options", "nosniff")?;
            headers.set("Referrer-Policy", "no-referrer")?;
            headers.set("Cache-Control", "no-store")?;
            return Ok(Response::from_json(&json!({
                "name": "VPN Gate Connect",
                "short_name": "VPN Gate",
                "start_url": "/",
                "display": "standalone",
                "background_color": "#070B14",
                "theme_color": "#070B14",
                "icons": [{ "src": "/icon.svg", "sizes": "any", "type": "image/svg+xml" }],
            }))?
            .with_headers(headers));
        }

        if path == "/icon.svg" {
            let mut headers = Headers::new();
            headers.set("Content-Type", "image/svg+xml; charset=utf-8")?;
            headers.set("Cache-Control", "public, max-age=86400")?;
            return Ok(Response::ok(ICON_SVG)?.with_headers(headers));
        }

        if (path.starts_with("/profiles/") && path.ends_with(".mobileconfig"))
            || path == "/api/profile/mobileconfig"
        {
            let ip = match valid_public_ipv4(&param(&url, "ip")) {
                Some(ip) => ip,
                None => {
                    return json_response(
                        &json!({"ok": false, "error": "Valid public IPv4 'ip' parameter is required."}),
                        400,
                    );
                }
            };
            let gate = assert_verified_for_profile(&ctx, &ip, "l2tp").await;
            if let Some(err) = gate.error {
                return json_response(
                    &json!({
                        "ok": false,
                        "error": err,
                        "ip": ip,
                        "handshake": gate.verified,
                    }),
                    gate.status,
                );
            }
            let dns = sanitize_dns_list(Some(&param(&url, "dns")));
            let found = gate.found.unwrap();
            let xml = build_apple_l2tp_mobileconfig(&found, &dns);
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/x-apple-aspen-config")?;
            headers.set("Cache-Control", "no-store")?;
            return Ok(Response::ok(xml)?.with_headers(headers));
        }

        if (path.starts_with("/profiles/") && path.ends_with(".ovpn"))
            || path == "/api/profile/ovpn"
        {
            let ip = match valid_public_ipv4(&param(&url, "ip")) {
                Some(ip) => ip,
                None => {
                    return json_response(
                        &json!({"ok": false, "error": "Valid public IPv4 'ip' parameter is required."}),
                        400,
                    );
                }
            };
            let transport = if param(&url, "proto") == "tcp" {
                "tcp"
            } else {
                "udp"
            };
            let compat_raw = param(&url, "compat");
            let compat = match compat_raw.as_str() {
                "ovpn26" | "ovpn25" | "ovpn24" | "mobile3" => compat_raw.as_str(),
                _ => "mobile3",
            };
            let dns = sanitize_dns_list(Some(&param(&url, "dns")));
            let win_drv = param(&url, "windows_driver");
            let gate = assert_verified_for_profile(&ctx, &ip, transport).await;
            if let Some(err) = gate.error {
                return json_response(
                    &json!({
                        "ok": false,
                        "error": err,
                        "ip": ip,
                        "handshake": gate.verified,
                    }),
                    gate.status,
                );
            }
            let mut srv = gate.found.unwrap();
            let snap = gate.snap.unwrap();
            if let Some(b64) = snap.ovpn_by_ip.get(&ip).and_then(|v| v.as_str()) {
                srv.ovpn_b64 = b64.to_string();
            }
            if let Some(v) = &gate.verified {
                if v.port > 0 {
                    srv.tcp_port = v.port;
                }
            }
            let patched = build_patched_ovpn(
                &srv,
                &snap.donor_ovpn_b64,
                &OvpnOpts {
                    transport,
                    compat,
                    dns_servers: &dns,
                    windows_driver: &win_drv,
                },
            );
            let Some(patched) = patched else {
                return json_response(
                    &json!({"ok": false, "error": "OpenVPN configuration certificate unavailable for this relay."}),
                    404,
                );
            };
            let cc = if srv.country_short.len() == 2
                && srv.country_short.chars().all(|c| c.is_ascii_uppercase())
            {
                srv.country_short.clone()
            } else {
                "VG".into()
            };
            let file_name = format!("vpngate-{cc}-{ip}-{transport}.ovpn");
            let dest = req.headers().get("Sec-Fetch-Dest")?.unwrap_or_default();
            let mode = req.headers().get("Sec-Fetch-Mode")?.unwrap_or_default();
            let ua = req.headers().get("User-Agent")?.unwrap_or_default();
            let ovpn_client = ua.to_ascii_lowercase().contains("openvpn");
            if !ovpn_client && (mode == "navigate" || dest == "document") {
                let home = url.join("/")?;
                return Response::redirect_with_status(home, 303);
            }
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/x-openvpn-profile")?;
            headers.set(
                "Content-Disposition",
                &format!(
                    "attachment; filename=\"{file_name}\"; filename*=UTF-8''{}",
                    utf8_percent(&file_name)
                ),
            )?;
            headers.set("X-Content-Type-Options", "nosniff")?;
            headers.set("Cache-Control", "no-store")?;
            return Ok(Response::ok(patched)?.with_headers(headers));
        }

        if path == "/api/servers" {
            let force = param(&url, "refresh") == "1";
            let custom = param(&url, "mirror");
            let snap = get_pool_snapshot(&ctx, force, custom.trim()).await;
            let servers = decorate_servers(&snap.public_payload.servers);
            let live = servers
                .iter()
                .filter(|s| s.verify_state.as_deref() == Some("live"))
                .count();
            let mut payload = serde_json::to_value(&snap.public_payload).unwrap_or(json!({}));
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("servers".into(), serde_json::to_value(&servers)?);
                let mut counts = snap.public_payload.counts.clone();
                counts.live = Some(live);
                obj.insert("counts".into(), serde_json::to_value(&counts)?);
                obj.insert("cached".into(), json!(false));
            }
            return json_response(&payload, 200);
        }

        if path == "/api/mirrors" {
            let want_probe = param(&url, "probe") == "1";
            if !want_probe {
                let snap = get_pool_snapshot(&ctx, false, "").await;
                let mirrors = snap.public_payload.mirrors;
                return json_response(&json!({"ok": true, "mirrors": mirrors}), 200);
            }
            let (online, mirrors) = probe_mirrors(&ctx).await;
            return json_response(
                &json!({"ok": true, "online_count": online, "mirrors": mirrors}),
                200,
            );
        }

        if path == "/api/verify" {
            let snap = get_pool_snapshot(&ctx, false, "").await;
            let servers = decorate_servers(&snap.public_payload.servers);
            let ip = valid_public_ipv4(&param(&url, "ip")).unwrap_or_default();
            let proto = param(&url, "proto").to_ascii_lowercase();
            let proto = if proto.is_empty() {
                "auto".into()
            } else {
                proto
            };
            let country = {
                let c = param(&url, "country");
                if c.is_empty() {
                    "ALL".into()
                } else {
                    c
                }
            };
            let sort_raw = param(&url, "sort").to_ascii_lowercase();
            let sort = match sort_raw.as_str() {
                "speed" | "ping" | "score" | "recommended" => sort_raw,
                _ => "recommended".into(),
            };
            let force = param(&url, "force") == "1";
            let exclude: Vec<String> = param(&url, "exclude")
                .split(',')
                .filter_map(|s| valid_public_ipv4(s.trim()))
                .collect();
            let result = recursive_verify_relays(
                &servers,
                &country,
                &proto,
                &sort,
                &exclude,
                &ip,
                force,
                Some(&ctx),
            )
            .await;
            if result.verified.is_none() {
                return json_response(
                    &json!({
                        "ok": true,
                        "verified": null,
                        "attempts": result.attempts,
                        "scanned": result.scanned,
                        "widened": result.widened,
                        "remaining": result.remaining,
                        "error": "No candidate completed a live OpenVPN TCP handshake.",
                    }),
                    200,
                );
            }
            let mut v = serde_json::to_value(&result)?;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("ok".into(), json!(true));
            }
            return json_response(&v, 200);
        }

        if path == "/api/probe" {
            let ip = valid_public_ipv4(&param(&url, "ip"));
            let port: u16 = param(&url, "port").parse().unwrap_or(0);
            let Some(ip) = ip else {
                return json_response(
                    &json!({"ok": false, "error": "Valid public IPv4 'ip' and TCP 'port' are required."}),
                    400,
                );
            };
            if port == 0 {
                return json_response(
                    &json!({"ok": false, "error": "Valid public IPv4 'ip' and TCP 'port' are required."}),
                    400,
                );
            }
            let snap = get_pool_snapshot(&ctx, false, "").await;
            if !snap.public_payload.servers.iter().any(|s| s.ip == ip) {
                return json_response(
                    &json!({"ok": false, "error": "Target IP is not an active VPN Gate relay."}),
                    403,
                );
            }
            let res = probe_openvpn_handshake(&ip, port, HANDSHAKE_TIMEOUT_MS).await;
            remember_probe(&ip, res.clone(), &ctx);
            let mut payload = serde_json::to_value(&res)?;
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("ok".into(), json!(true));
                obj.insert("ip".into(), json!(ip));
                obj.insert("port".into(), json!(port));
                obj.insert("reachable".into(), json!(res.tcp_handshake));
                obj.insert("handshake".into(), json!(res.tcp_handshake));
            }
            return json_response(&payload, 200);
        }

        if path == "/api/doctor" {
            return handle_doctor(req, &ctx).await;
        }

        if path == "/" || path == "/index.html" {
            let mut headers = Headers::new();
            headers.set("Content-Type", "text/html; charset=utf-8")?;
            headers.set(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            )?;
            headers.set("X-Content-Type-Options", "nosniff")?;
            headers.set("Referrer-Policy", "no-referrer")?;
            headers.set(
                "Permissions-Policy",
                "geolocation=(), microphone=(), camera=()",
            )?;
            return Ok(Response::ok(render_portal_html())?.with_headers(headers));
        }

        json_response(&json!({"ok": false, "error": "Not Found"}), 404)
    }

    async fn handle_doctor(req: Request, ctx: &Context) -> Result<Response> {
        let mut checks = Vec::new();
        let visitor = req
            .headers()
            .get("CF-Connecting-IP")?
            .unwrap_or_else(|| "client".into());
        let (colo, country, proto, tls) = if let Some(cf) = req.cf() {
            (
                cf.colo(),
                cf.country().unwrap_or_else(|| "XX".into()),
                cf.http_protocol(),
                cf.tls_version(),
            )
        } else {
            (
                "LOCAL".into(),
                "XX".into(),
                "HTTP/2".into(),
                "TLSv1.3".into(),
            )
        };
        checks.push(json!({
            "name": "Visitor Egress & Cloudflare PoP",
            "status": "READY",
            "detail": format!("Client {visitor} · Edge PoP {colo} ({country}) · {proto} {tls}"),
        }));

        let doh_start = now_ms();
        let doh_upstreams = [
            "https://cloudflare-dns.com/dns-query?name=www.vpngate.net&type=A",
            "https://dns.google/resolve?name=www.vpngate.net&type=A",
            "https://dns.quad9.net/dns-query?name=www.vpngate.net&type=A",
        ];
        let mut doh_hit: Option<(String, Vec<String>)> = None;
        for upstream in doh_upstreams {
            if let Some(text) =
                fetch_text(upstream, 2500, &[("Accept", "application/dns-json")]).await
            {
                let parsed: Value = serde_json::from_str(&text).unwrap_or(json!({}));
                let ips: Vec<String> = parsed
                    .get("Answer")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(1))
                            .filter_map(|a| a.get("data").and_then(|d| d.as_str()))
                            .filter_map(valid_public_ipv4)
                            .collect()
                    })
                    .unwrap_or_default();
                if !ips.is_empty() {
                    let label = if upstream.contains("dns.google") {
                        "Google 8.8.8.8"
                    } else if upstream.contains("quad9") {
                        "Quad9 9.9.9.9"
                    } else {
                        "Cloudflare 1.1.1.1"
                    };
                    doh_hit = Some((label.to_string(), ips));
                    break;
                }
            }
        }
        match doh_hit {
            Some((label, ips)) => {
                checks.push(json!({
                    "name": "DoH mesh (1.1.1.1 / 8.8.8.8 / 9.9.9.9)",
                    "status": "READY",
                    "detail": format!(
                        "{label} resolved www.vpngate.net → {} ({} ms, bogon-verified)",
                        ips.join(", "),
                        now_ms().saturating_sub(doh_start)
                    ),
                }));
            }
            None => {
                checks.push(json!({
                    "name": "DoH mesh (1.1.1.1 / 8.8.8.8 / 9.9.9.9)",
                    "status": "WARN",
                    "detail": "No DoH upstream returned unpoisoned IPv4 A records",
                }));
            }
        }

        let snap = get_pool_snapshot(ctx, false, "").await;
        let counts = &snap.public_payload.counts;
        checks.push(json!({
            "name": "Multi-Source Relay & Mirror Pool",
            "status": if counts.total > 0 { "READY" } else { "ISSUE" },
            "detail": format!(
                "{} listed relays ({} L2TP/IPsec, {} OpenVPN) · {} Official Mirrors",
                counts.total, counts.l2tp, counts.openvpn, counts.mirrors
            ),
        }));

        if let Some(tcp_candidate) = snap.public_payload.servers.iter().find(|s| s.tcp_port > 0) {
            let p_res = probe_openvpn_handshake(
                &tcp_candidate.ip,
                tcp_candidate.tcp_port,
                HANDSHAKE_TIMEOUT_MS,
            )
            .await;
            checks.push(json!({
                "name": "Live OpenVPN TCP Handshake",
                "status": if p_res.tcp_handshake { "READY" } else { "WARN" },
                "detail": if p_res.tcp_handshake {
                    format!(
                        "HARD_RESET_SERVER_V2 from {}:{} in {} ms",
                        tcp_candidate.ip,
                        tcp_candidate.tcp_port,
                        p_res.rtt_ms.unwrap_or(0)
                    )
                } else {
                    format!(
                        "{}: {}",
                        p_res.engine,
                        p_res.error.unwrap_or_else(|| "relay did not complete OpenVPN handshake".into())
                    )
                },
            }));
        } else {
            checks.push(json!({
                "name": "Live OpenVPN TCP Handshake",
                "status": "WARN",
                "detail": "No TCP-advertised relay currently in the pool",
            }));
        }

        let dummy = Server {
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
        let mc_xml = build_apple_l2tp_mobileconfig(&dummy, &["1.1.1.1".into(), "1.0.0.1".into()]);
        let sample = patch_ovpn_text(
            "client\ndev tun\nproto udp\nremote 10.0.0.1 1194\ncipher AES-128-CBC\nauth-user-pass\n<ca>\nCERT\n</ca>\n",
            &dummy,
            &OvpnOpts {
                transport: "udp",
                compat: "mobile3",
                dns_servers: &["1.1.1.1".into(), "1.0.0.1".into()],
                windows_driver: "",
            },
        );
        let profile_ok = mc_xml.contains("com.apple.vpn.managed")
            && mc_xml.contains("dnBu")
            && sample.contains("remote 219.100.37.10 1195")
            && !sample.contains("auth-user-pass");
        checks.push(json!({
            "name": "Profile Engine (.mobileconfig & .ovpn Patcher)",
            "status": if profile_ok { "READY" } else { "ISSUE" },
            "detail": if profile_ok {
                "Generators healthy — delivery remains gated on a live OpenVPN HARD_RESET for the target relay"
            } else {
                "Profile self-test mismatch"
            },
        }));
        checks.push(json!({
            "name": "Profile Gate (handshake required)",
            "status": "READY",
            "detail": "GET /profiles/*.mobileconfig and GET /profiles/*.ovpn refuse issuance unless the relay answers OpenVPN TCP HARD_RESET_SERVER_V2",
        }));
        let _ = APP_VERSION;
        json_response(&json!({"ok": true, "checks": checks}), 200)
    }

    fn utf8_percent(s: &str) -> String {
        s.bytes().map(|b| format!("%{b:02X}")).collect()
    }
}
