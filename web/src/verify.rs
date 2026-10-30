use std::cell::RefCell;
use std::collections::HashMap;

use futures::future::{select, Either};
use gloo_timers::future::TimeoutFuture;
use serde::Serialize;
use serde_json::json;
use std::pin::pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Cache, Context, Response, SecureTransport, Socket};

use crate::discover::get_pool_snapshot;
use crate::model::{
    LockedKind, Server, VerifyRec, DEAD_PENALTY_MS, HANDSHAKE_TIMEOUT_MS, VERIFY_FAIL_TTL_MS,
    VERIFY_IP_CACHE_PREFIX, VERIFY_MEM_CACHE_URL, VERIFY_OK_TTL_MS,
};
use crate::parse::sort_servers_desktop;
use crate::timeutil::now_ms;

const OPENVPN_HARD_RESET_CLIENT_V2: u8 = 0x38;
const OPENVPN_HARD_RESET_SERVER_V2: u8 = 0x40;

thread_local! {
    static VERIFIED: RefCell<HashMap<String, VerifyRec>> = RefCell::new(HashMap::new());
    static LOADED: RefCell<bool> = RefCell::new(false);
}

fn verify_record_ttl(rec: &VerifyRec) -> u64 {
    if rec.ok {
        VERIFY_OK_TTL_MS
    } else {
        VERIFY_FAIL_TTL_MS
    }
}

fn wait_until_put(ctx: &Context, url: String, body: String, max_age: u64) {
    ctx.wait_until(async move {
        let mut headers = worker::Headers::new();
        let _ = headers.set("Content-Type", "application/json");
        let _ = headers.set("Cache-Control", &format!("public, max-age={max_age}"));
        if let Ok(resp) = Response::ok(body) {
            let resp = resp.with_headers(headers);
            let _ = Cache::default().put(url.as_str(), resp).await;
        }
    });
}

fn persist_verify_ip(ip: &str, rec: &VerifyRec, ctx: &Context) {
    let ttl = verify_record_ttl(rec);
    if let Ok(body) = serde_json::to_string(rec) {
        wait_until_put(
            ctx,
            format!("{VERIFY_IP_CACHE_PREFIX}{ip}"),
            body,
            (ttl / 1000).max(1),
        );
    }
}

fn persist_verify_memory(ctx: &Context) {
    let now = now_ms();
    let entries = VERIFIED.with(|m| {
        let mut entries = serde_json::Map::new();
        for (ip, rec) in m.borrow().iter() {
            if now.saturating_sub(rec.ts) <= verify_record_ttl(rec) {
                if let Ok(v) = serde_json::to_value(rec) {
                    entries.insert(ip.clone(), v);
                }
            }
        }
        entries
    });
    let body = json!({ "entries": entries, "saved_at": now }).to_string();
    wait_until_put(ctx, VERIFY_MEM_CACHE_URL.into(), body, DEAD_PENALTY_MS / 1000);
}

fn remember_verify(ip: &str, rec: VerifyRec, ctx: Option<&Context>) -> VerifyRec {
    let mut stored = rec;
    stored.ts = now_ms();
    VERIFIED.with(|m| {
        m.borrow_mut().insert(ip.to_string(), stored.clone());
    });
    if let Some(ctx) = ctx {
        persist_verify_ip(ip, &stored, ctx);
        persist_verify_memory(ctx);
    }
    stored
}

fn recall_verify_sync(ip: &str) -> Option<VerifyRec> {
    VERIFIED.with(|m| {
        let mut map = m.borrow_mut();
        let rec = map.get(ip).cloned()?;
        if now_ms().saturating_sub(rec.ts) > verify_record_ttl(&rec) {
            map.remove(ip);
            return None;
        }
        Some(rec)
    })
}

async fn recall_verify(ip: &str) -> Option<VerifyRec> {
    if let Some(hit) = recall_verify_sync(ip) {
        return Some(hit);
    }
    let cache = Cache::default();
    let key = format!("{VERIFY_IP_CACHE_PREFIX}{ip}");
    let mut cached = cache.get(key.as_str(), false).await.ok().flatten()?;
    let rec: VerifyRec = cached.json().await.ok()?;
    if now_ms().saturating_sub(rec.ts) > verify_record_ttl(&rec) {
        return None;
    }
    VERIFIED.with(|m| {
        m.borrow_mut().insert(ip.to_string(), rec.clone());
    });
    Some(rec)
}

pub async fn ensure_verify_memory(_ctx: &Context) {
    let already = LOADED.with(|c| *c.borrow());
    if already {
        return;
    }
    LOADED.with(|c| *c.borrow_mut() = true);
    VERIFIED.with(|m| m.borrow_mut().clear());
    let cache = Cache::default();
    if let Ok(Some(mut hit)) = cache.get(VERIFY_MEM_CACHE_URL, false).await {
        if let Ok(parsed) = hit.json::<serde_json::Value>().await {
            let now = now_ms();
            if let Some(entries) = parsed.get("entries").and_then(|v| v.as_object()) {
                VERIFIED.with(|m| {
                    let mut map = m.borrow_mut();
                    for (ip, rec_v) in entries {
                        if let Ok(rec) = serde_json::from_value::<VerifyRec>(rec_v.clone()) {
                            if now.saturating_sub(rec.ts) <= verify_record_ttl(&rec) {
                                map.insert(ip.clone(), rec);
                            }
                        }
                    }
                });
            }
        }
    }
}

pub fn advertised_profile_kinds(server: &Server) -> Vec<String> {
    let mut kinds = Vec::new();
    if server.l2tp {
        kinds.push("l2tp".into());
    }
    if server.supports_openvpn_udp() {
        kinds.push("udp".into());
    }
    if server.supports_openvpn_tcp() {
        kinds.push("tcp".into());
    }
    kinds
}

pub fn profile_availability(server: &Server, result: &VerifyRec) -> (Vec<String>, Vec<LockedKind>) {
    let mut unlocked = Vec::new();
    let mut locked = Vec::new();
    let tcp_hs = result.tcp_handshake
        || (result.ok && result.engine == "openvpn-tcp-v2" && result.tcp_handshake);
    let tcp_hs = tcp_hs || (result.ok && result.engine == "openvpn-tcp-v2");
    let host_up = result.host_up || result.tcp_open || tcp_hs;
    let adv_tcp = server.supports_openvpn_tcp();
    let adv_udp = server.supports_openvpn_udp();
    let adv_l2tp = server.l2tp;
    if adv_tcp {
        if tcp_hs {
            unlocked.push("tcp".into());
        } else {
            locked.push(LockedKind {
                kind: "tcp".into(),
                reason: "no OpenVPN HARD_RESET".into(),
            });
        }
    }
    if adv_udp {
        if tcp_hs {
            unlocked.push("udp".into());
        } else if !adv_tcp && host_up {
            unlocked.push("udp".into());
        } else {
            locked.push(LockedKind {
                kind: "udp".into(),
                reason: "OpenVPN not live".into(),
            });
        }
    }
    if adv_l2tp {
        if host_up || tcp_hs {
            unlocked.push("l2tp".into());
        } else {
            locked.push(LockedKind {
                kind: "l2tp".into(),
                reason: "host unreachable".into(),
            });
        }
    }
    (unlocked, locked)
}

fn build_openvpn_hard_reset() -> ([u8; 16], [u8; 8]) {
    let sid = now_ms().to_le_bytes();
    let mut pkt = [0u8; 16];
    pkt[1] = 14;
    pkt[2] = OPENVPN_HARD_RESET_CLIENT_V2;
    pkt[3..11].copy_from_slice(&sid);
    pkt[11] = 0;
    (pkt, sid)
}

fn buffer_contains_sid(buf: &[u8], sid: &[u8; 8]) -> bool {
    if buf.len() < 8 {
        return false;
    }
    buf.windows(8).any(|w| w == sid)
}

fn parse_openvpn_hard_reset_reply(buf: &[u8], client_sid: &[u8; 8]) -> bool {
    if buf.len() < 16 {
        return false;
    }
    let opcode = buf[2];
    if opcode & 0xf8 != OPENVPN_HARD_RESET_SERVER_V2 {
        return false;
    }
    buffer_contains_sid(buf, client_sid)
}

async fn with_timeout<T>(ms: u32, fut: impl std::future::Future<Output = T>) -> Option<T> {
    let mut f = pin!(fut);
    let mut t = pin!(TimeoutFuture::new(ms));
    match select(f, t).await {
        Either::Left((v, _)) => Some(v),
        Either::Right(_) => None,
    }
}

async fn read_socket_bytes(socket: &mut Socket, min_bytes: usize, deadline_ms: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    while out.len() < min_bytes {
        let remain = deadline_ms.saturating_sub(now_ms()).max(1) as u32;
        let read_fut = socket.read(&mut buf);
        match with_timeout(remain, read_fut).await {
            Some(Ok(0)) | None => break,
            Some(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Some(Err(_)) => break,
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

pub async fn probe_openvpn_handshake(ip: &str, port: u16, timeout_ms: u64) -> VerifyRec {
    let t0 = now_ms();
    let deadline = t0 + timeout_ms;
    let built = Socket::builder()
        .secure_transport(SecureTransport::Off)
        .connect(ip, port);
    let mut socket = match built {
        Ok(s) => s,
        Err(e) => {
            return VerifyRec {
                ok: false,
                port,
                rtt_ms: None,
                engine: "openvpn-tcp-v2".into(),
                error: Some(e.to_string()),
                ..VerifyRec::default()
            };
        }
    };
    match with_timeout(timeout_ms as u32, socket.opened()).await {
        Some(Ok(_)) => {}
        _ => {
            let _ = socket.close().await;
            return VerifyRec {
                ok: false,
                port,
                rtt_ms: None,
                engine: "openvpn-tcp-v2".into(),
                tcp_open: false,
                error: Some("TCP connect timeout".into()),
                ..VerifyRec::default()
            };
        }
    }
    let (pkt, sid) = build_openvpn_hard_reset();
    if socket.write_all(&pkt).await.is_err() {
        let _ = socket.close().await;
        return VerifyRec {
            ok: false,
            port,
            rtt_ms: Some((now_ms().saturating_sub(t0)).max(1)),
            engine: "openvpn-tcp-v2".into(),
            tcp_open: true,
            host_up: true,
            error: Some("write failed".into()),
            ..VerifyRec::default()
        };
    }
    let buf = read_socket_bytes(&mut socket, 16, deadline).await;
    let _ = socket.close().await;
    let handshake = buf
        .as_deref()
        .map(|b| parse_openvpn_hard_reset_reply(b, &sid))
        .unwrap_or(false);
    VerifyRec {
        ok: handshake,
        port,
        rtt_ms: Some((now_ms().saturating_sub(t0)).max(1)),
        engine: "openvpn-tcp-v2".into(),
        tcp_handshake: handshake,
        host_up: true,
        tcp_open: true,
        error: if handshake {
            None
        } else {
            Some("no OpenVPN HARD_RESET_SERVER_V2".into())
        },
        ..VerifyRec::default()
    }
}

async fn probe_tcp_connect(ip: &str, port: u16, timeout_ms: u64) -> VerifyRec {
    let t0 = now_ms();
    let mut socket = match Socket::builder()
        .secure_transport(SecureTransport::Off)
        .connect(ip, port)
    {
        Ok(s) => s,
        Err(e) => {
            return VerifyRec {
                ok: false,
                port,
                engine: "tcp-connect".into(),
                error: Some(e.to_string()),
                ..VerifyRec::default()
            };
        }
    };
    let opened = with_timeout(timeout_ms as u32, socket.opened()).await;
    let _ = socket.close().await;
    match opened {
        Some(Ok(_)) => VerifyRec {
            ok: true,
            port,
            rtt_ms: Some((now_ms().saturating_sub(t0)).max(1)),
            engine: "tcp-connect".into(),
            host_up: true,
            tcp_open: true,
            ..VerifyRec::default()
        },
        _ => VerifyRec {
            ok: false,
            port,
            engine: "tcp-connect".into(),
            error: Some("TCP connect timeout".into()),
            ..VerifyRec::default()
        },
    }
}

fn ports_to_probe(server: &Server) -> Vec<u16> {
    let mut ports = Vec::new();
    if server.tcp_port > 0 {
        ports.push(server.tcp_port);
    }
    for p in [443u16, 995, 5555] {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    ports.into_iter().take(1).collect()
}

async fn verify_relay(server: &Server) -> VerifyRec {
    let adv_tcp = server.supports_openvpn_tcp();
    let adv_udp = server.supports_openvpn_udp();
    let adv_l2tp = server.l2tp;
    let ports = ports_to_probe(server);
    let port0 = *ports.first().unwrap_or(&443);
    let mut tcp_handshake = false;
    let mut host_up = false;
    let mut port = port0;
    let mut rtt_ms = None;
    let mut engine = "openvpn-tcp-v2".to_string();
    let mut error = Some("no probe".to_string());

    if adv_tcp {
        for p in ports {
            let r = probe_openvpn_handshake(&server.ip, p, HANDSHAKE_TIMEOUT_MS).await;
            port = p;
            rtt_ms = r.rtt_ms;
            engine = r.engine.clone();
            if r.tcp_open {
                host_up = true;
            }
            if r.tcp_handshake {
                tcp_handshake = true;
                host_up = true;
                error = None;
                break;
            }
            error = r.error.clone().or(Some("handshake failed".into()));
        }
    } else if adv_udp || adv_l2tp {
        let r = probe_tcp_connect(&server.ip, port0, HANDSHAKE_TIMEOUT_MS).await;
        host_up = r.ok || r.host_up;
        rtt_ms = r.rtt_ms;
        engine = r.engine;
        error = if host_up {
            None
        } else {
            r.error.or(Some("TCP connect failed".into()))
        };
    }

    let mut rec = VerifyRec {
        ok: false,
        port,
        rtt_ms,
        engine: if tcp_handshake {
            "openvpn-tcp-v2".into()
        } else {
            engine
        },
        tcp_handshake,
        host_up,
        tcp_open: host_up,
        error: error.clone(),
        ..VerifyRec::default()
    };
    let (unlocked, locked) = profile_availability(server, &rec);
    rec.unlocked = unlocked;
    rec.locked = locked;
    rec.ok = !rec.unlocked.is_empty();
    if rec.ok {
        rec.error = None;
    }
    rec
}

async fn verify_relay_cached(server: &Server, force: bool, ctx: Option<&Context>) -> VerifyRec {
    if !force {
        if let Some(hit) = recall_verify(&server.ip).await {
            return hit;
        }
    }
    let res = verify_relay(server).await;
    remember_verify(&server.ip, res, ctx)
}

pub fn decorate_servers(servers: &[Server]) -> Vec<Server> {
    let now = now_ms();
    servers
        .iter()
        .map(|s| {
            let rec = recall_verify_sync(&s.ip);
            let mut out = s.clone();
            let Some(rec) = rec else {
                out.verify_state = Some("untested".into());
                out.unlocked.clear();
                out.locked.clear();
                out.dead_until = 0;
                return out;
            };
            if now.saturating_sub(rec.ts) > verify_record_ttl(&rec) {
                out.verify_state = Some("untested".into());
                out.unlocked.clear();
                out.locked.clear();
                out.dead_until = 0;
                return out;
            }
            let (avail_u, avail_l) = profile_availability(s, &rec);
            let unlocked = if rec.unlocked.is_empty() {
                avail_u
            } else {
                rec.unlocked.clone()
            };
            let locked = if rec.locked.is_empty() {
                avail_l
            } else {
                rec.locked.clone()
            };
            let adv = advertised_profile_kinds(s);
            let full_live = !adv.is_empty() && adv.iter().all(|k| unlocked.contains(k));
            out.verify_state = Some(if rec.ok || !unlocked.is_empty() {
                if full_live {
                    "live".into()
                } else {
                    "partial".into()
                }
            } else {
                "dead".into()
            });
            out.verified_port = Some(rec.port);
            out.verified_rtt_ms = rec.rtt_ms;
            out.unlocked = unlocked;
            out.locked = locked;
            out.dead_until = if rec.ok || !out.unlocked.is_empty() {
                0
            } else {
                rec.ts + DEAD_PENALTY_MS
            };
            out
        })
        .collect()
}

fn match_country(srv: &Server, query: &str) -> bool {
    if query.is_empty() || query.eq_ignore_ascii_case("ALL") || query.eq_ignore_ascii_case("any") {
        return true;
    }
    let q = query.trim();
    let up = q.to_ascii_uppercase();
    if q.len() == 2 && q.chars().all(|c| c.is_ascii_alphabetic()) {
        let iso = if up == "UK" { "GB" } else { up.as_str() };
        return srv.country_short.eq_ignore_ascii_case(iso);
    }
    let low = q.to_ascii_lowercase();
    srv.country_short.eq_ignore_ascii_case(&up) || srv.country_long.to_ascii_lowercase().contains(&low)
}

fn match_proto(srv: &Server, proto: &str) -> bool {
    match proto {
        "" | "auto" | "all" => srv.l2tp || srv.openvpn,
        "l2tp" => srv.l2tp,
        "openvpn" | "ovpn" => srv.openvpn,
        "udp" | "openvpn-udp" => srv.supports_openvpn_udp(),
        "tcp" | "openvpn-tcp" => srv.supports_openvpn_tcp(),
        _ => srv.l2tp || srv.openvpn,
    }
}

#[derive(Serialize)]
pub struct VerifyAttempt {
    pub ip: String,
    pub hostname: String,
    pub country_short: String,
    pub port: u16,
    pub ok: bool,
    pub rtt_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub engine: String,
    pub unlocked: Vec<String>,
    pub locked: Vec<LockedKind>,
    pub tcp_handshake: bool,
    pub host_up: bool,
    pub dead_until: u64,
    pub cached: bool,
}

#[derive(Serialize)]
pub struct VerifyOutcome {
    pub verified: Option<serde_json::Value>,
    pub attempts: Vec<VerifyAttempt>,
    pub scanned: usize,
    pub widened: bool,
    pub remaining: usize,
}

pub async fn recursive_verify_relays(
    servers: &[Server],
    country: &str,
    proto: &str,
    sort: &str,
    exclude: &[String],
    ip: &str,
    force: bool,
    ctx: Option<&Context>,
) -> VerifyOutcome {
    let exclude_set: std::collections::HashSet<&str> = exclude.iter().map(String::as_str).collect();
    let mut widened = false;
    let mut candidates: Vec<Server> = if !ip.is_empty() {
        servers.iter().filter(|s| s.ip == ip).cloned().collect()
    } else {
        let mut list: Vec<Server> = servers
            .iter()
            .filter(|s| match_country(s, country) && match_proto(s, proto) && !exclude_set.contains(s.ip.as_str()))
            .cloned()
            .collect();
        sort_servers_desktop(&mut list, sort, proto);
        if list.is_empty() && !country.is_empty() && country != "ALL" {
            widened = true;
            list = servers
                .iter()
                .filter(|s| match_proto(s, proto) && !exclude_set.contains(s.ip.as_str()))
                .cloned()
                .collect();
            sort_servers_desktop(&mut list, sort, proto);
        }
        list
    };
    let max_attempts = if ip.is_empty() { 12 } else { 1 };
    let batch_size = if ip.is_empty() { 4 } else { 1 };
    let slice_len = candidates.len().min(max_attempts);
    let slice: Vec<Server> = candidates.drain(..slice_len).collect();
    let remaining = candidates.len();
    let mut attempts = Vec::new();
    let mut winner: Option<(Server, VerifyRec)> = None;
    let mut i = 0;
    while i < slice.len() && winner.is_none() {
        let batch = &slice[i..(i + batch_size).min(slice.len())];
        let futs = batch.iter().map(|s| {
            let s = s.clone();
            async move { (s.clone(), verify_relay_cached(&s, force, ctx).await) }
        });
        let results = futures::future::join_all(futs).await;
        for (srv, res) in results {
            let (u, l) = profile_availability(&srv, &res);
            let unlocked = if res.unlocked.is_empty() { u } else { res.unlocked.clone() };
            let locked = if res.locked.is_empty() { l } else { res.locked.clone() };
            attempts.push(VerifyAttempt {
                ip: srv.ip.clone(),
                hostname: srv.hostname.clone(),
                country_short: srv.country_short.clone(),
                port: res.port,
                ok: res.ok,
                rtt_ms: res.rtt_ms,
                error: if res.ok { None } else { res.error.clone() },
                engine: res.engine.clone(),
                unlocked,
                locked,
                tcp_handshake: res.tcp_handshake,
                host_up: res.host_up,
                dead_until: if res.ok { 0 } else { res.ts + DEAD_PENALTY_MS },
                cached: res.ts > 0 && now_ms().saturating_sub(res.ts) > 250 && !force,
            });
            if res.ok && winner.is_none() {
                winner = Some((srv, res));
            }
        }
        i += batch_size;
    }
    if let Some((srv, res)) = winner {
        let (u, l) = profile_availability(&srv, &res);
        let unlocked = if res.unlocked.is_empty() { u } else { res.unlocked };
        let locked = if res.locked.is_empty() { l } else { res.locked };
        let scanned = attempts.len();
        return VerifyOutcome {
            verified: Some(json!({
                "ip": srv.ip,
                "hostname": srv.hostname,
                "country_short": srv.country_short,
                "country_long": srv.country_long,
                "port": res.port,
                "rtt_ms": res.rtt_ms,
                "handshake": if res.tcp_handshake { "openvpn-tcp-v2" } else { res.engine.as_str() },
                "l2tp": srv.l2tp,
                "openvpn": srv.openvpn,
                "tcp_port": srv.tcp_port,
                "udp_port": srv.udp_port,
                "has_ovpn_cert": srv.has_ovpn_cert,
                "score": srv.score,
                "speed_bps": srv.speed_bps,
                "ping_ms": srv.ping_ms,
                "sessions": srv.sessions,
                "operator": srv.operator,
                "tcp_handshake": res.tcp_handshake,
                "host_up": res.host_up,
                "unlocked": unlocked,
                "locked": locked,
            })),
            attempts,
            scanned,
            widened,
            remaining,
        };
    }
    let scanned = attempts.len();
    VerifyOutcome {
        verified: None,
        attempts,
        scanned,
        widened,
        remaining,
    }
}

pub struct ProfileGate {
    pub error: Option<String>,
    pub status: u16,
    pub found: Option<Server>,
    pub verified: Option<VerifyRec>,
    pub snap: Option<crate::model::PoolSnapshot>,
}

pub async fn assert_verified_for_profile(ctx: &Context, ip: &str, kind: &str) -> ProfileGate {
    let snap = get_pool_snapshot(ctx, false, "").await;
    let found = snap
        .public_payload
        .servers
        .iter()
        .find(|s| s.ip == ip)
        .cloned();
    let Some(found) = found else {
        return ProfileGate {
            error: Some("Relay is not in the active VPN Gate pool.".into()),
            status: 404,
            found: None,
            verified: None,
            snap: None,
        };
    };
    if kind == "l2tp" && !found.l2tp {
        return ProfileGate {
            error: Some("Relay does not advertise L2TP/IPsec.".into()),
            status: 409,
            found: Some(found),
            verified: None,
            snap: None,
        };
    }
    if kind == "tcp" && !found.openvpn {
        return ProfileGate {
            error: Some("Relay does not advertise OpenVPN TCP.".into()),
            status: 409,
            found: Some(found),
            verified: None,
            snap: None,
        };
    }
    if kind == "udp" && !(found.openvpn && found.udp_port > 0) {
        return ProfileGate {
            error: Some("Relay does not advertise OpenVPN UDP.".into()),
            status: 409,
            found: Some(found),
            verified: None,
            snap: None,
        };
    }
    let verified = verify_relay_cached(&found, false, Some(ctx)).await;
    let (unlocked, locked) = profile_availability(&found, &verified);
    if !unlocked.iter().any(|k| k == kind) {
        let why = locked
            .iter()
            .find(|l| l.kind == kind)
            .map(|l| l.reason.clone())
            .unwrap_or_else(|| {
                if !verified.ok {
                    "relay did not answer a live path".into()
                } else {
                    "this protocol stayed locked on the host".into()
                }
            });
        return ProfileGate {
            error: Some(format!(
                "Profile locked ({kind}): {why}. Other protocols on this relay may still be available."
            )),
            status: 409,
            found: Some(found),
            verified: Some(verified),
            snap: None,
        };
    }
    ProfileGate {
        error: None,
        status: 200,
        found: Some(found),
        verified: Some(verified),
        snap: Some(snap),
    }
}

pub fn remember_probe(ip: &str, rec: VerifyRec, ctx: &Context) -> VerifyRec {
    remember_verify(ip, rec, Some(ctx))
}
