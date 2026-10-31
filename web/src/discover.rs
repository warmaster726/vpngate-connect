use std::collections::HashMap;

use futures::future::join_all;
use serde_json::json;
use worker::{Cache, Context, Method};

use crate::fetchutil::{fetch_get, fetch_text_timeout};
use crate::model::{
    Counts, LogLine, Mirror, PoolSnapshot, PublicPayload, Server, APP_VERSION,
    DAILY_MIRROR_JSON_URLS, MAX_OFFICIAL_MIRROR_CSV, MIRROR_CSV_URLS, OFFICIAL_CSV_URLS,
    OFFICIAL_HTML_URLS, OFFICIAL_MIRROR_SITES_URLS, POOL_CACHE_KEY_URL, POOL_CACHE_TTL_MS,
    SDISE_CSV_URL, WAYBACK_MIRROR_SITES_CDX_URL, WAYBACK_PORTAL_CDX_URLS,
};
use crate::parse::{
    extract_aspnet_fields, merge_mirror_lists, normalize_mirror_base_url, parse_mirror_sites_html,
    parse_sdise_csv_into, parse_vpngate_csv_into, parse_vpngate_html_into, sort_servers_desktop,
    summarize_countries, valid_public_ipv4,
};
use crate::timeutil::now_ms;

use std::cell::RefCell;

thread_local! {
    static POOL_MEM: RefCell<Option<PoolSnapshot>> = RefCell::new(None);
}

fn log_line(level: &str, msg: impl Into<String>) -> LogLine {
    LogLine {
        level: level.into(),
        msg: msg.into(),
    }
}

async fn post_protocol_filter(
    portal_url: &str,
    asp: &HashMap<String, String>,
    cookie: &str,
    checkbox_name: &str,
    timeout_ms: u32,
) -> String {
    let mut body = String::new();
    for (k, v) in asp {
        if !body.is_empty() {
            body.push('&');
        }
        body.push_str(&urlencoding_pair(k, v));
    }
    body.push('&');
    body.push_str(&urlencoding_pair(checkbox_name, "on"));
    body.push('&');
    body.push_str(&urlencoding_pair("Button3", "Refresh Servers List"));
    let mut extra = vec![
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Referer", portal_url),
    ];
    if !cookie.is_empty() {
        extra.push(("Cookie", cookie));
    }
    let extra_refs: Vec<(&str, &str)> = extra.iter().map(|(k, v)| (*k, *v)).collect();
    fetch_text_timeout(
        portal_url,
        timeout_ms,
        Method::Post,
        Some(body),
        &extra_refs,
    )
    .await
    .map(|r| {
        if r.text.len() > 256 {
            r.text
        } else {
            String::new()
        }
    })
    .unwrap_or_default()
}

fn urlencoding_pair(k: &str, v: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair(k, v)
        .finish()
}

async fn fetch_fallback_mirrors() -> Vec<Mirror> {
    let daily_task = async {
        for url in DAILY_MIRROR_JSON_URLS {
            let Some(res) = fetch_get(url, 3200).await else {
                continue;
            };
            let Ok(rows) = serde_json::from_str::<serde_json::Value>(&res.text) else {
                continue;
            };
            let Some(arr) = rows.as_array() else {
                continue;
            };
            let mut list = Vec::new();
            for r in arr {
                let ip = r
                    .get("IP")
                    .or_else(|| r.get("ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let port = r
                    .get("PORT")
                    .or_else(|| r.get("port"))
                    .map(|v| {
                        v.as_u64()
                            .map(|n| n.to_string())
                            .or_else(|| v.as_str().map(|s| s.to_string()))
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                if ip.is_empty() || port.is_empty() {
                    continue;
                }
                if let Some((base_url, portal_url)) =
                    normalize_mirror_base_url(&format!("http://{ip}:{port}/en/"))
                {
                    let loc = r
                        .get("LOCATION")
                        .or_else(|| r.get("location"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Mirror")
                        .trim();
                    list.push(Mirror {
                        base_url,
                        portal_url,
                        location: if loc.is_empty() {
                            "Mirror".into()
                        } else {
                            loc.into()
                        },
                        source: "daily-mirror-feed".into(),
                        reachable: None,
                        rtt_ms: None,
                        servers_count: None,
                    });
                }
            }
            if !list.is_empty() {
                return list;
            }
        }
        Vec::new()
    };
    let wayback_task = async {
        let Some(cdx) = fetch_get(WAYBACK_MIRROR_SITES_CDX_URL, 2800).await else {
            return Vec::new();
        };
        let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&cdx.text) else {
            return Vec::new();
        };
        if rows.len() < 2 {
            return Vec::new();
        }
        for r in rows.iter().skip(1).rev() {
            let Some(arr) = r.as_array() else {
                continue;
            };
            if arr.len() < 3 {
                continue;
            }
            let ts = arr[1].as_str().unwrap_or("");
            let orig = arr[2].as_str().unwrap_or("");
            if ts.is_empty() || orig.is_empty() {
                continue;
            }
            let snap_url = format!("https://web.archive.org/web/{ts}id_/{orig}");
            if let Some(snap) = fetch_get(&snap_url, 3200).await {
                let parsed = parse_mirror_sites_html(&snap.text, "wayback-sites");
                if !parsed.is_empty() {
                    return parsed;
                }
            }
        }
        Vec::new()
    };
    let (daily, wb) = futures::join!(daily_task, wayback_task);
    merge_mirror_lists(&[daily, wb])
}

async fn fetch_from_official_mirror_portal(
    mirror: &Mirror,
) -> Option<(String, String, String, String, Vec<Mirror>)> {
    let csv_url = format!("{}/api/iphone/", mirror.base_url);
    let sites_url = format!("{}/en/sites.aspx", mirror.base_url);
    let csv_fut = fetch_get(&csv_url, 4000);
    let en_fut = fetch_get(&mirror.portal_url, 4000);
    let sites_fut = fetch_get(&sites_url, 3200);
    let (csv_res, en_res, sites_res) = futures::join!(csv_fut, en_fut, sites_fut);
    let csv_body = csv_res
        .as_ref()
        .filter(|r| r.text.contains("*vpn_servers") || r.text.contains("#HostName"))
        .map(|r| r.text.clone())
        .unwrap_or_default();
    let base_html = en_res
        .as_ref()
        .filter(|r| r.text.contains("vg_table_row_"))
        .map(|r| r.text.clone())
        .unwrap_or_default();
    if csv_body.is_empty() && base_html.is_empty() {
        return None;
    }
    let mut l2tp_html = String::new();
    let mut ovpn_html = String::new();
    if !base_html.is_empty() {
        let asp = extract_aspnet_fields(&base_html);
        if asp.contains_key("__VIEWSTATE") {
            let cookie = en_res.as_ref().map(|r| r.cookie.as_str()).unwrap_or("");
            let (l2, ov) = futures::join!(
                post_protocol_filter(&mirror.portal_url, &asp, cookie, "C_L2TP", 4200),
                post_protocol_filter(&mirror.portal_url, &asp, cookie, "C_OpenVPN", 4200),
            );
            l2tp_html = l2;
            ovpn_html = ov;
        }
    }
    let extra = sites_res
        .map(|r| parse_mirror_sites_html(&r.text, "mirror-sites.aspx"))
        .unwrap_or_default();
    Some((csv_body, base_html, l2tp_html, ovpn_html, extra))
}

async fn fetch_mirror_csv_only(mirror: &Mirror) -> String {
    if let Some(csv) = fetch_get(&format!("{}/api/iphone/", mirror.base_url), 4000).await {
        if csv.text.contains("*vpn_servers") || csv.text.contains("#HostName") {
            return csv.text;
        }
    }
    String::new()
}

async fn fetch_https_csv_bodies() -> (Vec<String>, String) {
    let tasks = MIRROR_CSV_URLS.iter().map(|u| fetch_get(u, 4500));
    let sdise_task = fetch_get(SDISE_CSV_URL, 4000);
    let (csv_results, sdise) = futures::join!(join_all(tasks), sdise_task);
    let mut bodies = Vec::new();
    for r in csv_results.into_iter().flatten() {
        if r.text.contains("*vpn_servers") || r.text.contains("#HostName") {
            bodies.push(r.text);
        }
    }
    (bodies, sdise.map(|r| r.text).unwrap_or_default())
}

async fn fetch_wayback_portal_html() -> String {
    for cdx_url in WAYBACK_PORTAL_CDX_URLS {
        let Some(cdx) = fetch_get(cdx_url, 2600).await else {
            continue;
        };
        let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&cdx.text) else {
            continue;
        };
        if rows.len() < 2 {
            continue;
        }
        let Some(last) = rows.last().and_then(|v| v.as_array()) else {
            continue;
        };
        if last.len() < 3 {
            continue;
        }
        let ts = last[1].as_str().unwrap_or("");
        let orig = last[2].as_str().unwrap_or("");
        let snap = fetch_get(&format!("https://web.archive.org/web/{ts}id_/{orig}"), 3500).await;
        if let Some(snap) = snap {
            if snap.text.contains("vg_table_row_") {
                return snap.text;
            }
        }
    }
    String::new()
}

pub async fn discover_pool_fresh(custom_mirror_raw: &str) -> PoolSnapshot {
    let mut logs = Vec::new();
    let mut servers_by_ip: HashMap<String, Server> = HashMap::new();
    let mut custom_mirrors = Vec::new();
    if !custom_mirror_raw.is_empty() {
        for part in custom_mirror_raw
            .split(|c: char| c == ',' || c == ';' || c == '\n' || c == '\r' || c.is_whitespace())
        {
            if part.is_empty() || part.starts_with('#') {
                continue;
            }
            if let Some((base_url, portal_url)) = normalize_mirror_base_url(part) {
                if custom_mirrors
                    .iter()
                    .any(|m: &Mirror| m.base_url == base_url)
                {
                    continue;
                }
                custom_mirrors.push(Mirror {
                    base_url,
                    portal_url: portal_url.clone(),
                    location: "Custom Mirror".into(),
                    source: "custom".into(),
                    reachable: None,
                    rtt_ms: None,
                    servers_count: None,
                });
                logs.push(log_line(
                    "info",
                    format!("Seeding extra Official Mirror Portal (merged with all others): {portal_url}"),
                ));
            }
        }
        if custom_mirrors.is_empty() {
            logs.push(log_line(
                "warn",
                "Ignored invalid or private custom mirror URL.",
            ));
        }
    }

    logs.push(log_line(
        "info",
        "Querying primary vpngate.net (/api/iphone/ + /en/ + sites.aspx) ...",
    ));

    let csv_task = async {
        for u in OFFICIAL_CSV_URLS {
            if let Some(r) = fetch_get(u, 3200).await {
                if r.text.contains("*vpn_servers") || r.text.contains("#HostName") {
                    return r.text;
                }
            }
        }
        String::new()
    };
    let html_task = async {
        for u in OFFICIAL_HTML_URLS {
            if let Some(r) = fetch_get(u, 3200).await {
                if r.text.contains("vg_table_row_") {
                    return Some(r);
                }
            }
        }
        None
    };
    let sites_task = async {
        for u in OFFICIAL_MIRROR_SITES_URLS {
            if let Some(r) = fetch_get(u, 3000).await {
                let p = parse_mirror_sites_html(&r.text, "sites.aspx");
                if !p.is_empty() {
                    return p;
                }
            }
        }
        Vec::new()
    };
    let (primary_csv, html_res, primary_mirrors) = futures::join!(csv_task, html_task, sites_task);

    let mut l2tp_html = String::new();
    let mut ovpn_html = String::new();
    let mut base_html = String::new();
    if let Some(html_res) = html_res {
        base_html = html_res.text.clone();
        let asp = extract_aspnet_fields(&base_html);
        if asp.contains_key("__VIEWSTATE") {
            let (l2, ov) = futures::join!(
                post_protocol_filter(&html_res.url, &asp, &html_res.cookie, "C_L2TP", 4200),
                post_protocol_filter(&html_res.url, &asp, &html_res.cookie, "C_OpenVPN", 4200),
            );
            l2tp_html = l2;
            ovpn_html = ov;
        }
    }
    if !primary_csv.is_empty() {
        parse_vpngate_csv_into(&primary_csv, &mut servers_by_ip);
    }
    if !ovpn_html.is_empty() || !l2tp_html.is_empty() {
        if !ovpn_html.is_empty() {
            parse_vpngate_html_into(&ovpn_html, &mut servers_by_ip);
        }
        if !l2tp_html.is_empty() {
            parse_vpngate_html_into(&l2tp_html, &mut servers_by_ip);
        }
    } else if !base_html.is_empty() {
        parse_vpngate_html_into(&base_html, &mut servers_by_ip);
    }
    if !servers_by_ip.is_empty() {
        logs.push(log_line(
            "ok",
            format!(
                "Primary vpngate.net online — parsed {} live relays ({} mirrors).",
                servers_by_ip.len(),
                primary_mirrors.len()
            ),
        ));
    }

    logs.push(log_line(
        "info",
        "Harvesting Official VPNGate Mirror Portals for direct pool merge ...",
    ));
    let fb_mirrors = fetch_fallback_mirrors().await;
    let mut harvested = merge_mirror_lists(&[custom_mirrors.clone(), primary_mirrors, fb_mirrors]);

    let mut mirror_slice: Vec<Mirror> = harvested
        .iter()
        .take(MAX_OFFICIAL_MIRROR_CSV)
        .cloned()
        .collect();
    if !mirror_slice.is_empty() {
        let csv_bodies = join_all(mirror_slice.iter().map(fetch_mirror_csv_only)).await;
        let mut portal_hits = 0usize;
        for (i, body) in csv_bodies.into_iter().enumerate() {
            if body.is_empty() {
                continue;
            }
            parse_vpngate_csv_into(&body, &mut servers_by_ip);
            portal_hits += 1;
            mirror_slice[i].reachable = Some(true);
        }
        if portal_hits > 0 {
            logs.push(log_line(
                "ok",
                format!(
                    "Merged {portal_hits}/{} Official Mirror /api/iphone/ feed(s) directly into the pool.",
                    mirror_slice.len()
                ),
            ));
        } else {
            logs.push(log_line(
                "warn",
                "Official Mirror CSVs were unreachable this round — continuing with other feeds.",
            ));
        }
        // write reachable flags back
        for m in &mirror_slice {
            if m.reachable == Some(true) {
                if let Some(h) = harvested.iter_mut().find(|x| x.base_url == m.base_url) {
                    h.reachable = Some(true);
                }
            }
        }
    }

    if l2tp_html.is_empty() || !custom_mirrors.is_empty() {
        let deep: Vec<Mirror> = if !custom_mirrors.is_empty() {
            custom_mirrors.clone()
        } else {
            harvested.iter().take(2).cloned().collect()
        };
        for m in deep {
            if let Some((csv_body, base, l2, ov, extra)) =
                fetch_from_official_mirror_portal(&m).await
            {
                if !csv_body.is_empty() {
                    parse_vpngate_csv_into(&csv_body, &mut servers_by_ip);
                }
                parse_vpngate_html_into(&ov, &mut servers_by_ip);
                parse_vpngate_html_into(&l2, &mut servers_by_ip);
                parse_vpngate_html_into(&base, &mut servers_by_ip);
                if !l2.is_empty() && l2tp_html.is_empty() {
                    l2tp_html = l2;
                }
                if !extra.is_empty() {
                    harvested = merge_mirror_lists(&[harvested.clone(), extra]);
                }
                logs.push(log_line(
                    "ok",
                    format!(
                        "Official Mirror {} ({}) HTML tables merged.",
                        m.portal_url, m.location
                    ),
                ));
                if !l2tp_html.is_empty() {
                    break;
                }
            }
        }
    }

    logs.push(log_line(
        "info",
        "Merging every HTTPS CSV / SDISE / archive feed into the live pool ...",
    ));
    let https_fut = fetch_https_csv_bodies();
    let wb_fut = async {
        if l2tp_html.is_empty() {
            fetch_wayback_portal_html().await
        } else {
            String::new()
        }
    };
    let ((https_bodies, sdise_text), wb_html) = futures::join!(https_fut, wb_fut);
    let mut hits = 0usize;
    for body in &https_bodies {
        parse_vpngate_csv_into(body, &mut servers_by_ip);
        hits += 1;
    }
    if !sdise_text.is_empty() {
        parse_sdise_csv_into(&sdise_text, &mut servers_by_ip);
    }
    if !wb_html.is_empty() {
        let mut wb_map = HashMap::new();
        parse_vpngate_html_into(&wb_html, &mut wb_map);
        for (ip, wb_srv) in wb_map {
            if wb_srv.l2tp {
                if let Some(s) = servers_by_ip.get_mut(&ip) {
                    s.l2tp = true;
                }
            }
        }
    }
    if hits > 0 {
        logs.push(log_line(
            "ok",
            format!(
                "Merged {hits} HTTPS CSV mirror feed(s){} ({} total relays).",
                if sdise_text.is_empty() {
                    ""
                } else {
                    " + SDISE"
                },
                servers_by_ip.len()
            ),
        ));
    }

    let mut donor = String::new();
    for s in servers_by_ip.values() {
        if s.ovpn_b64.len() > 400 {
            donor = s.ovpn_b64.clone();
            break;
        }
    }
    let mut full = Vec::new();
    for mut s in servers_by_ip.into_values() {
        if s.openvpn
            && s.ovpn_b64.is_empty()
            && !donor.is_empty()
            && (s.udp_port > 0 || s.tcp_port > 0)
        {
            s.ovpn_b64 = donor.clone();
        }
        if !s.l2tp && !s.openvpn {
            continue;
        }
        full.push(s);
    }
    sort_servers_desktop(&mut full, "recommended", "auto");
    let mut ovpn_by_ip = serde_json::Map::new();
    let mut light = Vec::new();
    for mut s in full {
        if !s.ovpn_b64.is_empty() {
            ovpn_by_ip.insert(s.ip.clone(), json!(s.ovpn_b64));
        }
        s.has_ovpn_cert = !s.ovpn_b64.is_empty();
        s.ovpn_b64.clear();
        light.push(s);
    }
    let countries = summarize_countries(&light);
    let l2tp_count = light.iter().filter(|s| s.l2tp).count();
    let ovpn_count = light.iter().filter(|s| s.openvpn).count();
    logs.push(log_line(
        "ok",
        format!(
            "Pool ready: {} relays across {} countries ({l2tp_count} L2TP/IPsec, {ovpn_count} OpenVPN).",
            light.len(),
            countries.len()
        ),
    ));
    let generated_at = now_ms();
    PoolSnapshot {
        generated_at,
        donor_ovpn_b64: donor,
        ovpn_by_ip,
        public_payload: PublicPayload {
            ok: true,
            version: APP_VERSION.into(),
            generated_at,
            counts: Counts {
                total: light.len(),
                l2tp: l2tp_count,
                openvpn: ovpn_count,
                countries: countries.len(),
                mirrors: harvested.len(),
                live: None,
            },
            logs,
            countries,
            servers: light,
            mirrors: harvested,
        },
    }
}

pub async fn get_pool_snapshot(
    ctx: &Context,
    force_refresh: bool,
    custom_mirror: &str,
) -> PoolSnapshot {
    let now = now_ms();
    if !force_refresh && custom_mirror.is_empty() {
        let mem = POOL_MEM.with(|c| c.borrow().clone());
        if let Some(mem) = mem {
            if now.saturating_sub(mem.generated_at) < POOL_CACHE_TTL_MS
                && !mem.public_payload.servers.is_empty()
            {
                return mem;
            }
        }
        let cache = Cache::default();
        if let Ok(Some(mut hit)) = cache.get(POOL_CACHE_KEY_URL, false).await {
            if let Ok(parsed) = hit.json::<PoolSnapshot>().await {
                if !parsed.public_payload.servers.is_empty() {
                    POOL_MEM.with(|c| *c.borrow_mut() = Some(parsed.clone()));
                    return parsed;
                }
            }
        }
    }
    let fresh = discover_pool_fresh(custom_mirror).await;
    if custom_mirror.is_empty() && !fresh.public_payload.servers.is_empty() {
        POOL_MEM.with(|c| *c.borrow_mut() = Some(fresh.clone()));
        if let Ok(body) = serde_json::to_string(&fresh) {
            let mut headers = worker::Headers::new();
            let _ = headers.set("Content-Type", "application/json");
            let _ = headers.set(
                "Cache-Control",
                &format!("public, max-age={}", POOL_CACHE_TTL_MS / 1000),
            );
            if let Ok(resp) = worker::Response::ok(body) {
                let resp = resp.with_headers(headers);
                let cache = Cache::default();
                let key = POOL_CACHE_KEY_URL.to_string();
                ctx.wait_until(async move {
                    let _ = cache.put(key.as_str(), resp).await;
                });
            }
        }
    }
    fresh
}

pub async fn probe_mirrors(ctx: &Context) -> (usize, Vec<Mirror>) {
    let snap = get_pool_snapshot(ctx, false, "").await;
    let mut mirrors = snap.public_payload.mirrors;
    if mirrors.is_empty() {
        mirrors = fetch_fallback_mirrors().await;
    }
    let slice_len = mirrors.len().min(10);
    let slice = mirrors[..slice_len].to_vec();
    let probed = join_all(slice.into_iter().map(|m| async move {
        let t0 = now_ms();
        let mut reachable = false;
        let mut rtt_ms = None;
        let mut servers_count = 0u64;
        if let Some(csv) = fetch_get(&format!("{}/api/iphone/", m.base_url), 3500).await {
            if csv.text.contains("*vpn_servers") || csv.text.contains("#HostName") {
                let mut map = HashMap::new();
                parse_vpngate_csv_into(&csv.text, &mut map);
                reachable = true;
                servers_count = map.len() as u64;
                rtt_ms = Some((now_ms().saturating_sub(t0)).max(1));
            }
        }
        if !reachable {
            if let Some(en) = fetch_get(&m.portal_url, 3500).await {
                if en.text.contains("vg_table_row_") {
                    let mut map = HashMap::new();
                    parse_vpngate_html_into(&en.text, &mut map);
                    reachable = true;
                    servers_count = map.len() as u64;
                    rtt_ms = Some((now_ms().saturating_sub(t0)).max(1));
                }
            }
        }
        let mut out = m;
        out.reachable = Some(reachable);
        out.rtt_ms = rtt_ms;
        out.servers_count = Some(servers_count);
        out
    }))
    .await;
    let rest = mirrors[slice_len..].to_vec();
    let online = probed.iter().filter(|m| m.reachable == Some(true)).count();
    let mut combined = probed;
    combined.sort_by(|a, b| {
        let ar = i32::from(a.reachable == Some(true));
        let br = i32::from(b.reachable == Some(true));
        br.cmp(&ar)
            .then(a.rtt_ms.unwrap_or(99_999).cmp(&b.rtt_ms.unwrap_or(99_999)))
    });
    combined.extend(rest);
    (online, combined)
}

/// Used by doctor DoH check.
pub async fn fetch_text(url: &str, timeout_ms: u32, extra: &[(&str, &str)]) -> Option<String> {
    fetch_text_timeout(url, timeout_ms, Method::Get, None, extra)
        .await
        .map(|r| r.text)
}
