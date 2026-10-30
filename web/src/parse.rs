use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use url::Url;

use crate::country::normalize_country_pair;
use crate::model::{CountrySummary, Mirror, Server};

pub fn parse_ipv4_octets(raw: &str) -> Option<[u8; 4]> {
    let s = raw.trim();
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        if !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u16 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        *slot = n as u8;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

pub fn is_poisoned_ipv4(o: [u8; 4]) -> bool {
    let [a, b, c, _] = o;
    if a == 0 || a == 10 || a == 127 || a >= 224 {
        return true;
    }
    if a == 169 && b == 254 {
        return true;
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && b == 168 {
        return true;
    }
    if a == 192 && b == 0 && (c == 0 || c == 2) {
        return true;
    }
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    if a == 198 && (b == 18 || b == 19) {
        return true;
    }
    if a == 198 && b == 51 && c == 100 {
        return true;
    }
    if a == 203 && b == 0 && c == 113 {
        return true;
    }
    false
}

pub fn valid_public_ipv4(raw: &str) -> Option<String> {
    let o = parse_ipv4_octets(raw)?;
    if is_poisoned_ipv4(o) {
        return None;
    }
    Some(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
}

fn strip_tags(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_tag = false;
    for c in raw.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

fn decode_basic_entities(raw: &str) -> String {
    raw.replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// VPN Gate HTML/CSV cells sometimes wrap values in `<span style='font-size: 9pt;'>`.
fn strip_markup(raw: &str) -> String {
    let decoded = decode_basic_entities(&strip_tags(raw));
    strip_tags(&decoded)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn clean_hostname(raw: &str, ip: &str) -> String {
    let host = strip_markup(raw);
    if host.is_empty() {
        ip.to_string()
    } else {
        host
    }
}

fn strip_opengw_suffix(host: &str) -> String {
    let low = host.to_ascii_lowercase();
    if let Some(stripped) = low.strip_suffix(".opengw.net") {
        host[..stripped.len()].trim().to_string()
    } else {
        host.to_string()
    }
}

pub fn normalize_mirror_base_url(raw: &str) -> Option<(String, String)> {
    let trimmed = raw
        .trim()
        .trim_matches(|c| c == '\'' || c == '"' || c == '.')
        .to_string();
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.to_ascii_lowercase().starts_with("http://")
        || trimmed.to_ascii_lowercase().starts_with("https://")
    {
        trimmed
    } else {
        format!("http://{trimmed}")
    };
    let parsed = Url::parse(&with_scheme).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return None;
    }
    const EXCLUDED: &[&str] = &[
        "www.vpngate.net",
        "vpngate.net",
        "www.tsukuba.ac.jp",
        "tsukuba.ac.jp",
        "www.softether.org",
        "softether.org",
        "icondrawer.com",
        "www.win10pcap.org",
        "web.archive.org",
    ];
    if EXCLUDED.contains(&host.as_str())
        || host.ends_with(".tsukuba.ac.jp")
        || host.ends_with(".archive.org")
    {
        return None;
    }
    if let Some(octets) = parse_ipv4_octets(&host) {
        if is_poisoned_ipv4(octets) {
            return None;
        }
    }
    if host.contains(':') {
        return None;
    }
    let port_part = parsed
        .port()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let base_url = format!("{}//{host}{port_part}", parsed.scheme());
    Some((base_url.clone(), format!("{base_url}/en/")))
}

fn parse_uint_clean(s: &str, fallback: u64) -> u64 {
    let mut n = 0u64;
    let mut found = false;
    for ch in s.chars() {
        if let Some(d) = ch.to_digit(10) {
            n = n.saturating_mul(10).saturating_add(d as u64);
            found = true;
        }
    }
    if found { n } else { fallback }
}

fn split_csv_row_fast(line: &str, max_cols: usize) -> Vec<String> {
    let mut cols = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '"' {
            if in_quotes && chars.get(i + 1) == Some(&'"') {
                cur.push('"');
                i += 1;
            } else {
                in_quotes = !in_quotes;
            }
        } else if ch == ',' && !in_quotes {
            cols.push(std::mem::take(&mut cur));
            if cols.len() == max_cols.saturating_sub(1) {
                cols.push(chars[i + 1..].iter().collect());
                return cols;
            }
        } else {
            cur.push(ch);
        }
        i += 1;
    }
    cols.push(cur);
    cols
}

fn b64_decode_lossy(s: &str) -> Option<String> {
    let mut t = s.trim().as_bytes().to_vec();
    while t.len() % 4 != 0 {
        t.push(b'=');
    }
    let bytes = BASE64_STD.decode(&t).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn extract_ovpn_ports_fast(b64: &str) -> (bool, u16, u16) {
    if b64.len() < 40 {
        return (false, 0, 0);
    }
    let head = if b64.len() > 4800 {
        let win = b64_decode_lossy(&b64[2160.min(b64.len())..3800.min(b64.len())]).unwrap_or_default();
        if win.contains("remote ") {
            win
        } else {
            b64_decode_lossy(&b64[..7200.min(b64.len())]).unwrap_or_default()
        }
    } else {
        let aligned = b64.len() - (b64.len() % 4);
        let decoded = match b64_decode_lossy(&b64[..aligned]) {
            Some(d) => d,
            None => return (false, 0, 0),
        };
        if !decoded.contains("<ca>") {
            return (false, 0, 0);
        }
        decoded
    };
    let proto = head.lines().find_map(|ln| {
        let t = ln.trim();
        let low = t.to_ascii_lowercase();
        low.strip_prefix("proto ").map(|rest| rest.trim().to_string())
    });
    let port = head.lines().find_map(|ln| {
        let t = ln.trim();
        let low = t.to_ascii_lowercase();
        if let Some(rest) = low.strip_prefix("remote ") {
            rest.split_whitespace().nth(1)?.parse::<u16>().ok()
        } else {
            None
        }
    });
    let mut tcp = 0u16;
    let mut udp = 0u16;
    if let (Some(proto), Some(port)) = (proto, port) {
        if port > 0 {
            if proto.to_ascii_lowercase().starts_with("tcp") {
                tcp = port;
            } else {
                udp = port;
            }
        }
    }
    (true, tcp, udp)
}

pub fn parse_vpngate_csv_into(csv_raw: &str, servers: &mut HashMap<String, Server>) {
    for line in csv_raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('*') || trimmed.starts_with('#') {
            continue;
        }
        let row = split_csv_row_fast(trimmed, 15);
        if row.len() < 15 {
            continue;
        }
        let Some(ip) = valid_public_ipv4(&row[1]) else {
            continue;
        };
        let b64 = row[14].trim().to_string();
        let (ovpn_ok, tcp_port, udp_port) = extract_ovpn_ports_fast(&b64);
        let score = parse_uint_clean(&row[2], 0);
        let mut ping_ms = parse_uint_clean(&row[3], 9999);
        if ping_ms == 0 {
            ping_ms = 9999;
        }
        let speed_bps = parse_uint_clean(&row[4], 0);
        let sessions = parse_uint_clean(&row[7], 0);
        let uptime_ms = parse_uint_clean(&row[8], 0);
        let (country_long, country_short) =
            normalize_country_pair(&strip_markup(&row[5]), &strip_markup(&row[6]));
        let hostname = clean_hostname(&row[0], &ip);
        let operator = {
            let op = strip_markup(&row[12]);
            if op.is_empty() {
                "VPNGate Volunteer".to_string()
            } else {
                op
            }
        };
        if let Some(existing) = servers.get_mut(&ip) {
            if ovpn_ok {
                existing.openvpn = true;
                if existing.ovpn_b64.is_empty() || score >= existing.score {
                    existing.ovpn_b64 = b64;
                }
            }
            if tcp_port > 0 {
                existing.tcp_port = tcp_port;
            }
            if udp_port > 0 {
                existing.udp_port = udp_port;
            }
            if score > existing.score {
                existing.score = score;
            }
            if ping_ms > 0 && ping_ms < existing.ping_ms {
                existing.ping_ms = ping_ms;
            }
            if speed_bps > existing.speed_bps {
                existing.speed_bps = speed_bps;
            }
            if existing.country_short == "XX" && country_short != "XX" {
                existing.country_short = country_short;
                existing.country_long = country_long;
            }
        } else {
            servers.insert(
                ip.clone(),
                Server {
                    hostname,
                    ip,
                    score,
                    ping_ms,
                    speed_bps,
                    country_long,
                    country_short,
                    sessions,
                    uptime_ms,
                    operator,
                    l2tp: false,
                    openvpn: ovpn_ok,
                    tcp_port,
                    udp_port,
                    ovpn_b64: if ovpn_ok { b64 } else { String::new() },
                    has_ovpn_cert: ovpn_ok,
                    verify_state: None,
                    verified_port: None,
                    verified_rtt_ms: None,
                    unlocked: Vec::new(),
                    locked: Vec::new(),
                    dead_until: 0,
                },
            );
        }
    }
}

pub fn parse_sdise_csv_into(csv_raw: &str, servers: &mut HashMap<String, Server>) {
    for line in csv_raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let row = split_csv_row_fast(trimmed, 5);
        if row.len() < 4 {
            continue;
        }
        if row[0].trim().eq_ignore_ascii_case("country") {
            continue;
        }
        let Some(ip) = valid_public_ipv4(&row[2]) else {
            continue;
        };
        if servers.contains_key(&ip) {
            continue;
        }
        let (country_long, country_short) = normalize_country_pair(&strip_markup(&row[0]), "");
        let mut host = strip_opengw_suffix(&strip_markup(&row[1]));
        if host.is_empty() {
            host = ip.clone();
        }
        let mbps: f64 = row[3].replace(',', "").parse().unwrap_or(0.0);
        let speed_bps = (mbps.max(0.0) * 1_000_000.0).round() as u64;
        servers.insert(
            ip.clone(),
            Server {
                hostname: host,
                ip,
                score: 100_000u64.max(speed_bps / 500),
                ping_ms: 9999,
                speed_bps,
                country_long,
                country_short,
                sessions: 0,
                uptime_ms: 0,
                operator: "VPNGate Volunteer".into(),
                l2tp: false,
                openvpn: false,
                tcp_port: 0,
                udp_port: 0,
                ovpn_b64: String::new(),
                has_ovpn_cert: false,
                verify_state: None,
                verified_port: None,
                verified_rtt_ms: None,
                unlocked: Vec::new(),
                locked: Vec::new(),
                dead_until: 0,
            },
        );
    }
}

fn capture_after<'a>(hay: &'a str, prefix: &str) -> Option<&'a str> {
    let i = hay.find(prefix)?;
    Some(&hay[i + prefix.len()..])
}

pub fn parse_vpngate_html_into(html_raw: &str, servers: &mut HashMap<String, Server>) {
    for chunk in html_raw.split("<tr>").skip(1) {
        if !chunk.contains("vg_table_row_") || !chunk.contains("width='32' height='32'") {
            continue;
        }
        let Some(ip_raw) = extract_ipv4_from_html(chunk) else {
            continue;
        };
        let Some(ip) = valid_public_ipv4(ip_raw) else {
            continue;
        };
        let has_l2tp = chunk.contains("howto_l2tp.aspx");
        let mut tcp_port = 0u16;
        let mut udp_port = 0u16;
        let mut has_ovpn = false;
        if let Some(rest) = capture_after(chunk, "do_openvpn.aspx?") {
            let qs = rest.split(|c| c == '\'' || c == '"').next().unwrap_or("");
            has_ovpn = true;
            if let Some(v) = query_param(qs, "tcp") {
                tcp_port = v.parse().unwrap_or(0);
            }
            if let Some(v) = query_param(qs, "udp") {
                udp_port = v.parse().unwrap_or(0);
            }
        }
        if let Some(existing) = servers.get_mut(&ip) {
            if has_l2tp {
                existing.l2tp = true;
            }
            if tcp_port > 0 {
                existing.tcp_port = tcp_port;
            }
            if udp_port > 0 {
                existing.udp_port = udp_port;
            }
            if has_ovpn {
                existing.openvpn = true;
            }
            if existing.score > 0 && existing.country_short != "XX" {
                continue;
            }
        }
        let flag = capture_after(chunk, "../images/flags/")
            .and_then(|r| r.get(..2))
            .filter(|s| s.bytes().all(|b| b.is_ascii_uppercase()));
        let cname = extract_country_name(chunk);
        let (country_long, country_short) = normalize_country_pair(&cname, flag.unwrap_or(""));
        let hostname = extract_hostname(chunk).unwrap_or_else(|| ip.clone());
        let parsed_score = extract_last_bold_number(chunk);
        let parsed_ping = capture_after(chunk, "Ping:")
            .and_then(|r| {
                let i = r.find("<b>")?;
                Some(parse_uint_clean(&r[i..], 9999))
            })
            .unwrap_or(9999);
        let speed_bps = capture_after(chunk, "Mbps")
            .and_then(|_| {
                let i = chunk.to_ascii_lowercase().rfind("mbps")?;
                let before = &chunk[..i];
                let num = before
                    .rsplit('>')
                    .next()?
                    .trim()
                    .trim_end_matches('<')
                    .replace(',', "");
                let mbps: f64 = num.parse().ok()?;
                Some((mbps * 1_000_000.0).round() as u64)
            })
            .unwrap_or(0);
        let sessions = if let Some(r) = chunk
            .to_ascii_lowercase()
            .find("sessions")
            .map(|i| &chunk[..i])
        {
            parse_uint_clean(r.rsplit('>').next().unwrap_or(""), 0)
        } else {
            0
        };
        if let Some(existing) = servers.get_mut(&ip) {
            if parsed_score > existing.score {
                existing.score = parsed_score;
            }
            if parsed_ping > 0 && parsed_ping < existing.ping_ms {
                existing.ping_ms = parsed_ping;
            }
            if speed_bps > existing.speed_bps {
                existing.speed_bps = speed_bps;
            }
            if existing.country_short == "XX" && country_short != "XX" {
                existing.country_short = country_short;
                existing.country_long = country_long;
            }
        } else {
            servers.insert(
                ip.clone(),
                Server {
                    hostname,
                    ip,
                    score: parsed_score,
                    ping_ms: parsed_ping,
                    speed_bps,
                    country_long,
                    country_short,
                    sessions,
                    uptime_ms: 0,
                    operator: "VPNGate Volunteer".into(),
                    l2tp: has_l2tp,
                    openvpn: has_ovpn,
                    tcp_port,
                    udp_port,
                    ovpn_b64: String::new(),
                    has_ovpn_cert: false,
                    verify_state: None,
                    verified_port: None,
                    verified_rtt_ms: None,
                    unlocked: Vec::new(),
                    locked: Vec::new(),
                    dead_until: 0,
                },
            );
        }
    }
}

fn extract_ipv4_from_html(chunk: &str) -> Option<&str> {
    let bytes = chunk.as_bytes();
    let mut i = 0;
    while i + 7 < bytes.len() {
        if bytes[i] == b'>' {
            let rest = &chunk[i + 1..];
            let end = rest.find('<')?;
            let cand = &rest[..end];
            if parse_ipv4_octets(cand).is_some() {
                return Some(cand);
            }
        }
        i += 1;
    }
    None
}

fn query_param<'a>(qs: &'a str, key: &str) -> Option<&'a str> {
    for part in qs.split('&') {
        let mut kv = part.splitn(2, '=');
        if kv.next()? == key {
            return kv.next();
        }
    }
    None
}

fn extract_country_name(chunk: &str) -> String {
    let Some(i) = chunk
        .find("height='32'")
        .or_else(|| chunk.find("height=\"32\""))
    else {
        return String::new();
    };
    let Some(slash) = chunk[i..].find("/>") else {
        return String::new();
    };
    let after_img = &chunk[i + slash + 2..];
    let after_br = if let Some(b) = after_img.find("<br") {
        match after_img[b..].find('>') {
            Some(gt) => &after_img[b + gt + 1..],
            None => after_img,
        }
    } else {
        after_img
    };
    strip_markup(after_br.split("</td>").next().unwrap_or("").trim())
}

fn extract_hostname(chunk: &str) -> Option<String> {
    // `<b><span style='font-size: 9pt;'>host</span></b>` — skip past the
    // span tag, not the `>` that closes `<b>`.
    let marker = "<b><span";
    let i = chunk.find(marker)?;
    let rest = &chunk[i + marker.len()..];
    let gt = rest.find('>')?;
    let inner = &rest[gt + 1..];
    let end = inner.find("</span>")?;
    let host = strip_opengw_suffix(&strip_markup(&inner[..end]));
    if host.is_empty() { None } else { Some(host) }
}

fn extract_last_bold_number(chunk: &str) -> u64 {
    let mut best = 0u64;
    let mut rest = chunk;
    while let Some(i) = rest.find("<b><span") {
        rest = &rest[i + 8..];
        if let Some(gt) = rest.find('>') {
            rest = &rest[gt + 1..];
            if let Some(end) = rest.find("</span>") {
                best = parse_uint_clean(&rest[..end], best);
                rest = &rest[end + 7..];
            }
        }
    }
    best
}

pub fn parse_mirror_sites_html(html: &str, source_label: &str) -> Vec<Mirror> {
    if html.is_empty() {
        return Vec::new();
    }
    let normalized = html.replace("<li", "\n<li").replace("<br", "\n<br");
    let mut out: Vec<Mirror> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for line in normalized.lines() {
        let mut loc_clean = "Unknown".to_string();
        let low = line.to_ascii_lowercase();
        if let Some(idx) = low.find("location:") {
            let mut s = line[idx + "location:".len()..]
                .replace("&nbsp;", " ")
                .split("(LOCAL")
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches(')')
                .trim()
                .to_string();
            // original also matched "(Mirror location:"
            if s.is_empty() {
                if let Some(j) = low.find("mirror location:") {
                    s = line[j + "mirror location:".len()..]
                        .replace("&nbsp;", " ")
                        .split("(LOCAL")
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_end_matches(')')
                        .trim()
                        .to_string();
                }
            }
            if !s.is_empty() {
                loc_clean = strip_markup(&s);
            }
        }
        let mut search = line;
        while let Some(at) = search.find("http://").or_else(|| search.find("https://")) {
            let slice = &search[at..];
            let end = slice
                .find(|c: char| c.is_whitespace() || c == '<' || c == '"' || c == '\'')
                .unwrap_or(slice.len());
            let raw = &slice[..end];
            search = &slice[end.max(1)..];
            if let Some((base_url, portal_url)) = normalize_mirror_base_url(raw) {
                if let Some(&idx) = seen.get(&base_url) {
                    if out[idx].location == "Unknown" && loc_clean != "Unknown" {
                        out[idx].location = loc_clean.clone();
                    }
                } else {
                    seen.insert(base_url.clone(), out.len());
                    out.push(Mirror {
                        base_url,
                        portal_url,
                        location: loc_clean.clone(),
                        source: source_label.to_string(),
                        reachable: None,
                        rtt_ms: None,
                        servers_count: None,
                    });
                }
            }
        }
    }
    out
}

pub fn extract_aspnet_fields(html: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut rest = html;
    while let Some(i) = rest.find("<input") {
        let tag_end = rest[i..].find('>').map(|e| i + e + 1).unwrap_or(rest.len());
        let tag = &rest[i..tag_end];
        rest = &rest[tag_end..];
        let low = tag.to_ascii_lowercase();
        if !low.contains("type=\"hidden\"") && !low.contains("type='hidden'") {
            continue;
        }
        let name = attr_value(tag, "name");
        let value = attr_value(tag, "value").unwrap_or_default();
        if let Some(name) = name {
            fields.insert(name, value);
        }
    }
    fields
}

fn attr_value(tag: &str, key: &str) -> Option<String> {
    let low = tag.to_ascii_lowercase();
    let key_eq_dq = format!("{key}=\"");
    let key_eq_sq = format!("{key}='");
    if let Some(i) = low.find(&key_eq_dq) {
        let rest = &tag[i + key_eq_dq.len()..];
        return Some(rest.split('"').next().unwrap_or("").to_string());
    }
    if let Some(i) = low.find(&key_eq_sq) {
        let rest = &tag[i + key_eq_sq.len()..];
        return Some(rest.split('\'').next().unwrap_or("").to_string());
    }
    None
}

pub fn merge_mirror_lists(lists: &[Vec<Mirror>]) -> Vec<Mirror> {
    let mut out: Vec<Mirror> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for list in lists {
        for m in list {
            if m.base_url.is_empty() {
                continue;
            }
            if let Some(&idx) = seen.get(&m.base_url) {
                if out[idx].location == "Unknown" && m.location != "Unknown" && !m.location.is_empty()
                {
                    out[idx].location = m.location.clone();
                }
            } else {
                seen.insert(m.base_url.clone(), out.len());
                out.push(m.clone());
            }
        }
    }
    out
}

pub fn summarize_countries(servers: &[Server]) -> Vec<CountrySummary> {
    let mut map: HashMap<String, CountrySummary> = HashMap::new();
    for s in servers {
        if !s.l2tp && !s.openvpn {
            continue;
        }
        let code = if s.country_short.is_empty() {
            "XX"
        } else {
            &s.country_short
        };
        let entry = map.entry(code.to_string()).or_insert_with(|| CountrySummary {
            country_short: code.to_string(),
            country_long: if s.country_long.is_empty() {
                "Unknown".into()
            } else {
                s.country_long.clone()
            },
            total_servers: 0,
            l2tp_count: 0,
            openvpn_udp_count: 0,
            openvpn_tcp_count: 0,
            max_speed_bps: 0,
            best_ping_ms: 9999,
        });
        entry.total_servers += 1;
        if s.l2tp {
            entry.l2tp_count += 1;
        }
        if s.supports_openvpn_udp() {
            entry.openvpn_udp_count += 1;
        }
        if s.supports_openvpn_tcp() {
            entry.openvpn_tcp_count += 1;
        }
        if s.speed_bps > entry.max_speed_bps {
            entry.max_speed_bps = s.speed_bps;
        }
        if s.ping_ms > 0 && s.ping_ms < entry.best_ping_ms {
            entry.best_ping_ms = s.ping_ms;
        }
    }
    let mut out: Vec<_> = map.into_values().collect();
    out.sort_by(|a, b| {
        b.total_servers
            .cmp(&a.total_servers)
            .then(b.l2tp_count.cmp(&a.l2tp_count))
            .then(a.country_short.cmp(&b.country_short))
    });
    out
}

fn auto_priority_tier(s: &Server) -> i32 {
    if s.l2tp {
        0
    } else if s.supports_openvpn_udp() {
        1
    } else if s.supports_openvpn_tcp() || s.openvpn {
        2
    } else {
        3
    }
}

fn effective_ping(s: &Server) -> u64 {
    if s.ping_ms == 0 || s.ping_ms >= 9999 {
        999999
    } else {
        s.ping_ms
    }
}

pub fn sort_servers_desktop(list: &mut [Server], sort_key: &str, proto_filter: &str) {
    list.sort_by(|a, b| {
        let tier_diff = if proto_filter == "auto" || proto_filter == "all" || proto_filter.is_empty()
        {
            auto_priority_tier(a) - auto_priority_tier(b)
        } else if proto_filter == "openvpn" {
            i32::from(b.supports_openvpn_udp()) - i32::from(a.supports_openvpn_udp())
        } else {
            0
        };
        let ping_a = effective_ping(a);
        let ping_b = effective_ping(b);
        let tier = tier_diff.cmp(&0);
        match sort_key {
            "speed" => b
                .speed_bps
                .cmp(&a.speed_bps)
                .then(tier)
                .then(b.score.cmp(&a.score)),
            "ping" => ping_a
                .cmp(&ping_b)
                .then(tier)
                .then(b.speed_bps.cmp(&a.speed_bps)),
            "score" => tier.then(b.score.cmp(&a.score)).then(b.speed_bps.cmp(&a.speed_bps)),
            _ => tier
                .then(b.score.cmp(&a.score))
                .then(b.speed_bps.cmp(&a.speed_bps))
                .then(ping_a.cmp(&ping_b)),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_poisoned_and_leading_zeros() {
        assert!(valid_public_ipv4("10.0.0.1").is_none());
        assert!(valid_public_ipv4("127.0.0.1").is_none());
        assert!(valid_public_ipv4("192.168.1.1").is_none());
        assert!(valid_public_ipv4("01.2.3.4").is_none());
        assert_eq!(valid_public_ipv4("219.100.37.10").as_deref(), Some("219.100.37.10"));
    }

    #[test]
    fn parses_official_csv_row() {
        let csv = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n\
vpn123,8.8.8.8,1000,20,1000000,Japan,JP,1,0,0,0,2,op,,QUJDRA==\n";
        // 8.8.8.8 is public; b64 too short so openvpn false
        let mut map = HashMap::new();
        parse_vpngate_csv_into(csv, &mut map);
        assert!(map.contains_key("8.8.8.8"));
        let s = &map["8.8.8.8"];
        assert_eq!(s.country_short, "JP");
        assert_eq!(s.hostname, "vpn123");
    }

    #[test]
    fn strips_html_from_csv_hostname_and_operator() {
        let csv = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n\
<span style='font-size: 9pt;'>public-vpn-213</span>,219.100.37.200,1000,20,1000000,Japan,JP,1,0,0,0,2,<b>Tsukuba</b>,,QUJDRA==\n";
        let mut map = HashMap::new();
        parse_vpngate_csv_into(csv, &mut map);
        let s = &map["219.100.37.200"];
        assert_eq!(s.hostname, "public-vpn-213");
        assert_eq!(s.operator, "Tsukuba");
    }

    #[test]
    fn html_hostname_ignores_font_size_span() {
        let html = r#"
        <table>
        <tr><td class='vg_table_row_1'><img src='../images/flags/JP.png' width='32' height='32' /><br>Japan</td>
        <td class='vg_table_row_1'><b><span style='font-size: 9pt;'>public-vpn-213.opengw.net</span></b><br><span style='font-size: 9pt;'>219.100.37.200</span></td>
        <td class='vg_table_row_1'><b><span style='font-size: 9pt;'>12 VPN sessions</span></b></td>
        <td class='vg_table_row_1'><b><span style='font-size: 9pt;'>167.7 Mbps</span></b><br>Ping: <b>14 ms</b></td>
        <td class='vg_table_row_1'><a href='do_openvpn.aspx?fqdn=x&ip=219.100.37.200&tcp=443&udp=1195'>OpenVPN</a></td>
        <td class='vg_table_row_1'><a href='howto_l2tp.aspx'>L2TP/IPsec</a></td>
        <td class='vg_table_row_1'><b><span style='font-size: 9pt;'>1,890,500</span></b></td></tr>
        </table>"#;
        let mut map = HashMap::new();
        parse_vpngate_html_into(html, &mut map);
        let s = map.get("219.100.37.200").expect("html server");
        assert_eq!(s.hostname, "public-vpn-213");
        assert_eq!(s.country_short, "JP");
        assert!(s.l2tp);
        assert_eq!(s.tcp_port, 443);
        assert_eq!(s.udp_port, 1195);
    }
}
