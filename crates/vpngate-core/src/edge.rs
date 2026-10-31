//! Cloudflare Workers (`workers.dev`) origins used as a GitHub bypass.
//!
//! Custom hostnames are not used. `*.workers.dev` does not reach mainland China.

use std::env;

const BUNDLED_EDGE_ORIGINS: &str = include_str!("../../../assets/edge-origins.txt");

/// Trailing-slash-stripped `https://…` origins from `VPNGATE_EDGE` then `assets/edge-origins.txt`.
pub fn edge_origins() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(raw) = env::var("VPNGATE_EDGE") {
        for part in raw.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            push_origin(&mut out, part);
        }
    }
    for origin in parse_edge_origins_text(BUNDLED_EDGE_ORIGINS) {
        if !out.iter().any(|x| x == &origin) {
            out.push(origin);
        }
    }
    out
}

fn push_origin(out: &mut Vec<String>, part: &str) {
    let origin = part.trim().trim_end_matches('/');
    if origin.len() < 12 || origin.len() > 253 {
        return;
    }
    if !origin.starts_with("https://") {
        return;
    }
    if origin[8..].contains("://") || origin.contains("..") {
        return;
    }
    if !out.iter().any(|x: &String| x == origin) {
        out.push(origin.to_string());
    }
}

pub fn parse_edge_origins_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for part in line.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            push_origin(&mut out, part);
        }
    }
    out
}

pub fn edge_path_urls(path: &str) -> Vec<String> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    edge_origins()
        .into_iter()
        .map(|origin| format!("{origin}{path}"))
        .collect()
}

pub fn is_edge_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    if u.contains(".workers.dev/") || u.ends_with(".workers.dev") {
        return true;
    }
    edge_origins().iter().any(|origin| {
        let o = origin.to_ascii_lowercase();
        u == o || u.starts_with(&(o.clone() + "/"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_origins_and_skips_comments() {
        let text = "# comment\nhttps://vpngate-connect.example.workers.dev/\nhttp://insecure.example\nhttps://ok.example.com\n";
        let got = parse_edge_origins_text(text);
        assert_eq!(
            got,
            vec![
                "https://vpngate-connect.example.workers.dev".to_string(),
                "https://ok.example.com".to_string()
            ]
        );
    }

    #[test]
    fn bundled_file_has_no_live_origin_until_deploy_url_is_pasted() {
        assert!(parse_edge_origins_text(BUNDLED_EDGE_ORIGINS).is_empty());
    }
}
