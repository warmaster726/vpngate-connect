use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::server::VpnServer;

/// Canonical ISO-3166 alpha-2 table used across VPN Gate CSV, HTML, and mirror feeds.
const ISO2_TABLE: &[(&str, &str)] = &[
    ("AE", "United Arab Emirates"),
    ("AL", "Albania"),
    ("AM", "Armenia"),
    ("AR", "Argentina"),
    ("AT", "Austria"),
    ("AU", "Australia"),
    ("AZ", "Azerbaijan"),
    ("BA", "Bosnia and Herzegovina"),
    ("BD", "Bangladesh"),
    ("BE", "Belgium"),
    ("BG", "Bulgaria"),
    ("BH", "Bahrain"),
    ("BO", "Bolivia"),
    ("BR", "Brazil"),
    ("BY", "Belarus"),
    ("CA", "Canada"),
    ("CH", "Switzerland"),
    ("CL", "Chile"),
    ("CN", "China"),
    ("CO", "Colombia"),
    ("CR", "Costa Rica"),
    ("CY", "Cyprus"),
    ("CZ", "Czech Republic"),
    ("DE", "Germany"),
    ("DK", "Denmark"),
    ("DO", "Dominican Republic"),
    ("DZ", "Algeria"),
    ("EC", "Ecuador"),
    ("EE", "Estonia"),
    ("EG", "Egypt"),
    ("ES", "Spain"),
    ("FI", "Finland"),
    ("FR", "France"),
    ("GB", "United Kingdom"),
    ("GE", "Georgia"),
    ("GH", "Ghana"),
    ("GR", "Greece"),
    ("GT", "Guatemala"),
    ("HK", "Hong Kong"),
    ("HN", "Honduras"),
    ("HR", "Croatia"),
    ("HU", "Hungary"),
    ("ID", "Indonesia"),
    ("IE", "Ireland"),
    ("IL", "Israel"),
    ("IN", "India"),
    ("IQ", "Iraq"),
    ("IR", "Iran"),
    ("IS", "Iceland"),
    ("IT", "Italy"),
    ("JO", "Jordan"),
    ("JP", "Japan"),
    ("KE", "Kenya"),
    ("KG", "Kyrgyzstan"),
    ("KH", "Cambodia"),
    ("KR", "Korea Republic of"),
    ("KW", "Kuwait"),
    ("KZ", "Kazakhstan"),
    ("LA", "Laos"),
    ("LB", "Lebanon"),
    ("LK", "Sri Lanka"),
    ("LT", "Lithuania"),
    ("LU", "Luxembourg"),
    ("LV", "Latvia"),
    ("MA", "Morocco"),
    ("MD", "Moldova"),
    ("MK", "North Macedonia"),
    ("MM", "Myanmar"),
    ("MN", "Mongolia"),
    ("MT", "Malta"),
    ("MU", "Mauritius"),
    ("MX", "Mexico"),
    ("MY", "Malaysia"),
    ("NG", "Nigeria"),
    ("NI", "Nicaragua"),
    ("NL", "Netherlands"),
    ("NO", "Norway"),
    ("NP", "Nepal"),
    ("NZ", "New Zealand"),
    ("OM", "Oman"),
    ("PA", "Panama"),
    ("PE", "Peru"),
    ("PH", "Philippines"),
    ("PK", "Pakistan"),
    ("PL", "Poland"),
    ("PR", "Puerto Rico"),
    ("PT", "Portugal"),
    ("PY", "Paraguay"),
    ("QA", "Qatar"),
    ("RO", "Romania"),
    ("RS", "Serbia"),
    ("RU", "Russian Federation"),
    ("SA", "Saudi Arabia"),
    ("SE", "Sweden"),
    ("SG", "Singapore"),
    ("SI", "Slovenia"),
    ("SK", "Slovakia"),
    ("SN", "Senegal"),
    ("SV", "El Salvador"),
    ("TH", "Thailand"),
    ("TN", "Tunisia"),
    ("TR", "Turkey"),
    ("TW", "Taiwan"),
    ("TZ", "Tanzania"),
    ("UA", "Ukraine"),
    ("US", "United States"),
    ("UY", "Uruguay"),
    ("UZ", "Uzbekistan"),
    ("VE", "Venezuela"),
    ("VN", "Viet Nam"),
    ("ZA", "South Africa"),
    ("ZW", "Zimbabwe"),
];

pub fn lookup_country_long(iso2: &str) -> Option<&'static str> {
    let code = iso2.trim().to_ascii_uppercase();
    ISO2_TABLE.iter().find(|(k, _)| *k == code).map(|(_, v)| *v)
}

pub fn lookup_iso2_by_name(name: &str) -> Option<&'static str> {
    let low = name.trim().to_ascii_lowercase();
    if low.is_empty() {
        return None;
    }
    if let Some((code, _)) = ISO2_TABLE
        .iter()
        .find(|(_, long_name)| long_name.to_ascii_lowercase() == low)
    {
        return Some(*code);
    }
    match low.as_str() {
        "south korea" | "republic of korea" | "korea, republic of" | "korea" => Some("KR"),
        "vietnam" => Some("VN"),
        "russia" => Some("RU"),
        "united states of america" | "usa" => Some("US"),
        "uk" | "great britain" => Some("GB"),
        "taiwan, province of china" => Some("TW"),
        "hong kong sar" => Some("HK"),
        "iran (islamic republic of)" => Some("IR"),
        "czechia" => Some("CZ"),
        "turkiye" | "türkiye" => Some("TR"),
        "moldova, republic of" => Some("MD"),
        "venezuela, bolivarian republic of" => Some("VE"),
        _ => None,
    }
}

/// Normalizes `(country_long, country_short)` pairs across heterogeneous CSV/HTML feeds.
pub fn normalize_country_pair(raw_long: &str, raw_short: &str) -> (String, String) {
    let mut cl = raw_long.trim().to_string();
    let mut cs = raw_short.trim().to_ascii_uppercase();

    if cs.len() != 2 || !cs.chars().all(|c| c.is_ascii_alphabetic()) {
        cs.clear();
    }
    if cs.is_empty()
        && let Some(mapped) = lookup_iso2_by_name(&cl)
    {
        cs = mapped.to_string();
    }
    if (cl.is_empty() || cl.eq_ignore_ascii_case(&cs))
        && let Some(long_name) = lookup_country_long(&cs)
    {
        cl = long_name.to_string();
    }

    let final_long = if cl.is_empty() {
        "Unknown".to_string()
    } else {
        cl
    };
    let final_short = if cs.is_empty() { "XX".to_string() } else { cs };
    (final_long, final_short)
}

/// Per-country protocol availability summary for CLI and interactive console views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountrySummary {
    pub country_short: String,
    pub country_long: String,
    pub total_servers: usize,
    pub l2tp_count: usize,
    pub openvpn_udp_count: usize,
    pub openvpn_tcp_count: usize,
    pub max_speed_bps: u64,
    pub best_ping_ms: u32,
}

impl CountrySummary {
    pub fn max_speed_mbps(&self) -> f64 {
        (self.max_speed_bps as f64) / 1_000_000.0
    }
}

/// Aggregates a server pool into sorted per-country summaries (ordered by server count desc, then ISO2).
pub fn summarize_countries(servers: &[VpnServer]) -> Vec<CountrySummary> {
    let mut map: BTreeMap<String, CountrySummary> = BTreeMap::new();

    for srv in servers {
        if !srv.has_any_protocol() {
            continue;
        }
        let code = if srv.country_short.is_empty() {
            "XX".to_string()
        } else {
            srv.country_short.to_ascii_uppercase()
        };
        let entry = map.entry(code.clone()).or_insert_with(|| CountrySummary {
            country_short: code,
            country_long: srv.country_long.clone(),
            total_servers: 0,
            l2tp_count: 0,
            openvpn_udp_count: 0,
            openvpn_tcp_count: 0,
            max_speed_bps: 0,
            best_ping_ms: 9999,
        });
        entry.total_servers += 1;
        if srv.l2tp {
            entry.l2tp_count += 1;
        }
        if srv.supports_openvpn_udp() {
            entry.openvpn_udp_count += 1;
        }
        if srv.supports_openvpn_tcp() {
            entry.openvpn_tcp_count += 1;
        }
        if srv.speed_bps > entry.max_speed_bps {
            entry.max_speed_bps = srv.speed_bps;
        }
        if srv.ping_ms > 0 && srv.ping_ms < entry.best_ping_ms {
            entry.best_ping_ms = srv.ping_ms;
        }
    }

    let mut list: Vec<CountrySummary> = map.into_values().collect();
    list.sort_by(|a, b| {
        b.total_servers
            .cmp(&a.total_servers)
            .then_with(|| b.l2tp_count.cmp(&a.l2tp_count))
            .then_with(|| a.country_short.cmp(&b.country_short))
    });
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_country_aliases() {
        assert_eq!(
            normalize_country_pair("South Korea", ""),
            ("South Korea".to_string(), "KR".to_string())
        );
        assert_eq!(
            normalize_country_pair("", "hk"),
            ("Hong Kong".to_string(), "HK".to_string())
        );
    }
}
