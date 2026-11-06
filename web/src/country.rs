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

fn lookup_long(iso2: &str) -> Option<&'static str> {
    ISO2_TABLE.iter().find(|(k, _)| *k == iso2).map(|(_, v)| *v)
}

fn lookup_iso2(name: &str) -> Option<&'static str> {
    let low = name.trim().to_ascii_lowercase();
    if low.is_empty() {
        return None;
    }
    if let Some((code, _)) = ISO2_TABLE
        .iter()
        .find(|(_, long)| long.to_ascii_lowercase() == low)
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

pub fn normalize_country_pair(raw_long: &str, raw_short: &str) -> (String, String) {
    let mut cl = raw_long.trim().to_string();
    let mut cs = raw_short.trim().to_ascii_uppercase();
    if cs.len() != 2 || !cs.chars().all(|c| c.is_ascii_uppercase()) {
        cs.clear();
    }
    if cs.is_empty() && !cl.is_empty() {
        if let Some(code) = lookup_iso2(&cl) {
            cs = code.to_string();
        }
    }
    if (cl.is_empty() || cl.eq_ignore_ascii_case(&cs)) && !cs.is_empty() {
        if let Some(long) = lookup_long(&cs) {
            cl = long.to_string();
        }
    }
    (
        if cl.is_empty() {
            "Unknown".to_string()
        } else {
            cl
        },
        if cs.is_empty() {
            "XX".to_string()
        } else {
            cs
        },
    )
}

pub fn is_all_country_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "all" | "any" | "*" | "worldwide"
    )
}

/// Splits `JP,KR` / `JP KR` (ISO codes) while leaving `United States` as one name.
pub fn split_country_query(raw: &str) -> Vec<String> {
    let q = raw.trim();
    if q.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<String> = q
        .split(|c: char| c == ',' || c == ';' || c == '/')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() == 1 {
        let ws: Vec<&str> = parts[0].split_whitespace().collect();
        if ws.len() > 1
            && ws.iter().all(|t| {
                is_all_country_token(t) || (t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()))
            })
        {
            parts = ws.iter().map(|s| (*s).to_string()).collect();
        }
    }
    parts
}

fn country_token_matches(country_short: &str, country_long: &str, token: &str) -> bool {
    let q = token.trim();
    if q.is_empty() || is_all_country_token(q) {
        return true;
    }
    let up = q.to_ascii_uppercase();
    if q.len() == 2 && q.chars().all(|c| c.is_ascii_alphabetic()) {
        let iso = if up == "UK" { "GB" } else { up.as_str() };
        return country_short.eq_ignore_ascii_case(iso);
    }
    let low = q.to_ascii_lowercase();
    country_short.eq_ignore_ascii_case(&up) || country_long.to_ascii_lowercase().contains(&low)
}

/// Union filter matching desktop `filter_by_country`. `all` is worldwide.
pub fn match_country_fields(country_short: &str, country_long: &str, query: &str) -> bool {
    if query.is_empty() || is_all_country_token(query.trim()) {
        return true;
    }
    let parts = split_country_query(query);
    if parts.is_empty() || parts.iter().any(|t| is_all_country_token(t)) {
        return true;
    }
    parts
        .iter()
        .any(|t| country_token_matches(country_short, country_long, t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_country_unions_iso_list() {
        assert!(match_country_fields("JP", "Japan", "JP,KR"));
        assert!(match_country_fields("KR", "Korea", "JP KR"));
        assert!(!match_country_fields("US", "United States", "JP,KR"));
        assert!(match_country_fields("US", "United States", "ALL"));
        assert!(match_country_fields("JP", "Japan", "UK,JP"));
        assert!(match_country_fields("GB", "United Kingdom", "UK"));
        assert!(match_country_fields("US", "United States", "United"));
        assert!(!match_country_fields("AU", "Australia", "US"));
    }
}
