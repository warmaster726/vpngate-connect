pub fn render_portal_html() -> String {
    include_str!("../assets/portal.html.in")
        .replace("${PORTAL_CSS}", include_str!("../assets/portal.css"))
        .replace("${PORTAL_JS}", include_str!("../assets/portal.js"))
}

pub const ICON_SVG: &str = include_str!("../assets/icon.svg");

#[cfg(test)]
mod tests {
    #[test]
    fn portal_js_has_no_uninterpolated_placeholders() {
        let js = include_str!("../assets/portal.js");
        assert!(
            !js.contains("${"),
            "portal.js still contains a Worker template placeholder; the console would stay on BOOTING"
        );
    }

    #[test]
    fn portal_lets_users_add_several_countries() {
        let html = include_str!("../assets/portal.html.in");
        let js = include_str!("../assets/portal.js");
        assert!(html.contains("id=\"selected-country-chips\""));
        assert!(html.contains("id=\"all-country-pills\""));
        assert!(html.contains("aria-multiselectable=\"true\""));
        assert!(html.contains("id=\"connect-country-list\""));
        assert!(js.contains("function toggleCountryCode"));
        assert!(js.contains("function setCountryMenuOpen"));
        assert!(js.contains("function rebuildCountryList"));
    }
}
