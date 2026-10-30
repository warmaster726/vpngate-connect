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
}
