pub fn render_portal_html() -> String {
    include_str!("../assets/portal.html.in")
        .replace("${PORTAL_CSS}", include_str!("../assets/portal.css"))
        .replace("${PORTAL_JS}", include_str!("../assets/portal.js"))
}

pub const ICON_SVG: &str = include_str!("../assets/icon.svg");
