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

    #[test]
    fn portal_uses_platform_installer_artifacts_instead_of_legacy_scripts() {
        let html = include_str!("../assets/portal.html.in");
        let js = include_str!("../assets/portal.js");
        assert!(html.contains("id=\"desktop-installer-link\""));
        assert!(html.contains("data-install-os=\"macos\""));
        assert!(html.contains("14 days"));
        assert!(js.contains("actions/workflows/build-installers.yml?query=branch%3Amain"));
        assert!(js.contains("vpngate-installer-linux-x64-run"));
        assert!(js.contains("vpngate-installer-windows-x64-msi"));
        assert!(js.contains("vpngate-installer-macos-arm64-pkg"));
        for retired in ["install-vpngate.sh", "install-vpngate.ps1", "install-vpngate.cmd"] {
            assert!(!html.contains(retired));
            assert!(!js.contains(retired));
        }
    }
}
