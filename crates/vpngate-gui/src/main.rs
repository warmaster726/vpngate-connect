#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use vpngate_core::cache::ServerCacheFile;
use vpngate_core::{
    ActiveSessionState, AppPaths, PRODUCT_VERSION, VpnServer, assert_supported_native_host,
    cpu_isa_label, detect_host_os_label, is_root_or_admin, now_unix_secs, read_json_opt,
};

const APP_ID: &str = "net.vpngate.connect";
const ACTIVE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const IDLE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(15);
const CACHE_POLL_INTERVAL: Duration = Duration::from_secs(60);
const MAX_RELAY_ROWS: usize = 100;

fn main() -> eframe::Result {
    if let Err(error) = assert_supported_native_host() {
        eprintln!("vpngate-gui: {error}");
        std::process::exit(2);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("VPN Gate Connect")
            .with_inner_size([1040.0, 700.0])
            .with_min_inner_size([800.0, 580.0]),
        ..Default::default()
    };

    eframe::run_native(
        APP_ID,
        options,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Connect,
    Relays,
    Activity,
}

impl Page {
    const ALL: [Self; 3] = [Self::Connect, Self::Relays, Self::Activity];

    fn title(self) -> &'static str {
        match self {
            Self::Connect => "Connect",
            Self::Relays => "Relays",
            Self::Activity => "System & diagnostics",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::Connect => "Connection status and selected relay",
            Self::Relays => "Browse the locally cached relay list",
            Self::Activity => "Host information and integration status",
        }
    }

    fn navigation_label(self) -> &'static str {
        match self {
            Self::Connect => "Connect",
            Self::Relays => "Relays",
            Self::Activity => "System",
        }
    }
}

struct GuiApp {
    paths: AppPaths,
    page: Page,
    theme: egui::ThemePreference,
    session: Option<ActiveSessionState>,
    cached_servers: Vec<VpnServer>,
    matched_relay_indices: Vec<usize>,
    cache_timestamp: Option<u64>,
    relay_search: String,
    last_state_poll: Instant,
    last_cache_poll: Instant,
    host_label: String,
    native_arch: &'static str,
    elevated: bool,
}

impl GuiApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_native_theme(&cc.egui_ctx);
        install_platform_font(&cc.egui_ctx);

        let paths = AppPaths::resolve();
        let mut app = Self {
            paths,
            page: Page::Connect,
            theme: egui::ThemePreference::System,
            session: None,
            cached_servers: Vec::new(),
            matched_relay_indices: Vec::new(),
            cache_timestamp: None,
            relay_search: String::new(),
            last_state_poll: Instant::now(),
            last_cache_poll: Instant::now(),
            host_label: detect_host_os_label(),
            native_arch: cpu_isa_label(),
            elevated: is_root_or_admin(),
        };
        app.reload_session();
        app.reload_cache();
        app
    }

    fn reload_session(&mut self) {
        self.session = read_json_opt::<ActiveSessionState>(&self.paths.active_state);
        self.last_state_poll = Instant::now();
    }

    fn reload_cache(&mut self) {
        if let Some(snapshot) = read_json_opt::<ServerCacheFile>(&self.paths.servers_cache) {
            self.cache_timestamp = Some(snapshot.timestamp);
            self.cached_servers = snapshot.servers;
        } else {
            self.cache_timestamp = None;
            self.cached_servers = Vec::new();
        }
        self.last_cache_poll = Instant::now();
        self.rebuild_relay_matches();
    }

    fn rebuild_relay_matches(&mut self) {
        let query = self.relay_search.trim();
        self.matched_relay_indices = self
            .cached_servers
            .iter()
            .enumerate()
            .filter_map(|(index, server)| relay_matches(server, query).then_some(index))
            .collect();
    }

    #[cfg(not(target_os = "windows"))]
    fn appearance_picker(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("appearance")
                .selected_text(match self.theme {
                    egui::ThemePreference::System => "System",
                    egui::ThemePreference::Light => "Light",
                    egui::ThemePreference::Dark => "Dark",
                })
                .show_ui(ui, |ui| {
                    for (theme, label) in [
                        (egui::ThemePreference::System, "System"),
                        (egui::ThemePreference::Light, "Light"),
                        (egui::ThemePreference::Dark, "Dark"),
                    ] {
                        if ui.selectable_value(&mut self.theme, theme, label).changed() {
                            ctx.set_theme(theme);
                        }
                    }
                });
            ui.label(RichText::new("Appearance").weak());
        });
    }

    #[cfg(target_os = "windows")]
    fn appearance_menu(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        for (theme, label) in [
            (egui::ThemePreference::System, "System default"),
            (egui::ThemePreference::Light, "Light"),
            (egui::ThemePreference::Dark, "Dark"),
        ] {
            if ui.selectable_value(&mut self.theme, theme, label).changed() {
                ctx.set_theme(theme);
                ui.close();
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn desktop_header(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("VPN Gate Connect").heading().strong());
                ui.label(RichText::new("Read-only preview").weak().small());
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (label, color) = self.status_badge();
                ui.colored_label(color, RichText::new(label).strong());
                ui.add_space(18.0);
                self.appearance_picker(ui, ctx);
            });
        });
    }

    #[cfg(target_os = "windows")]
    fn windows_menu(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Reload relay cache").clicked() {
                    self.reload_cache();
                    ui.close();
                }
                ui.separator();
                if ui.button("Exit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    ui.close();
                }
            });

            ui.menu_button("View", |ui| {
                ui.menu_button("Appearance", |ui| self.appearance_menu(ui, ctx));
            });

            ui.menu_button("Help", |ui| {
                if ui.button("System & diagnostics").clicked() {
                    self.page = Page::Activity;
                    ui.close();
                }
                ui.separator();
                ui.label(
                    RichText::new(format!("Version {PRODUCT_VERSION}"))
                        .weak()
                        .small(),
                );
            });
        });
    }

    #[cfg(target_os = "windows")]
    fn windows_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for page in Page::ALL {
                ui.selectable_value(&mut self.page, page, page.navigation_label());
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (label, color) = self.status_badge();
                ui.colored_label(color, RichText::new(label).strong());
            });
        });
    }

    #[cfg(not(target_os = "windows"))]
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.label(RichText::new("NAVIGATION").weak().small().strong());
            ui.add_space(8.0);
            for page in Page::ALL {
                if ui
                    .selectable_label(self.page == page, page.navigation_label())
                    .clicked()
                {
                    self.page = page;
                }
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.separator();
                ui.label(
                    RichText::new(format!("Version {PRODUCT_VERSION}"))
                        .weak()
                        .small(),
                );
            });
        });
    }

    fn page_contents(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.page.title());
        ui.label(RichText::new(self.page.subtitle()).weak());
        ui.add_space(12.0);

        match self.page {
            Page::Connect => self.connect_page(ui),
            Page::Relays => self.relays_page(ui),
            Page::Activity => self.activity_page(ui),
        }
    }

    fn connect_page(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                let (label, color) = self.status_badge();
                let (dot_rect, _) =
                    ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(dot_rect.center(), 5.0, color);
                ui.vertical(|ui| {
                    ui.label(RichText::new(label).strong().size(18.0));
                    ui.label(RichText::new("Current VPN session").weak());
                });
            });

            ui.add_space(10.0);
            ui.separator();
            if let Some(session) = &self.session {
                egui::Grid::new("session_details")
                    .num_columns(2)
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        detail_row(ui, "Profile", &session.profile_name);
                        detail_row(ui, "Protocol", &session.protocol);
                        detail_row(
                            ui,
                            "Region",
                            &format!("{} ({})", session.country_long, session.country_short),
                        );
                        detail_row(
                            ui,
                            "Relay",
                            &format!("{} · {}", session.hostname, session.server_ip),
                        );
                        detail_row(ui, "Device", &session.device);
                        if !session.egress_ip.is_empty() {
                            detail_row(
                                ui,
                                "Egress",
                                &format!("{} {}", session.egress_ip, session.egress_loc),
                            );
                        }
                        ui.end_row();
                    });
            } else {
                ui.label("No active VPN session was found.");
            }
        });

        ui.add_space(12.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Connection controls").strong());
            ui.label("Connection actions are not available in this window yet.");
            ui.horizontal(|ui| {
                ui.add_enabled(false, egui::Button::new("Connect"));
                ui.add_enabled(false, egui::Button::new("Disconnect"));
                ui.label(
                    RichText::new("Use the existing CLI or GTK/VTE window to manage the tunnel.")
                        .weak(),
                );
            });
        });
    }

    fn relays_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.relay_search)
                    .hint_text("Country, relay, or IP")
                    .desired_width(260.0),
            );
            if response.changed() {
                self.rebuild_relay_matches();
            }
            if ui.button("Reload cache").clicked() {
                self.reload_cache();
            }
            ui.label(RichText::new(format!("{} relays", self.cached_servers.len())).weak());
        });
        ui.add_space(8.0);

        if self.cached_servers.is_empty() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(RichText::new("No cached relays").strong());
                ui.label(
                    "Run `vpngate refresh` in the existing terminal window to populate this list.",
                );
            });
            return;
        }

        let cache_age = self
            .cache_timestamp
            .map(|timestamp| format_age(now_unix_secs().saturating_sub(timestamp)))
            .unwrap_or_else(|| "unknown age".to_string());
        ui.label(
            RichText::new(format!(
                "Local cache · {cache_age} · {} matching relays",
                self.matched_relay_indices.len()
            ))
            .weak()
            .small(),
        );

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("relay_table")
                    .striped(true)
                    .num_columns(6)
                    .spacing([14.0, 7.0])
                    .show(ui, |ui| {
                        for header in ["Relay", "Country", "Address", "Speed", "Ping", "Protocols"]
                        {
                            ui.label(RichText::new(header).strong());
                        }
                        ui.end_row();

                        for &index in self.matched_relay_indices.iter().take(MAX_RELAY_ROWS) {
                            let server = &self.cached_servers[index];
                            ui.label(&server.hostname);
                            ui.label(format!(
                                "{} ({})",
                                server.country_long, server.country_short
                            ));
                            ui.monospace(&server.ip);
                            ui.label(format!("{:.1} Mbps", server.speed_mbps()));
                            ui.label(format!("{} ms", server.ping_ms));
                            ui.label(protocol_labels(server));
                            ui.end_row();
                        }
                    });
            });

        if self.matched_relay_indices.len() > MAX_RELAY_ROWS {
            ui.label(
                RichText::new(format!(
                    "Showing the first {MAX_RELAY_ROWS} of {} matching relays.",
                    self.matched_relay_indices.len()
                ))
                .weak()
                .small(),
            );
        }
    }

    fn activity_page(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Host information").strong());
            egui::Grid::new("host_details")
                .num_columns(2)
                .spacing([20.0, 8.0])
                .show(ui, |ui| {
                    detail_row(ui, "Operating system", &self.host_label);
                    detail_row(ui, "Native architecture", self.native_arch);
                    detail_row(
                        ui,
                        "Privilege level",
                        if self.elevated {
                            "Elevated"
                        } else {
                            "Standard user"
                        },
                    );
                    detail_row(
                        ui,
                        "Cache directory",
                        &self.paths.cache_dir.display().to_string(),
                    );
                    detail_row(ui, "Cached relays", &self.cached_servers.len().to_string());
                    detail_row(
                        ui,
                        "Core state",
                        if self.session.is_some() {
                            "Session file present"
                        } else {
                            "No session file"
                        },
                    );
                });
        });

        ui.add_space(12.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Integration status").strong());
            ui.label("Session and relay data are read-only snapshots from vpngate-core.");
            ui.label(
                "Connection, progress, cancellation, and privilege handoff still need integration.",
            );
            ui.label("The existing CLI and GTK/VTE window remain available for live operations.");
        });
    }

    fn status_badge(&self) -> (&str, Color32) {
        match self.session.as_ref().map(|state| state.status.as_str()) {
            Some("connected") => ("CONNECTED", Color32::from_rgb(44, 154, 84)),
            Some("reconnecting") => ("RECONNECTING", Color32::from_rgb(190, 125, 30)),
            Some(other) => (other, Color32::from_rgb(105, 115, 125)),
            None => ("DISCONNECTED", Color32::from_rgb(105, 115, 125)),
        }
    }

    fn session_poll_interval(&self) -> Duration {
        match self.session.as_ref().map(|state| state.status.as_str()) {
            Some("connected" | "reconnecting") => ACTIVE_STATE_POLL_INTERVAL,
            _ => IDLE_STATE_POLL_INTERVAL,
        }
    }
}

impl eframe::App for GuiApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let state_interval = self.session_poll_interval();
        if self.last_state_poll.elapsed() >= state_interval {
            self.reload_session();
        }
        let mut next_repaint = state_interval.saturating_sub(self.last_state_poll.elapsed());

        if self.page == Page::Relays {
            if self.last_cache_poll.elapsed() >= CACHE_POLL_INTERVAL {
                self.reload_cache();
            }
            next_repaint = next_repaint
                .min(CACHE_POLL_INTERVAL.saturating_sub(self.last_cache_poll.elapsed()));
        }

        ctx.request_repaint_after(next_repaint);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        #[cfg(target_os = "windows")]
        {
            egui::Panel::top("windows_menu")
                .exact_size(32.0)
                .show(ui, |ui| self.windows_menu(ui, &ctx));
            egui::Panel::top("windows_toolbar")
                .exact_size(42.0)
                .show(ui, |ui| self.windows_toolbar(ui));
        }

        #[cfg(not(target_os = "windows"))]
        {
            egui::Panel::top("desktop_header")
                .exact_size(62.0)
                .frame(
                    egui::Frame::new()
                        .fill(ui.visuals().panel_fill)
                        .inner_margin(egui::Margin::same(12)),
                )
                .show(ui, |ui| self.desktop_header(ui, &ctx));
            egui::Panel::left("desktop_navigation")
                .resizable(false)
                .exact_size(190.0)
                .show(ui, |ui| self.sidebar(ui));
        }

        egui::CentralPanel::default().show(ui, |ui| self.page_contents(ui));
    }
}

fn configure_native_theme(ctx: &egui::Context) {
    let accent = if cfg!(target_os = "windows") {
        Color32::from_rgb(0, 120, 212)
    } else {
        Color32::from_rgb(53, 132, 228)
    };

    ctx.options_mut(|options| {
        options.theme_preference = egui::ThemePreference::System;
        options.fallback_theme = egui::Theme::Light;
        options.sync_window_theme = true;

        let mut light = (*options.light_style).clone();
        light.visuals.selection.bg_fill = accent;
        light.visuals.hyperlink_color = accent;
        options.light_style = std::sync::Arc::new(light);

        let mut dark = (*options.dark_style).clone();
        dark.visuals.selection.bg_fill = accent;
        dark.visuals.hyperlink_color = accent;
        options.dark_style = std::sync::Arc::new(dark);
    });
    ctx.set_theme(egui::ThemePreference::System);
}

#[cfg(target_os = "windows")]
fn install_platform_font(ctx: &egui::Context) {
    use std::{env, fs, path::PathBuf, sync::Arc};

    let windows_dir = env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let font_dir = windows_dir.join("Fonts");
    let mut fonts = egui::FontDefinitions::default();

    if let Ok(bytes) = fs::read(font_dir.join("segoeui.ttf")) {
        const WINDOWS_UI_FONT: &str = "vpn_gate_segoe_ui";
        fonts.font_data.insert(
            WINDOWS_UI_FONT.to_owned(),
            Arc::new(egui::FontData::from_owned(bytes)),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, WINDOWS_UI_FONT.to_owned());
    }

    if let Ok(bytes) = fs::read(font_dir.join("consola.ttf")) {
        const WINDOWS_MONO_FONT: &str = "vpn_gate_consolas";
        fonts.font_data.insert(
            WINDOWS_MONO_FONT.to_owned(),
            Arc::new(egui::FontData::from_owned(bytes)),
        );
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .insert(0, WINDOWS_MONO_FONT.to_owned());
    }

    ctx.set_fonts(fonts);
}

#[cfg(not(target_os = "windows"))]
fn install_platform_font(_ctx: &egui::Context) {}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).weak());
    ui.label(value);
    ui.end_row();
}

fn relay_matches(server: &VpnServer, query: &str) -> bool {
    query.is_empty()
        || contains_ascii_case_insensitive(&server.hostname, query)
        || contains_ascii_case_insensitive(&server.ip, query)
        || contains_ascii_case_insensitive(&server.country_short, query)
        || contains_ascii_case_insensitive(&server.country_long, query)
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    needle.is_empty()
        || haystack
            .as_bytes()
            .windows(needle.len())
            .any(|candidate| candidate.eq_ignore_ascii_case(needle))
}

fn protocol_labels(server: &VpnServer) -> &'static str {
    match (
        server.l2tp,
        server.supports_openvpn_udp(),
        server.supports_openvpn_tcp(),
    ) {
        (false, false, false) => "—",
        (true, false, false) => "L2TP/IPsec",
        (false, true, false) => "OVPN UDP",
        (false, false, true) => "OVPN TCP",
        (true, true, false) => "L2TP/IPsec · OVPN UDP",
        (true, false, true) => "L2TP/IPsec · OVPN TCP",
        (false, true, true) => "OVPN UDP · OVPN TCP",
        (true, true, true) => "L2TP/IPsec · OVPN UDP · OVPN TCP",
    }
}

fn format_age(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s old")
    } else if seconds < 3600 {
        format!("{}m old", seconds / 60)
    } else {
        format!("{}h old", seconds / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::{format_age, protocol_labels, relay_matches};
    use vpngate_core::VpnServer;

    fn server() -> VpnServer {
        VpnServer {
            hostname: "relay.example".to_string(),
            ip: "192.0.2.7".to_string(),
            score: 10,
            ping_ms: 42,
            speed_bps: 10_000_000,
            country_long: "Japan".to_string(),
            country_short: "JP".to_string(),
            sessions: 1,
            uptime_ms: 0,
            operator: String::new(),
            l2tp: true,
            openvpn: true,
            tcp_port: 443,
            udp_port: 1194,
            ovpn_b64: String::new(),
            ovpn_dl_query: String::new(),
        }
    }

    #[test]
    fn relay_filter_matches_country_name_code_hostname_and_ip() {
        let relay = server();
        assert!(relay_matches(&relay, "japan"));
        assert!(relay_matches(&relay, "JAPAN"));
        assert!(relay_matches(&relay, "jp"));
        assert!(relay_matches(&relay, "relay.example"));
        assert!(relay_matches(&relay, "192.0.2"));
        assert!(!relay_matches(&relay, "korea"));
        assert!(relay_matches(&relay, ""));
    }

    #[test]
    fn protocol_labels_cover_available_kinds_without_allocating() {
        assert_eq!(
            protocol_labels(&server()),
            "L2TP/IPsec · OVPN UDP · OVPN TCP"
        );

        let mut no_protocols = server();
        no_protocols.l2tp = false;
        no_protocols.openvpn = false;
        assert_eq!(protocol_labels(&no_protocols), "—");
    }

    #[test]
    fn cache_age_is_human_readable() {
        assert_eq!(format_age(42), "42s old");
        assert_eq!(format_age(120), "2m old");
        assert_eq!(format_age(7200), "2h old");
    }
}
