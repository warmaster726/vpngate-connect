#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use vpngate_core::cache::ServerCacheFile;
use vpngate_core::{
    ActiveSessionState, AppPaths, PRODUCT_VERSION, VpnServer, assert_supported_native_host,
    cpu_isa_label, detect_host_os_label, is_root_or_admin, now_unix_secs, read_json_opt,
};

const APP_ID: &str = "net.vpngate.connect.eframe";
const STATE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const CACHE_POLL_INTERVAL: Duration = Duration::from_secs(30);
const MAX_RELAY_ROWS: usize = 200;

fn main() -> eframe::Result {
    if let Err(error) = assert_supported_native_host() {
        eprintln!("vpngate-gui: {error}");
        std::process::exit(2);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("VPN Gate Connect — GUI preview")
            .with_inner_size([1080.0, 740.0])
            .with_min_inner_size([800.0, 580.0]),
        ..Default::default()
    };

    eframe::run_native(
        APP_ID,
        options,
        Box::new(|cc| Ok(Box::new(GuiSpike::new(cc)))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThemeMode {
    Light,
    Dark,
}

impl ThemeMode {
    fn apply(self, ctx: &egui::Context) {
        let mut visuals = match self {
            Self::Light => egui::Visuals::light(),
            Self::Dark => egui::Visuals::dark(),
        };
        let accent = Color32::from_rgb(20, 157, 145);
        visuals.selection.bg_fill = accent;
        visuals.hyperlink_color = accent;
        ctx.set_visuals(visuals);
    }
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
            Self::Activity => "Activity & system",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::Connect => "Session overview and connection controls",
            Self::Relays => "Read-only view of the local relay cache",
            Self::Activity => "Local diagnostics and integration status",
        }
    }
}

struct GuiSpike {
    paths: AppPaths,
    page: Page,
    theme: ThemeMode,
    session: Option<ActiveSessionState>,
    cached_servers: Vec<VpnServer>,
    cache_timestamp: Option<u64>,
    relay_search: String,
    last_state_poll: Instant,
    last_cache_poll: Instant,
    host_label: String,
    native_arch: &'static str,
    elevated: bool,
}

impl GuiSpike {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let theme = ThemeMode::Dark;
        theme.apply(&cc.egui_ctx);

        let paths = AppPaths::resolve();
        let mut app = Self {
            paths,
            page: Page::Connect,
            theme,
            session: None,
            cached_servers: Vec::new(),
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
        let snapshot = read_json_opt::<ServerCacheFile>(&self.paths.servers_cache);
        self.cached_servers = snapshot
            .as_ref()
            .map(|cache| cache.servers.clone())
            .unwrap_or_default();
        self.cache_timestamp = snapshot.map(|cache| cache.timestamp);
        self.last_cache_poll = Instant::now();
    }

    fn top_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("VPN Gate Connect").heading().strong());
                ui.label(RichText::new("Cross-platform GUI preview").weak().small());
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut selected = self.theme;
                ui.selectable_value(&mut selected, ThemeMode::Dark, "Dark");
                ui.selectable_value(&mut selected, ThemeMode::Light, "Light");
                ui.label(RichText::new("Appearance").weak());
                if selected != self.theme {
                    self.theme = selected;
                    self.theme.apply(ctx);
                }

                ui.add_space(18.0);
                let (label, color) = self.status_badge();
                ui.colored_label(color, RichText::new(label).strong());
            });
        });
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.label(RichText::new("WORKSPACE").weak().small().strong());
            ui.add_space(8.0);
            for page in Page::ALL {
                if ui
                    .selectable_label(self.page == page, page.title())
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
                ui.label(RichText::new("Opt-in GUI spike").weak().small());
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
                    ui.label(
                        RichText::new("Session data is read from the shared core state file.")
                            .weak(),
                    );
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
                ui.label("No active-session snapshot was found.");
            }
        });

        ui.add_space(12.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Connection controls").strong());
            ui.label("Tunnel actions are intentionally disabled in this first UI spike.");
            ui.horizontal(|ui| {
                ui.add_enabled(false, egui::Button::new("Connect"));
                ui.add_enabled(false, egui::Button::new("Disconnect"));
                ui.label(
                    RichText::new("No network or VPN state can be changed from this window.")
                        .weak(),
                );
            });
        });

        ui.add_space(10.0);
        ui.label(
            RichText::new("The existing CLI and GTK/VTE window remain the live control paths during this trial.")
                .weak()
                .small(),
        );
    }

    fn relays_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.relay_search)
                    .hint_text("Country, relay, or IP")
                    .desired_width(260.0),
            );
            if ui.button("Reload local cache").clicked() {
                self.reload_cache();
            }
            ui.label(RichText::new(format!("{} cached relays", self.cached_servers.len())).weak());
        });
        ui.add_space(8.0);

        let query = self.relay_search.trim().to_ascii_lowercase();
        let visible: Vec<&VpnServer> = self
            .cached_servers
            .iter()
            .filter(|server| relay_matches(server, &query))
            .take(MAX_RELAY_ROWS)
            .collect();

        if self.cached_servers.is_empty() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(RichText::new("No local relay cache").strong());
                ui.label("Refresh relays from the existing CLI. This spike does not start network discovery.");
            });
            return;
        }

        let cache_age = self
            .cache_timestamp
            .map(|timestamp| format_age(now_unix_secs().saturating_sub(timestamp)))
            .unwrap_or_else(|| "unknown age".to_string());
        ui.label(
            RichText::new(format!(
                "Local cache · {cache_age} · first {} matching rows",
                visible.len()
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

                        for server in visible {
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

        if self
            .cached_servers
            .iter()
            .filter(|s| relay_matches(s, &query))
            .count()
            > MAX_RELAY_ROWS
        {
            ui.label(
                RichText::new(
                    "More matches are available; the preview caps rendering at 200 rows.",
                )
                .weak()
                .small(),
            );
        }
    }

    fn activity_page(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Host snapshot").strong());
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
            ui.label("This preview reads local session and relay-cache snapshots through vpngate-core.");
            ui.label("It does not scrape terminal output, perform discovery, or invoke tunnel operations.");
            ui.label("Structured progress events, cancellation/rollback, and privilege handoff remain follow-up work.");
        });

        ui.add_space(12.0);
        ui.label(
            RichText::new("Activity log and Doctor actions are not wired in this spike.").weak(),
        );
    }

    fn status_badge(&self) -> (String, Color32) {
        match self.session.as_ref().map(|state| state.status.as_str()) {
            Some("connected") => ("CONNECTED".to_string(), Color32::from_rgb(50, 170, 95)),
            Some("reconnecting") => ("RECONNECTING".to_string(), Color32::from_rgb(220, 160, 55)),
            Some(other) => (other.to_ascii_uppercase(), Color32::from_rgb(130, 145, 160)),
            None => ("NO SESSION".to_string(), Color32::from_rgb(130, 145, 160)),
        }
    }
}

impl eframe::App for GuiSpike {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_state_poll.elapsed() >= STATE_POLL_INTERVAL {
            self.reload_session();
        }
        if self.last_cache_poll.elapsed() >= CACHE_POLL_INTERVAL {
            self.reload_cache();
        }
        ctx.request_repaint_after(STATE_POLL_INTERVAL);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::top("header")
            .exact_size(62.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin::same(12)))
            .show(ui, |ui| self.top_bar(ui, &ctx));

        egui::Panel::left("navigation")
            .resizable(false)
            .exact_size(190.0)
            .show(ui, |ui| self.sidebar(ui));

        egui::CentralPanel::default().show(ui, |ui| self.page_contents(ui));
    }
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).weak());
    ui.label(value);
    ui.end_row();
}

fn relay_matches(server: &VpnServer, query: &str) -> bool {
    query.is_empty()
        || server.hostname.to_ascii_lowercase().contains(query)
        || server.ip.to_ascii_lowercase().contains(query)
        || server.country_short.to_ascii_lowercase().contains(query)
        || server.country_long.to_ascii_lowercase().contains(query)
}

fn protocol_labels(server: &VpnServer) -> String {
    let mut protocols = Vec::with_capacity(3);
    if server.l2tp {
        protocols.push("L2TP/IPsec");
    }
    if server.supports_openvpn_udp() {
        protocols.push("OVPN UDP");
    }
    if server.supports_openvpn_tcp() {
        protocols.push("OVPN TCP");
    }
    if protocols.is_empty() {
        "—".to_string()
    } else {
        protocols.join(" · ")
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
    use super::{format_age, relay_matches};
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
        assert!(relay_matches(&relay, "jp"));
        assert!(relay_matches(&relay, "relay.example"));
        assert!(relay_matches(&relay, "192.0.2"));
        assert!(!relay_matches(&relay, "korea"));
        assert!(relay_matches(&relay, ""));
    }

    #[test]
    fn cache_age_is_human_readable() {
        assert_eq!(format_age(42), "42s old");
        assert_eq!(format_age(120), "2m old");
        assert_eq!(format_age(7200), "2h old");
    }
}
