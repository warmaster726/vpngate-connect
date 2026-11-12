#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use eframe::egui::{self, Color32, RichText};
use vpngate_core::cache::ServerCacheFile;
use vpngate_core::{
    ActiveSessionState, AppPaths, PRODUCT_VERSION, ProtocolFilter, RemoteDesktopVersion, SortBy,
    UI_CONTROL_PROTOCOL_VERSION, UiControlError, UiControlLease, UiControlSnapshot, VpnServer,
    acquire_ui_control, cpu_isa_label, detect_host_os_label, filter_by_country, filter_by_protocol,
    installed_desktop_version, is_root_or_admin, load_cached_mirrors, load_update_cache,
    now_unix_secs, read_json_opt, record_update_declined, refresh_update_cache, should_auto_prompt,
    sort_servers, summarize_countries, tunnel_aid_dns_cli, ui_control_status,
};

const APP_ID: &str = "net.vpngate.connect";
const ACTIVE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const IDLE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(15);
const CACHE_POLL_INTERVAL: Duration = Duration::from_secs(60);
const BUSY_CACHE_POLL_INTERVAL: Duration = Duration::from_secs(3);
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(700);
const MAX_RELAY_ROWS: usize = 100;
const MAX_LOG_LINES: usize = 600;
const MAX_UI_OBSERVER_LOG_BYTES: u64 = 2 * 1024 * 1024;

fn main() -> eframe::Result {
    if let Err(error) = vpngate_core::assert_supported_native_host() {
        eprintln!("vpngate-gui: {error}");
        std::process::exit(2);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("VPN Gate Connect")
            .with_inner_size([1080.0, 760.0])
            .with_min_inner_size([820.0, 620.0]),
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
    Tools,
    Activity,
}

impl Page {
    const ALL: [Self; 4] = [Self::Connect, Self::Relays, Self::Tools, Self::Activity];

    fn title(self) -> &'static str {
        match self {
            Self::Connect => "Connect",
            Self::Relays => "Relays",
            Self::Tools => "More actions",
            Self::Activity => "System & activity",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::Connect => {
                "Choose one or more regions and connect with the desktop tunnel engine"
            }
            Self::Relays => "Browse, filter, list, and start a connection from a ranked relay",
            Self::Tools => "Manage relay discovery, diagnostics, and connection preferences",
            Self::Activity => {
                "Live tunnel state, shared control, system checks, and recent activity"
            }
        }
    }

    fn navigation_label(self) -> &'static str {
        match self {
            Self::Connect => "Connect",
            Self::Relays => "Relays",
            Self::Tools => "More actions",
            Self::Activity => "System",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum UpdateKind {
    Update,
    Upgrade,
}

impl UpdateKind {
    fn command(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Upgrade => "upgrade",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateCheckMode {
    Startup,
    Diagnostics,
}

#[derive(Debug, Clone, Copy)]
enum ToolAction {
    Countries,
    List,
    Mirrors,
    Refresh,
    ResetCooldowns,
    Status,
    Doctor,
    Probe,
    Disconnect,
    Watchdog(&'static str),
    Help,
}

enum CommandEvent {
    Output(String),
    UpdateCheck(UpdateCheckMode, Result<RemoteDesktopVersion, String>),
    Finished(i32),
    Failed(String),
}

struct CommandWorker {
    receiver: Receiver<CommandEvent>,
    operation: String,
    started_at: Instant,
    cancellable: bool,
    cancel_requested: bool,
}

struct GuiApp {
    paths: AppPaths,
    cli_binary: Option<PathBuf>,
    cli_notice: Option<String>,
    page: Page,
    theme: egui::ThemePreference,
    session: Option<ActiveSessionState>,
    cached_servers: Vec<VpnServer>,
    cache_timestamp: Option<u64>,
    cached_mirror_count: usize,
    relay_search: String,
    relay_country_filter: String,
    relay_protocol: String,
    relay_sort: String,
    selected_relay_ip: Option<String>,
    last_state_poll: Instant,
    last_cache_poll: Instant,
    last_control_poll: Instant,
    control_status: Option<UiControlSnapshot>,
    control_lease: Option<UiControlLease>,
    worker: Option<CommandWorker>,
    command_log: VecDeque<String>,
    status_message: String,
    observer_status: String,
    host_label: String,
    native_arch: &'static str,
    elevated: bool,

    connect_country: String,
    connect_protocol: String,
    connect_sort: String,
    connect_limit: usize,
    connect_timeout_secs: u64,
    connect_engine: String,
    connect_dns: String,
    connect_start_index: usize,
    connect_autoreconnect: String,
    connect_force_refresh: bool,
    connect_mirrors: String,

    tools_country: String,
    tools_protocol: String,
    tools_sort: String,
    tools_limit: usize,
    tools_force_refresh: bool,
    tools_mirrors: String,
    probe_ip: String,
    pending_update: Option<UpdateKind>,
    update_offer: Option<RemoteDesktopVersion>,
    pending_update_check: Option<UpdateCheckMode>,
}

impl GuiApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_native_theme(&cc.egui_ctx);
        install_platform_font(&cc.egui_ctx);

        let paths = AppPaths::resolve();
        let (cli_binary, cli_notice) = resolve_cli_binary();
        let observer_status = start_legacy_observer(cli_binary.as_deref(), &paths, "started");
        let mut app = Self {
            paths,
            cli_binary,
            cli_notice,
            page: Page::Connect,
            theme: egui::ThemePreference::System,
            session: None,
            cached_servers: Vec::new(),
            cache_timestamp: None,
            cached_mirror_count: 0,
            relay_search: String::new(),
            relay_country_filter: String::new(),
            relay_protocol: "auto".to_string(),
            relay_sort: "score".to_string(),
            selected_relay_ip: None,
            last_state_poll: Instant::now(),
            last_cache_poll: Instant::now(),
            last_control_poll: Instant::now(),
            control_status: None,
            control_lease: None,
            worker: None,
            command_log: VecDeque::new(),
            status_message: String::new(),
            observer_status,
            host_label: detect_host_os_label(),
            native_arch: cpu_isa_label(),
            elevated: is_root_or_admin(),

            connect_country: "all".to_string(),
            connect_protocol: "auto".to_string(),
            connect_sort: "score".to_string(),
            connect_limit: 0,
            connect_timeout_secs: 22,
            connect_engine: "auto".to_string(),
            connect_dns: tunnel_aid_dns_cli(),
            connect_start_index: 1,
            connect_autoreconnect: "default".to_string(),
            connect_force_refresh: false,
            connect_mirrors: String::new(),

            tools_country: String::new(),
            tools_protocol: "auto".to_string(),
            tools_sort: "score".to_string(),
            tools_limit: 25,
            tools_force_refresh: false,
            tools_mirrors: String::new(),
            probe_ip: String::new(),
            pending_update: None,
            update_offer: None,
            pending_update_check: Some(UpdateCheckMode::Startup),
        };
        app.reload_session();
        app.reload_cache();
        app.control_status = ui_control_status(&app.paths);
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
            self.cached_servers.clear();
        }
        self.cached_mirror_count = load_cached_mirrors(&self.paths).len();
        self.last_cache_poll = Instant::now();
    }

    fn reload_control(&mut self) {
        self.control_status = ui_control_status(&self.paths);
        self.last_control_poll = Instant::now();
    }

    fn actions_blocked(&self) -> bool {
        self.worker.is_some()
            || self.control_lease.is_some()
            || self
                .control_status
                .as_ref()
                .is_some_and(|state| state.owner_pid != std::process::id())
    }

    fn action_service_notice(&self) -> &str {
        self.cli_notice.as_deref().unwrap_or(
            "The synchronized desktop action service is unavailable. Install the desktop components together and restart this app.",
        )
    }

    fn control_badge(&self) -> Option<(String, Color32)> {
        if let Some(worker) = &self.worker {
            return Some((
                format!("RUNNING · {}", worker.operation),
                Color32::from_rgb(53, 132, 228),
            ));
        }
        self.control_status.as_ref().and_then(|state| {
            (state.owner_pid != std::process::id()).then(|| {
                (
                    format!("OBSERVE ONLY · {}: {}", state.owner, state.operation),
                    Color32::from_rgb(190, 125, 30),
                )
            })
        })
    }

    fn control_banner(&self, ui: &mut egui::Ui) {
        if let Some(state) = self.control_status.as_ref()
            && state.owner_pid != std::process::id()
        {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        Color32::from_rgb(190, 125, 30),
                        RichText::new("OBSERVE ONLY").strong(),
                    );
                    ui.label(format!(
                        "{} is running {} — {}. Controls unlock when that window finishes.",
                        state.owner, state.operation, state.phase
                    ));
                });
            });
            ui.add_space(8.0);
        } else if let Some(worker) = &self.worker {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        Color32::from_rgb(53, 132, 228),
                        RichText::new("GUI HAS CONTROL").strong(),
                    );
                    ui.label(format!(
                        "{} · elapsed {}s",
                        worker.operation,
                        worker.started_at.elapsed().as_secs()
                    ));
                });
            });
            ui.add_space(8.0);
        }
    }

    fn available_countries(&self) -> Vec<(String, String)> {
        summarize_countries(&self.cached_servers)
            .into_iter()
            .map(|country| (country.country_short, country.country_long))
            .collect()
    }

    fn parsed_protocol(value: &str) -> ProtocolFilter {
        ProtocolFilter::from_cli_str(value).unwrap_or(ProtocolFilter::Auto)
    }

    fn parsed_sort(value: &str) -> SortBy {
        SortBy::from_cli_str(value).unwrap_or(SortBy::Score)
    }

    fn matched_relays(&self) -> Vec<(usize, VpnServer)> {
        let protocol = Self::parsed_protocol(&self.relay_protocol);
        let available = filter_by_protocol(&self.cached_servers, protocol);
        let query = self.relay_country_filter.trim();
        let mut relays = filter_by_country(&available, (!query.is_empty()).then_some(query));
        sort_servers(&mut relays, Self::parsed_sort(&self.relay_sort), protocol);
        relays
            .into_iter()
            .enumerate()
            .filter_map(|(rank, server)| {
                relay_matches(&server, self.relay_search.trim()).then_some((rank, server))
            })
            .collect()
    }

    fn selected_relay(&self) -> Option<(usize, VpnServer)> {
        let selected = self.selected_relay_ip.as_deref()?;
        self.matched_relays()
            .into_iter()
            .find(|(_, server)| server.ip == selected)
    }

    fn connect_args(&self) -> Vec<String> {
        let mut args = vec![
            "connect".to_string(),
            "--country".to_string(),
            self.connect_country.trim().to_string(),
            "--proto".to_string(),
            self.connect_protocol.clone(),
            "--sort".to_string(),
            self.connect_sort.clone(),
            "--limit".to_string(),
            self.connect_limit.to_string(),
            "--timeout".to_string(),
            self.connect_timeout_secs.to_string(),
            "--engine".to_string(),
            self.connect_engine.clone(),
            "--dns".to_string(),
            self.connect_dns.trim().to_string(),
            "--start".to_string(),
            self.connect_start_index.to_string(),
        ];
        if self.connect_force_refresh {
            args.push("--refresh".to_string());
        }
        match self.connect_autoreconnect.as_str() {
            "on" => args.push("--autoreconnect".to_string()),
            "off" => args.push("--no-autoreconnect".to_string()),
            _ => {}
        }
        append_mirror_args(&mut args, &self.connect_mirrors);
        args
    }

    fn tool_list_args(&self) -> Vec<String> {
        let mut args = vec![
            "list".to_string(),
            "--proto".to_string(),
            self.tools_protocol.clone(),
            "--sort".to_string(),
            self.tools_sort.clone(),
            "--limit".to_string(),
            self.tools_limit.to_string(),
        ];
        if !self.tools_country.trim().is_empty() {
            args.push("--country".to_string());
            args.push(self.tools_country.trim().to_string());
        }
        if self.tools_force_refresh {
            args.push("--refresh".to_string());
        }
        append_mirror_args(&mut args, &self.tools_mirrors);
        args
    }

    fn start_connect(&mut self) {
        if self.connect_country.trim().is_empty() {
            self.status_message = "Enter a country code/name or use `all`. Multiple regions can be comma-separated (for example JP,KR).".to_string();
            return;
        }
        let args = self.connect_args();
        self.start_cli_command("Connect", args, true, true);
    }

    fn fetch_connect_regions(&mut self) {
        let args = connect_regions_fetch_args(&self.connect_protocol, &self.connect_mirrors);
        self.start_cli_command("Fetch regions", args, false, false);
    }

    fn start_cli_command(
        &mut self,
        operation: &str,
        args: Vec<String>,
        cancellable: bool,
        requires_privilege: bool,
    ) {
        if self.actions_blocked() {
            self.status_message =
                "Another UI currently owns the shared control lock; this window is observe-only."
                    .to_string();
            return;
        }
        let Some(cli_binary) = self.cli_binary.clone() else {
            self.status_message = self.action_service_notice().to_string();
            return;
        };

        let lease = match acquire_ui_control(&self.paths, "GUI", operation) {
            Ok(lease) => lease,
            Err(UiControlError::Busy(state)) => {
                self.control_status = Some(state.clone());
                self.status_message = format!(
                    "Observe-only: {} is running {} ({}).",
                    state.owner, state.operation, state.phase
                );
                return;
            }
            Err(error) => {
                self.status_message =
                    format!("Could not acquire the shared UI control lock: {error}");
                return;
            }
        };
        let token = lease.token().to_string();
        lease.set_phase("Starting desktop operation");
        self.command_log.clear();
        self.push_log(format!("Starting {operation}…"));
        let _ = append_observer_log(&self.paths, &format!("=== GUI started {operation} ==="));
        self.status_message.clear();
        self.control_lease = Some(lease);
        self.reload_control();

        let paths = self.paths.clone();
        let (sender, receiver) = mpsc::channel();
        let worker_operation = operation.to_string();
        thread::spawn(move || {
            run_cli_command(cli_binary, args, paths, token, requires_privilege, sender);
        });
        self.worker = Some(CommandWorker {
            receiver,
            operation: worker_operation,
            started_at: Instant::now(),
            cancellable,
            cancel_requested: false,
        });
    }

    fn start_update_check(&mut self, mode: UpdateCheckMode) {
        if self.worker.is_some() || self.control_lease.is_some() {
            return;
        }
        let lease = match acquire_ui_control(&self.paths, "GUI", "Check desktop updates") {
            Ok(lease) => lease,
            Err(UiControlError::Busy(state)) => {
                self.control_status = Some(state);
                return;
            }
            Err(error) => {
                self.pending_update_check = None;
                self.status_message = format!("Could not start the update check: {error}");
                return;
            }
        };
        lease.set_phase("Checking the public desktop version");
        self.control_lease = Some(lease);
        self.command_log.clear();
        self.push_log("Checking for desktop updates…".to_string());
        let _ = append_observer_log(&self.paths, "=== GUI started desktop update check ===");
        self.status_message.clear();
        self.reload_control();

        let paths = self.paths.clone();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(refresh_update_cache(
                    &paths,
                    mode == UpdateCheckMode::Diagnostics,
                )),
                Err(error) => Err(format!("Could not start the update-check runtime: {error}")),
            };
            let _ = sender.send(CommandEvent::UpdateCheck(mode, result));
        });
        self.worker = Some(CommandWorker {
            receiver,
            operation: "Check desktop updates".to_string(),
            started_at: Instant::now(),
            cancellable: false,
            cancel_requested: false,
        });
        self.pending_update_check = None;
    }

    fn cancel_connect(&mut self) {
        let can_cancel = self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.cancellable && !worker.cancel_requested);
        if !can_cancel {
            return;
        }
        let requested = self
            .control_lease
            .as_ref()
            .is_some_and(UiControlLease::request_cancel);
        if requested {
            if let Some(worker) = &mut self.worker {
                worker.cancel_requested = true;
            }
            let message =
                "Cancellation requested — tunnel changes will be rolled back before returning.";
            let _ = append_observer_log(&self.paths, message);
            self.push_log(message.to_string());
            self.status_message = "Cancelling and rolling back…".to_string();
            self.reload_control();
        } else {
            self.status_message = "The shared cancellation request could not be sent.".to_string();
        }
    }

    fn execute_tool_action(&mut self, action: ToolAction) {
        match action {
            ToolAction::Countries => {
                let mut args = vec![
                    "countries".to_string(),
                    "--proto".to_string(),
                    self.tools_protocol.clone(),
                ];
                if self.tools_force_refresh {
                    args.push("--refresh".to_string());
                }
                append_mirror_args(&mut args, &self.tools_mirrors);
                self.start_cli_command("List countries", args, false, false);
            }
            ToolAction::List => {
                let args = self.tool_list_args();
                self.start_cli_command("List relays", args, false, false);
            }
            ToolAction::Mirrors => {
                let mut args = vec!["mirrors".to_string()];
                append_mirror_args(&mut args, &self.tools_mirrors);
                self.start_cli_command("Discover mirrors", args, false, false);
            }
            ToolAction::Refresh => {
                let mut args = vec!["refresh".to_string()];
                append_mirror_args(&mut args, &self.tools_mirrors);
                self.start_cli_command("Refresh relay pool", args, false, false);
            }
            ToolAction::ResetCooldowns => {
                self.start_cli_command(
                    "Reset relay cooldowns",
                    vec!["cooldowns".to_string(), "reset".to_string()],
                    false,
                    false,
                );
            }
            ToolAction::Status => {
                self.start_cli_command(
                    "Connection status",
                    vec!["status".to_string()],
                    false,
                    false,
                );
            }
            ToolAction::Doctor => {
                self.start_cli_command(
                    "System diagnostics",
                    vec!["doctor".to_string()],
                    false,
                    false,
                );
            }
            ToolAction::Probe => {
                if self.probe_ip.trim().is_empty() {
                    self.status_message = "Enter an IPv4 address to probe.".to_string();
                    return;
                }
                self.start_cli_command(
                    "Probe relay",
                    vec!["probe".to_string(), self.probe_ip.trim().to_string()],
                    false,
                    false,
                );
            }
            ToolAction::Disconnect => {
                self.start_cli_command("Disconnect", vec!["disconnect".to_string()], false, true);
            }
            ToolAction::Watchdog(mode) => {
                let needs_privilege =
                    self.session.is_some() && matches!(mode, "on" | "off" | "toggle");
                self.start_cli_command(
                    &format!("Watchdog {mode}"),
                    vec!["watchdog".to_string(), mode.to_string()],
                    false,
                    needs_privilege,
                );
            }
            ToolAction::Help => {
                self.start_cli_command("Help and usage", vec!["--help".to_string()], false, false);
            }
        }
    }

    fn request_update(&mut self, kind: UpdateKind) {
        self.pending_update = Some(kind);
    }

    fn update_confirmation_ui(&mut self, ctx: &egui::Context) {
        let Some(kind) = self.pending_update else {
            return;
        };
        let mut confirmed = false;
        let mut dismissed = false;
        egui::Window::new("Confirm desktop update")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                if let Some(remote) = &self.update_offer {
                    ui.label(format!(
                        "Installed v{PRODUCT_VERSION} · latest v{}. Installing the update is strongly recommended.",
                        remote.raw
                    ));
                    ui.label(
                        RichText::new(format!("Version source: {}", remote.source_url))
                            .weak()
                            .small(),
                    );
                } else {
                    ui.label(
                        "Continue with the desktop installer? It may replace this installation.",
                    );
                    ui.label(
                        RichText::new(
                            "The update is downloaded anonymously from the public repository.",
                        )
                        .weak(),
                    );
                }
                ui.label(
                    RichText::new(
                        "Installing replaces this desktop version and removes the old binary.",
                    )
                    .weak(),
                );
                ui.add_space(8.0);
                if self.cli_binary.is_none() {
                    ui.colored_label(Color32::from_rgb(190, 125, 30), self.action_service_notice());
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.cli_binary.is_some(), egui::Button::new("Install update"))
                        .clicked()
                    {
                        confirmed = true;
                    }
                    if ui.button("Cancel").clicked() {
                        dismissed = true;
                    }
                });
            });
        if confirmed {
            self.pending_update = None;
            let update_offer = self.update_offer.take();
            self.start_cli_command(
                kind.command(),
                vec![kind.command().to_string(), "--yes".to_string()],
                false,
                true,
            );
            if self.worker.is_none() {
                self.update_offer = update_offer;
                self.pending_update = Some(kind);
            }
        } else if dismissed {
            if let Some(remote) = self.update_offer.take() {
                record_update_declined(&self.paths, &remote);
            }
            self.pending_update = None;
        }
    }

    fn pump_command_events(&mut self) {
        let events: Vec<CommandEvent> = self
            .worker
            .as_ref()
            .map(|worker| worker.receiver.try_iter().collect())
            .unwrap_or_default();
        let mut finished = false;
        let mut latest_phase = None;
        let mut observer_output = Vec::new();
        for event in events {
            match event {
                CommandEvent::Output(line) => {
                    let clean = strip_ansi(&line);
                    if !clean.trim().is_empty() {
                        observer_output.push(clean.clone());
                        latest_phase = Some(clean.clone());
                        self.push_log(clean);
                    }
                }
                CommandEvent::UpdateCheck(mode, Ok(remote)) => {
                    if remote.version > installed_desktop_version() {
                        let should_prompt = mode == UpdateCheckMode::Diagnostics
                            || load_update_cache(&self.paths)
                                .is_none_or(|cache| should_auto_prompt(&cache, &remote.version));
                        if should_prompt {
                            let message = format!(
                                "Desktop update v{} is available; installing it is strongly recommended.",
                                remote.raw
                            );
                            observer_output.push(message.clone());
                            self.push_log(message.clone());
                            self.status_message = message;
                            self.update_offer = Some(remote);
                            self.pending_update = Some(UpdateKind::Update);
                        } else {
                            let message = format!(
                                "Desktop update v{} is available; its reminder is snoozed after your earlier choice.",
                                remote.raw
                            );
                            observer_output.push(message.clone());
                            self.push_log(message.clone());
                            self.status_message = message;
                        }
                    } else {
                        let message =
                            format!("VPN Gate Connect is up to date (v{PRODUCT_VERSION}).");
                        observer_output.push(message.clone());
                        self.push_log(message.clone());
                        self.status_message = message;
                    }
                    finished = true;
                }
                CommandEvent::UpdateCheck(_, Err(error)) => {
                    let message = format!("Desktop update check did not complete: {error}");
                    observer_output.push(message.clone());
                    self.push_log(message.clone());
                    self.status_message = message;
                    finished = true;
                }
                CommandEvent::Finished(code) => {
                    let operation = self
                        .worker
                        .as_ref()
                        .map(|worker| worker.operation.as_str())
                        .unwrap_or("Action");
                    let message = action_result_message(operation, code);
                    observer_output.push(message.clone());
                    if code != 0 {
                        let detail = format!("Technical result status: {code}");
                        observer_output.push(detail.clone());
                        self.push_log(detail);
                    }
                    self.push_log(message.clone());
                    self.status_message = message;
                    finished = true;
                }
                CommandEvent::Failed(error) => {
                    let operation = self
                        .worker
                        .as_ref()
                        .map(|worker| worker.operation.as_str())
                        .unwrap_or("Action");
                    let message = format!("Could not start {operation}: {error}");
                    observer_output.push(message.clone());
                    self.push_log(message.clone());
                    self.status_message = message;
                    finished = true;
                }
            }
        }
        if !observer_output.is_empty() {
            let _ = append_observer_log(&self.paths, &observer_output.join("\n"));
        }
        if let (Some(phase), Some(lease)) = (latest_phase, self.control_lease.as_ref()) {
            lease.set_phase(phase.chars().take(180).collect::<String>());
        }
        if finished {
            let update_after_doctor = self
                .worker
                .as_ref()
                .is_some_and(|worker| worker.operation == "System diagnostics");
            self.worker = None;
            self.control_lease = None;
            self.reload_session();
            self.reload_cache();
            self.reload_control();
            if update_after_doctor {
                self.pending_update_check = Some(UpdateCheckMode::Diagnostics);
            }
        }
    }

    fn push_log(&mut self, line: String) {
        for part in line.lines() {
            self.command_log.push_back(part.to_string());
            while self.command_log.len() > MAX_LOG_LINES {
                self.command_log.pop_front();
            }
        }
    }

    fn activity_details_panel(&mut self, ui: &mut egui::Ui, max_height: f32) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Recent activity").strong());
                if let Some(worker) = &self.worker {
                    ui.label(
                        RichText::new(format!(
                            "{} · {}s",
                            worker.operation,
                            worker.started_at.elapsed().as_secs()
                        ))
                        .weak(),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Clear").clicked() {
                        self.command_log.clear();
                    }
                });
            });
            if !self.status_message.is_empty() {
                ui.label(RichText::new(&self.status_message).weak());
            }
            egui::CollapsingHeader::new("Technical details")
                .default_open(false)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(max_height)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            if self.command_log.is_empty() {
                                ui.label(RichText::new("No recent details.").weak());
                            } else {
                                for line in &self.command_log {
                                    ui.monospace(line);
                                }
                            }
                        });
                });
        });
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

    #[cfg(not(target_os = "windows"))]
    fn desktop_header(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("VPN Gate Connect").heading().strong());
                ui.label(
                    RichText::new(format!("Functional GUI · v{PRODUCT_VERSION}"))
                        .weak()
                        .small(),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                self.appearance_picker(ui, ctx);
                ui.add_space(12.0);
                if let Some((label, color)) = self.control_badge() {
                    ui.colored_label(color, RichText::new(label).strong());
                    ui.add_space(12.0);
                }
                let (label, color) = self.status_badge();
                ui.colored_label(color, RichText::new(label).strong());
            });
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
                if ui.button("System & activity").clicked() {
                    self.page = Page::Activity;
                    ui.close();
                }
                if ui.button("Help and usage").clicked() {
                    self.execute_tool_action(ToolAction::Help);
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
                if let Some((label, color)) = self.control_badge() {
                    ui.add_space(12.0);
                    ui.colored_label(color, RichText::new(label).strong());
                }
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
        ui.add_space(10.0);
        self.control_banner(ui);

        match self.page {
            Page::Connect => self.connect_page(ui),
            Page::Relays => self.relays_page(ui),
            Page::Tools => self.tools_page(ui),
            Page::Activity => self.activity_page(ui),
        }
    }

    fn connect_page(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                let (label, color) = self.status_badge();
                let (dot_rect, _) =
                    ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(dot_rect.center(), 5.0, color);
                ui.vertical(|ui| {
                    ui.label(RichText::new(label).strong().size(18.0));
                    ui.label(
                        RichText::new("Live session state from the shared desktop cache").weak(),
                    );
                });
            });
            ui.add_space(6.0);
            if let Some(session) = &self.session {
                egui::Grid::new("session_details")
                    .num_columns(2)
                    .spacing([20.0, 6.0])
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
                    });
            } else {
                ui.label("No active VPN session was found.");
            }
        });

        ui.add_space(10.0);
        let blocked = self.actions_blocked();
        let countries = self.available_countries();
        let selected_country_label = country_picker_label(&self.connect_country, &countries);
        let region_cache_label = self
            .cache_timestamp
            .map(|timestamp| {
                format!(
                    "{} regions · cache {}",
                    countries.len(),
                    format_age(now_unix_secs().saturating_sub(timestamp))
                )
            })
            .unwrap_or_else(|| "No region cache yet".to_string());
        let mut connect_clicked = false;
        let mut disconnect_clicked = false;
        let mut fetch_regions_clicked = false;
        ui.add_enabled_ui(!blocked, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(RichText::new("Connection options").strong());
                egui::Grid::new("connect_options")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Country / region");
                        ui.horizontal_wrapped(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.connect_country)
                                    .desired_width(150.0)
                                    .hint_text("all or JP,KR"),
                            );
                            egui::ComboBox::from_id_salt("connect_country_picker")
                                .selected_text(selected_country_label)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.connect_country,
                                        "all".to_string(),
                                        "All countries",
                                    );
                                    for (code, name) in &countries {
                                        ui.selectable_value(
                                            &mut self.connect_country,
                                            code.clone(),
                                            format!("{name} ({code})"),
                                        );
                                    }
                                });
                            fetch_regions_clicked = ui
                                .button("Fetch regions")
                                .on_hover_text("Refresh the live relay pool and update this region picker without leaving Connect")
                                .clicked();
                            ui.label(RichText::new(&region_cache_label).weak().small());
                        });
                        ui.end_row();

                        ui.label("Protocol");
                        egui::ComboBox::from_id_salt("connect_protocol")
                            .selected_text(&self.connect_protocol)
                            .show_ui(ui, |ui| {
                                for item in
                                    ["auto", "l2tp", "openvpn-udp", "openvpn-tcp", "openvpn"]
                                {
                                    ui.selectable_value(
                                        &mut self.connect_protocol,
                                        item.to_string(),
                                        item,
                                    );
                                }
                            });
                        ui.end_row();

                        ui.label("Sort order");
                        egui::ComboBox::from_id_salt("connect_sort")
                            .selected_text(&self.connect_sort)
                            .show_ui(ui, |ui| {
                                for item in ["score", "speed", "ping", "recommended"] {
                                    ui.selectable_value(
                                        &mut self.connect_sort,
                                        item.to_string(),
                                        item,
                                    );
                                }
                            });
                        ui.end_row();

                        ui.label("Auto-reconnect");
                        egui::ComboBox::from_id_salt("connect_watchdog")
                            .selected_text(match self.connect_autoreconnect.as_str() {
                                "on" => "Enable",
                                "off" => "Disable",
                                _ => "Use saved preference",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.connect_autoreconnect,
                                    "default".to_string(),
                                    "Use saved preference",
                                );
                                ui.selectable_value(
                                    &mut self.connect_autoreconnect,
                                    "on".to_string(),
                                    "Enable for this session",
                                );
                                ui.selectable_value(
                                    &mut self.connect_autoreconnect,
                                    "off".to_string(),
                                    "Disable for this session",
                                );
                            });
                        ui.end_row();
                    });

                egui::CollapsingHeader::new("Advanced connection options")
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::Grid::new("connect_advanced")
                            .num_columns(2)
                            .spacing([12.0, 8.0])
                            .show(ui, |ui| {
                                ui.label("Try at most");
                                ui.add(
                                    egui::DragValue::new(&mut self.connect_limit)
                                        .range(0..=1000)
                                        .suffix(" relays (0 = all)"),
                                );
                                ui.end_row();

                                ui.label("Attempt timeout");
                                ui.add(
                                    egui::DragValue::new(&mut self.connect_timeout_secs)
                                        .range(5..=300)
                                        .suffix(" s"),
                                );
                                ui.end_row();

                                ui.label("Start at ranked relay");
                                ui.add(
                                    egui::DragValue::new(&mut self.connect_start_index)
                                        .range(1..=10000),
                                );
                                ui.end_row();

                                ui.label("OpenVPN engine");
                                egui::ComboBox::from_id_salt("connect_engine")
                                    .selected_text(&self.connect_engine)
                                    .show_ui(ui, |ui| {
                                        for item in ["auto", "nm", "daemon"] {
                                            ui.selectable_value(
                                                &mut self.connect_engine,
                                                item.to_string(),
                                                item,
                                            );
                                        }
                                    });
                                ui.end_row();

                                ui.label("Extra DNS servers");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.connect_dns)
                                        .desired_width(320.0),
                                );
                                ui.end_row();

                                ui.label("Custom mirrors");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.connect_mirrors)
                                        .desired_width(320.0)
                                        .hint_text("URLs separated by semicolon"),
                                );
                                ui.end_row();
                            });
                        ui.checkbox(
                            &mut self.connect_force_refresh,
                            "Force refresh relay pool before connecting (-r)",
                        );
                    });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    connect_clicked = ui.button(RichText::new("Connect").strong()).clicked();
                    disconnect_clicked = ui.button("Disconnect").clicked();
                    if ui.button("Browse relays").clicked() {
                        self.page = Page::Relays;
                    }
                    if ui.button("More actions").clicked() {
                        self.page = Page::Tools;
                    }
                });
            });
        });

        if self.cli_binary.is_none() {
            ui.colored_label(
                Color32::from_rgb(190, 125, 30),
                self.action_service_notice(),
            );
        }
        if !self.status_message.is_empty() {
            ui.label(RichText::new(&self.status_message).weak());
        }
        if let Some(worker) = &self.worker
            && worker.cancellable
        {
            let mut cancel_clicked = false;
            let enabled = !worker.cancel_requested;
            ui.horizontal(|ui| {
                ui.colored_label(
                    Color32::from_rgb(190, 125, 30),
                    "Connect is running. Cancelling performs the normal tunnel rollback.",
                );
                cancel_clicked = ui
                    .add_enabled(enabled, egui::Button::new("Cancel connect"))
                    .clicked();
            });
            if cancel_clicked {
                self.cancel_connect();
            }
        }

        if fetch_regions_clicked {
            self.fetch_connect_regions();
        } else if connect_clicked {
            self.start_connect();
        } else if disconnect_clicked {
            self.execute_tool_action(ToolAction::Disconnect);
        }
        ui.add_space(8.0);
        self.activity_details_panel(ui, 180.0);
    }

    fn relays_page(&mut self, ui: &mut egui::Ui) {
        let blocked = self.actions_blocked();
        let mut run_list = false;
        let mut connect_selected = false;
        let mut reload = false;
        ui.add_enabled_ui(!blocked, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Country");
                ui.add(
                    egui::TextEdit::singleline(&mut self.relay_country_filter)
                        .desired_width(90.0)
                        .hint_text("all"),
                );
                ui.label("Protocol");
                egui::ComboBox::from_id_salt("relay_protocol")
                    .selected_text(&self.relay_protocol)
                    .show_ui(ui, |ui| {
                        for item in ["auto", "l2tp", "openvpn-udp", "openvpn-tcp", "openvpn"] {
                            ui.selectable_value(&mut self.relay_protocol, item.to_string(), item);
                        }
                    });
                ui.label("Sort");
                egui::ComboBox::from_id_salt("relay_sort")
                    .selected_text(&self.relay_sort)
                    .show_ui(ui, |ui| {
                        for item in ["score", "speed", "ping", "recommended"] {
                            ui.selectable_value(&mut self.relay_sort, item.to_string(), item);
                        }
                    });
                ui.label("Find");
                ui.add(
                    egui::TextEdit::singleline(&mut self.relay_search)
                        .desired_width(150.0)
                        .hint_text("host, country, IP"),
                );
                run_list = ui.button("Load relay data").clicked();
                reload = ui.button("Reload cache").clicked();
            });
        });
        if reload {
            self.reload_cache();
        }
        if run_list {
            let mut args = vec![
                "list".to_string(),
                "--proto".to_string(),
                self.relay_protocol.clone(),
                "--sort".to_string(),
                self.relay_sort.clone(),
                "--limit".to_string(),
                "0".to_string(),
            ];
            if !self.relay_country_filter.trim().is_empty() {
                args.push("--country".to_string());
                args.push(self.relay_country_filter.trim().to_string());
            }
            self.start_cli_command("List relays", args, false, false);
        }

        let relays = self.matched_relays();
        let cache_age = self
            .cache_timestamp
            .map(|timestamp| format_age(now_unix_secs().saturating_sub(timestamp)))
            .unwrap_or_else(|| "unknown age".to_string());
        ui.label(
            RichText::new(format!(
                "Local pool: {} relays · {} matching · cache {cache_age}",
                self.cached_servers.len(),
                relays.len()
            ))
            .weak()
            .small(),
        );
        ui.add_space(6.0);

        if self.cached_servers.is_empty() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(RichText::new("No cached relays").strong());
                ui.label(
                    "Load relay data from More actions or start a connection to populate the shared pool.",
                );
            });
        } else if relays.is_empty() {
            ui.label("No cached relays match these filters.");
        } else {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(420.0)
                .show(ui, |ui| {
                    egui::Grid::new("relay_table")
                        .striped(true)
                        .num_columns(6)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            for header in [
                                "# / relay",
                                "Country",
                                "Address",
                                "Speed",
                                "Ping",
                                "Protocols",
                            ] {
                                ui.label(RichText::new(header).strong());
                            }
                            ui.end_row();
                            for (rank, server) in relays.iter().take(MAX_RELAY_ROWS) {
                                let selected =
                                    self.selected_relay_ip.as_deref() == Some(server.ip.as_str());
                                if ui
                                    .selectable_label(
                                        selected,
                                        format!("{} · {}", rank + 1, server.hostname),
                                    )
                                    .clicked()
                                {
                                    self.selected_relay_ip = Some(server.ip.clone());
                                }
                                ui.label(format!(
                                    "{} ({})",
                                    server.country_long, server.country_short
                                ));
                                ui.monospace(&server.ip);
                                ui.label(format!("{:.1} Mbps", server.speed_mbps()));
                                ui.label(if server.ping_ms < 9999 {
                                    format!("{} ms", server.ping_ms)
                                } else {
                                    "N/A".to_string()
                                });
                                ui.label(protocol_labels(server));
                                ui.end_row();
                            }
                        });
                });
            if relays.len() > MAX_RELAY_ROWS {
                ui.label(
                    RichText::new(format!(
                        "Showing the first {MAX_RELAY_ROWS} of {} matches.",
                        relays.len()
                    ))
                    .weak()
                    .small(),
                );
            }
        }

        if let Some((rank, server)) = self.selected_relay() {
            let label = format!(
                "Connect from selected relay #{} — {} ({})",
                rank + 1,
                server.hostname,
                server.country_short
            );
            connect_selected = ui.add_enabled(!blocked, egui::Button::new(label)).clicked();
        } else if self.selected_relay_ip.is_some() {
            ui.label(RichText::new("Selected relay is outside the current filters.").weak());
        }
        if connect_selected && let Some((_, server)) = self.selected_relay() {
            let protocol = Self::parsed_protocol(&self.relay_protocol);
            let sort = Self::parsed_sort(&self.relay_sort);
            self.connect_country = server.country_short.clone();
            self.connect_protocol = self.relay_protocol.clone();
            self.connect_sort = self.relay_sort.clone();
            self.connect_start_index =
                selected_relay_start_index(&self.cached_servers, &server, protocol, sort)
                    .unwrap_or(1);
            self.start_connect();
        }
        ui.add_space(8.0);
        self.activity_details_panel(ui, 150.0);
    }

    fn tools_page(&mut self, ui: &mut egui::Ui) {
        let blocked = self.actions_blocked();
        let mut action = None;
        ui.add_enabled_ui(!blocked, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(RichText::new("Action filters").strong());
                egui::Grid::new("tool_options")
                    .num_columns(4)
                    .spacing([10.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Country filter");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.tools_country)
                                .desired_width(120.0)
                                .hint_text("JP,KR or all"),
                        );
                        ui.label("Protocol");
                        egui::ComboBox::from_id_salt("tools_protocol")
                            .selected_text(&self.tools_protocol)
                            .show_ui(ui, |ui| {
                                for item in
                                    ["auto", "l2tp", "openvpn-udp", "openvpn-tcp", "openvpn"]
                                {
                                    ui.selectable_value(
                                        &mut self.tools_protocol,
                                        item.to_string(),
                                        item,
                                    );
                                }
                            });
                        ui.end_row();
                        ui.label("Sort");
                        egui::ComboBox::from_id_salt("tools_sort")
                            .selected_text(&self.tools_sort)
                            .show_ui(ui, |ui| {
                                for item in ["score", "speed", "ping", "recommended"] {
                                    ui.selectable_value(
                                        &mut self.tools_sort,
                                        item.to_string(),
                                        item,
                                    );
                                }
                            });
                        ui.label("List limit");
                        ui.add(
                            egui::DragValue::new(&mut self.tools_limit)
                                .range(0..=1000)
                                .suffix(" (0 = all)"),
                        );
                        ui.end_row();
                        ui.label("Custom mirror URLs");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.tools_mirrors)
                                .desired_width(240.0)
                                .hint_text("separate URLs with semicolons"),
                        );
                        ui.label("Probe IPv4");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.probe_ip)
                                .desired_width(150.0)
                                .hint_text("192.0.2.1"),
                        );
                        ui.end_row();
                    });
                ui.checkbox(
                    &mut self.tools_force_refresh,
                    "Force live server-pool refresh for countries/list (-r)",
                );
            });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("Countries").clicked() {
                    action = Some(ToolAction::Countries);
                }
                if ui.button("List relays").clicked() {
                    action = Some(ToolAction::List);
                }
                if ui.button("Find mirrors").clicked() {
                    action = Some(ToolAction::Mirrors);
                }
                if ui.button("Refresh relay pool").clicked() {
                    action = Some(ToolAction::Refresh);
                }
                if ui
                    .button("Reset relay cooldowns")
                    .on_hover_text("Clear the 30-minute failure penalties so relays can be retried immediately.")
                    .clicked()
                {
                    action = Some(ToolAction::ResetCooldowns);
                }
                if ui.button("Connection status").clicked() {
                    action = Some(ToolAction::Status);
                }
                if ui.button("System check").clicked() {
                    action = Some(ToolAction::Doctor);
                }
                if ui.button("Check relay address").clicked() {
                    action = Some(ToolAction::Probe);
                }
                if ui.button("Disconnect").clicked() {
                    action = Some(ToolAction::Disconnect);
                }
            });
            ui.horizontal_wrapped(|ui| {
                if ui.button("Watchdog status").clicked() {
                    action = Some(ToolAction::Watchdog("status"));
                }
                if ui.button("Watchdog on").clicked() {
                    action = Some(ToolAction::Watchdog("on"));
                }
                if ui.button("Watchdog off").clicked() {
                    action = Some(ToolAction::Watchdog("off"));
                }
                if ui.button("Watchdog toggle").clicked() {
                    action = Some(ToolAction::Watchdog("toggle"));
                }
                if ui.button("Help and usage").clicked() {
                    action = Some(ToolAction::Help);
                }
                if ui.button("Update desktop…").clicked() {
                    self.request_update(UpdateKind::Update);
                }
                if ui.button("Upgrade desktop…").clicked() {
                    self.request_update(UpdateKind::Upgrade);
                }
            });
        });
        if let Some(action) = action {
            self.execute_tool_action(action);
        }
        if self.cli_binary.is_none() {
            ui.colored_label(
                Color32::from_rgb(190, 125, 30),
                self.action_service_notice(),
            );
        }
        ui.add_space(10.0);
        self.activity_details_panel(ui, 260.0);
    }

    fn activity_page(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Host and shared state").strong());
            egui::Grid::new("host_details")
                .num_columns(2)
                .spacing([18.0, 7.0])
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
                        "Action service",
                        &self
                            .cli_binary
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "Unavailable".to_string()),
                    );
                    detail_row(
                        ui,
                        "Cache directory",
                        &self.paths.cache_dir.display().to_string(),
                    );
                    detail_row(ui, "Cached relays", &self.cached_servers.len().to_string());
                    detail_row(ui, "Cached mirrors", &self.cached_mirror_count.to_string());
                    detail_row(
                        ui,
                        "Watchdog preference",
                        if vpngate_core::load_watchdog_pref(&self.paths) {
                            "Enabled"
                        } else {
                            "Disabled"
                        },
                    );
                    detail_row(
                        ui,
                        "Active session",
                        if self.session.is_some() {
                            "Session file present"
                        } else {
                            "No session file"
                        },
                    );
                    detail_row(ui, "Original UI observer", &self.observer_status);
                    ui.end_row();
                });
        });
        let mut reopen_observer = false;
        ui.horizontal(|ui| {
            reopen_observer = ui.button("Open another terminal observer").clicked();
            ui.label(
                RichText::new("Read-only CLI view; mirrors GUI operations and output.").weak(),
            );
        });
        if reopen_observer {
            self.observer_status =
                start_legacy_observer(self.cli_binary.as_deref(), &self.paths, "reopened");
        }
        ui.add_space(10.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Shared controller").strong());
            if let Some(control) = &self.control_status {
                ui.label(format!(
                    "{} · {} · {}",
                    control.owner, control.operation, control.phase
                ));
                ui.label(
                    RichText::new(format!(
                        "Since {} · owner process {}",
                        control.started_at, control.owner_pid
                    ))
                    .weak()
                    .small(),
                );
            } else {
                ui.label("No UI currently owns the shared exclusive-control lock.");
            }
            if let Some(worker) = &self.worker {
                ui.label(format!(
                    "This GUI operation: {} ({}s)",
                    worker.operation,
                    worker.started_at.elapsed().as_secs()
                ));
            }
        });
        ui.add_space(10.0);
        self.activity_details_panel(ui, 340.0);
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
        self.pump_command_events();
        if self.last_state_poll.elapsed() >= self.session_poll_interval() {
            self.reload_session();
        }
        if self.last_control_poll.elapsed() >= CONTROL_POLL_INTERVAL {
            self.reload_control();
        }
        let cache_interval = if self.control_status.is_some() {
            BUSY_CACHE_POLL_INTERVAL
        } else {
            CACHE_POLL_INTERVAL
        };
        if matches!(self.page, Page::Relays | Page::Tools | Page::Activity)
            && self.last_cache_poll.elapsed() >= cache_interval
        {
            self.reload_cache();
        }
        if let Some(mode) = self.pending_update_check
            && self.worker.is_none()
            && self.control_lease.is_none()
            && self.control_status.is_none()
        {
            self.start_update_check(mode);
        }

        let state_interval = self.session_poll_interval();
        let mut next_repaint = state_interval.saturating_sub(self.last_state_poll.elapsed());
        next_repaint = next_repaint
            .min(CONTROL_POLL_INTERVAL.saturating_sub(self.last_control_poll.elapsed()));
        if matches!(self.page, Page::Relays | Page::Tools | Page::Activity) {
            next_repaint =
                next_repaint.min(cache_interval.saturating_sub(self.last_cache_poll.elapsed()));
        }
        if self.worker.is_some() {
            next_repaint = next_repaint.min(Duration::from_millis(180));
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

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| self.page_contents(ui));
        });
        self.update_confirmation_ui(&ctx);
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
    use std::{env, fs, path::PathBuf};

    let windows_dir = env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let font_dir = windows_dir.join("Fonts");
    let mut fonts = egui::FontDefinitions::default();

    if let Ok(bytes) = fs::read(font_dir.join("segoeui.ttf")) {
        const WINDOWS_UI_FONT: &str = "vpn_gate_segoe_ui";
        fonts.font_data.insert(
            WINDOWS_UI_FONT.to_owned(),
            std::sync::Arc::new(egui::FontData::from_owned(bytes)),
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
            std::sync::Arc::new(egui::FontData::from_owned(bytes)),
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

fn selected_relay_start_index(
    servers: &[VpnServer],
    selected: &VpnServer,
    protocol: ProtocolFilter,
    sort: SortBy,
) -> Option<usize> {
    let available = filter_by_protocol(servers, protocol);
    let mut candidates = filter_by_country(&available, Some(&selected.country_short));
    sort_servers(&mut candidates, sort, protocol);
    candidates
        .iter()
        .position(|candidate| candidate.ip == selected.ip)
        .map(|rank| rank + 1)
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

fn country_picker_label(selection: &str, countries: &[(String, String)]) -> String {
    let selection = selection.trim();
    if selection.eq_ignore_ascii_case("all") {
        return "All countries".to_string();
    }
    if let Some((code, name)) = countries
        .iter()
        .find(|(code, _)| code.eq_ignore_ascii_case(selection))
    {
        return format!("{name} ({code})");
    }
    if selection.is_empty() {
        "Choose a region".to_string()
    } else {
        selection.to_string()
    }
}

fn connect_regions_fetch_args(protocol: &str, mirrors: &str) -> Vec<String> {
    let mut args = vec![
        "countries".to_string(),
        "--proto".to_string(),
        protocol.to_string(),
        "--refresh".to_string(),
    ];
    append_mirror_args(&mut args, mirrors);
    args
}

fn append_mirror_args(args: &mut Vec<String>, value: &str) {
    for mirror in value
        .split([';', '\n'])
        .map(str::trim)
        .filter(|mirror| !mirror.is_empty())
    {
        args.push("--mirror".to_string());
        args.push(mirror.to_string());
    }
}

fn action_result_message(operation: &str, code: i32) -> String {
    if code == vpngate_core::INTERRUPTED_EXIT {
        return format!(
            "{operation} was canceled. Tunnel changes were rolled back or left unchanged."
        );
    }

    match code {
        0 => format!("{operation} completed."),
        2 => format!(
            "{operation} was rejected. Expand Technical details to see the reason; if service compatibility is reported, update both desktop components."
        ),
        75 => format!(
            "{operation} did not start because another app window currently controls the connection. Wait for it to finish, then retry."
        ),
        _ => format!(
            "{operation} did not complete (status {code}). Expand Technical details for more information."
        ),
    }
}

fn resolve_cli_binary() -> (Option<PathBuf>, Option<String>) {
    let mut candidates = Vec::new();
    let executable = std::env::current_exe().ok();
    if let Some(executable) = executable.as_ref() {
        let binary_name = if cfg!(windows) {
            "vpngate.exe"
        } else {
            "vpngate"
        };
        let mut ancestor = executable.parent();
        while let Some(directory) = ancestor {
            candidates.push(directory.join(binary_name));
            for profile in ["debug", "release"] {
                candidates.push(directory.join("target").join(profile).join(binary_name));
            }
            ancestor = directory.parent();
        }
    }
    if let Some(path) = vpngate_core::which_bin(if cfg!(windows) {
        "vpngate.exe"
    } else {
        "vpngate"
    }) {
        candidates.push(path);
    }
    #[cfg(target_os = "linux")]
    candidates.push(PathBuf::from("/usr/local/bin/vpngate"));
    #[cfg(target_os = "macos")]
    {
        candidates.push(PathBuf::from("/usr/local/bin/vpngate"));
        candidates.push(PathBuf::from("/opt/homebrew/bin/vpngate"));
    }

    let mut seen = HashSet::new();
    let mut found_candidate = false;
    let mut unsupported_protocol = None;
    let mut probe_failure = None;
    for path in candidates {
        if !path.is_file() || !seen.insert(path.clone()) {
            continue;
        }
        found_candidate = true;
        match probe_ui_control_protocol(&path) {
            Ok(version) if protocol_version_compatible(version) => return (Some(path), None),
            Ok(version) => unsupported_protocol = Some(version),
            Err(error) => probe_failure = Some(error),
        }
    }

    let notice = if let Some(version) = unsupported_protocol {
        format!(
            "The installed desktop service uses synchronization protocol {version}, but this app requires protocol {UI_CONTROL_PROTOCOL_VERSION}. Update or install the desktop components together, then restart this app."
        )
    } else if found_candidate {
        format!(
            "An installed desktop service could not confirm shared-control support ({}). Update or install the desktop components together, then restart this app.",
            probe_failure.unwrap_or_else(|| "compatibility check failed".to_string())
        )
    } else {
        "The synchronized desktop action service was not found. Install it beside this app or make it available in PATH.".to_string()
    };
    (None, Some(notice))
}

fn start_legacy_observer(cli_binary: Option<&Path>, paths: &AppPaths, reason: &str) -> String {
    let Some(cli_binary) = cli_binary else {
        return "Not started — the compatible desktop CLI was not found.".to_string();
    };
    if !cli_supports_observer(cli_binary) {
        return "Not started — update the desktop CLI component to enable live observation."
            .to_string();
    }
    if let Err(error) = append_observer_log(
        paths,
        &format!("=== GUI {reason}; launching read-only CLI observer ==="),
    ) {
        return format!("Not started — could not prepare the shared output log: {error}");
    }
    match launch_legacy_observer_window(cli_binary, paths) {
        Ok(window) => format!("Running in {window} (observe-only)"),
        Err(error) => {
            let message = format!("Could not launch the CLI observer: {error}");
            let _ = append_observer_log(paths, &message);
            message
        }
    }
}

fn cli_supports_observer(cli_binary: &Path) -> bool {
    let mut command = Command::new(cli_binary);
    command
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);

    command.output().is_ok_and(|output| {
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("--observe")
    })
}

fn append_observer_log(paths: &AppPaths, message: &str) -> std::io::Result<()> {
    fs::create_dir_all(&paths.cache_dir)?;
    if fs::metadata(&paths.ui_observer_log)
        .is_ok_and(|metadata| metadata.len() > MAX_UI_OBSERVER_LOG_BYTES)
    {
        fs::write(
            &paths.ui_observer_log,
            "=== Older GUI output trimmed to keep the observer log bounded ===\n",
        )?;
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&paths.ui_observer_log)?;
    #[cfg(unix)]
    fs::set_permissions(&paths.ui_observer_log, fs::Permissions::from_mode(0o600))?;

    for line in message.lines() {
        writeln!(file, "{}", line.trim_end_matches('\r'))?;
    }
    file.flush()
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn add_observer_cli_args(command: &mut Command, cli_binary: &Path, paths: &AppPaths) {
    command
        .arg(cli_binary)
        .arg("--cache-dir")
        .arg(&paths.cache_dir)
        .arg("--observe");
}

#[cfg(target_os = "linux")]
fn launch_legacy_observer_window(
    cli_binary: &Path,
    paths: &AppPaths,
) -> Result<&'static str, String> {
    let mut launcher_candidates = Vec::new();
    if let Some(directory) = cli_binary.parent() {
        launcher_candidates.push(directory.join("vpngate-launcher"));
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        launcher_candidates.push(directory.join("vpngate-launcher"));
    }
    launcher_candidates.push(PathBuf::from("/usr/local/bin/vpngate-launcher"));
    if let Some(path) = vpngate_core::which_bin("vpngate-launcher") {
        launcher_candidates.push(path);
    }

    if let Some(launcher) = launcher_candidates.into_iter().find(|path| path.is_file()) {
        let mut command = Command::new(launcher);
        command
            .arg("--cache-dir")
            .arg(&paths.cache_dir)
            .arg("--observe")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if command.spawn().is_ok() {
            return Ok("the GTK/VTE window");
        }
    }

    let terminal_candidates: [(&str, &[&str]); 4] = [
        (
            "gnome-terminal",
            &["--wait", "--title", "VPN Gate Observer", "--"],
        ),
        (
            "konsole",
            &["--separate", "--title", "VPN Gate Observer", "-e"],
        ),
        ("x-terminal-emulator", &["-T", "VPN Gate Observer", "-e"]),
        ("xterm", &["-T", "VPN Gate Observer", "-e"]),
    ];
    for (binary, prefix) in terminal_candidates {
        let Some(path) = vpngate_core::which_bin(binary) else {
            continue;
        };
        let mut command = Command::new(path);
        command.args(prefix);
        add_observer_cli_args(&mut command, cli_binary, paths);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if command.spawn().is_ok() {
            return Ok("a terminal window");
        }
    }
    Err("no GTK/VTE launcher or supported terminal emulator was found".to_string())
}

#[cfg(target_os = "windows")]
fn launch_legacy_observer_window(
    cli_binary: &Path,
    paths: &AppPaths,
) -> Result<&'static str, String> {
    if let Some(windows_terminal) =
        vpngate_core::which_bin("wt.exe").or_else(|| vpngate_core::which_bin("wt"))
    {
        let mut command = Command::new(windows_terminal);
        command.args(["-w", "new", "--title", "VPN Gate Observer"]);
        add_observer_cli_args(&mut command, cli_binary, paths);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000);
        if command.spawn().is_ok() {
            return Ok("Windows Terminal");
        }
    }

    let powershell = vpngate_core::which_bin("powershell.exe")
        .or_else(|| vpngate_core::which_bin("powershell"))
        .unwrap_or_else(|| PathBuf::from("powershell.exe"));
    let command_line = format!(
        "& {} {} {} {}",
        powershell_quote(&cli_binary.display().to_string()),
        powershell_quote("--cache-dir"),
        powershell_quote(&paths.cache_dir.display().to_string()),
        powershell_quote("--observe"),
    );
    let mut command = Command::new(powershell);
    command
        .args(["-NoLogo", "-NoExit", "-Command", &command_line])
        .creation_flags(0x0000_0010);
    command
        .spawn()
        .map_err(|error| format!("could not open Windows Terminal or PowerShell: {error}"))?;
    Ok("a PowerShell window")
}

#[cfg_attr(not(windows), allow(dead_code))]
fn powershell_quote(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "''"))
}

#[cfg(target_os = "macos")]
fn launch_legacy_observer_window(
    cli_binary: &Path,
    paths: &AppPaths,
) -> Result<&'static str, String> {
    let command_line = [
        cli_binary.display().to_string(),
        "--cache-dir".to_string(),
        paths.cache_dir.display().to_string(),
        "--observe".to_string(),
    ]
    .iter()
    .map(|argument| shell_quote(argument))
    .collect::<Vec<_>>()
    .join(" ");
    let script = format!(
        "tell application \"Terminal\"\nactivate\ndo script \"{}\"\nend tell",
        applescript_escape(&command_line)
    );
    let mut command = Command::new("/usr/bin/osascript");
    command
        .args(["-e", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
        .spawn()
        .map_err(|error| format!("could not open the macOS Terminal observer: {error}"))?;
    Ok("the macOS Terminal window")
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn launch_legacy_observer_window(
    _cli_binary: &Path,
    _paths: &AppPaths,
) -> Result<&'static str, String> {
    Err("automatic terminal observers are not supported on this operating system".to_string())
}

fn probe_ui_control_protocol(binary: &Path) -> Result<u32, String> {
    let mut command = Command::new(binary);
    command
        .arg("--ui-control-protocol-version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);

    let output = command
        .output()
        .map_err(|error| format!("could not launch the service: {error}"))?;
    if !output.status.success() {
        return Err("service does not support the shared-control handshake".to_string());
    }
    parse_ui_control_protocol_output(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| "service returned an invalid synchronization protocol version".to_string())
}

fn parse_ui_control_protocol_output(output: &str) -> Option<u32> {
    output.trim().parse().ok()
}

fn protocol_version_compatible(version: u32) -> bool {
    version == UI_CONTROL_PROTOCOL_VERSION
}

fn build_cli_command(
    cli_binary: &Path,
    args: &[String],
    paths: &AppPaths,
    token: &str,
    requires_privilege: bool,
) -> Command {
    let mut cli_args = vec![
        "--cache-dir".to_string(),
        paths.cache_dir.display().to_string(),
        "--ui-control-token".to_string(),
        token.to_string(),
    ];
    cli_args.extend_from_slice(args);
    #[cfg(target_os = "windows")]
    let _ = requires_privilege;

    #[cfg(target_os = "linux")]
    if requires_privilege
        && !is_root_or_admin()
        && let Some(pkexec) = vpngate_core::which_bin("pkexec")
    {
        let (uid, gid, user) = unix_identity();
        let mut command = Command::new(pkexec);
        command
            .arg("/usr/bin/env")
            .arg(format!("SUDO_UID={uid}"))
            .arg(format!("SUDO_GID={gid}"))
            .arg(format!("SUDO_USER={user}"))
            .arg(cli_binary)
            .args(&cli_args);
        return command;
    }

    #[cfg(target_os = "macos")]
    if requires_privilege && !is_root_or_admin() {
        let (uid, gid, user) = unix_identity();
        let mut shell_words = vec![
            "/usr/bin/env".to_string(),
            format!("SUDO_UID={uid}"),
            format!("SUDO_GID={gid}"),
            format!("SUDO_USER={user}"),
            cli_binary.display().to_string(),
        ];
        shell_words.extend(cli_args);
        let shell_line = shell_words
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ");
        let apple_script = format!(
            "do shell script \"{}\" with administrator privileges",
            applescript_escape(&shell_line)
        );
        let mut command = Command::new("/usr/bin/osascript");
        command.args(["-e", &apple_script]);
        return command;
    }

    let mut command = Command::new(cli_binary);
    command.args(&cli_args);
    command
}

fn run_cli_command(
    cli_binary: PathBuf,
    args: Vec<String>,
    paths: AppPaths,
    token: String,
    requires_privilege: bool,
    sender: Sender<CommandEvent>,
) {
    let mut command = build_cli_command(&cli_binary, &args, &paths, &token, requires_privilege);
    command
        .env("VPNGATE_UI_NAME", "GUI")
        .env("VPNGATE_UI_CONTROL_TOKEN", &token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = sender.send(CommandEvent::Failed(error.to_string()));
            return;
        }
    };

    let stdout_thread = child
        .stdout
        .take()
        .map(|stdout| spawn_pipe_reader(stdout, sender.clone(), false));
    let stderr_thread = child
        .stderr
        .take()
        .map(|stderr| spawn_pipe_reader(stderr, sender.clone(), true));

    let code = child
        .wait()
        .ok()
        .and_then(|status| status.code())
        .unwrap_or(1);
    if let Some(handle) = stdout_thread {
        let _ = handle.join();
    }
    if let Some(handle) = stderr_thread {
        let _ = handle.join();
    }
    let _ = sender.send(CommandEvent::Finished(code));
}

fn spawn_pipe_reader<R>(
    reader: R,
    sender: Sender<CommandEvent>,
    is_stderr: bool,
) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let line = line.trim_end_matches(['\r', '\n']);
                    if line.is_empty() {
                        continue;
                    }
                    let message = if is_stderr {
                        format!("[stderr] {line}")
                    } else {
                        line.to_string()
                    };
                    if sender.send(CommandEvent::Output(message)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ =
                        sender.send(CommandEvent::Output(format!("[output read error] {error}")));
                    break;
                }
            }
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_identity() -> (String, String, String) {
    fn query(flag: &str) -> String {
        Command::new("id")
            .arg(flag)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_default()
    }
    (query("-u"), query("-g"), query("-un"))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn applescript_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn strip_ansi(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            if !ch.is_control() || ch == '\t' {
                output.push(ch);
            }
            continue;
        }
        match chars.next() {
            Some('[') => {
                for code in chars.by_ref() {
                    if ('@'..='~').contains(&code) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(code) = chars.next() {
                    if code == '\u{7}' {
                        break;
                    }
                    if code == '\u{1b}' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            Some(_) | None => {}
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        action_result_message, append_mirror_args, append_observer_log, connect_regions_fetch_args,
        country_picker_label, format_age, parse_ui_control_protocol_output, protocol_labels,
        protocol_version_compatible, relay_matches, selected_relay_start_index, strip_ansi,
    };
    use vpngate_core::{AppPaths, ProtocolFilter, SortBy, VpnServer};

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

    fn relay(ip: &str, country_short: &str, country_long: &str, score: u64) -> VpnServer {
        let mut server = server();
        server.hostname = format!("relay-{ip}");
        server.ip = ip.to_string();
        server.country_short = country_short.to_string();
        server.country_long = country_long.to_string();
        server.score = score;
        server
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
    fn selected_relay_start_index_uses_the_cli_country_scoped_order() {
        let servers = vec![
            relay("192.0.2.1", "KR", "Korea", 100),
            relay("192.0.2.2", "JP", "Japan", 80),
            relay("192.0.2.3", "KR", "Korea", 70),
            relay("192.0.2.4", "JP", "Japan", 60),
        ];
        let selected = &servers[3];
        let mut all_country_candidates = servers.clone();
        vpngate_core::sort_servers(
            &mut all_country_candidates,
            SortBy::Score,
            ProtocolFilter::Auto,
        );
        let all_country_rank = all_country_candidates
            .iter()
            .position(|candidate| candidate.ip == selected.ip)
            .unwrap()
            + 1;
        let japan_count = servers
            .iter()
            .filter(|candidate| candidate.country_short == "JP")
            .count();

        assert!(all_country_rank > japan_count);
        assert_eq!(
            selected_relay_start_index(&servers, selected, ProtocolFilter::Auto, SortBy::Score,),
            Some(2)
        );
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

    #[test]
    fn country_picker_includes_all_and_resolves_fetched_regions() {
        let countries = vec![
            ("JP".to_string(), "Japan".to_string()),
            ("KR".to_string(), "Korea".to_string()),
        ];
        assert_eq!(country_picker_label("all", &countries), "All countries");
        assert_eq!(country_picker_label("jp", &countries), "Japan (JP)");
        assert_eq!(country_picker_label("JP,KR", &countries), "JP,KR");
    }

    #[test]
    fn inline_region_fetch_forces_refresh_and_keeps_custom_mirrors() {
        assert_eq!(
            connect_regions_fetch_args("auto", "http://one/en/; http://two/en/"),
            [
                "countries",
                "--proto",
                "auto",
                "--refresh",
                "--mirror",
                "http://one/en/",
                "--mirror",
                "http://two/en/",
            ]
        );
    }

    #[test]
    fn observer_log_preserves_gui_output_lines() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let cache_dir = std::env::temp_dir().join(format!(
            "vpngate-observer-test-{}-{nonce}",
            std::process::id()
        ));
        let paths = AppPaths::with_base_dir(cache_dir.clone());
        append_observer_log(&paths, "=== Connect started ===").unwrap();
        append_observer_log(&paths, "[Attempt 1/2] Testing relay.example").unwrap();
        assert_eq!(
            std::fs::read_to_string(&paths.ui_observer_log).unwrap(),
            "=== Connect started ===\n[Attempt 1/2] Testing relay.example\n"
        );
        std::fs::remove_dir_all(cache_dir).unwrap();
    }

    #[test]
    fn synchronized_action_service_protocol_is_checked_explicitly() {
        assert_eq!(parse_ui_control_protocol_output("1\n"), Some(1));
        assert_eq!(parse_ui_control_protocol_output("unknown option\n"), None);
        assert!(protocol_version_compatible(1));
        assert!(!protocol_version_compatible(2));
    }

    #[test]
    fn action_failures_are_explained_without_cli_exit_code_jargon() {
        let message = action_result_message("List relays", 2);
        assert!(message.contains("List relays was rejected"));
        assert!(message.contains("Technical details"));
        assert!(!message.contains("exit code 2"));
        assert!(action_result_message("Connect", 0).contains("Connect completed"));
    }

    #[test]
    fn mirror_input_splits_repeated_values_without_empty_arguments() {
        let mut args = vec!["connect".to_string()];
        append_mirror_args(&mut args, "http://one/en/;\nhttp://two/en/;");
        assert_eq!(
            args,
            [
                "connect",
                "--mirror",
                "http://one/en/",
                "--mirror",
                "http://two/en/"
            ]
        );
    }

    #[test]
    fn console_output_is_sanitized_before_rendering() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m"), "red");
    }

    #[test]
    fn terminal_arguments_are_escaped_for_windows_and_macos() {
        use super::{applescript_escape, powershell_quote, shell_quote};
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(powershell_quote("a'b"), "'a''b'");
        assert_eq!(applescript_escape("\""), "\\\"");
    }
}
