#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use eframe::egui::{self, Color32, RichText};
use vpngate_core::cache::ServerCacheFile;
use vpngate_core::{
    ActiveSessionState, AppPaths, InteractiveInstanceError, PRODUCT_VERSION, ProtocolFilter,
    RemoteDesktopVersion, SortBy, VpnServer, acquire_interactive_instances, cpu_isa_label,
    detect_host_os_label, filter_by_country, filter_by_protocol, installed_desktop_version,
    is_root_or_admin, load_cached_mirrors, now_unix_secs, read_json_opt, refresh_update_cache,
    sort_servers, summarize_countries, tunnel_aid_dns_cli,
};

const APP_ID: &str = "net.vpngate.connect";
const ACTIVE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const IDLE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(15);
const CACHE_POLL_INTERVAL: Duration = Duration::from_secs(60);
const MAX_RELAY_ROWS: usize = 100;
const MAX_LOG_LINES: usize = 600;
const CONNECT_ATTEMPT_TIMEOUT_SECS: u64 = 22;
static CANCEL_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn main() -> eframe::Result {
    if let Err(error) = vpngate_core::assert_supported_native_host() {
        eprintln!("vpngate-gui: {error}");
        std::process::exit(2);
    }

    let paths = AppPaths::resolve();
    let default_cache_dir = AppPaths::default_cache_dir();
    let instance_guards = match acquire_interactive_instances(&paths, &default_cache_dir) {
        Ok(guards) => guards,
        Err(InteractiveInstanceError::AlreadyRunning) => {
            return run_startup_notice(
                "Another VPN Gate Connect frontend is already open. Close it before starting this one.",
            );
        }
        Err(error) => {
            return run_startup_notice(&format!("Could not start VPN Gate Connect GUI: {error}"));
        }
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("VPN Gate Connect GUI")
            .with_inner_size([1080.0, 760.0])
            .with_min_inner_size([820.0, 620.0]),
        ..Default::default()
    };

    let result = eframe::run_native(
        APP_ID,
        options,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    );
    drop(instance_guards);
    result
}

fn run_startup_notice(message: &str) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("VPN Gate Connect")
            .with_inner_size([480.0, 190.0])
            .with_min_inner_size([420.0, 170.0]),
        ..Default::default()
    };
    let message = message.to_string();
    eframe::run_native(
        "net.vpngate.connect.notice",
        options,
        Box::new(move |_| Ok(Box::new(InstanceNoticeApp { message }))),
    )
}

struct InstanceNoticeApp {
    message: String,
}

impl eframe::App for InstanceNoticeApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_secs(3600));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.vertical_centered(|ui| {
            ui.add_space(18.0);
            ui.heading("Could not start VPN Gate Connect");
            ui.add_space(10.0);
            ui.label(&self.message);
            ui.add_space(16.0);
            if ui.button("Close").clicked() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }
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
            Self::Activity => "Live tunnel state, system checks, and recent activity",
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
    UpdateCheck(Result<RemoteDesktopVersion, String>),
    Finished(i32),
    Failed(String),
}

struct CommandWorker {
    receiver: Receiver<CommandEvent>,
    operation: String,
    started_at: Instant,
    cancellable: bool,
    cancel_requested: bool,
    cancel_file: Option<PathBuf>,
}

struct OperationProgress {
    operation: String,
    message: String,
    fraction: Option<f32>,
    completed: bool,
    succeeded: bool,
}

impl OperationProgress {
    fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            message: format!("Starting {operation}…"),
            fraction: None,
            completed: false,
            succeeded: false,
        }
    }
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
    worker: Option<CommandWorker>,
    command_log: VecDeque<String>,
    status_message: String,
    operation_progress: Option<OperationProgress>,
    host_label: String,
    native_arch: &'static str,
    elevated: bool,

    connect_country: String,
    connect_region_search: String,
    connect_protocol: String,
    connect_sort: String,
    connect_limit: usize,
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
            worker: None,
            command_log: VecDeque::new(),
            status_message: String::new(),
            operation_progress: None,
            host_label: detect_host_os_label(),
            native_arch: cpu_isa_label(),
            elevated: is_root_or_admin(),

            connect_country: "all".to_string(),
            connect_region_search: String::new(),
            connect_protocol: "auto".to_string(),
            connect_sort: "score".to_string(),
            connect_limit: 0,
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

    fn actions_blocked(&self) -> bool {
        self.worker.is_some()
    }

    fn action_service_notice(&self) -> &str {
        self.cli_notice.as_deref().unwrap_or(
            "The VPN Gate Connect command-line action service was not found. Install it beside this app or make it available in PATH.",
        )
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
            CONNECT_ATTEMPT_TIMEOUT_SECS.to_string(),
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
        if self.worker.is_some() {
            self.status_message = "An operation is already running in this window.".to_string();
            return;
        }
        let Some(cli_binary) = self.cli_binary.clone() else {
            self.status_message = self.action_service_notice().to_string();
            return;
        };
        if let Err(error) = fs::create_dir_all(&self.paths.cache_dir) {
            self.status_message =
                format!("Could not prepare the VPN Gate cache directory: {error}");
            return;
        }

        let paths = self.paths.clone();
        let cancel_file = cancellable.then(|| unique_cancel_file_path(&paths));
        if let Some(path) = &cancel_file {
            let _ = fs::remove_file(path);
        }
        self.command_log.clear();
        self.operation_progress = Some(OperationProgress::new(operation));
        self.push_log(format!("Starting {operation}…"));
        self.status_message.clear();

        let (sender, receiver) = mpsc::channel();
        let worker_operation = operation.to_string();
        let worker_cancel_file = cancel_file.clone();
        thread::spawn(move || {
            run_cli_command(
                cli_binary,
                args,
                paths,
                cancel_file,
                requires_privilege,
                sender,
            );
        });
        self.worker = Some(CommandWorker {
            receiver,
            operation: worker_operation,
            started_at: Instant::now(),
            cancellable,
            cancel_requested: false,
            cancel_file: worker_cancel_file,
        });
    }

    fn start_update_check(&mut self, mode: UpdateCheckMode) {
        if self.worker.is_some() {
            return;
        }
        self.command_log.clear();
        self.operation_progress = Some(OperationProgress::new("Check desktop updates"));
        self.push_log("Checking for desktop updates…".to_string());
        self.status_message.clear();

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
            let _ = sender.send(CommandEvent::UpdateCheck(result));
        });
        self.worker = Some(CommandWorker {
            receiver,
            operation: "Check desktop updates".to_string(),
            started_at: Instant::now(),
            cancellable: false,
            cancel_requested: false,
            cancel_file: None,
        });
        self.pending_update_check = None;
    }

    fn cancel_connect(&mut self) {
        let Some(worker) = self.worker.as_ref() else {
            return;
        };
        if !worker.cancellable || worker.cancel_requested {
            return;
        }
        let Some(path) = worker.cancel_file.clone() else {
            self.status_message = "The connect cancellation channel is unavailable.".to_string();
            return;
        };
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(path) {
            Ok(_) => {
                if let Some(worker) = &mut self.worker {
                    worker.cancel_requested = true;
                }
                let message =
                    "Cancellation requested — tunnel changes will be rolled back before returning.";
                self.push_log(message.to_string());
                self.status_message = "Cancelling and rolling back…".to_string();
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Some(worker) = &mut self.worker {
                    worker.cancel_requested = true;
                }
                self.status_message = "Cancellation requested — rolling back…".to_string();
            }
            Err(error) => {
                self.status_message = format!("The connect cancellation request failed: {error}");
            }
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
            self.update_offer = None;
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
        for event in events {
            match event {
                CommandEvent::Output(line) => {
                    let clean = strip_ansi(&line);
                    if !clean.trim().is_empty() {
                        self.update_operation_progress(&clean);
                        self.push_log(clean);
                    }
                }
                CommandEvent::UpdateCheck(Ok(remote)) => {
                    if remote.version > installed_desktop_version() {
                        let message = format!(
                            "Desktop update v{} is available; installing it is strongly recommended.",
                            remote.raw
                        );
                        self.push_log(message.clone());
                        self.status_message = message.clone();
                        self.finish_operation_progress(&message, true);
                        self.update_offer = Some(remote);
                        self.pending_update = Some(UpdateKind::Update);
                    } else {
                        let message =
                            format!("VPN Gate Connect is up to date (v{PRODUCT_VERSION}).");
                        self.push_log(message.clone());
                        self.status_message = message.clone();
                        self.finish_operation_progress(&message, true);
                    }
                    finished = true;
                }
                CommandEvent::UpdateCheck(Err(error)) => {
                    let message = format!("Desktop update check did not complete: {error}");
                    self.push_log(message.clone());
                    self.status_message = message.clone();
                    self.finish_operation_progress(&message, false);
                    finished = true;
                }
                CommandEvent::Finished(code) => {
                    let operation = self
                        .worker
                        .as_ref()
                        .map(|worker| worker.operation.as_str())
                        .unwrap_or("Action");
                    let message = action_result_message(operation, code);
                    if code != 0 {
                        self.push_log(format!("Technical result status: {code}"));
                    }
                    self.push_log(message.clone());
                    self.status_message = message.clone();
                    self.finish_operation_progress(&message, code == 0);
                    finished = true;
                }
                CommandEvent::Failed(error) => {
                    let operation = self
                        .worker
                        .as_ref()
                        .map(|worker| worker.operation.as_str())
                        .unwrap_or("Action");
                    let message = format!("Could not start {operation}: {error}");
                    self.push_log(message.clone());
                    self.status_message = message.clone();
                    self.finish_operation_progress(&message, false);
                    finished = true;
                }
            }
        }
        if finished {
            let update_after_doctor = self
                .worker
                .as_ref()
                .is_some_and(|worker| worker.operation == "System diagnostics");
            if let Some(path) = self
                .worker
                .as_ref()
                .and_then(|worker| worker.cancel_file.as_ref())
            {
                let _ = fs::remove_file(path);
            }
            self.worker = None;
            self.reload_session();
            self.reload_cache();
            if update_after_doctor {
                self.pending_update_check = Some(UpdateCheckMode::Diagnostics);
            }
        }
    }

    fn update_operation_progress(&mut self, line: &str) {
        let Some((fraction, message)) = progress_update_from_output(line) else {
            return;
        };
        if let Some(progress) = &mut self.operation_progress {
            if let Some(fraction) = fraction {
                progress.fraction = Some(fraction);
            }
            progress.message = message;
        }
    }

    fn finish_operation_progress(&mut self, message: &str, succeeded: bool) {
        if let Some(progress) = &mut self.operation_progress {
            progress.message = compact_progress_message(message);
            progress.completed = true;
            progress.succeeded = succeeded;
            if succeeded {
                progress.fraction = Some(1.0);
            }
        }
    }

    fn operation_progress_panel(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Operation progress").strong());
                if let Some(worker) = &self.worker {
                    ui.label(
                        RichText::new(format!(
                            "Running · {}s",
                            worker.started_at.elapsed().as_secs()
                        ))
                        .weak()
                        .small(),
                    );
                }
            });

            if let Some(progress) = &self.operation_progress {
                ui.label(RichText::new(&progress.operation).strong());
                if !progress.message.is_empty() {
                    ui.label(RichText::new(&progress.message).weak());
                }

                let running = self.worker.is_some();
                let fill = progress
                    .fraction
                    .unwrap_or(if running { 0.28 } else { 0.0 });
                let bar = egui::ProgressBar::new(fill)
                    .desired_width(ui.available_width())
                    .animate(running && progress.fraction.is_none());
                if progress.fraction.is_some() || progress.succeeded {
                    ui.add(bar.show_percentage());
                } else {
                    ui.add(bar);
                }

                if progress.completed {
                    ui.colored_label(
                        if progress.succeeded {
                            Color32::from_rgb(44, 154, 84)
                        } else {
                            Color32::from_rgb(190, 125, 30)
                        },
                        if progress.succeeded {
                            "Complete"
                        } else {
                            "Stopped"
                        },
                    );
                }
            } else {
                ui.label(
                    RichText::new("Progress appears here while an operation is running.").weak(),
                );
            }
        });
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
            egui::CollapsingHeader::new("Raw command output")
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

        match self.page {
            Page::Connect => self.connect_page(ui),
            Page::Relays => self.relays_page(ui),
            Page::Tools => self.tools_page(ui),
            Page::Activity => self.activity_page(ui),
        }
    }

    fn connect_page(&mut self, ui: &mut egui::Ui) {
        let countries = self.available_countries();
        let mut connect_clicked = false;
        let mut disconnect_clicked = false;
        let mut fetch_regions_clicked = false;

        // Keep connection setup and live session details side by side when there is
        // room, but return to a single column on compact windows.
        if ui.available_width() >= 760.0 {
            ui.columns(2, |columns| {
                self.connection_options_panel(
                    &mut columns[0],
                    &countries,
                    &mut connect_clicked,
                    &mut disconnect_clicked,
                    &mut fetch_regions_clicked,
                );
                self.session_status_panel(&mut columns[1]);
                columns[1].add_space(8.0);
                self.operation_progress_panel(&mut columns[1]);
            });
        } else {
            self.session_status_panel(ui);
            ui.add_space(8.0);
            self.operation_progress_panel(ui);
            ui.add_space(8.0);
            self.connection_options_panel(
                ui,
                &countries,
                &mut connect_clicked,
                &mut disconnect_clicked,
                &mut fetch_regions_clicked,
            );
        }

        if self.cli_binary.is_none() {
            ui.colored_label(
                Color32::from_rgb(190, 125, 30),
                self.action_service_notice(),
            );
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

    fn session_status_panel(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Current session").strong());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let (label, color) = self.status_badge();
                let (dot_rect, _) =
                    ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(dot_rect.center(), 5.0, color);
                ui.label(RichText::new(label).strong().size(18.0));
            });

            if let Some(session) = &self.session {
                ui.add_space(6.0);
                egui::Grid::new("session_details")
                    .num_columns(2)
                    .spacing([14.0, 6.0])
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
                ui.add_space(4.0);
                ui.label("No active VPN session was found.");
                ui.label(RichText::new("Choose regions below and connect when ready.").weak());
            }
        });
    }

    fn connection_options_panel(
        &mut self,
        ui: &mut egui::Ui,
        countries: &[(String, String)],
        connect_clicked: &mut bool,
        disconnect_clicked: &mut bool,
        fetch_regions_clicked: &mut bool,
    ) {
        let blocked = self.actions_blocked();
        ui.add_enabled_ui(!blocked, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(RichText::new("Connection setup").strong());
                ui.label(RichText::new("Choose one or more regions, then connect.").weak());
                ui.add_space(6.0);

                self.region_selection_panel(ui, countries, fetch_regions_clicked);

                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Protocol").weak().small());
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
                    });
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Sort order").weak().small());
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
                    });
                });

                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Auto-reconnect").weak());
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
                });

                egui::CollapsingHeader::new("Advanced connection options")
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::Grid::new("connect_advanced")
                            .num_columns(2)
                            .spacing([10.0, 8.0])
                            .show(ui, |ui| {
                                ui.label("Try at most");
                                ui.add(
                                    egui::DragValue::new(&mut self.connect_limit)
                                        .range(0..=1000)
                                        .suffix(" relays (0 = all)"),
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
                                        .desired_width(220.0),
                                );
                                ui.end_row();

                                ui.label("Custom mirrors");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.connect_mirrors)
                                        .desired_width(220.0)
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
                ui.horizontal_wrapped(|ui| {
                    *connect_clicked = ui
                        .add_enabled(
                            !self.connect_country.trim().is_empty(),
                            egui::Button::new(RichText::new("Connect").strong())
                                .min_size(egui::vec2(112.0, 34.0))
                                .fill(ui.visuals().selection.bg_fill),
                        )
                        .clicked();
                    *disconnect_clicked = ui.button("Disconnect").clicked();
                    if ui.button("Browse relays").clicked() {
                        self.page = Page::Relays;
                    }
                    if ui.button("More actions").clicked() {
                        self.page = Page::Tools;
                    }
                });
            });
        });
    }

    fn region_selection_panel(
        &mut self,
        ui: &mut egui::Ui,
        countries: &[(String, String)],
        fetch_regions_clicked: &mut bool,
    ) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Regions").strong());
                ui.label(
                    RichText::new(country_picker_label(&self.connect_country, countries)).strong(),
                );
            });

            ui.horizontal_wrapped(|ui| {
                ui.label("Codes or names");
                ui.add(
                    egui::TextEdit::singleline(&mut self.connect_country)
                        .desired_width(150.0)
                        .hint_text("all or JP,KR"),
                );
                *fetch_regions_clicked = ui
                    .button("Fetch regions")
                    .on_hover_text(
                        "Refresh the relay pool and update this checklist without leaving Connect",
                    )
                    .clicked();
                let cache_label = self
                    .cache_timestamp
                    .map(|timestamp| {
                        format!(
                            "{} regions · cache {}",
                            countries.len(),
                            format_age(now_unix_secs().saturating_sub(timestamp))
                        )
                    })
                    .unwrap_or_else(|| "No region cache yet".to_string());
                ui.label(RichText::new(cache_label).weak().small());
            });

            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.connect_region_search)
                        .desired_width(190.0)
                        .hint_text("Search available regions"),
                );
                let mut all_selected = country_selection_is_all(&self.connect_country);
                if ui.checkbox(&mut all_selected, "All countries").changed() {
                    self.connect_country = if all_selected {
                        "all".to_string()
                    } else {
                        String::new()
                    };
                }
                if ui.button("Clear selection").clicked() {
                    self.connect_country.clear();
                }
                ui.label(
                    RichText::new(country_selection_summary(&self.connect_country))
                        .weak()
                        .small(),
                );
            });

            egui::ScrollArea::vertical()
                .max_height(184.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if countries.is_empty() {
                        ui.label(
                            RichText::new(
                                "No regions are cached yet. Fetch regions or enter codes above.",
                            )
                            .weak(),
                        );
                        return;
                    }

                    let query = self.connect_region_search.trim().to_string();
                    let matches = countries
                        .iter()
                        .filter(|(code, name)| {
                            query.is_empty()
                                || contains_ascii_case_insensitive(code, &query)
                                || contains_ascii_case_insensitive(name, &query)
                        })
                        .collect::<Vec<_>>();
                    if matches.is_empty() {
                        ui.label(RichText::new("No matching regions.").weak());
                        return;
                    }

                    for (code, name) in matches {
                        let mut selected =
                            country_selection_contains(&self.connect_country, code, name);
                        if ui
                            .checkbox(&mut selected, format!("{name} ({code})"))
                            .changed()
                        {
                            set_country_selection(&mut self.connect_country, code, name, selected);
                        }
                    }
                });
        });
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
        self.operation_progress_panel(ui);
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
        self.operation_progress_panel(ui);
        ui.add_space(8.0);
        self.activity_details_panel(ui, 260.0);
    }

    fn activity_page(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Host and app state").strong());
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
                    ui.end_row();
                });
        });
        self.operation_progress_panel(ui);
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
        let cache_interval = CACHE_POLL_INTERVAL;
        if matches!(self.page, Page::Relays | Page::Tools | Page::Activity)
            && self.last_cache_poll.elapsed() >= cache_interval
        {
            self.reload_cache();
        }
        if let Some(mode) = self.pending_update_check
            && self.worker.is_none()
        {
            self.start_update_check(mode);
        }

        let state_interval = self.session_poll_interval();
        let mut next_repaint = state_interval.saturating_sub(self.last_state_poll.elapsed());
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

fn compact_progress_message(message: &str) -> String {
    let compact = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= 120 {
        return compact;
    }
    let mut truncated = compact.chars().take(117).collect::<String>();
    truncated.push('…');
    truncated
}

fn progress_update_from_output(line: &str) -> Option<(Option<f32>, String)> {
    let clean = strip_ansi(line);
    let clean = clean.trim();

    if let Some(attempt_start) = clean.find("[Attempt ") {
        let rest = &clean[attempt_start + "[Attempt ".len()..];
        if let Some(close) = rest.find(']') {
            let (attempt, total) = rest[..close].split_once('/')?;
            let attempt = attempt.parse::<usize>().ok()?;
            let total = total.parse::<usize>().ok()?;
            if total > 0 {
                let fraction = (attempt.min(total) as f32 / total as f32) * 0.9;
                let detail = rest[close + 1..]
                    .trim()
                    .strip_prefix("Testing ")
                    .unwrap_or(rest[close + 1..].trim());
                return Some((
                    Some(fraction),
                    compact_progress_message(&format!(
                        "Relay attempt {attempt}/{total} · {detail}"
                    )),
                ));
            }
        }
    }

    for prefix in ["[*] ", "[+] ", "[!] ", "[-] ", "[stderr] "] {
        if let Some(message) = clean.strip_prefix(prefix) {
            let message = if prefix == "[stderr] " {
                format!("Issue: {message}")
            } else {
                message.to_string()
            };
            return Some((None, compact_progress_message(&message)));
        }
    }
    None
}

fn country_selection_is_all(selection: &str) -> bool {
    selection.trim().eq_ignore_ascii_case("all")
}

fn country_selection_values(selection: &str) -> Vec<String> {
    if country_selection_is_all(selection) {
        return Vec::new();
    }

    let mut values = Vec::new();
    for value in selection
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !values
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(value))
        {
            values.push(value.to_string());
        }
    }
    values
}

fn country_selection_summary(selection: &str) -> String {
    if country_selection_is_all(selection) {
        return "All countries".to_string();
    }
    match country_selection_values(selection).len() {
        0 => "No regions selected".to_string(),
        1 => "1 region selected".to_string(),
        count => format!("{count} regions selected"),
    }
}

fn country_selection_contains(selection: &str, code: &str, name: &str) -> bool {
    !country_selection_is_all(selection)
        && country_selection_values(selection)
            .iter()
            .any(|value| value.eq_ignore_ascii_case(code) || value.eq_ignore_ascii_case(name))
}

fn set_country_selection(selection: &mut String, code: &str, name: &str, selected: bool) {
    let mut values = country_selection_values(selection)
        .into_iter()
        .filter(|value| !value.eq_ignore_ascii_case(code) && !value.eq_ignore_ascii_case(name))
        .collect::<Vec<_>>();
    if selected {
        values.push(code.to_string());
    }
    *selection = values.join(",");
}

fn country_picker_label(selection: &str, countries: &[(String, String)]) -> String {
    if country_selection_is_all(selection) {
        return "All countries".to_string();
    }

    let values = country_selection_values(selection);
    match values.as_slice() {
        [] => "Choose one or more regions".to_string(),
        [value] => countries
            .iter()
            .find(|(code, name)| {
                code.eq_ignore_ascii_case(value) || name.eq_ignore_ascii_case(value)
            })
            .map(|(code, name)| format!("{name} ({code})"))
            .unwrap_or_else(|| value.clone()),
        _ => format!("{} regions selected", values.len()),
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
            "{operation} was rejected. Expand Raw command output to see the command-line reason."
        ),
        75 => format!(
            "{operation} did not start because another VPN Gate Connect frontend is already running. Close it and retry."
        ),
        _ => format!(
            "{operation} did not complete (status {code}). Expand Raw command output for more information."
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
    for path in candidates {
        if path.is_file() && seen.insert(path.clone()) {
            return (Some(path), None);
        }
    }
    (
        None,
        Some("The VPN Gate Connect CLI action service was not found. Install it beside this app or make it available in PATH.".to_string()),
    )
}

fn unique_cancel_file_path(paths: &AppPaths) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = CANCEL_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    paths.cache_dir.join(format!(
        "gui-cancel-{}-{timestamp}-{sequence}.flag",
        std::process::id()
    ))
}

fn build_cli_command(
    cli_binary: &Path,
    args: &[String],
    paths: &AppPaths,
    cancel_file: Option<&Path>,
    requires_privilege: bool,
) -> Command {
    let mut cli_args = vec![
        "--cache-dir".to_string(),
        paths.cache_dir.display().to_string(),
    ];
    if let Some(path) = cancel_file {
        cli_args.push("--cancel-file".to_string());
        cli_args.push(path.display().to_string());
    }
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
    cancel_file: Option<PathBuf>,
    requires_privilege: bool,
    sender: Sender<CommandEvent>,
) {
    let mut command = build_cli_command(
        &cli_binary,
        &args,
        &paths,
        cancel_file.as_deref(),
        requires_privilege,
    );
    command
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
        CONNECT_ATTEMPT_TIMEOUT_SECS, action_result_message, append_mirror_args,
        connect_regions_fetch_args, country_picker_label, country_selection_contains,
        country_selection_summary, format_age, progress_update_from_output, protocol_labels,
        relay_matches, selected_relay_start_index, set_country_selection, strip_ansi,
    };
    use vpngate_core::{ProtocolFilter, SortBy, VpnServer};

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
        assert_eq!(
            country_picker_label("Japan,KR", &countries),
            "2 regions selected"
        );
        assert_eq!(
            country_picker_label("", &countries),
            "Choose one or more regions"
        );
        assert_eq!(country_selection_summary("JP,KR"), "2 regions selected");
    }

    #[test]
    fn region_checklist_adds_and_removes_multiple_regions() {
        let mut selection = "all".to_string();
        set_country_selection(&mut selection, "JP", "Japan", true);
        assert_eq!(selection, "JP");
        set_country_selection(&mut selection, "KR", "Korea", true);
        assert_eq!(selection, "JP,KR");
        assert!(country_selection_contains(&selection, "JP", "Japan"));
        assert!(country_selection_contains(&selection, "KR", "Korea"));

        set_country_selection(&mut selection, "JP", "Japan", false);
        assert_eq!(selection, "KR");
        set_country_selection(&mut selection, "KR", "Korea", false);
        assert!(selection.is_empty());
        assert_eq!(country_selection_summary(&selection), "No regions selected");

        selection = "jp,korea,FR".to_string();
        set_country_selection(&mut selection, "JP", "Japan", false);
        assert_eq!(selection, "korea,FR");
        set_country_selection(&mut selection, "KR", "Korea", false);
        assert_eq!(selection, "FR");
    }

    #[test]
    fn progress_parser_turns_attempts_and_status_lines_into_ui_updates() {
        let (fraction, message) = progress_update_from_output(
            "\u{1b}[1;36m[Attempt 3/10] Testing relay.example (192.0.2.3) | JP (Japan)\u{1b}[0m",
        )
        .unwrap();
        assert!((fraction.unwrap() - 0.27).abs() < 0.001);
        assert!(message.contains("Relay attempt 3/10"));
        assert!(message.contains("relay.example"));

        let (fraction, message) =
            progress_update_from_output("[+] Loaded 24 relays from cache").unwrap();
        assert!(fraction.is_none());
        assert_eq!(message, "Loaded 24 relays from cache");
        assert!(progress_update_from_output("JP Japan 42 relays 12 Mbps").is_none());
    }

    #[test]
    fn connection_attempt_timeout_is_implicit_in_the_gui() {
        assert_eq!(CONNECT_ATTEMPT_TIMEOUT_SECS, 22);
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
    fn action_failures_are_explained_without_cli_exit_code_jargon() {
        let message = action_result_message("List relays", 2);
        assert!(message.contains("List relays was rejected"));
        assert!(message.contains("Raw command output"));
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
        use super::{applescript_escape, shell_quote};
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(applescript_escape("\""), "\\\"");
    }
}
