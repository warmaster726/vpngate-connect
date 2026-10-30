//! GNOME GTK4 + VTE dark window for `vpngate`.
//!
//! Linux-only. Windows `-w` still uses Windows Terminal from `vpngate-cli`.

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "vpngate-launcher is the Linux GNOME window. On Windows run `vpngate -w` instead."
        );
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use gdk4::Display;
    use gio::prelude::*;
    use glib::ControlFlow;
    use gtk4::prelude::*;
    use gtk4::{
        Application, ApplicationWindow, Box as GtkBox, Button, CssProvider, HeaderBar, Label,
        Orientation, STYLE_PROVIDER_PRIORITY_APPLICATION,
    };
    use pango::FontDescription;
    use vte4::prelude::*;
    use vte4::{PtyFlags, Terminal};

    const APP_ID: &str = "net.vpngate.connect.launcher";
    const INITIAL_COLS: i32 = 88;
    const INITIAL_ROWS: i32 = 26;
    const DEFAULT_FONT_PT: i32 = 11;
    const CSS: &str = r#"
        window { background-color: #0d1117; }
        headerbar {
            background-image: none;
            background-color: #161b22;
            border-bottom: 1px solid #30363d;
            min-height: 38px;
            padding: 2px 8px;
        }
        headerbar windowtitle { color: #f0f6fc; font-weight: 700; }
        label.pill-off {
            background-color: #21262d; color: #8b949e;
            border: 1px solid #30363d; border-radius: 999px;
            padding: 2px 10px; font-size: 9pt; font-weight: 600;
        }
        label.pill-on {
            background-color: rgba(46, 160, 67, 0.18); color: #56d364;
            border: 1px solid rgba(63, 185, 80, 0.50); border-radius: 999px;
            padding: 2px 10px; font-size: 9pt; font-weight: 700;
        }
        label.pill-warn {
            background-color: rgba(210, 153, 34, 0.20); color: #e3b341;
            border: 1px solid rgba(210, 153, 34, 0.50); border-radius: 999px;
            padding: 2px 10px; font-size: 9pt; font-weight: 700;
        }
        button.ip-chip {
            background-image: none; background-color: #1f2937; color: #79c0ff;
            border: 1px solid #30363d; border-radius: 6px; padding: 1px 8px;
            font-family: monospace; font-size: 9pt;
        }
        button.ip-chip:hover { background-color: #2d3748; border-color: #58a6ff; }
    "#;

    pub fn run() {
        let mut hold = false;
        let mut passthrough = Vec::new();
        for a in env::args().skip(1) {
            if a == "--hold" {
                hold = true;
            } else {
                passthrough.push(a);
            }
        }

        let vpngate_bin = match resolve_vpngate_bin() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        let app = Application::builder().application_id(APP_ID).build();
        app.connect_activate(move |app| {
            if let Err(e) = build_window(app, &vpngate_bin, &passthrough, hold) {
                eprintln!("vpngate-launcher: {e}");
                app.quit();
            }
        });
        app.run_with_args(&[] as &[&str]);
    }

    fn resolve_vpngate_bin() -> Result<PathBuf, String> {
        let here = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        let mut cands = Vec::new();
        if let Some(d) = &here {
            cands.push(d.join("vpngate"));
            if let Some(root) = d.parent().and_then(|p| p.parent()) {
                cands.push(root.join("target/release/vpngate"));
                cands.push(root.join("target/debug/vpngate"));
            }
        }
        cands.push(PathBuf::from("/usr/local/bin/vpngate"));
        if let Ok(p) = env::var("PATH") {
            for dir in p.split(':') {
                cands.push(Path::new(dir).join("vpngate"));
            }
        }
        cands
            .into_iter()
            .find(|p| p.is_file())
            .ok_or_else(|| {
                "Could not locate compiled 'vpngate' binary. Run `sh ./install-vpngate.sh` or `cargo build --release -p vpngate-cli`."
                    .to_string()
            })
    }

    fn build_window(
        app: &Application,
        vpngate_bin: &Path,
        passthrough: &[String],
        hold: bool,
    ) -> Result<(), String> {
        if let Some(settings) = gtk4::Settings::default() {
            settings.set_gtk_application_prefer_dark_theme(true);
        }
        if let Some(display) = Display::default() {
            let css = CssProvider::new();
            css.load_from_data(CSS);
            gtk4::style_context_add_provider_for_display(
                &display,
                &css,
                STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }

        let win = ApplicationWindow::builder()
            .application(app)
            .title("VPN Gate")
            .build();
        win.set_icon_name(Some("vpngate"));

        let header = HeaderBar::new();
        let status = Label::new(Some("○ DISCONNECTED"));
        status.add_css_class("pill-off");
        let ip_chip = Button::with_label("");
        ip_chip.add_css_class("ip-chip");
        ip_chip.set_visible(false);
        header.pack_start(&status);
        header.pack_end(&ip_chip);
        win.set_titlebar(Some(&header));

        let term = Terminal::new();
        term.set_size(INITIAL_COLS as i64, INITIAL_ROWS as i64);
        term.set_scrollback_lines(6000);
        term.set_audible_bell(false);
        term.set_font(Some(&FontDescription::from_string(&format!(
            "Monospace {DEFAULT_FONT_PT}"
        ))));
        term.set_hexpand(true);
        term.set_vexpand(true);
        term.set_margin_start(12);
        term.set_margin_end(12);
        term.set_margin_top(10);
        term.set_margin_bottom(10);

        let pad = GtkBox::new(Orientation::Vertical, 0);
        pad.append(&term);
        win.set_child(Some(&pad));

        let run_base = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let sock_dir = tempfile_dir(&run_base)?;
        let sock_path = sock_dir.join("resize.sock");
        let sock = UnixDatagram::bind(&sock_path)
            .map_err(|e| format!("resize socket: {e}"))?;
        let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600));
        sock.set_nonblocking(true)
            .map_err(|e| format!("resize socket: {e}"))?;

        let mut argv: Vec<String> = vec![vpngate_bin.display().to_string()];
        argv.extend(passthrough.iter().cloned());
        if hold {
            let quoted: Vec<String> = argv.iter().map(|a| sh_quote(a)).collect();
            let snippet = format!(
                "{} ; rc=$?; echo ''; printf '\\033[1;36m[*]\\033[0m Command finished (exit %s). Press Enter to close window...' \"$rc\"; read -r _",
                quoted.join(" ")
            );
            argv = vec!["/bin/sh".to_string(), "-c".to_string(), snippet];
        }
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let envv = [
            format!("TERM=xterm-256color"),
            format!("COLORTERM=truecolor"),
            format!("VPNGATE_RESIZE_SOCK={}", sock_path.display()),
        ];
        let envv_refs: Vec<&str> = envv.iter().map(String::as_str).collect();
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        term.spawn_async(
            PtyFlags::DEFAULT,
            Some(home.as_str()),
            &argv_refs,
            &envv_refs,
            glib::SpawnFlags::DEFAULT,
            || {},
            -1,
            gio::Cancellable::NONE,
            |result| {
                    if let Err(e) = result {
                        eprintln!("vpngate-launcher: spawn failed: {e}");
                    }
                },
        );

        let status_l = status.clone();
        let ip_l = ip_chip.clone();
        glib::timeout_add_local(Duration::from_millis(1500), move || {
            refresh_header(&status_l, &ip_l);
            ControlFlow::Continue
        });
        refresh_header(&status, &ip_chip);

        let ip_copy = ip_chip.clone();
        ip_chip.connect_clicked(move |_| {
            let txt = ip_copy.label().unwrap_or_default();
            if txt.is_empty() {
                return;
            }
            if let Some(display) = Display::default() {
                display.clipboard().set_text(&txt);
            }
        });

        let term_r = term.clone();
        let win_r = win.clone();
        glib::timeout_add_local(Duration::from_millis(50), move || {
            let mut buf = [0u8; 1024];
            while let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&buf[..n]) {
                    let cols = v.get("cols").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
                    let rows = v.get("rows").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
                    if cols > 0 && rows > 0 {
                        apply_resize(&win_r, &term_r, cols, rows);
                    }
                }
            }
            ControlFlow::Continue
        });

        let app_q = app.clone();
        let sock_dir_c = sock_dir.clone();
        term.connect_child_exited(move |_, _| {
            let _ = fs::remove_dir_all(&sock_dir_c);
            app_q.quit();
        });
        let sock_dir_c2 = sock_dir.clone();
        win.connect_close_request(move |_| {
            let _ = fs::remove_dir_all(&sock_dir_c2);
            glib::Propagation::Proceed
        });

        win.present();
        apply_resize(&win, &term, INITIAL_COLS, INITIAL_ROWS);
        term.grab_focus();
        Ok(())
    }

    fn apply_resize(win: &ApplicationWindow, term: &Terminal, req_cols: i32, req_rows: i32) {
        if win.is_maximized() || win.is_fullscreen() {
            return;
        }
        let char_w = term.char_width().max(6) as i32;
        let char_h = term.char_height().max(12) as i32;
        let cols = req_cols.clamp(76, 155);
        let rows = req_rows.clamp(19, 44);
        let px_w = cols * char_w + 24;
        let px_h = rows * char_h + 20 + 44;
        term.set_size(cols as i64, rows as i64);
        win.set_default_size(px_w, px_h);
    }

    fn refresh_header(status: &Label, ip_chip: &Button) {
        let snap = read_fast_tunnel_snapshot();
        status.set_text(&snap.badge);
        status.remove_css_class("pill-off");
        status.remove_css_class("pill-on");
        status.remove_css_class("pill-warn");
        status.add_css_class(match snap.mode.as_str() {
            "connected" => "pill-on",
            "reconnecting" => "pill-warn",
            _ => "pill-off",
        });
        if snap.ip.is_empty() {
            ip_chip.set_visible(false);
        } else {
            ip_chip.set_label(&snap.ip);
            ip_chip.set_visible(true);
        }
    }

    struct Snap {
        mode: String,
        badge: String,
        ip: String,
    }

    fn read_fast_tunnel_snapshot() -> Snap {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let state = Path::new(&home).join(".cache/vpngate/active_state.json");
        let vpn_devs = list_vpn_devs();
        if let Ok(txt) = fs::read_to_string(&state)
            && let Ok(st) = serde_json::from_str::<serde_json::Value>(&txt)
        {
            if st.get("status").and_then(|v| v.as_str()) == Some("reconnecting") {
                let region = st
                    .get("region_label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("VPN");
                return Snap {
                    mode: "reconnecting".into(),
                    badge: format!("↻ RECONNECTING · {region}"),
                    ip: String::new(),
                };
            }
            let dev = st.get("device").and_then(|v| v.as_str()).unwrap_or("");
            if dev.is_empty() || vpn_devs.iter().any(|d| d == dev) || !vpn_devs.is_empty() {
                let cc = st
                    .get("country_short")
                    .and_then(|v| v.as_str())
                    .unwrap_or("??");
                let host = st.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
                let proto = st.get("protocol").and_then(|v| v.as_str()).unwrap_or("VPN");
                let egress = st
                    .get("egress_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Snap {
                    mode: "connected".into(),
                    badge: format!("● CONNECTED · {cc} ({host}) · {proto}"),
                    ip: egress,
                };
            }
        }
        if let Some(dev) = vpn_devs.first() {
            return Snap {
                mode: "connected".into(),
                badge: format!("● TUNNEL UP ({dev})"),
                ip: String::new(),
            };
        }
        Snap {
            mode: "disconnected".into(),
            badge: "○ DISCONNECTED".into(),
            ip: String::new(),
        }
    }

    fn list_vpn_devs() -> Vec<String> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir("/sys/class/net") else {
            return out;
        };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("ppp") || n.starts_with("tun") || n.starts_with("tap") {
                out.push(n);
            }
        }
        out.sort();
        out
    }

    fn tempfile_dir(run_base: &str) -> Result<PathBuf, String> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = Path::new(run_base).join(format!("vpngate-ui-{ts}"));
        fs::create_dir_all(&dir).map_err(|e| format!("ui dir: {e}"))?;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        Ok(dir)
    }

    fn sh_quote(s: &str) -> String {
        if s.is_empty() {
            return "''".into();
        }
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:@".contains(&b))
        {
            return s.to_string();
        }
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
