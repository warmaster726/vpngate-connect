#!/usr/bin/env python3
"""
vpngate-launcher - Native GNOME Dynamic-Resizing Window Launcher for `vpngate` (Rust Single-Binary Edition)

Hosts the compiled `vpngate` Rust binary inside a sleek dark GNOME GTK + VTE window on Linux
(Wayland & X11) with a native CSD HeaderBar, live zero-blocking VPN tunnel status pill,
one-click Egress IP clipboard copy, keyboard zoom (`Ctrl++` / `Ctrl+-` / `Ctrl+0`), and a Unix
datagram resize socket (`VPNGATE_RESIZE_SOCK`) that dynamically resizes the window around every
table, status box, and dashboard rendered by `vpngate`.

Fallback chain:
  1) GTK 3 + VTE 2.91 (`gir1.2-gtk-3.0` + `gir1.2-vte-2.91`) — live Wayland/X11 `win.resize()`
  2) GTK 4 + VTE 3.91 (`gir1.2-gtk-4.0` + `gir1.2-vte-3.91`) — `win.set_default_size()`
  3) External terminal emulators (`xterm` -> `qterminal` -> `kgx` -> `gnome-terminal`)
"""

import fcntl
import json
import os
import pty
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
from pathlib import Path


INITIAL_COLS = 88
INITIAL_ROWS = 26
PADDING_X = 24
PADDING_Y = 20
HEADERBAR_EST_H = 44
DEFAULT_FONT_PT = 11


def resolve_vpngate_bin() -> str:
    here = Path(os.path.realpath(sys.argv[0])).parent
    for cand in (
        here / "vpngate",
        here / "target" / "release" / "vpngate",
        here / "target" / "debug" / "vpngate",
        Path("/usr/local/bin/vpngate"),
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    found = shutil.which("vpngate")
    if found:
        return found
    raise FileNotFoundError(
        "Could not locate compiled 'vpngate' binary. Run `sh ./install-vpngate.sh` or `cargo build --release -p vpngate-cli`."
    )


def parse_launcher_args(argv: list) -> tuple:
    hold = False
    passthrough = []
    for a in argv:
        if a == "--hold":
            hold = True
        else:
            passthrough.append(a)
    return hold, passthrough


def build_child_command(vpngate_bin: str, passthrough: list, hold: bool) -> list:
    cmd = [vpngate_bin] + passthrough
    if not hold:
        return cmd
    quoted = " ".join(shlex.quote(c) for c in cmd)
    shell_snippet = (
        f"{quoted}; rc=$?; echo ''; "
        "printf '\\033[1;36m[*]\\033[0m Command finished (exit %s). Press Enter to close window...' \"$rc\"; "
        "read -r _"
    )
    return ["/bin/sh", "-c", shell_snippet]


def register_tty_socket_marker(slave_fd: int, sock_path: str) -> Path:
    try:
        tty_name = os.ttyname(slave_fd)
        key = tty_name.strip("/").replace("/", "_")
        ui_dir = Path.home() / ".cache" / "vpngate" / "ui_socks"
        ui_dir.mkdir(parents=True, exist_ok=True)
        marker = ui_dir / f"{key}.json"
        marker.write_text(json.dumps({"sock": sock_path, "pid": os.getpid()}), encoding="utf-8")
        return marker
    except Exception:
        return Path()


def _pty_child_setup():
    os.setsid()
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except Exception:
        pass


def read_fast_tunnel_snapshot() -> dict:
    state_file = Path.home() / ".cache" / "vpngate" / "active_state.json"
    net_ifaces = set()
    try:
        net_ifaces = set(os.listdir("/sys/class/net"))
    except Exception:
        pass

    vpn_devs = sorted(d for d in net_ifaces if d.startswith(("ppp", "tun", "tap")))
    if state_file.exists():
        try:
            st = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(st, dict) and st:
                if st.get("status") == "reconnecting":
                    return {
                        "mode": "reconnecting",
                        "badge": f"↻ RECONNECTING · {st.get('region_label', 'VPN')}",
                        "ip": "",
                    }
                dev = st.get("device", "")
                if not dev or dev in net_ifaces or vpn_devs:
                    cc = st.get("country_short", "??")
                    host = st.get("hostname", "")
                    proto = st.get("protocol", "VPN")
                    egress = st.get("egress_ip", "")
                    return {
                        "mode": "connected",
                        "badge": f"● CONNECTED · {cc} ({host}) · {proto}",
                        "ip": egress,
                    }
        except Exception:
            pass

    if vpn_devs:
        return {"mode": "connected", "badge": f"● TUNNEL UP ({vpn_devs[0]})", "ip": ""}

    return {"mode": "disconnected", "badge": "○ DISCONNECTED", "ip": ""}


def run_gtk3_vte(child_argv: list) -> bool:
    try:
        import gi

        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        gi.require_version("Pango", "1.0")
        gi.require_version("Vte", "2.91")
        from gi.repository import Gdk, GLib, Gtk, Pango, Vte
    except Exception:
        return False

    run_base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    sock_dir = Path(tempfile.mkdtemp(prefix="vpngate-ui-", dir=run_base))
    os.chmod(sock_dir, 0o700)
    sock_path = str(sock_dir / "resize.sock")

    srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv_sock.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv_sock.setblocking(False)

    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(
        slave_fd,
        termios.TIOCSWINSZ,
        struct.pack("HHHH", INITIAL_ROWS, INITIAL_COLS, 0, 0),
    )
    marker_path = register_tty_socket_marker(slave_fd, sock_path)

    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env["VPNGATE_RESIZE_SOCK"] = sock_path

    vte_pty = Vte.Pty.new_foreign_sync(master_fd, None)
    child_proc = subprocess.Popen(
        child_argv,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        cwd=str(Path.home()),
        preexec_fn=_pty_child_setup,
        close_fds=True,
    )
    os.close(slave_fd)

    settings = Gtk.Settings.get_default()
    if settings is not None:
        settings.set_property("gtk-application-prefer-dark-theme", True)

    css = Gtk.CssProvider()
    css.load_from_data(
        b"""
        window { background-color: #0d1117; }
        headerbar {
            background-image: none;
            background-color: #161b22;
            border-bottom: 1px solid #30363d;
            min-height: 38px;
            padding: 2px 8px;
        }
        headerbar .title { color: #f0f6fc; font-weight: 700; font-size: 10.5pt; }
        box.vpngate-pad { background-color: #0d1117; padding: 10px 12px; }
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
        """
    )
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        css,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )

    win = Gtk.Window(title="VPN Gate")
    win.set_icon_name("network-vpn")
    win.set_position(Gtk.WindowPosition.CENTER)

    hbar = Gtk.HeaderBar()
    hbar.set_show_close_button(True)
    hbar.set_title("VPN Gate")

    status_pill = Gtk.Label(label="○ DISCONNECTED")
    status_pill.get_style_context().add_class("pill-off")
    hbar.pack_start(status_pill)

    ip_btn = Gtk.Button(label="")
    ip_btn.get_style_context().add_class("ip-chip")
    ip_btn.set_tooltip_text("Click to copy active VPN Egress IP to clipboard")
    ip_btn.set_no_show_all(True)
    hbar.pack_end(ip_btn)
    win.set_titlebar(hbar)

    term = Vte.Terminal()
    term.set_pty(vte_pty)
    term.set_size(INITIAL_COLS, INITIAL_ROWS)
    term.set_scrollback_lines(6000)
    term.set_audible_bell(False)
    font_state = {"pt": DEFAULT_FONT_PT, "cols": INITIAL_COLS, "rows": INITIAL_ROWS}
    term.set_font(Pango.FontDescription.from_string(f"Monospace {font_state['pt']}"))

    def rgba(hex_s: str) -> Gdk.RGBA:
        c = Gdk.RGBA()
        c.parse(hex_s)
        return c

    palette = [
        rgba("#0d1117"),
        rgba("#ff7b72"),
        rgba("#3fb950"),
        rgba("#d29922"),
        rgba("#58a6ff"),
        rgba("#bc8cff"),
        rgba("#39c5cf"),
        rgba("#b1bac4"),
        rgba("#484f58"),
        rgba("#ffa198"),
        rgba("#56d364"),
        rgba("#e3b341"),
        rgba("#79c0ff"),
        rgba("#d2a8ff"),
        rgba("#56d4dd"),
        rgba("#f0f6fc"),
    ]
    term.set_colors(rgba("#e6edf3"), rgba("#0d1117"), palette)

    pad_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    pad_box.get_style_context().add_class("vpngate-pad")
    pad_box.pack_start(term, True, True, 0)
    win.add(pad_box)

    ip_state = {"ip": ""}

    def on_copy_ip(_btn):
        if ip_state["ip"]:
            clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clip.set_text(ip_state["ip"], -1)
            clip.store()
            ip_btn.set_label(f"Copied {ip_state['ip']}")
            GLib.timeout_add(
                1400,
                lambda: (ip_btn.set_label(ip_state["ip"]) if ip_state["ip"] else None) or False,
            )

    ip_btn.connect("clicked", on_copy_ip)

    def refresh_header_status():
        snap = read_fast_tunnel_snapshot()
        ctx = status_pill.get_style_context()
        for cls in ("pill-off", "pill-on", "pill-warn"):
            ctx.remove_class(cls)
        if snap["mode"] == "connected":
            ctx.add_class("pill-on")
        elif snap["mode"] == "reconnecting":
            ctx.add_class("pill-warn")
        else:
            ctx.add_class("pill-off")
        status_pill.set_text(snap["badge"])
        ip_state["ip"] = snap.get("ip", "")
        if ip_state["ip"]:
            ip_btn.set_label(ip_state["ip"])
            ip_btn.show()
        else:
            ip_btn.hide()
        return True

    def apply_dynamic_grid_resize(req_cols: int, req_rows: int):
        gdk_win = win.get_window()
        if gdk_win is not None:
            st = gdk_win.get_state()
            if st & (Gdk.WindowState.MAXIMIZED | Gdk.WindowState.FULLSCREEN):
                return
        char_w = max(6, term.get_char_width())
        char_h = max(12, term.get_char_height())
        max_cols, max_rows = 160, 46
        disp = Gdk.Display.get_default()
        if disp is not None:
            mon = (
                disp.get_monitor_at_window(gdk_win)
                if gdk_win is not None
                else disp.get_primary_monitor()
            )
            if mon is None and disp.get_n_monitors() > 0:
                mon = disp.get_monitor(0)
            if mon is not None:
                wa = mon.get_workarea()
                max_cols = max(80, int((wa.width * 0.92 - PADDING_X) // char_w))
                max_rows = max(20, int((wa.height * 0.88 - PADDING_Y - HEADERBAR_EST_H) // char_h))
        cols = max(76, min(int(req_cols), max_cols))
        rows = max(19, min(int(req_rows), max_rows))
        font_state["cols"], font_state["rows"] = cols, rows
        px_w = cols * char_w + PADDING_X
        px_h = rows * char_h + PADDING_Y + HEADERBAR_EST_H
        try:
            pty_fd = vte_pty.get_fd()
            if pty_fd >= 0:
                fcntl.ioctl(
                    pty_fd,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, px_w, px_h),
                )
        except Exception:
            pass
        term.set_size(cols, rows)
        win.resize(px_w, px_h)

    def set_font_pt(new_pt: int):
        clamped = max(8, min(20, int(new_pt)))
        if clamped != font_state["pt"]:
            font_state["pt"] = clamped
            term.set_font(Pango.FontDescription.from_string(f"Monospace {clamped}"))
            apply_dynamic_grid_resize(font_state["cols"], font_state["rows"])

    def on_sock_readable(_fd, _cond):
        while True:
            try:
                raw = srv_sock.recv(1024)
                if not raw:
                    break
                msg = json.loads(raw.decode("utf-8", errors="ignore"))
                c = int(msg.get("cols", 0))
                r = int(msg.get("rows", 0))
                if c > 0 and r > 0:
                    apply_dynamic_grid_resize(c, r)
            except BlockingIOError:
                break
            except Exception:
                break
        return True

    def on_vte_resize_window(_term, width_val, height_val):
        if 40 <= width_val <= 220 and 12 <= height_val <= 90:
            apply_dynamic_grid_resize(width_val, height_val)

    def on_key_press(_widget, event):
        mods = event.state & Gtk.accelerator_get_default_mod_mask()
        ctrl_only = (mods & Gdk.ModifierType.CONTROL_MASK) and not (
            mods & Gdk.ModifierType.SHIFT_MASK
        )
        ctrl_shift = Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK
        keyname = Gdk.keyval_name(event.keyval) or ""
        if (mods & ctrl_shift) == ctrl_shift:
            if keyname.upper() == "C":
                term.copy_clipboard_format(Vte.Format.TEXT)
                return True
            if keyname.upper() == "V":
                term.paste_clipboard()
                return True
            if keyname in ("plus", "equal", "KP_Add"):
                set_font_pt(font_state["pt"] + 1)
                return True
        if ctrl_only:
            if keyname in ("plus", "equal", "KP_Add"):
                set_font_pt(font_state["pt"] + 1)
                return True
            if keyname in ("minus", "underscore", "KP_Subtract"):
                set_font_pt(font_state["pt"] - 1)
                return True
            if keyname in ("0", "KP_0"):
                set_font_pt(DEFAULT_FONT_PT)
                return True
        return False

    def cleanup_and_quit(*_args):
        if child_proc.poll() is None:
            try:
                child_proc.terminate()
            except Exception:
                pass
        try:
            srv_sock.close()
        except Exception:
            pass
        if marker_path and marker_path.exists():
            marker_path.unlink(missing_ok=True)
        shutil.rmtree(sock_dir, ignore_errors=True)
        Gtk.main_quit()

    def poll_child():
        if child_proc.poll() is not None:
            cleanup_and_quit()
            return False
        return True

    GLib.io_add_watch(srv_sock.fileno(), GLib.IO_IN, on_sock_readable)
    GLib.timeout_add(150, poll_child)
    GLib.timeout_add(1500, refresh_header_status)
    term.connect("resize-window", on_vte_resize_window)
    win.connect("key-press-event", on_key_press)
    win.connect("destroy", cleanup_and_quit)

    refresh_header_status()
    win.show_all()
    apply_dynamic_grid_resize(INITIAL_COLS, INITIAL_ROWS)
    term.grab_focus()
    Gtk.main()
    return True


def run_gtk4_vte(child_argv: list) -> bool:
    try:
        import gi

        gi.require_version("Gdk", "4.0")
        gi.require_version("Gtk", "4.0")
        gi.require_version("Pango", "1.0")
        gi.require_version("Vte", "3.91")
        from gi.repository import GLib, Gtk, Pango, Vte
    except Exception:
        return False

    run_base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    sock_dir = Path(tempfile.mkdtemp(prefix="vpngate-ui-", dir=run_base))
    os.chmod(sock_dir, 0o700)
    sock_path = str(sock_dir / "resize.sock")

    srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv_sock.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv_sock.setblocking(False)

    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(
        slave_fd,
        termios.TIOCSWINSZ,
        struct.pack("HHHH", INITIAL_ROWS, INITIAL_COLS, 0, 0),
    )
    marker_path = register_tty_socket_marker(slave_fd, sock_path)

    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env["VPNGATE_RESIZE_SOCK"] = sock_path

    vte_pty = Vte.Pty.new_foreign_sync(master_fd, None)
    child_proc = subprocess.Popen(
        child_argv,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        cwd=str(Path.home()),
        preexec_fn=_pty_child_setup,
        close_fds=True,
    )
    os.close(slave_fd)

    app = Gtk.Application(application_id="net.vpngate.connect.launcher")

    def on_activate(application):
        settings = Gtk.Settings.get_default()
        if settings is not None:
            settings.set_property("gtk-application-prefer-dark-theme", True)

        win = Gtk.ApplicationWindow(application=application, title="VPN Gate")
        win.set_icon_name("network-vpn")

        hbar = Gtk.HeaderBar()
        status_lbl = Gtk.Label(label="○ DISCONNECTED")
        hbar.pack_start(status_lbl)
        win.set_titlebar(hbar)

        term = Vte.Terminal()
        term.set_pty(vte_pty)
        term.set_size(INITIAL_COLS, INITIAL_ROWS)
        term.set_scrollback_lines(6000)
        term.set_audible_bell(False)
        term.set_font(Pango.FontDescription.from_string(f"Monospace {DEFAULT_FONT_PT}"))
        term.set_hexpand(True)
        term.set_vexpand(True)
        term.set_margin_start(12)
        term.set_margin_end(12)
        term.set_margin_top(10)
        term.set_margin_bottom(10)
        win.set_child(term)

        def refresh_header_status():
            snap = read_fast_tunnel_snapshot()
            txt = snap["badge"] + (f"  [{snap['ip']}]" if snap.get("ip") else "")
            status_lbl.set_text(txt)
            return True

        def apply_dynamic_grid_resize(req_cols: int, req_rows: int):
            if win.is_maximized() or win.is_fullscreen():
                return
            char_w = max(6, term.get_char_width())
            char_h = max(12, term.get_char_height())
            cols = max(76, min(int(req_cols), 155))
            rows = max(19, min(int(req_rows), 44))
            px_w = cols * char_w + PADDING_X
            px_h = rows * char_h + PADDING_Y + HEADERBAR_EST_H
            try:
                pty_fd = vte_pty.get_fd()
                if pty_fd >= 0:
                    fcntl.ioctl(
                        pty_fd,
                        termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, px_w, px_h),
                    )
            except Exception:
                pass
            term.set_size(cols, rows)
            win.set_default_size(px_w, px_h)

        def on_sock_readable(_fd, _cond):
            while True:
                try:
                    raw = srv_sock.recv(1024)
                    if not raw:
                        break
                    msg = json.loads(raw.decode("utf-8", errors="ignore"))
                    c = int(msg.get("cols", 0))
                    r = int(msg.get("rows", 0))
                    if c > 0 and r > 0:
                        apply_dynamic_grid_resize(c, r)
                except BlockingIOError:
                    break
                except Exception:
                    break
            return True

        def cleanup():
            if child_proc.poll() is None:
                try:
                    child_proc.terminate()
                except Exception:
                    pass
            try:
                srv_sock.close()
            except Exception:
                pass
            if marker_path and marker_path.exists():
                marker_path.unlink(missing_ok=True)
            shutil.rmtree(sock_dir, ignore_errors=True)

        def poll_child():
            if child_proc.poll() is not None:
                cleanup()
                win.close()
                return False
            return True

        GLib.io_add_watch(srv_sock.fileno(), GLib.IO_IN, on_sock_readable)
        GLib.timeout_add(150, poll_child)
        GLib.timeout_add(1500, refresh_header_status)
        win.connect("close-request", lambda *_a: (cleanup(), False)[1])
        refresh_header_status()
        win.present()
        apply_dynamic_grid_resize(INITIAL_COLS, INITIAL_ROWS)
        term.grab_focus()

    app.connect("activate", on_activate)
    app.run([])
    return True


def run_fallback_terminal(child_argv: list) -> int:
    candidates = [
        (
            "xterm",
            lambda cmd: [
                "xterm",
                "-title",
                "VPN Gate",
                "-fa",
                "Monospace",
                "-fs",
                str(DEFAULT_FONT_PT),
                "-bg",
                "#0d1117",
                "-fg",
                "#e6edf3",
                "-geometry",
                f"{INITIAL_COLS}x{INITIAL_ROWS}",
                "-xrm",
                "XTerm*allowWindowOps: true",
                "-e",
            ]
            + cmd,
        ),
        ("qterminal", lambda cmd: ["qterminal", "-e"] + cmd),
        ("kgx", lambda cmd: ["kgx", "--title=VPN Gate", "--"] + cmd),
        ("gnome-terminal", lambda cmd: ["gnome-terminal", "--title=VPN Gate", "--"] + cmd),
    ]
    for bin_name, builder in candidates:
        if shutil.which(bin_name):
            return subprocess.call(builder(child_argv))
    return subprocess.call(child_argv)


def main() -> int:
    vpngate_bin = resolve_vpngate_bin()
    hold, passthrough = parse_launcher_args(sys.argv[1:])
    child_argv = build_child_command(vpngate_bin, passthrough, hold)

    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        if run_gtk3_vte(child_argv):
            return 0
        if run_gtk4_vte(child_argv):
            return 0
        return run_fallback_terminal(child_argv)

    return subprocess.call(child_argv)


if __name__ == "__main__":
    sys.exit(main())
