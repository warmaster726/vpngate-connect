use std::collections::HashMap;
use std::env;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vpngate_core::ProgressEvent;

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
#[cfg(windows)]
pub const DIM: &str = "\x1b[90m";
#[cfg(not(windows))]
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[1;31m";
pub const GREEN: &str = "\x1b[1;32m";
pub const YELLOW: &str = "\x1b[1;33m";
pub const CYAN: &str = "\x1b[1;36m";

static DYNAMIC_RESIZE_ENABLED: AtomicBool = AtomicBool::new(true);
static SCREEN_CLEAR_ENABLED: AtomicBool = AtomicBool::new(true);
static LAST_TRANSIENT_VIS_LEN: AtomicUsize = AtomicUsize::new(0);
static WIN_VT_ENABLED: AtomicBool = AtomicBool::new(!cfg!(windows));

#[cfg(windows)]
mod win_console {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    const CP_UTF8: u32 = 65001;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;
    const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Coord {
        x: i16,
        y: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ConsoleScreenBufferInfo {
        dw_size: Coord,
        dw_cursor_position: Coord,
        w_attributes: u16,
        sr_window: SmallRect,
        dw_maximum_window_size: Coord,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleOutputCP(code_page_id: u32) -> i32;
        fn SetConsoleCP(code_page_id: u32) -> i32;
        fn SetConsoleTitleW(console_title: *const u16) -> i32;
        fn GetStdHandle(std_handle: u32) -> *mut c_void;
        fn GetConsoleMode(console_handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(console_handle: *mut c_void, mode: u32) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
        fn GetConsoleScreenBufferInfo(
            console_output: *mut c_void,
            info: *mut ConsoleScreenBufferInfo,
        ) -> i32;
        fn FillConsoleOutputCharacterW(
            console_output: *mut c_void,
            character: u16,
            length: u32,
            write_coord: Coord,
            number_of_chars_written: *mut u32,
        ) -> i32;
        fn FillConsoleOutputAttribute(
            console_output: *mut c_void,
            attribute: u16,
            length: u32,
            write_coord: Coord,
            number_of_attrs_written: *mut u32,
        ) -> i32;
        fn SetConsoleCursorPosition(console_output: *mut c_void, cursor_position: Coord) -> i32;
        fn CloseHandle(object: *mut c_void) -> i32;
    }

    fn is_valid_handle(h: *mut c_void) -> bool {
        !h.is_null() && (h as isize) != -1
    }

    fn conout_wide() -> [u16; 8] {
        [
            b'C' as u16,
            b'O' as u16,
            b'N' as u16,
            b'O' as u16,
            b'U' as u16,
            b'T' as u16,
            b'$' as u16,
            0,
        ]
    }

    pub fn enable_vt_processing() -> bool {
        let mut vt_ok = false;
        // SAFETY: All Win32 console handles are checked against NULL and INVALID_HANDLE_VALUE (-1)
        // before querying/updating console output flags, and owned `CONOUT$` handles are closed.
        unsafe {
            for std_id in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                let h = GetStdHandle(std_id);
                if is_valid_handle(h) {
                    let mut mode: u32 = 0;
                    if GetConsoleMode(h, &mut mode) != 0
                        && SetConsoleMode(
                            h,
                            mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                        ) != 0
                    {
                        vt_ok = true;
                    }
                }
            }

            let name = conout_wide();
            let h_con = CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
            if is_valid_handle(h_con) {
                let mut cmode: u32 = 0;
                if GetConsoleMode(h_con, &mut cmode) != 0
                    && SetConsoleMode(
                        h_con,
                        cmode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                    ) != 0
                {
                    vt_ok = true;
                }
                let _ = CloseHandle(h_con);
            }
        }
        vt_ok
    }

    pub fn init(set_title: bool) -> bool {
        // SAFETY: `SetConsoleOutputCP`, `SetConsoleCP`, and `SetConsoleTitleW` accept valid values/UTF-16 NUL buffer.
        unsafe {
            let _ = SetConsoleOutputCP(CP_UTF8);
            let _ = SetConsoleCP(CP_UTF8);
            if set_title {
                let mut title: Vec<u16> = "VPN Gate Connect".encode_utf16().collect();
                title.push(0);
                let _ = SetConsoleTitleW(title.as_ptr());
            }
        }
        enable_vt_processing()
    }

    pub fn query_size() -> Option<(usize, usize)> {
        let name = conout_wide();
        // SAFETY: Opens `CONOUT$` read-only with shared access, queries `CONSOLE_SCREEN_BUFFER_INFO`, and closes handle.
        unsafe {
            let h_con = CreateFileW(
                name.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
            if !is_valid_handle(h_con) {
                return None;
            }
            let mut csbi = ConsoleScreenBufferInfo::default();
            let ok = GetConsoleScreenBufferInfo(h_con, &mut csbi);
            let _ = CloseHandle(h_con);
            if ok == 0 {
                return None;
            }
            let cols = i32::from(csbi.sr_window.right) - i32::from(csbi.sr_window.left) + 1;
            let rows = i32::from(csbi.sr_window.bottom) - i32::from(csbi.sr_window.top) + 1;
            if cols > 0 && rows > 0 {
                Some((cols as usize, rows as usize))
            } else {
                let _ = null::<u8>();
                None
            }
        }
    }

    pub fn clear_console_buffer() {
        let name = conout_wide();
        // SAFETY: Clears active `CONOUT$` screen buffer via Win32 console APIs when VT sequences are unavailable.
        unsafe {
            let h_con = CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
            if !is_valid_handle(h_con) {
                return;
            }
            let mut csbi = ConsoleScreenBufferInfo::default();
            if GetConsoleScreenBufferInfo(h_con, &mut csbi) != 0 {
                let cells = u32::from(csbi.dw_size.x.max(0) as u16)
                    .saturating_mul(u32::from(csbi.dw_size.y.max(0) as u16));
                let origin = Coord { x: 0, y: 0 };
                let mut written: u32 = 0;
                let _ = FillConsoleOutputCharacterW(
                    h_con,
                    b' ' as u16,
                    cells,
                    origin,
                    &mut written,
                );
                let _ =
                    FillConsoleOutputAttribute(h_con, csbi.w_attributes, cells, origin, &mut written);
                let _ = SetConsoleCursorPosition(h_con, origin);
            }
            let _ = CloseHandle(h_con);
        }
    }
}

/// Initializes UTF-8 codepage (65001) and VT100 ANSI processing on Windows 11 PowerShell / conhost.
pub fn init_console(set_title: bool) {
    #[cfg(windows)]
    {
        let ok = win_console::init(set_title);
        WIN_VT_ENABLED.store(ok, Ordering::Relaxed);
    }
    #[cfg(not(windows))]
    {
        let _ = set_title;
        WIN_VT_ENABLED.store(true, Ordering::Relaxed);
    }
}

/// Re-asserts VT100 mode on Windows in case a child console process modified `CONOUT$` flags.
pub fn ensure_windows_vt_mode() -> bool {
    #[cfg(windows)]
    {
        let ok = win_console::enable_vt_processing();
        WIN_VT_ENABLED.store(ok, Ordering::Relaxed);
        ok
    }
    #[cfg(not(windows))]
    {
        true
    }
}

pub fn win_vt_enabled() -> bool {
    WIN_VT_ENABLED.load(Ordering::Relaxed)
}

pub fn set_dynamic_resize(enabled: bool) {
    DYNAMIC_RESIZE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn dynamic_resize_enabled() -> bool {
    DYNAMIC_RESIZE_ENABLED.load(Ordering::Relaxed)
}

pub fn set_screen_clear(enabled: bool) {
    SCREEN_CLEAR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn screen_clear_enabled() -> bool {
    SCREEN_CLEAR_ENABLED.load(Ordering::Relaxed)
}

pub fn is_stdout_tty() -> bool {
    io::stdout().is_terminal()
}

pub fn ansi_stdout_enabled() -> bool {
    env::var_os("NO_COLOR").is_none() && is_stdout_tty() && (!cfg!(windows) || win_vt_enabled())
}

pub fn ansi_stderr_enabled() -> bool {
    env::var_os("NO_COLOR").is_none()
        && io::stderr().is_terminal()
        && (!cfg!(windows) || win_vt_enabled())
}

pub fn supports_utf8() -> bool {
    if cfg!(windows) {
        // Match Python v5.3: always use 1-cell ASCII borders/separators on Windows PowerShell/conhost
        // so CJK locales (e.g. Hong Kong CP950) & Consolas never suffer EAW='A' 2-cell glyph misalignment.
        return false;
    }
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(v) = env::var(var)
            && !v.is_empty()
        {
            return v.to_ascii_uppercase().contains("UTF");
        }
    }
    true
}

/// Sanitizes control tabs/carriage-returns and translates East-Asian-Ambiguous (`EAW='A'`) /
/// `Consolas`-missing glyphs to crisp 1-cell ASCII on Windows.
pub fn win_clean_text_for_platform(text: &str, is_windows: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\r' => {}
            '\t' => out.push_str("  "),
            '●' if is_windows => out.push('*'),
            '○' if is_windows => out.push('o'),
            '↻' if is_windows => out.push('~'),
            '—' | '–' if is_windows => out.push('-'),
            '·' if is_windows => out.push('|'),
            '…' if is_windows => out.push('.'),
            '✓' | '✔' if is_windows => out.push('+'),
            '✗' | '✘' if is_windows => out.push('x'),
            '╭' | '╮' | '╰' | '╯' | '├' | '┤' if is_windows => out.push('+'),
            '─' if is_windows => out.push('-'),
            '│' if is_windows => out.push('|'),
            other => out.push(other),
        }
    }
    out
}

pub fn win_clean_text(text: &str) -> String {
    win_clean_text_for_platform(text, cfg!(windows))
}

fn format_for_stdout(text: &str) -> String {
    let cleaned = win_clean_text(text);
    if ansi_stdout_enabled() {
        cleaned
    } else {
        strip_ansi(&cleaned)
    }
}

fn format_for_stderr(text: &str) -> String {
    let cleaned = win_clean_text(text);
    if ansi_stderr_enabled() {
        cleaned
    } else {
        strip_ansi(&cleaned)
    }
}

pub fn clear_transient_line() {
    let prev = LAST_TRANSIENT_VIS_LEN.swap(0, Ordering::Relaxed);
    if prev > 0 && is_stdout_tty() {
        let mut out = io::stdout().lock();
        let _ = write!(out, "\r{}\r", " ".repeat(prev));
        let _ = out.flush();
    }
}

pub fn print_line(msg: &str) {
    clear_transient_line();
    let rendered = format_for_stdout(msg);
    let _ = writeln!(io::stdout(), "{rendered}");
}

pub fn info(msg: &str) {
    clear_transient_line();
    let rendered = format_for_stdout(&format!("{CYAN}[*]{RESET} {msg}"));
    let _ = writeln!(io::stdout(), "{rendered}");
}

pub fn ok(msg: &str) {
    clear_transient_line();
    let rendered = format_for_stdout(&format!("{GREEN}[+]{RESET} {msg}"));
    let _ = writeln!(io::stdout(), "{rendered}");
}

pub fn warn(msg: &str) {
    clear_transient_line();
    let rendered = format_for_stderr(&format!("{YELLOW}[!]{RESET} {msg}"));
    let _ = writeln!(io::stderr(), "{rendered}");
}

pub fn err(msg: &str) {
    clear_transient_line();
    let rendered = format_for_stderr(&format!("{RED}[-]{RESET} {msg}"));
    let _ = writeln!(io::stderr(), "{rendered}");
}

pub fn format_thousands_u64(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (idx, ch) in s.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

/// Renders live `ProgressEvent` items (`PY` branch style in-place counters + step logs).
pub fn render_progress_event(ev: ProgressEvent) {
    match ev {
        ProgressEvent::ClearTransient => clear_transient_line(),
        ProgressEvent::Info(m) => info(&m),
        ProgressEvent::Ok(m) => ok(&m),
        ProgressEvent::Warn(m) => warn(&m),
        ProgressEvent::AttemptBanner {
            index,
            total,
            hostname,
            ip,
            country_short,
            country_long,
            speed_mbps,
            ping_ms,
            score,
        } => {
            clear_transient_line();
            let ping_tag = if ping_ms < 9999 {
                format!("{ping_ms} ms")
            } else {
                "N/A".to_string()
            };
            let score_s = format_thousands_u64(score);
            let banner = format_for_stdout(&format!(
                "\n{BOLD}[Attempt {index}/{total}]{RESET} Testing {CYAN}{hostname}{RESET} \
                 ({ip}) | {country_short} ({country_long}) | {speed_mbps:.1} Mbps | Ping: {ping_tag} | Score: {score_s}"
            ));
            let _ = writeln!(io::stdout(), "{banner}");
        }
        ProgressEvent::Transient {
            stage,
            elapsed_secs,
            max_secs,
            tick,
        } => {
            if !is_stdout_tty() {
                return;
            }
            let stage_clean = win_clean_text(&stage);
            const FRAMES: [&str; 4] = ["-", "\\", "|", "/"];
            let spin = FRAMES[tick % FRAMES.len()];
            let cnt_str = if max_secs > 0 {
                format!("{elapsed_secs}s/{max_secs}s")
            } else {
                format!("{elapsed_secs}s")
            };
            let (cols, _) = get_live_terminal_size(100, 30);
            // Leave at least a 2-column EOL margin on Windows so `ENABLE_WRAP_AT_EOL_OUTPUT`
            // never wraps the in-place `\r` spinner onto a second row.
            let max_vis = cols.saturating_sub(if cfg!(windows) { 2 } else { 1 }).max(20);

            let plain_full =
                format!("[*] [{spin}] {stage_clean} [{cnt_str}] - Press Ctrl+C to interrupt");
            let full_w = visible_len(&plain_full);
            let (vis_len, raw_colored) = if full_w <= max_vis {
                (
                    full_w,
                    format!(
                        "{CYAN}{BOLD}[*]{RESET} {CYAN}{BOLD}[{spin}]{RESET} {stage_clean} \
                         {CYAN}{BOLD}[{cnt_str}]{RESET} - {YELLOW}Press Ctrl+C to interrupt{RESET}"
                    ),
                )
            } else {
                let plain_short = format!("[*] [{spin}] {stage_clean} [{cnt_str}]");
                let short_w = visible_len(&plain_short);
                if short_w <= max_vis {
                    (
                        short_w,
                        format!(
                            "{CYAN}{BOLD}[*]{RESET} {CYAN}{BOLD}[{spin}]{RESET} {stage_clean} \
                             {CYAN}{BOLD}[{cnt_str}]{RESET}"
                        ),
                    )
                } else {
                    let clipped = truncate_plain(&plain_short, max_vis);
                    let l = visible_len(&clipped);
                    (l, clipped)
                }
            };

            let rendered = if ansi_stdout_enabled() {
                raw_colored
            } else {
                strip_ansi(&raw_colored)
            };
            let prev = LAST_TRANSIENT_VIS_LEN.swap(vis_len, Ordering::Relaxed);
            let pad_len = prev.saturating_sub(vis_len).min(max_vis.saturating_sub(vis_len));
            let pad = " ".repeat(pad_len);
            let mut out = io::stdout().lock();
            let _ = write!(out, "\r{rendered}{pad}");
            let _ = out.flush();
        }
    }
}

pub fn format_duration(secs: u64) -> String {
    let hrs = secs / 3600;
    let rem = secs % 3600;
    let mins = rem / 60;
    let s = rem % 60;
    if hrs > 0 {
        format!("{hrs:02}:{mins:02}:{s:02}")
    } else {
        format!("{mins:02}:{s:02}")
    }
}

fn char_width(ch: char) -> usize {
    if ch.is_control() {
        return 0;
    }
    let u = ch as u32;
    // Zero-width combining marks and variation selectors
    if (0x0300..=0x036F).contains(&u)
        || (0x1AB0..=0x1AFF).contains(&u)
        || (0x1DC0..=0x1DFF).contains(&u)
        || (0x20D0..=0x20FF).contains(&u)
        || (0xFE00..=0xFE0F).contains(&u)
        || (0xFE20..=0xFE2F).contains(&u)
    {
        return 0;
    }
    // Wide / Fullwidth East Asian & Emoji blocks
    if (0x1100..=0x115F).contains(&u)
        || (0x2E80..=0xA4CF).contains(&u)
        || (0xAC00..=0xD7A3).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0xFE10..=0xFE6F).contains(&u)
        || (0xFF00..=0xFF60).contains(&u)
        || (0xFFE0..=0xFFE6).contains(&u)
        || (0x1F300..=0x1F9FF).contains(&u)
        || (0x20000..=0x3FFFD).contains(&u)
    {
        2
    } else {
        1
    }
}

pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for seq_c in chars.by_ref() {
                if ('@'..='~').contains(&seq_c) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn visible_len(text: &str) -> usize {
    let cleaned = win_clean_text(text);
    strip_ansi(&cleaned).chars().map(char_width).sum()
}

pub fn truncate_plain(text: &str, max_width: usize) -> String {
    let cleaned = win_clean_text(text);
    if max_width == 0 {
        return String::new();
    }
    if visible_len(&cleaned) <= max_width {
        return cleaned;
    }
    let ellipsis = if supports_utf8() { "…" } else { "." };
    let target = max_width.saturating_sub(1);
    let mut acc = String::new();
    let mut w = 0usize;
    for ch in cleaned.chars() {
        let cw = char_width(ch);
        if w + cw > target {
            break;
        }
        acc.push(ch);
        w += cw;
    }
    acc.push_str(ellipsis);
    acc
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

pub fn pad_plain(text: &str, width: usize, align: Align) -> String {
    let truncated = truncate_plain(text, width);
    let vlen = visible_len(&truncated);
    let pad = width.saturating_sub(vlen);
    match align {
        Align::Right => format!("{}{truncated}", " ".repeat(pad)),
        Align::Left => format!("{truncated}{}", " ".repeat(pad)),
    }
}

pub fn fit_ansi_line(text: &str, width: usize) -> String {
    let cleaned = win_clean_text(text);
    let vlen = visible_len(&cleaned);
    if vlen <= width {
        return format!("{cleaned}{}", " ".repeat(width - vlen));
    }
    // Truncate visible characters while preserving ANSI sequences
    let ellipsis = if supports_utf8() { "…" } else { "." };
    let target = width.saturating_sub(1);
    let mut out = String::new();
    let mut vis = 0usize;
    let mut chars = cleaned.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            out.push(c);
            if let Some(br) = chars.next() {
                out.push(br);
            }
            for seq_c in chars.by_ref() {
                out.push(seq_c);
                if ('@'..='~').contains(&seq_c) {
                    break;
                }
            }
        } else {
            let cw = char_width(c);
            if vis + cw > target {
                break;
            }
            out.push(c);
            vis += cw;
        }
    }
    out.push_str(RESET);
    out.push_str(ellipsis);
    let rem = width.saturating_sub(vis + 1);
    if rem > 0 {
        out.push_str(&" ".repeat(rem));
    }
    out
}

pub fn get_live_terminal_size(fallback_cols: usize, fallback_rows: usize) -> (usize, usize) {
    #[cfg(windows)]
    {
        if let Some((cols, rows)) = win_console::query_size() {
            return (cols, rows);
        }
    }
    #[cfg(unix)]
    {
        for fd in [libc::STDOUT_FILENO, libc::STDIN_FILENO, libc::STDERR_FILENO] {
            // SAFETY: `isatty` and `ioctl(..., TIOCGWINSZ, ...)` operate on standard file descriptors 0..=2.
            unsafe {
                if libc::isatty(fd) == 1 {
                    let mut ws: libc::winsize = std::mem::zeroed();
                    if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0
                        && ws.ws_col > 0
                        && ws.ws_row > 0
                    {
                        return (usize::from(ws.ws_col), usize::from(ws.ws_row));
                    }
                }
            }
        }
    }
    let cols = env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&c| c > 0)
        .unwrap_or(fallback_cols);
    let rows = env::var("LINES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&r| r > 0)
        .unwrap_or(fallback_rows);
    (cols, rows)
}

#[cfg(unix)]
fn discover_launcher_resize_sock() -> Option<std::path::PathBuf> {
    if let Ok(sock) = env::var("VPNGATE_RESIZE_SOCK") {
        let p = std::path::PathBuf::from(sock.trim());
        if p.exists() {
            return Some(p);
        }
    }
    // Fallback across `sudo`: inspect controlling TTY marker in `<user_home>/.cache/vpngate/ui_socks/`
    unsafe {
        let ptr = libc::ttyname(libc::STDOUT_FILENO);
        if ptr.is_null() {
            return None;
        }
        let tty_str = std::ffi::CStr::from_ptr(ptr).to_string_lossy();
        let key = tty_str.trim_start_matches('/').replace('/', "_");
        let marker = vpngate_core::AppPaths::resolve()
            .cache_dir
            .join("ui_socks")
            .join(format!("{key}.json"));
        let raw = std::fs::read_to_string(marker).ok()?;
        let val: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let sock_str = val.get("sock")?.as_str()?;
        let p = std::path::PathBuf::from(sock_str);
        p.exists().then_some(p)
    }
}

pub fn request_window_resize(needed_cols: usize, needed_rows: usize) {
    // Match Python v5.3: never emit CSI `8;r;ct` resize sequences on Windows 11 PowerShell / conhost
    // (prevents literal escape sequences and scrollbar/viewport jumping; boxes/tables fit to `CONOUT$`).
    if cfg!(windows) || !dynamic_resize_enabled() || !is_stdout_tty() {
        return;
    }
    let (cur_c, cur_r) = get_live_terminal_size(100, 30);
    let target_c = cur_c.max(needed_cols).min(170);
    let target_r = cur_r.max(needed_rows).min(50);

    #[cfg(unix)]
    if let Some(sock_path) = discover_launcher_resize_sock()
        && let Ok(dgram) = std::os::unix::net::UnixDatagram::unbound()
    {
        let payload = format!(r#"{{"cols":{target_c},"rows":{target_r}}}"#);
        let _ = dgram.send_to(payload.as_bytes(), sock_path);
    }

    if target_c > cur_c || target_r > cur_r {
        let _ = write!(io::stdout(), "\x1b[8;{target_r};{target_c}t");
        let _ = io::stdout().flush();
    }
}

pub fn clear_screen_if_tty() {
    clear_transient_line();
    if !screen_clear_enabled() || !is_stdout_tty() {
        return;
    }
    #[cfg(windows)]
    {
        if ensure_windows_vt_mode() {
            let _ = write!(io::stdout(), "\x1b[2J\x1b[H");
            let _ = io::stdout().flush();
        } else {
            win_console::clear_console_buffer();
        }
    }
    #[cfg(not(windows))]
    {
        let _ = write!(io::stdout(), "\x1b[2J\x1b[3J\x1b[H");
        let _ = io::stdout().flush();
    }
}

pub fn render_dynamic_box(
    lines: &[Option<String>],
    extra_rows_below: usize,
    min_inner: usize,
) -> io::Result<()> {
    clear_transient_line();
    let _ = ensure_windows_vt_mode();

    let cleaned_lines: Vec<Option<String>> = lines
        .iter()
        .map(|opt| opt.as_deref().map(win_clean_text))
        .collect();

    let mut natural_inner = min_inner;
    for l in cleaned_lines.iter().flatten() {
        natural_inner = natural_inner.max(visible_len(l));
    }
    request_window_resize(natural_inner + 6, cleaned_lines.len() + 2 + extra_rows_below);

    let (term_cols, _) = get_live_terminal_size(natural_inner + 6, 30);
    let mut inner_w = natural_inner;
    if is_stdout_tty() && term_cols > 16 {
        // Total box width is `inner_w + 4`; keep >= 2 cols margin on Windows (`inner_w <= term_cols - 6`)
        // so `ENABLE_WRAP_AT_EOL_OUTPUT` never double-wraps right-hand borders.
        let margin = if cfg!(windows) { 6 } else { 4 };
        inner_w = natural_inner.min(term_cols.saturating_sub(margin).max(36));
    }

    let (tl, tr, bl, br, hz, vt, ml, mr) = if supports_utf8() {
        ("╭", "╮", "╰", "╯", "─", "│", "├", "┤")
    } else {
        ("+", "+", "+", "+", "-", "|", "+", "+")
    };

    let use_ansi = ansi_stdout_enabled();
    let horiz = hz.repeat(inner_w + 2);
    let mut buf = String::new();
    buf.push('\n');
    let top = format!("{BOLD}{tl}{horiz}{tr}{RESET}");
    buf.push_str(&if use_ansi { top } else { strip_ansi(&top) });
    buf.push('\n');

    for item in &cleaned_lines {
        let row_line = match item {
            None => format!("{BOLD}{ml}{horiz}{mr}{RESET}"),
            Some(txt) => format!("{BOLD}{vt}{RESET} {} {BOLD}{vt}{RESET}", fit_ansi_line(txt, inner_w)),
        };
        buf.push_str(&if use_ansi {
            row_line
        } else {
            strip_ansi(&row_line)
        });
        buf.push('\n');
    }

    let bot = format!("{BOLD}{bl}{horiz}{br}{RESET}");
    buf.push_str(&if use_ansi { bot } else { strip_ansi(&bot) });
    buf.push('\n');

    let mut stdout = io::stdout().lock();
    stdout.write_all(buf.as_bytes())?;
    stdout.flush()
}

pub fn render_dynamic_table(
    headers: &[&str],
    rows: &[Vec<String>],
    aligns: &[Align],
    flex_cols: &HashMap<usize, usize>,
    col_colors: &HashMap<usize, &str>,
    footer_lines: &[String],
    extra_rows_below: usize,
) -> io::Result<()> {
    clear_transient_line();
    let _ = ensure_windows_vt_mode();

    let clean_headers: Vec<String> = headers.iter().map(|h| win_clean_text(h)).collect();
    let clean_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|cell| win_clean_text(cell)).collect())
        .collect();
    let clean_footers: Vec<String> = footer_lines.iter().map(|fl| win_clean_text(fl)).collect();

    let ncols = clean_headers.len();
    let mut widths: Vec<usize> = (0..ncols)
        .map(|c| {
            clean_rows
                .iter()
                .map(|r| visible_len(&r[c]))
                .max()
                .unwrap_or(0)
                .max(visible_len(&clean_headers[c]))
        })
        .collect();

    let mut gap = 2usize;
    let natural_width: usize = widths.iter().sum::<usize>() + gap * ncols.saturating_sub(1);
    request_window_resize(
        natural_width + 2,
        clean_rows.len() + clean_footers.len() + 6 + extra_rows_below,
    );

    let (term_cols, _) = get_live_terminal_size(natural_width + 2, 30);
    let avail_cols = if cfg!(windows) && term_cols > 24 {
        term_cols - 2
    } else {
        term_cols
    };

    if is_stdout_tty() && avail_cols > 20 && natural_width > avail_cols {
        gap = 1;
        let cur_total = widths.iter().sum::<usize>() + gap * ncols.saturating_sub(1);
        if cur_total > avail_cols {
            let mut overflow = cur_total - avail_cols;
            while overflow > 0 {
                let candidate = flex_cols
                    .iter()
                    .filter(|&(&c, &min_w)| widths[c] > min_w)
                    .map(|(&c, _)| c)
                    .max_by_key(|&c| widths[c])
                    .or_else(|| {
                        (0..ncols)
                            .filter(|&c| widths[c] > 4)
                            .max_by_key(|&c| widths[c])
                    });
                let Some(widest) = candidate else {
                    break;
                };
                widths[widest] -= 1;
                overflow -= 1;
            }
        }
    }

    let sep_char = if supports_utf8() { "─" } else { "-" };
    let table_width = widths.iter().sum::<usize>() + gap * ncols.saturating_sub(1);
    let sep_width = if is_stdout_tty() && avail_cols > 20 {
        table_width.min(avail_cols)
    } else {
        table_width
    };
    let gap_str = " ".repeat(gap);
    let use_ansi = ansi_stdout_enabled();

    let mut buf = String::new();
    let hdr_cells: Vec<String> = (0..ncols)
        .map(|c| pad_plain(&clean_headers[c], widths[c], aligns[c]))
        .collect();
    let hdr_line = format!("\n{BOLD}{}{RESET}", hdr_cells.join(&gap_str));
    buf.push_str(&if use_ansi {
        hdr_line
    } else {
        strip_ansi(&hdr_line)
    });
    buf.push('\n');

    let sep_line = format!("{DIM}{}{RESET}", sep_char.repeat(sep_width));
    let sep_rendered = if use_ansi {
        sep_line
    } else {
        strip_ansi(&sep_line)
    };
    buf.push_str(&sep_rendered);
    buf.push('\n');

    for r in &clean_rows {
        let cells: Vec<String> = (0..ncols)
            .map(|c| {
                let cell = pad_plain(&r[c], widths[c], aligns[c]);
                if use_ansi && let Some(&col) = col_colors.get(&c) {
                    format!("{col}{cell}{RESET}")
                } else {
                    cell
                }
            })
            .collect();
        buf.push_str(&cells.join(&gap_str));
        buf.push('\n');
    }

    buf.push_str(&sep_rendered);
    buf.push('\n');
    for fl in &clean_footers {
        buf.push_str(&if use_ansi {
            fl.clone()
        } else {
            strip_ansi(fl)
        });
        buf.push('\n');
    }
    buf.push('\n');

    let mut stdout = io::stdout().lock();
    stdout.write_all(buf.as_bytes())?;
    stdout.flush()
}

pub fn prompt_input(prompt: &str) -> Option<String> {
    clear_transient_line();
    let _ = ensure_windows_vt_mode();
    let rendered = format_for_stdout(prompt);
    print!("{rendered}");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    match io::stdin().read_line(&mut buf) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(buf.trim().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_visible_len_and_fits_ansi() {
        let styled = format!("{GREEN}{BOLD}● ACTIVE{RESET} -> JP");
        assert_eq!(visible_len(&styled), 14);
        let padded = fit_ansi_line(&styled, 20);
        assert_eq!(visible_len(&padded), 20);
        let trunc = fit_ansi_line(&styled, 10);
        assert_eq!(visible_len(&trunc), 10);
    }

    #[test]
    fn cleans_east_asian_ambiguous_glyphs_for_windows() {
        let raw = "● ACTIVE · JP — Tokyo ○ Standby ↻ Retry…\tOK\r";
        let win = win_clean_text_for_platform(raw, true);
        assert_eq!(win, "* ACTIVE | JP - Tokyo o Standby ~ Retry.  OK");
        assert!(win.is_ascii());
    }

    #[test]
    fn handles_combining_and_cjk_widths() {
        assert_eq!(visible_len("日本"), 4);
        assert_eq!(visible_len("e\u{0301}"), 1);
    }

    #[test]
    fn formats_durations_cleanly() {
        assert_eq!(format_duration(65), "01:05");
        assert_eq!(format_duration(3661), "01:01:01");
    }
}
