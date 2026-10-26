use std::collections::HashMap;
use std::env;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[1;31m";
pub const GREEN: &str = "\x1b[1;32m";
pub const YELLOW: &str = "\x1b[1;33m";
pub const CYAN: &str = "\x1b[1;36m";

static DYNAMIC_RESIZE_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_dynamic_resize(enabled: bool) {
    DYNAMIC_RESIZE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn dynamic_resize_enabled() -> bool {
    DYNAMIC_RESIZE_ENABLED.load(Ordering::Relaxed)
}

pub fn is_stdout_tty() -> bool {
    io::stdout().is_terminal()
}

pub fn supports_utf8() -> bool {
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(v) = env::var(var)
            && !v.is_empty()
        {
            return v.to_ascii_uppercase().contains("UTF");
        }
    }
    true
}

pub fn info(msg: &str) {
    let _ = writeln!(io::stdout(), "{CYAN}[*]{RESET} {msg}");
}

pub fn ok(msg: &str) {
    let _ = writeln!(io::stdout(), "{GREEN}[+]{RESET} {msg}");
}

pub fn warn(msg: &str) {
    let _ = writeln!(io::stderr(), "{YELLOW}[!]{RESET} {msg}");
}

pub fn err(msg: &str) {
    let _ = writeln!(io::stderr(), "{RED}[x]{RESET} {msg}");
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
    // Basic CJK / fullwidth block check
    if (0x1100..=0x115F).contains(&u)
        || (0x2E80..=0xA4CF).contains(&u)
        || (0xAC00..=0xD7A3).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0xFE10..=0xFE6F).contains(&u)
        || (0xFF00..=0xFF60).contains(&u)
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
    strip_ansi(text).chars().map(char_width).sum()
}

pub fn truncate_plain(text: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if visible_len(text) <= max_width {
        return text.to_string();
    }
    let ellipsis = if supports_utf8() { "…" } else { "." };
    let target = max_width.saturating_sub(1);
    let mut acc = String::new();
    let mut w = 0usize;
    for ch in text.chars() {
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
    let vlen = visible_len(text);
    if vlen <= width {
        return format!("{text}{}", " ".repeat(width - vlen));
    }
    // Truncate visible characters while preserving ANSI sequences
    let ellipsis = if supports_utf8() { "…" } else { "." };
    let target = width.saturating_sub(1);
    let mut out = String::new();
    let mut vis = 0usize;
    let mut chars = text.chars().peekable();
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
    #[cfg(unix)]
    {
        if is_stdout_tty() {
            // SAFETY: zero-initialized `winsize` passed to `TIOCGWINSZ` on stdout fd (1).
            unsafe {
                let mut ws: libc::winsize = std::mem::zeroed();
                if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
                    && ws.ws_col > 0
                    && ws.ws_row > 0
                {
                    return (usize::from(ws.ws_col), usize::from(ws.ws_row));
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
    if !dynamic_resize_enabled() || !is_stdout_tty() {
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
    if is_stdout_tty() {
        let _ = write!(io::stdout(), "\x1b[2J\x1b[H");
        let _ = io::stdout().flush();
    }
}

pub fn render_dynamic_box(
    lines: &[Option<String>],
    extra_rows_below: usize,
    min_inner: usize,
) -> io::Result<()> {
    let mut natural_inner = min_inner;
    for l in lines.iter().flatten() {
        natural_inner = natural_inner.max(visible_len(l));
    }
    request_window_resize(natural_inner + 6, lines.len() + 2 + extra_rows_below);

    let (term_cols, _) = get_live_terminal_size(natural_inner + 6, 30);
    let mut inner_w = natural_inner;
    if is_stdout_tty() && term_cols > 16 {
        let margin = if cfg!(windows) { 6 } else { 4 };
        inner_w = natural_inner.min(term_cols.saturating_sub(margin).max(36));
    }

    let (tl, tr, bl, br, hz, vt, ml, mr) = if supports_utf8() {
        ("╭", "╮", "╰", "╯", "─", "│", "├", "┤")
    } else {
        ("+", "+", "+", "+", "-", "|", "+", "+")
    };

    let mut stdout = io::stdout().lock();
    let horiz = hz.repeat(inner_w + 2);
    writeln!(stdout)?;
    writeln!(stdout, "{BOLD}{tl}{horiz}{tr}{RESET}")?;
    for item in lines {
        match item {
            None => writeln!(stdout, "{BOLD}{ml}{horiz}{mr}{RESET}")?,
            Some(txt) => writeln!(
                stdout,
                "{BOLD}{vt}{RESET} {} {BOLD}{vt}{RESET}",
                fit_ansi_line(txt, inner_w)
            )?,
        }
    }
    writeln!(stdout, "{BOLD}{bl}{horiz}{br}{RESET}")?;
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
    let ncols = headers.len();
    let mut widths: Vec<usize> = (0..ncols)
        .map(|c| {
            rows.iter()
                .map(|r| visible_len(&r[c]))
                .max()
                .unwrap_or(0)
                .max(visible_len(headers[c]))
        })
        .collect();

    let mut gap = 2usize;
    let natural_width: usize = widths.iter().sum::<usize>() + gap * ncols.saturating_sub(1);
    request_window_resize(
        natural_width + 2,
        rows.len() + footer_lines.len() + 6 + extra_rows_below,
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

    let mut stdout = io::stdout().lock();
    let hdr_cells: Vec<String> = (0..ncols)
        .map(|c| pad_plain(headers[c], widths[c], aligns[c]))
        .collect();
    writeln!(stdout, "\n{BOLD}{}{RESET}", hdr_cells.join(&gap_str))?;
    writeln!(stdout, "{DIM}{}{RESET}", sep_char.repeat(sep_width))?;

    for r in rows {
        let cells: Vec<String> = (0..ncols)
            .map(|c| {
                let cell = pad_plain(&r[c], widths[c], aligns[c]);
                if let Some(&col) = col_colors.get(&c) {
                    format!("{col}{cell}{RESET}")
                } else {
                    cell
                }
            })
            .collect();
        writeln!(stdout, "{}", cells.join(&gap_str))?;
    }

    writeln!(stdout, "{DIM}{}{RESET}", sep_char.repeat(sep_width))?;
    for fl in footer_lines {
        writeln!(stdout, "{fl}")?;
    }
    writeln!(stdout)?;
    stdout.flush()
}

pub fn prompt_input(prompt: &str) -> Option<String> {
    print!("{prompt}");
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
    fn formats_durations_cleanly() {
        assert_eq!(format_duration(65), "01:05");
        assert_eq!(format_duration(3661), "01:01:01");
    }
}
