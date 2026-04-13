//! Welcome screen — displayed after installation.

use std::env;
use std::io::{self, IsTerminal, Write};
use std::process::Command;

/// Wide ASCII logo for larger terminals.
const LOGO_WIDE: &[&str] = &[
    "  III  N   N N   N EEEEE RRRR   W   W  A   RRRR  DDDD  EEEEE N   N",
    "   I   NN  N NN  N E     R   R  W   W A A  R   R D   D E     NN  N",
    "   I   N N N N N N EEEE  RRRR   W W W AAA  RRRR  D   D EEEE  N N N",
    "   I   N  NN N  NN E     R  R   WW WW A A  R  R  D   D E     N  NN",
    "  III  N   N N   N EEEEE R   R   W W  A A  R   R DDDD  EEEEE N   N",
];

fn parse_env_size(key: &str) -> Option<usize> {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn terminal_size(is_tty: bool) -> (usize, usize) {
    if let (Some(cols), Some(rows)) = (parse_env_size("COLUMNS"), parse_env_size("LINES")) {
        return (cols, rows);
    }

    if is_tty {
        if let Ok(output) = Command::new("stty").arg("size").output() {
            if output.status.success() {
                let size_text = String::from_utf8_lossy(&output.stdout);
                let mut parts = size_text.split_whitespace();
                if let (Some(rows), Some(cols)) = (parts.next(), parts.next()) {
                    if let (Ok(rows), Ok(cols)) = (rows.parse::<usize>(), cols.parse::<usize>()) {
                        if cols > 0 && rows > 0 {
                            return (cols, rows);
                        }
                    }
                }
            }
        }
    }

    (80, 24)
}

fn centered_line(line: &str, cols: usize) -> String {
    let width = line.chars().count();
    let pad = cols.saturating_sub(width) / 2;
    format!("{}{}", " ".repeat(pad), line)
}

fn box_lines(lines: Vec<String>, cols: usize) -> Vec<String> {
    let inner_width = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let boxed_width = inner_width + 4;

    if boxed_width > cols {
        return lines;
    }

    let border = format!("+{}+", "-".repeat(inner_width + 2));
    let mut out = Vec::with_capacity(lines.len() + 2);
    out.push(border.clone());
    for line in lines {
        out.push(format!("| {:<width$} |", line, width = inner_width));
    }
    out.push(border);
    out
}

fn build_screen(cols: usize, ebpf_hooks: u32) -> Vec<String> {
    let mut lines = Vec::new();

    let logo_width = LOGO_WIDE
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    if cols >= logo_width + 4 {
        lines.extend(LOGO_WIDE.iter().map(|line| (*line).to_string()));
    } else {
        lines.push("INNERWARDEN".to_string());
    }

    lines.push(String::new());

    let hook_line = if ebpf_hooks > 0 {
        format!("Kernel hooks active: {ebpf_hooks}")
    } else {
        "Kernel hooks: initializing".to_string()
    };

    lines.extend(box_lines(
        vec![
            "Installed successfully".to_string(),
            "Observe-only mode is ON by default".to_string(),
            "Run: innerwarden setup".to_string(),
            hook_line,
        ],
        cols,
    ));

    lines
}

/// Show centered welcome screen in the active terminal.
pub fn run_welcome(ebpf_hooks: u32) {
    let mut out = io::stdout();
    let is_tty = out.is_terminal();

    if !is_tty {
        println!("InnerWarden installed");
        let _ = out.flush();
        return;
    }

    let (cols, rows) = terminal_size(is_tty);
    let lines = build_screen(cols, ebpf_hooks);
    let top_padding = rows.saturating_sub(lines.len() + 1) / 2;

    let _ = write!(out, "\x1b[2J\x1b[H");
    for _ in 0..top_padding {
        let _ = writeln!(out);
    }
    for line in lines {
        let _ = writeln!(out, "{}", centered_line(&line, cols));
    }
    let _ = writeln!(out);
    let _ = out.flush();
}
