//! Welcome screen — displayed after installation.

use std::env;
use std::io::{self, IsTerminal, Write};
use std::process::Command;

const INFO_BOX_OFFSET: usize = 4;

/// Compact double-sword logo with brand text between blades.
const LOGO_WIDE: &[&str] = &[
    "      .-.                       .-.",
    "     {{@}}                     {{@}}",
    "      8@8                       8@8",
    "      888      INNER WARDEN     888",
    "      8@8                       8@8",
    "     _    )8(    _             _    )8(    _",
    "      (@)__/8@8\\__(@)           (@)__/8@8\\__(@)",
    "     ~-=):(=-~                 ~-=):(=-~",
    "      |.|                       |.|",
    "      |.|                       |.|",
    "      |.|                       |.|",
    "      \\ /                       \\ /",
    "     ^                         ^",
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

    if cols >= boxed_width + INFO_BOX_OFFSET {
        let prefix = " ".repeat(INFO_BOX_OFFSET);
        out.into_iter()
            .map(|line| format!("{prefix}{line}"))
            .collect()
    } else {
        out
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centered_line_centers_text() {
        let result = centered_line("hello", 20);
        // "hello" has 5 chars, padding = (20-5)/2 = 7
        assert!(result.starts_with("       hello"));
    }

    #[test]
    fn centered_line_no_overflow() {
        // Line wider than cols should get 0 padding
        let result = centered_line("long text here", 5);
        assert_eq!(result, "long text here");
    }

    #[test]
    fn box_lines_wraps_content() {
        let lines = vec!["hello".to_string(), "world".to_string()];
        let boxed = box_lines(lines, 80);
        // Should have border lines (top + bottom) + 2 content lines
        assert!(boxed.len() >= 4);
        // Borders contain + and -
        assert!(boxed.first().unwrap().contains('+'));
        assert!(boxed.last().unwrap().contains('+'));
    }

    #[test]
    fn box_lines_skips_if_too_narrow() {
        let lines = vec!["a very long line that exceeds the terminal width".to_string()];
        let boxed = box_lines(lines.clone(), 10);
        // Should return original lines when boxed_width > cols
        assert_eq!(boxed.len(), 1);
    }

    #[test]
    fn build_screen_has_content() {
        let screen = build_screen(80, 5);
        assert!(!screen.is_empty());
        let joined = screen.join("\n");
        assert!(joined.contains("Kernel hooks active: 5"));
    }

    #[test]
    fn build_screen_narrow_terminal() {
        let screen = build_screen(20, 0);
        let joined = screen.join("\n");
        // Should use compact header
        assert!(joined.contains("INNERWARDEN"));
    }
}
