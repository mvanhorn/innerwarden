//! Startup banner for the `innerwarden` CLI.
//!
//! Shown when the binary runs with no arguments. The banner has no operational
//! purpose; it exists so the first run does not feel like talking to a
//! compiler.

use std::io::{IsTerminal, Write};

const BANNER: &str = r#"
   █ █▄░█ █▄░█ █▀▀ █▀█ █░█░█ ▄▀█ █▀█ █▀▄ █▀▀ █▄░█
   █ █░▀█ █░▀█ ██▄ █▀▄ ▀▄▀▄▀ █▀█ █▀▄ █▄▀ ██▄ █░▀█
"#;

const TAGLINES: &[&str] = &[
    "kernel-level. autonomous. no SOC.",
    "your server, with a shorter temper.",
    "detection, triage, response. one daemon.",
    "the guard dog that reads kernel events.",
    "ring -2 to ring 3. one binary.",
    "install once. forget. stay protected.",
];

pub fn render(version: &str, writer: &mut dyn Write) -> std::io::Result<()> {
    let use_color = should_color();
    let dim = if use_color { "\x1b[2m" } else { "" };
    let accent = if use_color { "\x1b[38;5;208m" } else { "" };
    let reset = if use_color { "\x1b[0m" } else { "" };

    writeln!(writer, "{accent}{}{reset}", BANNER.trim_end_matches('\n'))?;
    writeln!(
        writer,
        "      {dim}v{version} · {tag}{reset}",
        tag = pick_tagline(version),
    )?;
    writeln!(writer)?;
    Ok(())
}

fn should_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

fn pick_tagline(seed: &str) -> &'static str {
    if TAGLINES.is_empty() {
        return "";
    }
    let idx = seed
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
        .wrapping_add(seconds_of_day())
        % TAGLINES.len() as u64;
    TAGLINES[idx as usize]
}

fn seconds_of_day() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() % 86_400)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_writes_version_and_banner() {
        let mut buf = Vec::new();
        render("0.12.3", &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("v0.12.3"), "must print version: {out}");
        // Banner uses block glyphs for the stylized "INNER WARDEN" text.
        assert!(out.contains('█'), "must print banner glyphs: {out}");
    }

    #[test]
    fn render_writes_one_of_the_taglines() {
        let mut buf = Vec::new();
        render("0.12.3", &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            TAGLINES.iter().any(|t| out.contains(t)),
            "must print one of the taglines: {out}"
        );
    }

    #[test]
    fn pick_tagline_returns_non_empty_for_valid_input() {
        for seed in ["", "a", "version", "0.12.3"] {
            let t = pick_tagline(seed);
            assert!(!t.is_empty(), "tagline must be non-empty for seed {seed:?}");
        }
    }

    #[test]
    fn render_respects_no_color_env() {
        // The render function itself emits ANSI only when should_color() is
        // true; directly test should_color's NO_COLOR gate via env.
        // Save + restore so the test is hermetic.
        let prior = std::env::var_os("NO_COLOR");
        std::env::set_var("NO_COLOR", "1");
        assert!(!should_color());
        match prior {
            Some(v) => std::env::set_var("NO_COLOR", v),
            None => std::env::remove_var("NO_COLOR"),
        }
    }
}
