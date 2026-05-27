use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn cmd_rule_list_all(sensor_config: &Path, type_filter: Option<&str>) -> Result<()> {
    let rules_base = PathBuf::from("/etc/innerwarden/rules");

    let types: Vec<(&str, &str)> = vec![
        ("event_pipeline", "Event Pipeline"),
        ("sigma", "Sigma"),
        ("yara", "YARA"),
        ("atr", "ATR"),
    ];

    let mut total = 0u32;
    for (subdir, label) in &types {
        if let Some(filter) = type_filter {
            if filter != *subdir {
                continue;
            }
        }

        let dir = rules_base.join(subdir);
        if *subdir == "event_pipeline" {
            let ep_dir = resolve_rules_dir(Path::new("/var/lib/innerwarden"), sensor_config);
            let (rules, errors) = load_all_rules(&ep_dir);
            if !rules.is_empty() || !errors.is_empty() {
                println!("{label} ({} rules, {} errors):", rules.len(), errors.len());
                let header = format!(
                    "  {:<40} {:<10} {:<12} {:<8} {}",
                    "RULE ID", "PRIORITY", "ACTION", "STATUS", "SOURCE"
                );
                println!("{header}");
                for rule in &rules {
                    let status = if rule.disabled {
                        "disabled"
                    } else if rule.expired {
                        "expired"
                    } else {
                        "active"
                    };
                    println!(
                        "  {:<40} {:<10} {:<12} {:<8} {}",
                        rule.id, rule.priority, rule.action, status, rule.source_file
                    );
                }
                total += rules.len() as u32;
                println!();
            }
        } else if dir.is_dir() {
            let count = count_yaml_rules(&dir, subdir);
            if count > 0 {
                println!("{label} ({count} rules):");
                list_generic_rules(&dir, subdir);
                total += count;
                println!();
            }
        }
    }

    if total == 0 && type_filter.is_none() {
        println!("No rules found.");
    }

    println!("Rules directory: {}", rules_base.display());
    Ok(())
}

fn count_yaml_rules(dir: &Path, _rule_type: &str) -> u32 {
    let mut count = 0u32;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if (name.ends_with(".yml") || name.ends_with(".yaml"))
            && entry.file_type().is_ok_and(|t| t.is_file())
        {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                let doc: Result<serde_yaml::Value, _> = serde_yaml::from_str(&content);
                if let Ok(doc) = doc {
                    if let Some(rules) = doc.get("rules").and_then(|v| v.as_sequence()) {
                        count += rules.len() as u32;
                    } else if doc.get("title").is_some() {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

fn list_generic_rules(dir: &Path, rule_type: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<_> = entries.flatten().collect();
    files.sort_by_key(|e| e.file_name());

    for entry in files {
        let name = entry.file_name().to_string_lossy().to_string();
        if (!name.ends_with(".yml") && !name.ends_with(".yaml"))
            || !entry.file_type().is_ok_and(|t| t.is_file())
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
            println!("  {name}: parse error");
            continue;
        };

        if rule_type == "atr" {
            let id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("(no id)");
            let title = doc
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("(no title)");
            let status = doc
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("  {:<25} {:<12} {}", id, status, title);
        } else {
            // sigma / yara: title + id + level
            let id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("(no id)");
            let title = doc.get("title").and_then(|v| v.as_str()).unwrap_or(&name);
            let level = doc.get("level").and_then(|v| v.as_str()).unwrap_or("info");
            println!("  {:<40} {:<8} {}", &id[..id.len().min(38)], level, title);
        }
    }
}

#[allow(dead_code)]
pub fn cmd_rule_list(data_dir: &Path, sensor_config: &Path) -> Result<()> {
    let rules_dir = resolve_rules_dir(data_dir, sensor_config);
    let (rules, errors) = load_all_rules(&rules_dir);

    if rules.is_empty() && errors.is_empty() {
        println!("No event pipeline rules loaded.");
        println!(
            "  Rules directory: {} (does not exist)",
            rules_dir.display()
        );
        println!("  Built-in packs are embedded in the sensor binary and active by default.");
        return Ok(());
    }

    println!(
        "Event pipeline rules ({} active, {} errors):\n",
        rules.len(),
        errors.len()
    );
    let header = format!(
        "  {:<40} {:<10} {:<12} {:<8} {}",
        "RULE ID", "PRIORITY", "ACTION", "STATUS", "SOURCE"
    );
    println!("{header}");
    println!("  {}", "-".repeat(90));

    for rule in &rules {
        let status = if rule.disabled {
            "disabled"
        } else if rule.expired {
            "expired"
        } else {
            "active"
        };
        println!(
            "  {:<40} {:<10} {:<12} {:<8} {}",
            rule.id, rule.priority, rule.action, status, rule.source_file
        );
    }

    if !errors.is_empty() {
        println!("\nErrors:");
        for (file, err) in &errors {
            println!("  {file}: {err}");
        }
    }

    println!("\nRules directory: {}", rules_dir.display());
    println!("Add .yml files to this directory. The sensor hot-reloads every 60s.");

    Ok(())
}

pub fn cmd_rule_disable(data_dir: &Path, sensor_config: &Path, rule_id: &str) -> Result<()> {
    let rules_dir = resolve_rules_dir(data_dir, sensor_config);
    toggle_rule(&rules_dir, rule_id, true)
}

pub fn cmd_rule_enable(data_dir: &Path, sensor_config: &Path, rule_id: &str) -> Result<()> {
    let rules_dir = resolve_rules_dir(data_dir, sensor_config);
    toggle_rule(&rules_dir, rule_id, false)
}

fn toggle_rule(rules_dir: &Path, rule_id: &str, disable: bool) -> Result<()> {
    let verb = if disable { "disable" } else { "enable" };

    if !rules_dir.is_dir() {
        anyhow::bail!(
            "rules directory does not exist: {}. \
             Built-in rules can only be overridden by placing a file in this directory.",
            rules_dir.display()
        );
    }

    let mut found = false;
    for entry in std::fs::read_dir(rules_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }
        if !entry.file_type()?.is_file() {
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;

        if !content.contains(&format!("id: {rule_id}"))
            && !content.contains(&format!("id: \"{rule_id}\""))
        {
            continue;
        }

        found = true;
        let new_content = if disable {
            ensure_disabled(&content, rule_id)
        } else {
            remove_disabled(&content, rule_id)
        };

        if new_content == content {
            println!("Rule '{rule_id}' is already {verb}d in {name}.");
        } else {
            std::fs::write(&path, &new_content)
                .with_context(|| format!("writing {}", path.display()))?;
            println!("Rule '{rule_id}' {verb}d in {name}. Sensor will hot-reload within 60s.");
        }
        break;
    }

    if !found {
        println!("Rule '{rule_id}' not found in on-disk files.");
        println!("If this is a built-in rule, create an override file:");
        println!();
        println!("  cat > {}/10-override.yml << 'EOF'", rules_dir.display());
        println!("  version: 1");
        println!("  rules:");
        println!("    - id: {rule_id}");
        println!("      match:");
        println!("        source: ebpf");
        println!("      action: drop");
        if disable {
            println!("      disabled: true");
        }
        println!("  EOF");
    }

    Ok(())
}

fn ensure_disabled(content: &str, rule_id: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].contains(&format!("id: {rule_id}"))
            || lines[i].contains(&format!("id: \"{rule_id}\""))
        {
            // The `- id:` line has indent like "    - id: ...".
            // Sibling fields (priority, match, disabled) align with "id:",
            // which is 2 characters past the "- ". Use the next non-empty
            // line's indent, or fall back to id_column position.
            let id_col = lines[i].find("id:").unwrap_or(0);
            let field_indent = if let Some(next) = lines[i + 1..]
                .iter()
                .take(5)
                .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            {
                " ".repeat(next.len() - next.trim_start().len())
            } else {
                " ".repeat(id_col)
            };

            let already_disabled = lines[i + 1..]
                .iter()
                .take(10)
                .take_while(|l| !l.trim_start().starts_with("- id:"))
                .any(|l| l.trim() == "disabled: true");
            if !already_disabled {
                lines.insert(i + 1, format!("{field_indent}disabled: true"));
            }
            break;
        }
        i += 1;
    }
    lines.join("\n") + "\n"
}

fn remove_disabled(content: &str, rule_id: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut in_target_rule = false;
    let mut rule_indent = 0;

    for line in &lines {
        if line.contains(&format!("id: {rule_id}")) || line.contains(&format!("id: \"{rule_id}\""))
        {
            in_target_rule = true;
            rule_indent = line.len() - line.trim_start().len();
        } else if in_target_rule && line.trim_start().starts_with("- id:") {
            in_target_rule = false;
        }

        if in_target_rule && line.trim() == "disabled: true" {
            let line_indent = line.len() - line.trim_start().len();
            if line_indent >= rule_indent {
                continue;
            }
        }
        result.push(*line);
    }

    result.join("\n") + "\n"
}

struct RuleInfo {
    id: String,
    priority: u32,
    action: String,
    disabled: bool,
    expired: bool,
    source_file: String,
}

fn load_all_rules(rules_dir: &Path) -> (Vec<RuleInfo>, Vec<(String, String)>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let mut seen_ids: HashMap<String, usize> = HashMap::new();

    for (name, yaml) in innerwarden_sensor::event_pipeline_builtin_packs() {
        match parse_rules_from_yaml(yaml, name) {
            Ok(mut file_rules) => {
                for rule in &mut file_rules {
                    rule.source_file = format!("{name} (built-in)");
                }
                for rule in file_rules {
                    let idx = rules.len();
                    seen_ids.insert(rule.id.clone(), idx);
                    rules.push(rule);
                }
            }
            Err(e) => errors.push((name.to_string(), e)),
        }
    }

    if rules_dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(rules_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                (name.ends_with(".yml") || name.ends_with(".yaml"))
                    && e.file_type().is_ok_and(|t| t.is_file())
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            match std::fs::read_to_string(&path) {
                Ok(yaml) => match parse_rules_from_yaml(&yaml, &name) {
                    Ok(file_rules) => {
                        for rule in file_rules {
                            if let Some(&idx) = seen_ids.get(&rule.id) {
                                rules[idx] = rule;
                            } else {
                                let idx = rules.len();
                                seen_ids.insert(rule.id.clone(), idx);
                                rules.push(rule);
                            }
                        }
                    }
                    Err(e) => errors.push((name, e)),
                },
                Err(e) => errors.push((name, e.to_string())),
            }
        }
    }

    rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    (rules, errors)
}

fn parse_rules_from_yaml(yaml: &str, source: &str) -> Result<Vec<RuleInfo>, String> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|e| format!("YAML parse error: {e}"))?;

    let version = doc.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != 1 {
        return Err(format!("unsupported version {version}"));
    }

    let rules_val = doc
        .get("rules")
        .and_then(|v| v.as_sequence())
        .ok_or("missing 'rules' array")?;

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let mut rules = Vec::new();

    for rule_val in rules_val {
        let id = rule_val
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string();
        let priority = rule_val
            .get("priority")
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as u32;
        let action = rule_val
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("emit")
            .to_string();
        let disabled = rule_val
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let expired = rule_val
            .get("expires_at")
            .and_then(|v| v.as_str())
            .is_some_and(|exp| exp <= today.as_str());

        rules.push(RuleInfo {
            id,
            priority,
            action,
            disabled,
            expired,
            source_file: source.to_string(),
        });
    }

    Ok(rules)
}

pub fn cmd_migrate_allowlist(allowlist_path: &Path, output: Option<&Path>) -> Result<()> {
    let content = std::fs::read_to_string(allowlist_path)
        .with_context(|| format!("reading {}", allowlist_path.display()))?;

    let yaml = convert_allowlist_to_pipeline_yaml(&content);

    if let Some(out_path) = output {
        std::fs::write(out_path, &yaml)
            .with_context(|| format!("writing {}", out_path.display()))?;
        println!("Pipeline rule written to {}", out_path.display());
        println!("Move it to your rules/event_pipeline/ directory to activate.");
    } else {
        print!("{yaml}");
    }

    Ok(())
}

fn convert_allowlist_to_pipeline_yaml(content: &str) -> String {
    let mut processes: Vec<String> = Vec::new();
    let mut ips: Vec<String> = Vec::new();
    let mut ports: Vec<u16> = Vec::new();
    let mut per_detector: HashMap<String, Vec<String>> = HashMap::new();

    let mut section = String::new();
    let mut detector_section: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_string();
            detector_section = if section.starts_with("detectors.") {
                Some(section.strip_prefix("detectors.").unwrap().to_string())
            } else {
                None
            };
            continue;
        }
        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim().trim_matches('"');
            match section.as_str() {
                "processes" => {
                    if !processes.contains(&key.to_string()) {
                        processes.push(key.to_string());
                    }
                }
                "ips" => {
                    if !ips.contains(&key.to_string()) {
                        ips.push(key.to_string());
                    }
                }
                "ports" => {
                    let val = line.split_once('=').unwrap().1;
                    for part in val.trim().split(',') {
                        if let Ok(port) = part.trim().parse::<u16>() {
                            if !ports.contains(&port) {
                                ports.push(port);
                            }
                        }
                    }
                }
                _ => {
                    if let Some(ref det) = detector_section {
                        per_detector
                            .entry(det.clone())
                            .or_default()
                            .push(key.to_string());
                    }
                }
            }
        }
    }

    let mut yaml = String::new();
    yaml.push_str("# Auto-generated from allowlist.toml by `innerwarden rule migrate-allowlist`\n");
    yaml.push_str(&format!(
        "# Generated: {}\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));
    yaml.push_str("#\n");
    yaml.push_str("# Review before activating. Process entries become drop rules;\n");
    yaml.push_str("# per-detector entries become suppress_incident rules.\n\n");
    yaml.push_str("version: 1\n");
    yaml.push_str("metadata:\n");
    yaml.push_str("  description: >-\n");
    yaml.push_str("    Migrated from /etc/innerwarden/allowlist.toml. Process and IP\n");
    yaml.push_str("    allowlist entries converted to event pipeline drop rules.\n\n");
    yaml.push_str("rules:\n");

    if !processes.is_empty() {
        yaml.push_str("  - id: migrated-process-allowlist\n");
        yaml.push_str("    priority: 85\n");
        yaml.push_str("    match:\n");
        yaml.push_str("      source: ebpf\n");
        yaml.push_str("      kind_in:\n");
        yaml.push_str("        - file.read_access\n");
        yaml.push_str("        - file.write_access\n");
        yaml.push_str("      comm_in:\n");
        for p in &processes {
            yaml.push_str(&format!("        - \"{p}\"\n"));
        }
        yaml.push_str("    action: drop\n");
        yaml.push_str("    drop_reason: migrated-process-allowlist\n\n");
    }

    if !ips.is_empty() {
        yaml.push_str("  # NOTE: IP-based filtering is not yet supported in the event\n");
        yaml.push_str("  # pipeline DSL. These IPs remain in allowlist.toml for now.\n");
        yaml.push_str("  # IPs from allowlist.toml:\n");
        for ip in &ips {
            yaml.push_str(&format!("  #   - {ip}\n"));
        }
        yaml.push('\n');
    }

    if !ports.is_empty() {
        yaml.push_str("  # NOTE: Ignored ports remain in allowlist.toml for now.\n");
        yaml.push_str(&format!("  # Ports: {:?}\n\n", ports));
    }

    if !per_detector.is_empty() {
        let mut detectors: Vec<_> = per_detector.iter().collect();
        detectors.sort_by_key(|(k, _)| (*k).clone());
        for (det, entries) in detectors {
            let rule_id = format!("migrated-suppress-{det}");
            yaml.push_str(&format!("  - id: {rule_id}\n"));
            yaml.push_str("    action: suppress_incident\n");
            yaml.push_str("    suppress:\n");
            yaml.push_str(&format!("      detector: {det}\n"));
            yaml.push_str("      values:\n");
            for entry in entries {
                yaml.push_str(&format!("        - \"{entry}\"\n"));
            }
            yaml.push('\n');
        }
    }

    yaml
}

fn resolve_rules_dir(data_dir: &Path, sensor_config: &Path) -> PathBuf {
    if let Ok(content) = std::fs::read_to_string(sensor_config) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("rules_dir") {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if !val.is_empty() {
                        let p = Path::new(val);
                        if p.is_absolute() {
                            return p.to_path_buf();
                        }
                        return data_dir.join(val);
                    }
                }
            }
        }
    }
    PathBuf::from("/etc/innerwarden/rules/event_pipeline")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rules_dir_default() {
        let dir = resolve_rules_dir(
            Path::new("/var/lib/innerwarden"),
            Path::new("/nonexistent/config.toml"),
        );
        assert_eq!(dir, PathBuf::from("/etc/innerwarden/rules/event_pipeline"));
    }

    #[test]
    fn parse_builtin_packs() {
        for (name, yaml) in innerwarden_sensor::event_pipeline_builtin_packs() {
            let rules = parse_rules_from_yaml(yaml, name);
            assert!(
                rules.is_ok(),
                "built-in pack {name} failed: {:?}",
                rules.err()
            );
            assert!(!rules.unwrap().is_empty(), "{name} has no rules");
        }
    }

    #[test]
    fn load_all_rules_includes_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let (rules, errors) = load_all_rules(dir.path());
        assert!(rules.len() >= 5, "expected >= 5 built-in rules");
        assert!(errors.is_empty());
    }

    #[test]
    fn load_all_rules_on_disk_overrides_builtin() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: drop-innerwarden-self-reads
    match:
      source: ebpf
    action: drop
    disabled: true
"#;
        std::fs::write(dir.path().join("01-override.yml"), yaml).unwrap();
        let (rules, _) = load_all_rules(dir.path());
        let overridden = rules
            .iter()
            .find(|r| r.id == "drop-innerwarden-self-reads")
            .unwrap();
        assert!(overridden.disabled);
        assert_eq!(overridden.source_file, "01-override.yml");
    }

    #[test]
    fn ensure_disabled_adds_flag() {
        let content =
            "  - id: my-rule\n    priority: 50\n    match:\n      source: ebpf\n    action: drop\n";
        let result = ensure_disabled(content, "my-rule");
        assert!(result.contains("disabled: true"));
        assert!(
            result.contains("    disabled: true"),
            "disabled should align with priority (4-space indent), got:\n{result}"
        );
    }

    #[test]
    fn ensure_disabled_produces_valid_yaml() {
        let content = "version: 1\nrules:\n  - id: my-rule\n    priority: 50\n    match:\n      source: ebpf\n    action: drop\n";
        let result = ensure_disabled(content, "my-rule");
        let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&result);
        assert!(
            parsed.is_ok(),
            "disabled YAML should still parse, got error: {:?}\n---\n{result}",
            parsed.err()
        );
    }

    #[test]
    fn ensure_disabled_idempotent() {
        let content = "  - id: my-rule\n    disabled: true\n    priority: 50\n";
        let result = ensure_disabled(content, "my-rule");
        assert_eq!(
            result.matches("disabled: true").count(),
            1,
            "should not duplicate disabled flag"
        );
    }

    #[test]
    fn remove_disabled_removes_flag() {
        let content = "  - id: my-rule\n    disabled: true\n    priority: 50\n    action: drop\n";
        let result = remove_disabled(content, "my-rule");
        assert!(!result.contains("disabled: true"));
        assert!(result.contains("id: my-rule"));
    }

    #[test]
    fn toggle_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "version: 1\nrules:\n  - id: test-toggle\n    match:\n      source: ebpf\n    action: drop\n";
        let path = dir.path().join("10-test.yml");
        std::fs::write(&path, yaml).unwrap();

        toggle_rule(dir.path(), "test-toggle", true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("disabled: true"));

        toggle_rule(dir.path(), "test-toggle", false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("disabled: true"));
    }

    #[test]
    fn toggle_nonexistent_rule_prints_hint() {
        let dir = tempfile::tempdir().unwrap();
        let result = toggle_rule(dir.path(), "nonexistent-rule", true);
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_rule_list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = cmd_rule_list(dir.path(), Path::new("/nonexistent"));
        assert!(result.is_ok());
    }

    #[test]
    fn migrate_allowlist_converts_processes() {
        let toml = r#"
[processes]
"brew" = "Linuxbrew"
"narrate.py" = "narrator tool"

[ips]
"172.18.0.0/16" = "Docker internal"

[ports]
ignored = 9, 67

[detectors.kernel_module_load]
"bcache" = "Ubuntu cache module"
"#;
        let yaml = convert_allowlist_to_pipeline_yaml(toml);
        assert!(yaml.contains("id: migrated-process-allowlist"));
        assert!(yaml.contains("brew"));
        assert!(yaml.contains("narrate.py"));
        assert!(yaml.contains("action: drop"));
        assert!(yaml.contains("172.18.0.0/16"));
        assert!(yaml.contains("id: migrated-suppress-kernel_module_load"));
        assert!(yaml.contains("action: suppress_incident"));
        assert!(yaml.contains("detector: kernel_module_load"));
        assert!(yaml.contains("bcache"));
    }

    #[test]
    fn migrate_allowlist_empty_input() {
        let yaml = convert_allowlist_to_pipeline_yaml("");
        assert!(yaml.contains("version: 1"));
        assert!(yaml.contains("rules:"));
        assert!(!yaml.contains("id: migrated"));
    }

    #[test]
    fn migrate_allowlist_roundtrip_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("allowlist.toml");
        let out_path = dir.path().join("20-migrated.yml");

        std::fs::write(&toml_path, "[processes]\n\"nginx\" = \"web server\"\n").unwrap();

        let result = cmd_migrate_allowlist(&toml_path, Some(&out_path));
        assert!(result.is_ok());
        assert!(out_path.exists());

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("nginx"));
        assert!(content.contains("version: 1"));
    }

    #[test]
    fn migrate_allowlist_deduplicates_repeated_sections() {
        let toml = r#"
[processes]
"brew" = "first"

[processes]
"cargo" = "second"
"#;
        let yaml = convert_allowlist_to_pipeline_yaml(toml);
        assert!(yaml.contains("brew"));
        assert!(yaml.contains("cargo"));
        // Should appear in one rule, not two
        assert_eq!(yaml.matches("id: migrated-process-allowlist").count(), 1);
    }
}
