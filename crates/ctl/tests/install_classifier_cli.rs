use std::process::Command;

#[test]
fn install_classifier_dry_run_goes_through_cli_dispatch() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let sensor = tmp.path().join("config.toml");
    let agent = tmp.path().join("agent.toml");
    std::fs::write(&sensor, "").expect("write sensor config");
    std::fs::write(&agent, "").expect("write agent config");

    let output = Command::new(env!("CARGO_BIN_EXE_innerwarden-ctl"))
        .arg("--dry-run")
        .arg("--sensor-config")
        .arg(&sensor)
        .arg("--agent-config")
        .arg(&agent)
        .arg("--data-dir")
        .arg(tmp.path())
        .arg("install-classifier")
        .arg("--model")
        .arg("minilm-l6")
        .arg("--sha256")
        .arg("deadbeef")
        .arg("--yes")
        .output()
        .expect("run innerwarden-ctl");

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("[dry-run] would download"),
        "unexpected stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
