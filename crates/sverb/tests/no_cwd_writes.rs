//! Running sverb with `SVERB_HOME` set never writes into the
//! current working directory (the template's `./.data` fallback is gone).

use std::{path::PathBuf, process::Command};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn unique_dir(tag: &str) -> std::io::Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("sverb-t12-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn version_with_sverb_home_creates_nothing_in_cwd() -> TestResult {
    let cwd = unique_dir("cwd")?;
    let home = unique_dir("home")?.join("sverb-home");

    let output = Command::new(env!("CARGO_BIN_EXE_sverb"))
        .arg("--version")
        .current_dir(&cwd)
        .env("SVERB_HOME", &home)
        // Without a home directory the template fell back to `./.data`.
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "sverb --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("SVERB_HOME"), "{stdout}");
    assert!(
        stdout.contains(&home.join("config").display().to_string()),
        "{stdout}"
    );

    let leftovers: Vec<_> = std::fs::read_dir(&cwd)?.collect::<Result<_, _>>()?;
    assert!(
        leftovers.is_empty(),
        "sverb wrote into the working directory: {:?}",
        leftovers.iter().map(|e| e.path()).collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(&cwd);
    let _ = std::fs::remove_dir_all(home.parent().unwrap_or(&home));
    Ok(())
}
