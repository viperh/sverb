//! `unsafe_code = "deny"` is inherited by every crate from `[workspace.lints]`.
//!
//! The level is `deny`, not `forbid` (SPEC §17): the two documented `unsafe`
//! modules lift it with an inner `allow`, which `forbid` would reject. That those
//! tested at the end of this file).
//!
//! trybuild cannot prove this: the project it generates for compile-fail cases
//! does not carry over the crate's `[lints]` table, so an `unsafe` block compiles
//! there. Instead this test builds a throwaway workspace whose `[workspace.lints]`
//! is copied verbatim from the real root manifest, adds a probe crate with
//! `[lints] workspace = true` (exactly what every real crate declares, which is
//! checked too), and asserts that the compile-fail fixture
//! `crates/sverb-core/tests/compile_fail/unsafe_block.rs` is rejected with the
//! `deny(unsafe_code)` diagnostic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, path::PathBuf, process::Command};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read_toml(path: &std::path::Path) -> toml::Table {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .parse()
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Every workspace member opts into the workspace lints.
#[test]
fn every_crate_inherits_workspace_lints() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(workspace_root().join("Cargo.toml"))
        .no_deps()
        .exec()
        .unwrap();
    let mut missing = Vec::new();
    for package in metadata.workspace_packages() {
        let manifest = read_toml(package.manifest_path.as_std_path());
        let inherits = manifest
            .get("lints")
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true);
        if !inherits {
            missing.push(package.name.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "crates without `[lints] workspace = true`: {missing:?}"
    );
}

/// The workspace lints, applied through `[lints] workspace = true`, reject `unsafe`.
/// (`-D unsafe-code`, the `deny` level.)
#[test]
fn unsafe_block_fails_with_forbid_diagnostic() {
    let root = workspace_root();
    let lints = read_toml(&root.join("Cargo.toml"))["workspace"]["lints"].clone();

    let mut workspace = toml::Table::new();
    let mut ws = toml::Table::new();
    ws.insert("resolver".into(), "3".into());
    ws.insert("members".into(), toml::Value::Array(vec!["probe".into()]));
    ws.insert("lints".into(), lints);
    workspace.insert("workspace".into(), ws.into());

    let probe_manifest = r#"[package]
name = "probe"
version = "0.0.0"
edition = "2024"
publish = false

[lints]
workspace = true

[lib]
path = "src/lib.rs"
"#;

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("forbid-unsafe-probe");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("probe/src")).unwrap();
    fs::write(dir.join("Cargo.toml"), toml::to_string(&workspace).unwrap()).unwrap();
    fs::write(dir.join("probe/Cargo.toml"), probe_manifest).unwrap();
    fs::copy(
        root.join("crates/sverb-core/tests/compile_fail/unsafe_block.rs"),
        dir.join("probe/src/lib.rs"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", dir.join("target"))
        // Plain diagnostics: CI sets CARGO_TERM_COLOR=always.
        .env("CARGO_TERM_COLOR", "never")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "unsafe block compiled; workspace lints not applied:\n{stderr}"
    );
    assert!(
        stderr.contains("error: usage of an `unsafe` block"),
        "unexpected diagnostic:\n{stderr}"
    );
    assert!(
        stderr.contains("-D unsafe-code"),
        "error not caused by deny(unsafe_code):\n{stderr}"
    );
}

// `scripts/check-unsafe.py` passes on the repository and fails when
// `allow(unsafe_code)` appears outside the two allowed modules.

/// Runs the check on `root`; `(success, stderr)`.
fn check_unsafe(root: &std::path::Path) -> Option<(bool, String)> {
    let script = workspace_root().join("scripts/check-unsafe.py");
    let output = Command::new("python3")
        .arg(&script)
        .arg("--root")
        .arg(root)
        .output()
        .ok()?;
    Some((
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// A minimal tree the script accepts: a workspace manifest with `deny`, one crate
/// that inherits it.
fn fake_repo(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("crates/sverb-core/src/hardening")).unwrap();
    fs::create_dir_all(dir.join("crates/sverb-conn/src/agent")).unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n[workspace.lints.rust]\nunsafe_code = \"deny\"\n",
    )
    .unwrap();
    for krate in ["sverb-core", "sverb-conn"] {
        fs::write(
            dir.join(format!("crates/{krate}/Cargo.toml")),
            format!("[package]\nname = \"{krate}\"\n[lints]\nworkspace = true\n"),
        )
        .unwrap();
    }
    fs::write(
        dir.join("crates/sverb-core/src/hardening/unix.rs"),
        "#![allow(unsafe_code)]\n",
    )
    .unwrap();
    fs::write(
        dir.join("crates/sverb-conn/src/agent/dacl_windows.rs"),
        "#![allow(unsafe_code)]\n",
    )
    .unwrap();
    fs::write(
        dir.join("crates/sverb-core/src/lib.rs"),
        "// a comment may say #[allow(unsafe_code)]\npub fn f() {}\n",
    )
    .unwrap();
    dir
}

#[test]
fn t04_unsafe_check_passes_on_the_repository() {
    let Some((ok, stderr)) = check_unsafe(&workspace_root()) else {
        eprintln!("SKIP: python3 not available");
        return;
    };
    assert!(ok, "{stderr}");
}

#[test]
fn t04_unsafe_check_fails_outside_the_allowed_modules() {
    let clean = fake_repo("check-unsafe-clean");
    let Some((ok, stderr)) = check_unsafe(&clean) else {
        eprintln!("SKIP: python3 not available");
        return;
    };
    assert!(ok, "the allowed modules were flagged: {stderr}");

    for (i, attr) in [
        "#![allow(unsafe_code)]",
        "#[allow(dead_code, unsafe_code)]",
        "#[cfg_attr(unix, expect(unsafe_code))]",
        "#![warn(unsafe_code)]",
    ]
    .into_iter()
    .enumerate()
    {
        let dir = fake_repo(&format!("check-unsafe-dirty-{i}"));
        fs::write(
            dir.join("crates/sverb-core/src/lib.rs"),
            format!("{attr}\npub fn f() {{}}\n"),
        )
        .unwrap();
        let (ok, stderr) = check_unsafe(&dir).unwrap();
        assert!(!ok, "{attr} was not flagged");
        assert!(
            stderr.contains("crates/sverb-core/src/lib.rs:1"),
            "{stderr}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // A crate manifest that lifts the lint, and a workspace level of `allow`.
    let dir = fake_repo("check-unsafe-manifest");
    fs::write(
        dir.join("crates/sverb-conn/Cargo.toml"),
        "[package]\nname = \"sverb-conn\"\n[lints.rust]\nunsafe_code = \"allow\"\n",
    )
    .unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\n[workspace.lints.rust]\nunsafe_code = \"allow\"\n",
    )
    .unwrap();
    let (ok, stderr) = check_unsafe(&dir).unwrap();
    assert!(!ok);
    assert!(stderr.contains("overrides `unsafe_code`"), "{stderr}");
    assert!(stderr.contains("expected \"deny\""), "{stderr}");
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&clean);
}
