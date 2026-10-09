#![allow(clippy::unwrap_used, clippy::expect_used)]

//! temporary `$HOME`: installing twice leaves one block, uninstalling removes it. The
//! container part (bash / zsh / fish users over SSH) is an e2e test.

use std::{path::PathBuf, process::Command};

use super::shell_integration::*;
use crate::snippet::{Builtins, RenderStyle, Template, Values};

struct TempHome(PathBuf);

impl TempHome {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sverb-m7-01-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("temp home");
        Self(dir)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn render(snippet: &crate::model::Snippet, shell: Option<&str>) -> String {
    let template = Template::parse(&snippet.script).expect("parses");
    let mut values = Values::new();
    for v in &snippet.variables {
        let value = shell.unwrap_or(v.default.as_deref().unwrap_or(""));
        values.set(v.name.clone(), value, false);
    }
    template
        .render(&values, &Builtins::default(), RenderStyle::Final)
        .expect("renders")
}

fn run(home: &TempHome, script: &str, login_shell: &str) -> (bool, String) {
    let out = Command::new("sh")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("HOME", &home.0)
        .env("SHELL", login_shell)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .expect("sh runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

#[test]
fn hooks_have_markers_and_emit_all_four_marks() {
    for shell in Shell::ALL {
        let hook = shell.hook();
        assert!(hook.starts_with(BEGIN_MARKER), "{shell:?}");
        assert!(hook.trim_end().ends_with(END_MARKER), "{shell:?}");
        for mark in ["133;A", "133;B", "133;C", "133;D"] {
            assert!(hook.contains(mark), "{shell:?} {mark}");
        }
        assert!(!hook.contains("{{"), "no template syntax in hooks");
    }
}

#[test]
fn t09_install_twice_is_idempotent_and_uninstall_removes_the_block() {
    let home = TempHome::new("bash");
    let rc = home.0.join(".bashrc");
    std::fs::write(&rc, "export FOO=1").expect("write"); // no final newline
    let install = render(&install_snippet(), None);
    for _ in 0..2 {
        let (ok, out) = run(&home, &install, "/bin/bash");
        assert!(ok, "{out}");
    }
    let text = std::fs::read_to_string(&rc).expect("read");
    assert_eq!(count(&text, BEGIN_MARKER), 1, "{text}");
    assert!(text.starts_with("export FOO=1\n# >>>"), "{text}");

    let (ok, out) = run(&home, &uninstall_script(), "/bin/bash");
    assert!(ok, "{out}");
    assert!(out.contains("removed"), "{out}");
    let text = std::fs::read_to_string(&rc).expect("read");
    assert_eq!(text, "export FOO=1\n");
    // Again: nothing to do.
    let (ok, out) = run(&home, &uninstall_script(), "/bin/bash");
    assert!(ok && out.contains("not installed"), "{out}");
}

#[test]
fn t09_zsh_and_fish_files() {
    let home = TempHome::new("zf");
    let install = render(&install_snippet(), Some("zsh"));
    let (ok, out) = run(&home, &install, "/bin/sh");
    assert!(ok, "{out}");
    let zshrc = std::fs::read_to_string(home.0.join(".zshrc")).expect("zshrc");
    assert_eq!(zshrc, Shell::Zsh.hook());

    let install = render(&install_snippet(), None);
    for _ in 0..2 {
        let (ok, out) = run(&home, &install, "/usr/bin/fish");
        assert!(ok, "{out}");
    }
    let fish = home.0.join(".config/fish/conf.d/sverb.fish");
    assert_eq!(
        std::fs::read_to_string(&fish).expect("fish"),
        Shell::Fish.hook()
    );

    let (ok, out) = run(&home, &uninstall_script(), "/bin/sh");
    assert!(ok, "{out}");
    assert!(!fish.exists(), "the emptied fish file is removed");
    assert_eq!(
        std::fs::read_to_string(home.0.join(".zshrc")).expect("zshrc"),
        ""
    );
}

#[test]
fn unsupported_shell_fails_without_writing() {
    let home = TempHome::new("tcsh");
    let install = render(&install_snippet(), Some("tcsh"));
    let (ok, out) = run(&home, &install, "/bin/sh");
    assert!(!ok);
    assert!(out.contains("unsupported shell"), "{out}");
    assert_eq!(std::fs::read_dir(&home.0).expect("dir").count(), 0);
}

#[test]
fn the_bash_hook_is_valid_bash() {
    let Ok(out) = Command::new("bash")
        .arg("-n")
        .arg("-c")
        .arg(Shell::Bash.hook())
        .output()
    else {
        return; // no bash here
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn snippets_are_exec_and_parse() {
    for s in [install_snippet(), uninstall_snippet()] {
        assert_eq!(s.run_mode, crate::model::RunMode::Exec);
        Template::parse(&s.script).expect("parses");
    }
    assert_eq!(install_snippet().name, INSTALL_NAME);
}
