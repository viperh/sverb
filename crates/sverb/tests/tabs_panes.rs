//! propagation checked from inside the panes (`stty size`) and full-screen programs
//! (`htop`, `tmux`) drawn in split panes across an outer resize.
//!
//! (`#[ignore]`d there); local shells exercise the same pane, layout and resize code.
//! The screen is checked by feeding sverb's output into a terminal emulator
//! (`sverb-term`), since ratatui only writes the cells that changed.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{PtyRun, TIMEOUT, TestResult, init_vault, unique_home, unlock};
use portable_pty::CommandBuilder;
use ratatui::{buffer::Buffer, layout::Rect};
use sverb_core::layout::{Layout, PaneId, SplitDir};
use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig, ViewState};
use sverb_tui::app::Config;
use sverb_tui::views::{
    MainView, ShellState,
    sessions::panes::{content_size, pane_rects},
};

/// The `stty size` (rows, cols) each pane of `layout` should see in a `w`×`h` terminal.
fn expected(layout: &Layout, w: u16, h: u16) -> Vec<(u16, u16)> {
    let shell = ShellState {
        main_view: MainView::Sessions,
        ..ShellState::default()
    };
    let rects = sverb_tui::views::shell::layout(Rect::new(0, 0, w, h), &shell, &Config::default());
    pane_rects(layout, None, rects.main)
        .into_iter()
        .map(|(_, r)| {
            let (cols, rows) = content_size(r);
            (rows, cols)
        })
        .collect()
}

/// The outer screen: sverb's output since `from` (a full redraw: the start, or a resize)
/// fed into a `w`×`h` emulator.
struct Screen {
    from: usize,
    w: u16,
    h: u16,
}

impl Screen {
    fn text(&self, run: &PtyRun) -> String {
        let mut emu = AlacrittyEmulator::new(EmulatorConfig {
            cols: self.w,
            rows: self.h,
            scrollback: 0,
        });
        emu.feed(run.bytes_from(self.from));
        let area = Rect::new(0, 0, self.w, self.h);
        let mut buf = Buffer::empty(area);
        emu.render(area, &mut buf, &ViewState::default());
        let mut out = String::new();
        for y in 0..self.h {
            for x in 0..self.w {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Wait until the screen shows `needle`; returns the screen.
    fn wait(&self, run: &mut PtyRun, needle: &str) -> Result<String, Box<dyn std::error::Error>> {
        let started = Instant::now();
        loop {
            run.poll(Duration::from_millis(50));
            let text = self.text(run);
            if text.contains(needle) {
                return Ok(text);
            }
            if started.elapsed() > TIMEOUT {
                return Err(format!("timed out waiting for {needle:?} on screen:\n{text}").into());
            }
        }
    }

    /// `stty size` in the focused pane, tagged `n`; waits for `(rows, cols)`.
    fn check_size(&self, run: &mut PtyRun, n: u32, (rows, cols): (u16, u16)) -> TestResult {
        run.send(format!("echo S{n}:$(stty size | tr ' ' x)\r").as_bytes())?;
        self.wait(run, &format!("S{n}:{rows}x{cols}"))?;
        Ok(())
    }
}

/// Longer than the 50 ms resize debounce.
fn settle() {
    std::thread::sleep(Duration::from_millis(300));
}

fn have(tool: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn t15_local_tabs_splits_resize_and_full_screen_programs() -> TestResult {
    let home = unique_home("m1-17-tabs");
    init_vault(&home);
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.env("SVERB_HOME", &home);
    cmd.env("TERM", "xterm-256color");
    cmd.env("SVERB_KEYRING", "off");
    cmd.env("SHELL", "/bin/sh");
    cmd.env("PS1", "$ ");
    cmd.env("ENV", "/dev/null");
    cmd.env("TMUX_TMPDIR", &home);
    cmd.env_remove("TMUX");
    cmd.env_remove("SVERB_TEST_HOOK");
    cmd.env_remove("RUST_BACKTRACE");
    let mut run = PtyRun::spawn(cmd)?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    unlock(&mut run, entered)?;
    let screen = Screen {
        from: 0,
        w: 80,
        h: 24,
    };

    // Tab 1: a local shell at the full session-area size.
    run.send(b"\x1ct")?;
    screen.wait(&mut run, " 1 local ┬ + ")?;
    let single = Layout::leaf(PaneId(1));
    screen.check_size(&mut run, 1, expected(&single, 80, 24)[0])?;

    // `leader |`: a second shell on the right; both panes get their half (the left
    // one through the debounced resize).
    run.send(b"\x1c|")?;
    let split = single
        .split(PaneId(1), SplitDir::Vertical, PaneId(2))
        .unwrap();
    let want = expected(&split, 80, 24);
    screen.check_size(&mut run, 2, want[1])?;
    // The left pane's resize is debounced (50 ms).
    settle();
    run.send(b"\x1ch")?;
    screen.check_size(&mut run, 3, want[0])?;

    // A second tab, then back to the first.
    run.send(b"\x1ct")?;
    screen.wait(&mut run, " 2 local ┬ + ")?;
    run.send(b"\x1c1")?;
    std::thread::sleep(Duration::from_millis(200));

    // Outer resize: one debounced `window_change` per pane.
    let screen = Screen {
        from: run.resize(120, 40)?,
        w: 120,
        h: 40,
    };
    let want = expected(&split, 120, 40);
    settle();
    screen.check_size(&mut run, 4, want[0])?;
    run.send(b"\x1cl")?;
    screen.check_size(&mut run, 5, want[1])?;

    // Full-screen programs in the split panes (M1 exit criterion), across a resize.
    let htop = have("htop");
    let tmux = have("tmux");
    if htop {
        run.send(b"htop\r")?;
        screen.wait(&mut run, "Tasks:")?;
    }
    if tmux {
        // Left pane: tmux; its shell sees the pane minus tmux's status line.
        run.send(b"\x1ch")?;
        // A relative socket path: the absolute one would exceed `sun_path`.
        run.send(b"cd \"$TMUX_TMPDIR\" && tmux -S t.sock -f /dev/null new-session\r")?;
        screen.wait(&mut run, "[0] 0:")?;
        screen.check_size(&mut run, 6, (want[0].0 - 1, want[0].1))?;
    }
    std::thread::sleep(Duration::from_millis(200));
    let screen = Screen {
        from: run.resize(100, 30)?,
        w: 100,
        h: 30,
    };
    let want = expected(&split, 100, 30);
    settle();
    if tmux {
        screen.check_size(&mut run, 7, (want[0].0 - 1, want[0].1))?;
    }
    let shown = if htop {
        screen.wait(&mut run, "Tasks:")?
    } else {
        screen.wait(&mut run, " 1 local ┬ 2 local")?
    };
    let lines: Vec<&str> = shown.lines().collect();
    assert_eq!(lines.len(), 30, "{shown}");
    // The tab bar, two panes side by side, the status bar.
    // (Tab 2 shows `●` if its shell printed its prompt in the background.)
    assert!(lines[1].contains(" 1 local ┬ 2 local "), "{shown}");
    assert!(lines[1].contains(" ┬ + "), "{shown}");
    assert!(lines[2].matches('┌').count() >= 2, "{shown}");
    assert!(lines[29].contains("TERMINAL"), "{shown}");
    if tmux {
        assert!(shown.contains("[0] 0:"), "{shown}");
        run.send(b"exit\r")?;
    }
    if htop {
        run.send(b"\x1cl")?;
        run.send(b"q")?;
    }

    // Quit: sessions are open, so confirm.
    std::thread::sleep(Duration::from_millis(200));
    run.send(b"\x1cq")?;
    screen.wait(&mut run, "Quit")?;
    run.send(b"y")?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 0, "{status:?}");
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
