//! [`PtyApp`]: the real `sverb` binary in a PTY.
//!
//! Output is fed into a local `AlacrittyEmulator` (the emulator the product uses), so
//! tests read the *screen* rather than raw bytes (ratatui only writes changed
//! cells). The emulator's replies to terminal queries (DA, DSR, kitty keyboard) are
//! written back, like a real terminal would. Keys are sent in the keymap's chord
//! syntax (`"ctrl-\\ q"`) and encoded for the modes the app enabled.

use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{OnceLock, mpsc},
    time::{Duration, Instant},
};

use portable_pty::{
    Child, CommandBuilder, ExitStatus, MasterPty, PtySize, SlavePty, native_pty_system,
};
use sverb_term::{
    AlacrittyEmulator, Emulator, EmulatorConfig, GridPoint,
    input::{EncodeOpts, encode_key},
};
use sverb_tui::keymap::chord::KeyChord;

use crate::{E2eError, Result, TestHome, WaitError, diag, home::MASTER_PASSWORD};

/// How to launch the binary.
#[derive(Debug, Clone)]
pub struct PtyOptions {
    /// Terminal columns.
    pub cols: u16,
    /// Terminal rows.
    pub rows: u16,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Extra environment (after the home's `SVERB_HOME` and `SVERB_KEYRING=off`).
    pub env: Vec<(String, String)>,
    /// The binary (default: [`sverb_binary`]).
    pub bin: Option<PathBuf>,
}

impl Default for PtyOptions {
    fn default() -> Self {
        Self {
            cols: 100,
            rows: 30,
            args: Vec::new(),
            env: Vec::new(),
            bin: None,
        }
    }
}

/// The `sverb` binary to run: `SVERB_BIN`, else the binary of this build profile
/// next to the test executable, built once per process with `cargo build -p sverb`
/// (a no-op when it is fresh).
///
/// # Errors
/// The build failed or the binary is missing.
pub fn sverb_binary() -> Result<PathBuf> {
    static BIN: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();
    BIN.get_or_init(|| locate_or_build().map_err(|e| e.0))
        .clone()
        .map_err(E2eError)
}

fn locate_or_build() -> Result<PathBuf> {
    if let Ok(bin) = std::env::var("SVERB_BIN")
        && !bin.is_empty()
    {
        return Ok(PathBuf::from(bin));
    }
    // <target>/<profile>/deps/<test-exe>
    let exe = std::env::current_exe()?;
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .ok_or_else(|| E2eError::new(format!("unexpected test path {}", exe.display())))?;
    let bin = profile_dir.join(format!("sverb{}", std::env::consts::EXE_SUFFIX));
    let target_dir = profile_dir
        .parent()
        .ok_or_else(|| E2eError::new("no target directory"))?;
    let profile = profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("debug");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let mut cmd = std::process::Command::new(cargo);
    cmd.args(["build", "-p", "sverb", "--bin", "sverb", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target_dir);
    match profile {
        "debug" => {}
        "release" => {
            cmd.arg("--release");
        }
        other => {
            cmd.args(["--profile", other]);
        }
    }
    match cmd.output() {
        Ok(out) if out.status.success() => {}
        // Fall back to an existing binary (cargo unavailable at test time, or the
        // tree does not build right now): say so, but keep going.
        result if bin.exists() => {
            let why = match result {
                Ok(out) => diag::tail(&String::from_utf8_lossy(&out.stderr), 15),
                Err(e) => e.to_string(),
            };
            eprintln!(
                "sverb-e2e: `cargo build -p sverb` failed; using the existing {}\n{why}",
                bin.display()
            );
        }
        Ok(out) => {
            return Err(E2eError::new(format!(
                "`cargo build -p sverb` failed ({}); build it first or set SVERB_BIN\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Err(e) => {
            return Err(E2eError::new(format!(
                "cannot run cargo ({e}); build sverb first or set SVERB_BIN"
            )));
        }
    }
    if bin.exists() {
        Ok(bin)
    } else {
        Err(E2eError::new(format!("{} is missing", bin.display())))
    }
}

/// A rendered screen: one string per row (trailing spaces kept), cursor position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    /// The rows.
    pub lines: Vec<String>,
}

impl Screen {
    /// Whether any row contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.lines.iter().any(|l| l.contains(needle))
    }

    /// The screen as text (rows joined with `\n`, trailing spaces trimmed).
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl std::fmt::Display for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

/// The `sverb` binary on a PTY. Killed when dropped; the last screen is dumped first
/// if the test is failing.
pub struct PtyApp {
    child: Box<dyn Child + Send + Sync>,
    master: Box<dyn MasterPty + Send>,
    _slave: Box<dyn SlavePty + Send>,
    writer: Box<dyn Write + Send>,
    rx: mpsc::Receiver<Vec<u8>>,
    emu: AlacrittyEmulator,
    raw: Vec<u8>,
    exit: Option<ExitStatus>,
    timeout: Duration,
}

impl std::fmt::Debug for PtyApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyApp")
            .field("pid", &self.child.process_id())
            .field("bytes", &self.raw.len())
            .field("exit", &self.exit)
            .finish_non_exhaustive()
    }
}

impl PtyApp {
    /// Launch `sverb` with `home` as `SVERB_HOME` (working directory: the home).
    ///
    /// # Errors
    /// The binary is missing or the PTY could not be opened.
    pub fn launch(home: &TestHome, opts: PtyOptions) -> Result<Self> {
        let bin = match opts.bin.clone() {
            Some(b) => b,
            None => sverb_binary()?,
        };
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: opts.rows,
                cols: opts.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| E2eError::new(format!("openpty: {e}")))?;
        let mut cmd = CommandBuilder::new(&bin);
        cmd.args(&opts.args);
        cmd.cwd(home.path());
        cmd.env("TERM", "xterm-256color");
        cmd.env_remove("SVERB_LOG");
        for (k, v) in home.env().into_iter().chain(opts.env) {
            cmd.env(k, v);
        }
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| E2eError::new(format!("spawn {}: {e}", bin.display())))?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| E2eError::new(format!("pty reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| E2eError::new(format!("pty writer: {e}")))?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 8192];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            master: pair.master,
            _slave: pair.slave,
            writer,
            rx,
            emu: AlacrittyEmulator::new(EmulatorConfig {
                cols: opts.cols,
                rows: opts.rows,
                scrollback: 0,
            }),
            raw: Vec::new(),
            exit: None,
            timeout: crate::timeout().max(Duration::from_secs(20)),
        })
    }

    /// Use `timeout` for the waits.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The process id.
    pub fn pid(&self) -> Option<u32> {
        self.child.process_id()
    }

    fn feed(&mut self, chunk: &[u8]) {
        self.raw.extend_from_slice(chunk);
        self.emu.feed(chunk);
        for reply in self.emu.take_responses() {
            let _ = self.writer.write_all(&reply);
        }
        let _ = self.writer.flush();
        let _ = self.emu.take_events();
    }

    /// Process output, waiting up to `wait` for the first chunk.
    fn pump(&mut self, wait: Duration) {
        if let Ok(chunk) = self.rx.recv_timeout(wait) {
            self.feed(&chunk);
        }
        while let Ok(chunk) = self.rx.try_recv() {
            self.feed(&chunk);
        }
    }

    /// The current screen (after processing pending output).
    pub fn screen(&mut self) -> Screen {
        self.pump(Duration::ZERO);
        self.render()
    }

    fn render(&self) -> Screen {
        let (cols, rows) = self.emu.size();
        let lines = (0..i32::from(rows))
            .map(|row| {
                self.emu.grid_text(
                    GridPoint::new(row, 0),
                    GridPoint::new(row, usize::from(cols).saturating_sub(1)),
                )
            })
            .map(|l| l.trim_end_matches('\n').to_owned())
            .collect();
        Screen { lines }
    }

    /// Every byte the app wrote so far.
    pub fn raw_output(&self) -> &[u8] {
        &self.raw
    }

    /// Wait until `pred` holds for the screen. Returns that screen.
    ///
    /// # Errors
    /// Not within the timeout (or the app exited first); the error shows the screen.
    pub fn wait_for_screen(
        &mut self,
        what: &str,
        pred: impl Fn(&Screen) -> bool,
    ) -> std::result::Result<Screen, WaitError> {
        let started = Instant::now();
        loop {
            self.pump(Duration::from_millis(25));
            let screen = self.render();
            if pred(&screen) {
                return Ok(screen);
            }
            let exited = self.poll_exit();
            if exited.is_some() || started.elapsed() > self.timeout {
                let why = match exited {
                    Some(status) => format!("the app exited ({status:?})"),
                    None => "timed out".into(),
                };
                return Err(WaitError(format!(
                    "{what}: {why} after {:?}\n--- screen ---\n{}",
                    started.elapsed(),
                    screen.text()
                )));
            }
        }
    }

    /// Wait until the screen contains `needle`.
    ///
    /// # Errors
    /// As [`PtyApp::wait_for_screen`].
    pub fn wait_for_text(&mut self, needle: &str) -> std::result::Result<Screen, WaitError> {
        self.wait_for_screen(&format!("{needle:?} on screen"), |s| s.contains(needle))
    }

    /// Write raw bytes.
    ///
    /// # Errors
    /// The PTY is closed.
    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Type `text` literally.
    ///
    /// # Errors
    /// The PTY is closed.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_raw(text.as_bytes())
    }

    /// Press a chord sequence in keymap syntax (`"ctrl-\\ q"`, `"enter"`, `"g g"`),
    /// encoded for the keyboard modes the app enabled.
    ///
    /// # Errors
    /// Unparsable chords, keys without an encoding, or a closed PTY.
    pub fn send_keys(&mut self, chords: &str) -> Result<()> {
        let seq = KeyChord::parse_sequence(chords)
            .map_err(|e| E2eError::new(format!("chord {chords:?}: {e}")))?;
        for chord in seq {
            self.pump(Duration::ZERO);
            let input = chord
                .to_key_input()
                .ok_or_else(|| E2eError::new(format!("{chord} has no key encoding")))?;
            let bytes = encode_key(input, &self.emu.modes(), &EncodeOpts::default())
                .ok_or_else(|| E2eError::new(format!("{chord} has no byte encoding")))?;
            self.send_raw(&bytes)?;
        }
        Ok(())
    }

    /// Resize the PTY (the app gets `SIGWINCH`) and the local emulator.
    ///
    /// # Errors
    /// The resize failed.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.pump(Duration::ZERO);
        self.emu.resize(cols, rows);
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| E2eError::new(format!("resize: {e}")))
    }

    /// Unlock the vault of a [`TestHome`]: wait for the unlock prompt, type the master
    /// password, and wait until the Hosts view is drawn.
    ///
    /// # Errors
    /// A wait timed out.
    pub fn unlock(&mut self) -> std::result::Result<Screen, WaitError> {
        self.wait_for_text("Unlock sverb")?;
        self.send_text(MASTER_PASSWORD)
            .and_then(|()| self.send_raw(b"\r"))
            .map_err(|e| WaitError(e.to_string()))?;
        self.wait_for_screen("the unlocked Hosts view", |s| {
            s.contains("Hosts") && !s.contains("Unlock sverb")
        })
    }

    fn poll_exit(&mut self) -> Option<ExitStatus> {
        if self.exit.is_none()
            && let Ok(Some(status)) = self.child.try_wait()
        {
            self.exit = Some(status);
        }
        self.exit.clone()
    }

    /// Wait for the process to exit (processing its output meanwhile).
    ///
    /// # Errors
    /// It did not exit within the timeout (it is killed).
    pub fn wait_exit(&mut self) -> std::result::Result<ExitStatus, WaitError> {
        let started = Instant::now();
        loop {
            self.pump(Duration::from_millis(25));
            if let Some(status) = self.poll_exit() {
                // Drain what the app wrote while exiting (the reader ends at EOF).
                let drain_until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < drain_until {
                    match self.rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(chunk) => self.feed(&chunk),
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                return Ok(status);
            }
            if started.elapsed() > self.timeout {
                let _ = self.child.kill();
                return Err(WaitError(format!(
                    "the app did not exit within {:?}\n--- screen ---\n{}",
                    self.timeout,
                    self.render().text()
                )));
            }
        }
    }

    /// Dump the screen now ([`diag::dump`]).
    pub fn dump(&mut self) {
        let screen = self.screen();
        diag::dump(
            &format!("sverb screen (pid {:?})", self.child.process_id()),
            &screen.text(),
        );
    }
}

impl Drop for PtyApp {
    fn drop(&mut self) {
        if diag::failing() {
            self.dump();
        }
        if self.poll_exit().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
