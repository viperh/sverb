//! Shared helpers for the binary's PTY integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use portable_pty::{
    Child, CommandBuilder, ExitStatus, MasterPty, PtySize, SlavePty, native_pty_system,
};

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) const RESTORE_SEQUENCES: [(&str, &str); 5] = [
    ("\x1b[?1049l", "leave alt screen"),
    ("\x1b[?25h", "show cursor"),
    ("\x1b[?1000l", "mouse off"),
    ("\x1b[?1006l", "SGR mouse off"),
    ("\x1b[?2004l", "bracketed paste off"),
];

/// Asserts that `output` enabled TUI mode and then emitted every restore sequence.
pub(crate) fn assert_restored(output: &str) {
    let entered = output
        .find("\x1b[?1049h")
        .unwrap_or_else(|| panic!("never entered the alt screen: {output:?}"));
    let rest = &output[entered..];
    for (seq, what) in RESTORE_SEQUENCES {
        assert!(rest.contains(seq), "missing {what} ({seq:?}) in {output:?}");
    }
}

/// A fresh `SVERB_HOME` under the target's temp dir.
pub(crate) fn unique_home(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}-{nanos}", std::process::id()))
}

/// The master password of [`init_vault`].
pub(crate) const TEST_PASSWORD: &str = "correct horse battery staple violin";

/// Initialize the vault in `home` with cheap Argon2 parameters and without the
/// keyring (tests never touch the OS keyring; run the binary with
/// `SVERB_KEYRING=off`). The one-time leader notice is marked as seen so it does not
/// take the first key after unlocking.
pub(crate) fn init_vault(home: &std::path::Path) {
    use sverb_core::paths::{DirKind, MapEnv, Paths};
    let paths = Paths::resolve(&MapEnv::new().var("SVERB_HOME", home)).unwrap();
    paths.ensure(DirKind::Data).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let store = sverb_store::Store::open(&paths).unwrap();
        let engine = sverb_tui::services::vault::VaultEngine::new(
            store.clone(),
            std::sync::Arc::new(sverb_core::vault::NoKeyring),
            sverb_core::vault::Argon2Cost::TEST,
        );
        engine.initialize(TEST_PASSWORD, false).await.unwrap();
        store.set_meta("seen_leader_notice", vec![1]).await.unwrap();
    });
}

/// Type the master password into the unlock prompt shown after byte offset `from`,
/// and wait until the unlocked shell is drawn (the Hosts view appears where the lock
/// overlay was). Returns the offset after the unlocked frame.
pub(crate) fn unlock(run: &mut PtyRun, from: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let prompt = run.wait_for("Unlock sverb", from)?;
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    run.wait_for("hosts", prompt)
}

/// A child process on an 80×24 PTY, with its output collected in the background.
pub(crate) struct PtyRun {
    pub(crate) child: Box<dyn Child + Send + Sync>,
    master: Box<dyn MasterPty + Send>,
    _slave: Box<dyn SlavePty + Send>,
    writer: Box<dyn Write + Send>,
    rx: mpsc::Receiver<Vec<u8>>,
    output: Vec<u8>,
}

impl PtyRun {
    /// Spawn `cmd` on a new PTY.
    pub(crate) fn spawn(cmd: CommandBuilder) -> Result<Self, Box<dyn std::error::Error>> {
        let pair = native_pty_system().openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let child = pair.slave.spawn_command(cmd)?;
        let mut reader = pair.master.try_clone_reader()?;
        let writer = pair.master.take_writer()?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
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
            output: Vec::new(),
        })
    }

    /// Everything read so far, lossily decoded.
    pub(crate) fn output(&self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }

    /// Read until the output after byte offset `from` contains `needle`; returns the
    /// offset just past the match.
    pub(crate) fn wait_for(
        &mut self,
        needle: &str,
        from: usize,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let started = Instant::now();
        loop {
            let tail =
                String::from_utf8_lossy(&self.output[from.min(self.output.len())..]).into_owned();
            if let Some(pos) = tail.find(needle) {
                // Lossy decoding keeps byte offsets for the ASCII needles used here.
                return Ok(from + pos + needle.len());
            }
            if started.elapsed() > TIMEOUT {
                return Err(
                    format!("timed out waiting for {needle:?} in {:?}", self.output()).into(),
                );
            }
            if let Ok(chunk) = self.rx.recv_timeout(Duration::from_millis(50)) {
                self.output.extend(chunk);
            }
        }
    }

    /// Resize the PTY (the child gets `SIGWINCH`). Returns the output offset at the
    /// resize, so a caller can look only at what was drawn after it.
    pub(crate) fn resize(
        &mut self,
        cols: u16,
        rows: u16,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        while let Ok(chunk) = self.rx.try_recv() {
            self.output.extend(chunk);
        }
        let at = self.output.len();
        self.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        Ok(at)
    }

    /// Collect output for up to `wait`.
    pub(crate) fn poll(&mut self, wait: Duration) {
        if let Ok(chunk) = self.rx.recv_timeout(wait) {
            self.output.extend(chunk);
        }
        while let Ok(chunk) = self.rx.try_recv() {
            self.output.extend(chunk);
        }
    }

    /// The raw output bytes from byte offset `from`.
    pub(crate) fn bytes_from(&self, from: usize) -> &[u8] {
        &self.output[from.min(self.output.len())..]
    }

    /// Type `bytes` into the terminal.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> TestResult {
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Wait for the child to exit, then drain the remaining output.
    pub(crate) fn wait_exit(&mut self) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if started.elapsed() > TIMEOUT {
                self.child.kill()?;
                return Err(format!("did not exit in time: {:?}", self.output()).into());
            }
            while let Ok(chunk) = self.rx.try_recv() {
                self.output.extend(chunk);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        while let Ok(chunk) = self.rx.recv_timeout(Duration::from_millis(300)) {
            self.output.extend(chunk);
        }
        let _ = &self.master;
        Ok(status)
    }
}
