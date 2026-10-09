//! requests through the local `sh -c`, for loopback tests of exec channels and
//! install-key without Docker.
//!
//! - Users: `sverb` with password `secret`; public keys listed in
//!   `<home>/.ssh/authorized_keys` (read on every attempt, so a key installed by a test
//!   logs in afterwards).
//! - Commands run with `HOME=<home>` in `<home>` in their own process group. A PTY
//!   request merges stderr into stdout (as a real PTY would). `signal TERM` kills the
//!   group with SIGTERM, and a closed channel with SIGKILL.
//! - [`ExecServerOpts::posix`] `false` imitates Windows OpenSSH with `cmd.exe`: every
//!   command fails with "'…' is not recognized as an internal or external command".
//! - [`ExecResolver`] resolves every spec to the server, with the password and/or a
//!   key.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::{
    collections::HashMap, net::SocketAddr, path::PathBuf, process::Stdio, sync::Arc, time::Duration,
};

use async_trait::async_trait;
use parking_lot::Mutex;
use russh::{
    Channel, ChannelId, Pty, Sig,
    keys::{PrivateKey, PublicKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use sverb_core::{config::Config, model::Host, secret::SecretString};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    sync::mpsc,
};

use super::{HostResolver, KeyMaterial, SshError, SshTarget, resolve};
use crate::session::SshSpec;

/// How the server behaves.
#[derive(Debug, Clone)]
pub struct ExecServerOpts {
    /// `HOME` (and working directory) of every command.
    pub home: PathBuf,
    /// `false`: a Windows-like server where every command fails.
    pub posix: bool,
}

/// What the server saw.
#[derive(Debug, Default)]
pub struct ExecSeen {
    /// Commands, in order.
    pub commands: Vec<String>,
    /// Commands run with a PTY.
    pub pty_commands: Vec<String>,
    /// Signals received.
    pub signals: Vec<String>,
    /// Accepted logins (`password` / `publickey`).
    pub logins: Vec<String>,
}

#[derive(Default)]
struct Chan {
    pty: bool,
    stdin: Option<mpsc::UnboundedSender<Vec<u8>>>,
    pgid: Option<u32>,
}

/// The handler of one connection.
#[derive(Clone)]
struct ExecServer {
    opts: Arc<ExecServerOpts>,
    seen: Arc<Mutex<ExecSeen>>,
    chans: Arc<Mutex<HashMap<ChannelId, Chan>>>,
}

/// Send `sig` to the process group `pgid` (`kill -s SIG -- -PGID`).
///
/// The `--` matters: without it, procps-ng's `kill` (Ubuntu) parses `-PGID` as an
/// option, which on a CI runner signalled every process of the user, the runner
/// included. Groups 0 and 1 are never signalled.
fn kill_group(pgid: u32, sig: &str) {
    if pgid <= 1 {
        return;
    }
    let _ = std::process::Command::new("kill")
        .args(["-s", sig, "--"])
        .arg(format!("-{pgid}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

impl ExecServer {
    fn authorized(&self, key: &PublicKey) -> bool {
        let Ok(text) = std::fs::read_to_string(self.opts.home.join(".ssh/authorized_keys")) else {
            return false;
        };
        let Ok(want) = key.to_openssh() else {
            return false;
        };
        let want = want
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        text.lines()
            .any(|l| l.split_whitespace().nth(1) == Some(want.as_str()))
    }

    fn run(&self, channel: ChannelId, command: String, handle: server::Handle) {
        let pty = self.chans.lock().get(&channel).is_some_and(|c| c.pty);
        if !self.opts.posix {
            let word = command.split_whitespace().next().unwrap_or("").to_owned();
            tokio::spawn(async move {
                let msg = format!(
                    "'{word}' is not recognized as an internal or external command,\r\n\
                     operable program or batch file.\r\n"
                );
                let _ = handle.extended_data(channel, 1, msg.into_bytes()).await;
                let _ = handle.exit_status_request(channel, 1).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            return;
        }
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .env("HOME", &self.opts.home)
            .current_dir(&self.opts.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .expect("sh starts");
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        {
            let mut chans = self.chans.lock();
            let c = chans.entry(channel).or_default();
            c.stdin = Some(tx);
            c.pgid = child.id();
        }
        let mut stdin = child.stdin.take().unwrap();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
            }
            // Dropping `stdin` sends EOF.
        });
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (h1, h2) = (handle.clone(), handle.clone());
        let out_task = tokio::spawn(async move {
            let mut buf = vec![0_u8; 32 * 1024];
            while let Ok(n) = stdout.read(&mut buf).await {
                if n == 0 || h1.data(channel, buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        let err_task = tokio::spawn(async move {
            let mut buf = vec![0_u8; 32 * 1024];
            while let Ok(n) = stderr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let sent = if pty {
                    h2.data(channel, buf[..n].to_vec()).await
                } else {
                    h2.extended_data(channel, 1, buf[..n].to_vec()).await
                };
                if sent.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let status = child.wait().await;
            let _ = out_task.await;
            let _ = err_task.await;
            if let Ok(status) = status {
                use std::os::unix::process::ExitStatusExt as _;
                if let Some(code) = status.code() {
                    let _ = handle
                        .exit_status_request(channel, u32::try_from(code).unwrap_or(255))
                        .await;
                } else if let Some(sig) = status.signal() {
                    let sig = match sig {
                        15 => Sig::TERM,
                        9 => Sig::KILL,
                        2 => Sig::INT,
                        _ => Sig::Custom(sig.to_string()),
                    };
                    let _ = handle
                        .exit_signal_request(channel, sig, false, String::new(), String::new())
                        .await;
                }
            }
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }
}

impl server::Handler for ExecServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == "sverb" && password == "secret" {
            self.seen.lock().logins.push("password".to_owned());
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.authorized(key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if user == "sverb" && self.authorized(key) {
            self.seen.lock().logins.push("publickey".to_owned());
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.chans.lock().insert(channel.id(), Chan::default());
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_w: u32,
        _px_h: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.chans.lock().entry(channel).or_default().pty = true;
        session.channel_success(channel)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        {
            let pty = self.chans.lock().get(&channel).is_some_and(|c| c.pty);
            let mut seen = self.seen.lock();
            seen.commands.push(command.clone());
            if pty {
                seen.pty_commands.push(command.clone());
            }
        }
        session.channel_success(channel)?;
        self.run(channel, command, session.handle());
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self
            .chans
            .lock()
            .get(&channel)
            .and_then(|c| c.stdin.clone())
        {
            let _ = tx.send(data.to_vec());
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(c) = self.chans.lock().get_mut(&channel) {
            c.stdin = None;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.seen.lock().signals.push(format!("{signal:?}"));
        if matches!(signal, Sig::TERM)
            && let Some(pgid) = self.chans.lock().get(&channel).and_then(|c| c.pgid)
        {
            kill_group(pgid, "TERM");
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(pgid) = self.chans.lock().remove(&channel).and_then(|c| c.pgid) {
            kill_group(pgid, "KILL");
        }
        Ok(())
    }
}

/// Start a server on 127.0.0.1: its address and what it sees.
pub async fn start_exec_server(opts: ExecServerOpts) -> (SocketAddr, Arc<Mutex<ExecSeen>>) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[43; 32]));
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(ExecSeen::default()));
    let opts = Arc::new(opts);
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let handler = ExecServer {
                opts: Arc::clone(&opts),
                seen: Arc::clone(&seen2),
                chans: Arc::default(),
            };
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    (addr, seen)
}

/// Resolves every spec to the exec server.
#[derive(Debug, Clone)]
pub struct ExecResolver {
    /// The server.
    pub addr: SocketAddr,
    /// The stored password (`secret` is right; `None`: none stored).
    pub password: Option<&'static str>,
    /// An OpenSSH private key to log in with.
    pub key: Option<String>,
    /// `request_pty_for_exec` of the host.
    pub request_pty_for_exec: bool,
}

impl ExecResolver {
    /// Password login.
    pub fn password(addr: SocketAddr) -> Self {
        Self {
            addr,
            password: Some("secret"),
            key: None,
            request_pty_for_exec: false,
        }
    }
}

#[async_trait]
impl HostResolver for ExecResolver {
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError> {
        let host = Host {
            label: spec.label.clone().unwrap_or_else(|| "exec".into()),
            address: self.addr.ip().to_string(),
            port: Some(self.addr.port()),
            username: Some("sverb".into()),
            password: self.password.map(SecretString::from),
            request_pty_for_exec: Some(self.request_pty_for_exec),
            ..Host::default()
        };
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 5;
        config.ssh.use_system_agent = false;
        let mut t = resolve(&host, None, None, &config, || None);
        if let Some(key) = &self.key {
            t.auth.key = Some(KeyMaterial {
                key_id: None,
                label: "test key".into(),
                private_key: SecretString::from(key.as_str()),
                passphrase: None,
                certificates: Vec::new(),
            });
        }
        Ok(t)
    }
}

/// A fresh empty directory for [`ExecServerOpts::home`], removed on drop.
#[derive(Debug)]
pub struct TempHome(pub PathBuf);

impl TempHome {
    /// Create one under the system temp dir.
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sverb-exec-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Default for TempHome {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
