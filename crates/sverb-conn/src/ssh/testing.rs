//! Test support (`test-util` feature): an in-process russh server for loopback tests
//! without Docker, a pausable TCP proxy (simulates `docker pause`), and a resolver
//! pointing at the server. Kept in `sverb_conn::ssh` so russh stays confined here.
//!
//! The server accepts user `sverb` with password `secret`, accepts the env var `FOO`
//! only (`AcceptEnv FOO`), answers the shell request with `TERM=…` and `FOO=…` lines
//! plus one stderr line, echoes each input line as `out:<line>`, and on `exit 7\r`
//! sends exit status 7 and closes the channel.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use parking_lot::Mutex;
use russh::{
    Channel, ChannelId, Preferred, Pty,
    keys::{PrivateKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use sverb_core::{config::Config, model::Host, secret::SecretString};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::{HostResolver, SshError, SshTarget, resolve};
use crate::session::SshSpec;

/// Server preferences offering only `diffie-hellman-group14-sha1` for key exchange.
pub(crate) fn legacy_kex_only() -> Preferred {
    Preferred {
        kex: std::borrow::Cow::Owned(vec![russh::kex::DH_G14_SHA1]),
        ..Preferred::default()
    }
}

// ---------------------------------------------------------------- the test server

/// What the server saw.
#[derive(Debug, Default)]
pub struct Seen {
    /// Seen by the server.
    pub term: Option<String>,
    /// Seen by the server.
    pub modes: Vec<(Pty, u32)>,
    /// Seen by the server.
    pub env: Vec<(String, String, bool)>,
    /// Seen by the server.
    pub sizes: Vec<(u32, u32)>,
    /// Seen by the server.
    pub input: Vec<u8>,
    /// Seen by the server.
    pub users: Vec<String>,
    /// `direct-tcpip` requests (host as sent, port).
    pub direct: Vec<(String, u32)>,
    /// Active `tcpip-forward` listeners by (address, port).
    pub remote_forwards: std::collections::HashMap<(String, u32), tokio::task::AbortHandle>,
    /// `cancel-tcpip-forward` requests.
    pub cancelled: Vec<(String, u32)>,
    /// Channels carrying forwarded data (not the shell).
    pub tunnel_channels: std::collections::HashSet<ChannelId>,
    /// The shell prints nothing when it starts (tests of the startup-input delay).
    pub quiet_shell: bool,
}

/// The server's handler.
#[derive(Clone, Debug)]
pub struct TestServer {
    /// What it saw.
    pub seen: Arc<Mutex<Seen>>,
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.seen.lock().users.push(user.to_owned());
        Ok(if password == "secret" {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.open_direct(channel, host_to_connect, port_to_connect, reply)
            .await;
        Ok(())
    }

    // Listens on 127.0.0.1 whatever the requested address (tests stay on
    // loopback); `port = 0` allocates.
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Ok(want) = u16::try_from(*port) else {
            return Ok(false);
        };
        let Ok(listener) = TcpListener::bind(("127.0.0.1", want)).await else {
            return Ok(false);
        };
        let bound = listener.local_addr().map(|a| a.port()).unwrap_or(want);
        *port = u32::from(bound);
        let (handle, seen, address) =
            (session.handle(), Arc::clone(&self.seen), address.to_owned());
        let key = (address.clone(), u32::from(bound));
        let task = tokio::spawn(async move {
            while let Ok((tcp, peer)) = listener.accept().await {
                tokio::spawn(forward_accepted(
                    handle.clone(),
                    Arc::clone(&seen),
                    tcp,
                    peer,
                    address.clone(),
                    u32::from(bound),
                ));
            }
        });
        self.seen
            .lock()
            .remote_forwards
            .insert(key, task.abort_handle());
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut seen = self.seen.lock();
        seen.cancelled.push((address.to_owned(), port));
        Ok(
            match seen.remote_forwards.remove(&(address.to_owned(), port)) {
                Some(task) => {
                    task.abort();
                    true
                }
                None => false,
            },
        )
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // `AcceptEnv FOO`.
        let ok = name == "FOO";
        self.seen
            .lock()
            .env
            .push((name.to_owned(), value.to_owned(), ok));
        if ok {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _px_w: u32,
        _px_h: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut seen = self.seen.lock();
        seen.term = Some(term.to_owned());
        seen.modes = modes.to_vec();
        seen.sizes.push((cols, rows));
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        // A silent shell (the startup input then waits for the delay).
        if self.seen.lock().quiet_shell {
            return Ok(());
        }
        let (term, accepted) = {
            let seen = self.seen.lock();
            let accepted = seen
                .env
                .iter()
                .find(|(n, _, ok)| n == "FOO" && *ok)
                .map(|(_, v, _)| v.clone())
                .unwrap_or_default();
            (seen.term.clone().unwrap_or_default(), accepted)
        };
        session.data(
            channel,
            format!("TERM={term}\r\nFOO={accepted}\r\n").into_bytes(),
        )?;
        session.extended_data(channel, 1, b"ls: /nonexistent: No such file\r\n".to_vec())?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        cols: u32,
        rows: u32,
        _px_w: u32,
        _px_h: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.seen.lock().sizes.push((cols, rows));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let input = {
            let mut seen = self.seen.lock();
            // Forwarded data is handled by the channel's splice task.
            if seen.tunnel_channels.contains(&channel) {
                return Ok(());
            }
            seen.input.extend_from_slice(data);
            String::from_utf8_lossy(&seen.input).into_owned()
        };
        if input.ends_with("exit 7\r") {
            session.exit_status_request(channel, 7)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else if input.ends_with('\r') {
            let line = input.lines().last().unwrap_or_default().trim().to_owned();
            session.data(channel, format!("\r\nout:{line}\r\n").into_bytes())?;
        }
        Ok(())
    }
}

// Port forwarding on the test server (loopback only).

/// Where the test server connects a `direct-tcpip` request: loopback IPs, `localhost`,
/// and names ending in `.sverb-test` (→ 127.0.0.1, standing in for the remote side's
/// DNS). Anything else is refused, so tests never reach the network.
fn test_destination(host: &str) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    if host == "localhost" || host.ends_with(".sverb-test") {
        return Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok()
        .filter(IpAddr::is_loopback)
}

impl TestServer {
    async fn open_direct(
        &self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        reply: ChannelOpenHandle,
    ) {
        self.seen.lock().direct.push((host.to_owned(), port));
        let target = test_destination(host).zip(u16::try_from(port).ok());
        let tcp = match target {
            Some(addr) => TcpStream::connect(addr).await.ok(),
            None => None,
        };
        let Some(mut tcp) = tcp else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return;
        };
        self.seen.lock().tunnel_channels.insert(channel.id());
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
    }
}

/// Splice a connection accepted by a remote forward into a `forwarded-tcpip` channel.
async fn forward_accepted(
    handle: server::Handle,
    seen: Arc<Mutex<Seen>>,
    mut tcp: TcpStream,
    peer: SocketAddr,
    address: String,
    port: u32,
) {
    let opened = handle
        .channel_open_forwarded_tcpip(address, port, peer.ip().to_string(), u32::from(peer.port()))
        .await;
    if let Ok(channel) = opened {
        seen.lock().tunnel_channels.insert(channel.id());
        let mut stream = channel.into_stream();
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
    }
}

/// A server on 127.0.0.1 with russh's default algorithms: its address and what it
/// sees.
pub async fn start_server() -> (SocketAddr, Arc<Mutex<Seen>>) {
    start_server_with(Preferred::default()).await
}

/// A server offering only `diffie-hellman-group14-sha1` for key exchange.
pub async fn start_legacy_server() -> (SocketAddr, Arc<Mutex<Seen>>) {
    start_server_with(legacy_kex_only()).await
}

/// A server on 127.0.0.1 with `preferred` algorithms.
pub(crate) async fn start_server_with(preferred: Preferred) -> (SocketAddr, Arc<Mutex<Seen>>) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let config = Arc::new(server::Config {
        keys: vec![key],
        preferred,
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let handler = TestServer {
        seen: Arc::clone(&seen),
    };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let config = Arc::clone(&config);
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    (addr, seen)
}

/// A TCP proxy to `target` that can be "paused" (stops forwarding, like `docker pause`).
pub async fn pausable_proxy(target: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let paused = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&paused);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let server = TcpStream::connect(target).await.unwrap();
            let (cr, cw) = client.into_split();
            let (sr, sw) = server.into_split();
            for (mut from, mut to) in [
                (
                    Box::new(cr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box::new(sw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                ),
                (Box::new(sr), Box::new(cw)),
            ] {
                let flag = Arc::clone(&flag);
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    loop {
                        let Ok(n) = from.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        while flag.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        if to.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    });
    (addr, paused)
}

// ---------------------------------------------------------------- the client side

/// Resolves every spec to the test server with a stored password.
#[derive(Debug)]
pub struct TestResolver {
    /// The server.
    pub addr: SocketAddr,
    /// The stored password (`secret` is right).
    pub password: &'static str,
    /// Changes to the host before resolving.
    pub edit: fn(&mut Host),
}

#[async_trait]
impl HostResolver for TestResolver {
    async fn resolve(&self, _spec: &SshSpec) -> Result<SshTarget, SshError> {
        let mut host = Host {
            label: "test".into(),
            address: self.addr.ip().to_string(),
            port: Some(self.addr.port()),
            username: Some("sverb".into()),
            password: Some(SecretString::from(self.password)),
            env: vec![("FOO".into(), "bar".into()), ("BAR".into(), "nope".into())],
            ..Host::default()
        };
        (self.edit)(&mut host);
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 5;
        Ok(resolve(&host, None, None, &config, || None))
    }
}
