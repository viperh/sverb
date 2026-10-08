//! M2-06 tests: HTTP CONNECT and SOCKS5 against in-process mock proxies, ProxyCommand
//! streams, the approval stub, and SSH through each proxy kind to the in-process
//! russh server (no Docker). The Docker variants (T-09/T-10/T-11) are `#[ignore]`d at
//! the end for the M1-18 harness.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use sverb_core::{
    model::{DeviceId, ItemId},
    secret::SecretString,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::{TcpListener, TcpStream},
};

use super::*;
use crate::ssh::testing::start_server;

const WAIT: Duration = Duration::from_secs(10);

fn creds(user: &str, pw: &str) -> ProxyCredentials {
    ProxyCredentials {
        user: user.into(),
        password: Some(SecretString::from(pw)),
    }
}

fn target<'a>(host: &'a str, port: u16) -> HopTarget<'a> {
    HopTarget {
        host,
        port,
        user: "sverb",
        label: "db",
    }
}

// ------------------------------------------------------------- HTTP CONNECT

/// T-01: request formatting without and with auth, and an IPv6 target.
#[test]
fn t01_http_connect_request_format() {
    assert_eq!(
        connect_request("db.example", 22, None),
        "CONNECT db.example:22 HTTP/1.1\r\nHost: db.example:22\r\n\r\n"
    );
    assert_eq!(
        connect_request("db.example", 2222, Some(&creds("alice", "s3cret"))),
        "CONNECT db.example:2222 HTTP/1.1\r\nHost: db.example:2222\r\n\
         Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n\r\n"
    );
    for host in ["2001:db8::1", "[2001:db8::1]"] {
        assert_eq!(
            connect_request(host, 22, None),
            "CONNECT [2001:db8::1]:22 HTTP/1.1\r\nHost: [2001:db8::1]:22\r\n\r\n"
        );
    }
}

/// Run CONNECT against a scripted proxy that answers `reply` (after reading the
/// request) and keeps the connection open.
async fn http_against(
    reply: Vec<u8>,
    auth: Option<&ProxyCredentials>,
    limits: http_connect::Limits,
) -> (
    Result<PrefixedStream<tokio::io::DuplexStream>, HttpConnectError>,
    String,
) {
    let (client, mut server) = duplex(64 * 1024);
    let seen = Arc::new(StdMutex::new(String::new()));
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.ends_with(b"\r\n\r\n") {
            let n = server.read(&mut chunk).await.unwrap();
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        *seen2.lock().unwrap() = String::from_utf8(buf).unwrap();
        server.write_all(&reply).await.unwrap();
        // Echo afterwards (the tunnel).
        loop {
            let Ok(n) = server.read(&mut chunk).await else {
                return;
            };
            if n == 0 || server.write_all(&chunk[..n]).await.is_err() {
                return;
            }
        }
    });
    let res = http_connect::connect(client, "db.example", 22, auth, limits).await;
    let seen = seen.lock().unwrap().clone();
    (res, seen)
}

fn limits() -> http_connect::Limits {
    http_connect::Limits::with_timeout(Duration::from_secs(5))
}

/// T-02: bytes after the header terminator come first on the stream.
#[tokio::test]
async fn t02_http_early_bytes_are_preserved() {
    let reply =
        b"HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\nSSH-2.0-early\r\n".to_vec();
    let (res, request) = http_against(reply, None, limits()).await;
    assert!(request.starts_with("CONNECT db.example:22 HTTP/1.1\r\n"));
    let mut stream = res.unwrap();
    assert_eq!(stream.pending(), b"SSH-2.0-early\r\n");
    let mut first = [0u8; 15];
    stream.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"SSH-2.0-early\r\n");
    // Then the tunnel itself (the mock echoes).
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    // Any 2xx is success.
    let (res, _) = http_against(b"HTTP/1.0 204 No Content\r\n\r\n".to_vec(), None, limits()).await;
    assert!(res.unwrap().pending().is_empty());
}

/// T-03: 407, other codes, oversized headers, slowloris.
#[tokio::test]
async fn t03_http_errors() {
    let reply = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec();
    let (res, request) = http_against(reply.clone(), Some(&creds("a", "wrong")), limits()).await;
    assert!(request.contains("Proxy-Authorization: Basic "));
    assert_eq!(
        res.unwrap_err().to_string(),
        "proxy: authentication failed (407)"
    );
    let (res, _) = http_against(reply, None, limits()).await;
    assert_eq!(
        res.unwrap_err().to_string(),
        "proxy: authentication required (407)"
    );

    let reply = b"HTTP/1.1 502 Bad\x1b[31mGateway\r\n\r\n".to_vec();
    let (res, _) = http_against(reply, None, limits()).await;
    let err = res.unwrap_err();
    assert!(matches!(err, HttpConnectError::Status { code: 502, .. }));
    // Sanitized: no escape character.
    assert_eq!(
        err.to_string(),
        "proxy: CONNECT refused (502 Bad[31mGateway)"
    );
    let ssh = err.into_ssh_error("proxy:3128");
    assert_eq!(ssh.reason(), crate::DisconnectReason::Connect);
    assert_eq!(ssh.report().chain, ["HTTP proxy proxy:3128"]);

    let mut big = b"HTTP/1.1 200 OK\r\n".to_vec();
    while big.len() <= http_connect::MAX_HEADER_BYTES {
        big.extend_from_slice(b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    big.extend_from_slice(b"\r\n");
    let (res, _) = http_against(big, None, limits()).await;
    assert!(matches!(
        res.unwrap_err(),
        HttpConnectError::HeadersTooLarge
    ));

    let (res, _) = http_against(b"FTP nope\r\n\r\n".to_vec(), None, limits()).await;
    assert!(matches!(res.unwrap_err(), HttpConnectError::Malformed(_)));
}

/// T-03: no `\r\n\r\n` within the timeout → timeout.
#[tokio::test(start_paused = true)]
async fn t03_http_slowloris_times_out() {
    let started = tokio::time::Instant::now();
    let (res, _) = http_against(
        b"HTTP/1.1 200 OK\r\nX-Slow: ".to_vec(),
        None,
        http_connect::Limits::with_timeout(Duration::from_secs(15)),
    )
    .await;
    assert!(matches!(res.unwrap_err(), HttpConnectError::Timeout));
    assert_eq!(started.elapsed(), Duration::from_secs(15));
}

// ------------------------------------------------------------- SOCKS5 mock

/// What the mock SOCKS5 server saw.
#[derive(Debug, Default, Clone)]
struct SocksSeen {
    methods: Vec<u8>,
    auth: Option<(String, String)>,
    atyp: u8,
    host: String,
    port: u16,
}

#[derive(Clone)]
struct SocksMock {
    /// Require user/password (`Some((user, pass))`).
    creds: Option<(&'static str, &'static str)>,
    /// The CONNECT reply code.
    reply: u8,
    /// Where a successful CONNECT goes (any name resolves here: "remote DNS").
    upstream: Option<SocketAddr>,
}

async fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await.unwrap();
    buf
}

async fn socks_mock(mock: SocksMock) -> (SocketAddr, Arc<StdMutex<Vec<SocksSeen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(StdMutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mock = mock.clone();
            let log = Arc::clone(&log2);
            tokio::spawn(async move {
                let mut seen = SocksSeen::default();
                let head = read_n(&mut s, 2).await;
                assert_eq!(head[0], 5);
                seen.methods = read_n(&mut s, usize::from(head[1])).await;
                if let Some((user, pass)) = mock.creds {
                    if !seen.methods.contains(&2) {
                        s.write_all(&[5, 0xff]).await.unwrap();
                        log.lock().unwrap().push(seen);
                        return;
                    }
                    s.write_all(&[5, 2]).await.unwrap();
                    let v = read_n(&mut s, 2).await;
                    assert_eq!(v[0], 1);
                    let u = read_n(&mut s, usize::from(v[1])).await;
                    let plen = read_n(&mut s, 1).await[0];
                    let p = read_n(&mut s, usize::from(plen)).await;
                    let (u, p) = (String::from_utf8(u).unwrap(), String::from_utf8(p).unwrap());
                    let ok = u == user && p == pass;
                    seen.auth = Some((u, p));
                    s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                    if !ok {
                        log.lock().unwrap().push(seen);
                        return;
                    }
                } else {
                    s.write_all(&[5, 0]).await.unwrap();
                }
                let req = read_n(&mut s, 4).await;
                assert_eq!(&req[..3], &[5, 1, 0]);
                seen.atyp = req[3];
                match req[3] {
                    3 => {
                        let len = read_n(&mut s, 1).await[0];
                        seen.host =
                            String::from_utf8(read_n(&mut s, usize::from(len)).await).unwrap();
                    }
                    1 => seen.host = format!("{:?}", read_n(&mut s, 4).await),
                    4 => seen.host = format!("{:?}", read_n(&mut s, 16).await),
                    _ => panic!("bad atyp"),
                }
                let p = read_n(&mut s, 2).await;
                seen.port = u16::from_be_bytes([p[0], p[1]]);
                log.lock().unwrap().push(seen);
                s.write_all(&[5, mock.reply, 0, 1, 127, 0, 0, 1, 0, 22])
                    .await
                    .unwrap();
                if mock.reply != 0 {
                    return;
                }
                if let Some(up) = mock.upstream {
                    let mut up = TcpStream::connect(up).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                }
            });
        }
    });
    (addr, log)
}

/// T-04: CONNECT by domain name (ATYP 0x03, not a resolved IP), user/password
/// sub-negotiation, reply 0x05 → "connection refused".
#[tokio::test]
async fn t04_socks5_domain_auth_and_reply_codes() {
    let (proxy, log) = socks_mock(SocksMock {
        creds: Some(("alice", "pw")),
        reply: 5,
        upstream: None,
    })
    .await;
    let auth = creds("alice", "pw");
    let err = socks5::connect(
        &proxy.to_string(),
        Some(&auth),
        "db.internal.example",
        2222,
        WAIT,
    )
    .await
    .unwrap_err();
    assert_eq!(err.message(), "proxy: connection refused by destination");
    let seen = log.lock().unwrap()[0].clone();
    assert!(seen.methods.contains(&2), "{seen:?}");
    assert_eq!(seen.auth, Some(("alice".into(), "pw".into())));
    assert_eq!(seen.atyp, 3);
    assert_eq!(seen.host, "db.internal.example");
    assert_eq!(seen.port, 2222);

    // A wrong password.
    let bad = creds("alice", "nope");
    let err = socks5::connect(&proxy.to_string(), Some(&bad), "db", 22, WAIT)
        .await
        .unwrap_err();
    assert_eq!(err.message(), "proxy: authentication failed");

    // Without credentials the proxy accepts no method.
    let err = socks5::connect(&proxy.to_string(), None, "db", 22, WAIT)
        .await
        .unwrap_err();
    assert!(
        err.message().starts_with("proxy: authentication required"),
        "{}",
        err.message()
    );

    // An unreachable proxy.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap().to_string();
    drop(closed);
    let err = socks5::connect(&dead, None, "db", 22, WAIT)
        .await
        .unwrap_err();
    assert!(
        err.message().starts_with("proxy: could not connect to"),
        "{}",
        err.message()
    );
}

// ------------------------------------------------------------- ProxyCommand

/// T-05: substitution.
#[test]
fn t05_proxy_command_substitution() {
    assert_eq!(expand_command("nc %h %p", "a", 22, "u").unwrap(), "nc a 22");
    assert_eq!(
        expand_command("ssh -W %h:%p %r@bastion", "db", 2222, "ops").unwrap(),
        "ssh -W db:2222 ops@bastion"
    );
    assert_eq!(
        expand_command("echo 100%%", "a", 22, "u").unwrap(),
        "echo 100%"
    );
    assert_eq!(
        expand_command("x %r", "a", 22, "deploy").unwrap(),
        "x deploy"
    );
    assert_eq!(
        expand_command("nc %h %p", "[2001:db8::1]", 22, "u").unwrap(),
        "nc 2001:db8::1 22"
    );
    // Unsafe substituted values are quoted.
    assert_eq!(
        expand_command("x %r", "a", 22, "a b;rm -rf ~").unwrap(),
        "x 'a b;rm -rf ~'"
    );
    assert_eq!(
        expand_command("nc %x", "a", 22, "u").unwrap_err(),
        CommandError::UnknownToken('x')
    );
    assert_eq!(
        validate_command("nc %h %x"),
        Err(CommandError::UnknownToken('x'))
    );
    assert_eq!(validate_command("nc %"), Err(CommandError::TrailingPercent));
    assert_eq!(validate_command("  "), Err(CommandError::Empty));
    assert_eq!(validate_command("nc %h %p %r %%"), Ok(()));
}

/// T-06: data flows both ways through a ProxyCommand (`cat` echoes).
#[cfg(unix)]
#[tokio::test]
async fn t06_proxy_command_stream_echo() {
    let mut stream = ProxyCommandStream::spawn("cat").unwrap();
    stream.write_all(b"hello through cat\n").await.unwrap();
    let mut buf = [0u8; 18];
    tokio::time::timeout(WAIT, stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"hello through cat\n");
    // Closing stdin ends `cat`: a clean EOF (nothing on stderr).
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let n = tokio::time::timeout(WAIT, stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// T-07: the child is killed and reaped within 2 s of the stream being dropped.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_child_killed_on_close() {
    let stream = ProxyCommandStream::spawn("sleep 1000").unwrap();
    let pid = stream.pid().unwrap();
    assert!(alive(pid));
    drop(stream);
    let deadline = Instant::now() + Duration::from_secs(2);
    while alive(pid) {
        assert!(Instant::now() < deadline, "ProxyCommand {pid} still alive");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// T-08: stderr ends up in the error when the command gives up (the debug-log half is
/// `tests/proxy_logs.rs`, a process of its own for reliable capture).
#[cfg(unix)]
#[tokio::test]
async fn t08_stderr_captured() {
    let mut stream = ProxyCommandStream::spawn(
        "sh -c 'echo \"nc: connect to db port 22: refused\" >&2; exit 1'",
    )
    .unwrap();
    let mut buf = Vec::new();
    let err = tokio::time::timeout(WAIT, stream.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    assert_eq!(
        err.to_string(),
        "ProxyCommand closed the connection: nc: connect to db port 22: refused"
    );
    assert_eq!(stream.stderr_tail(), ["nc: connect to db port 22: refused"]);
}

/// T-12: a ProxyCommand stamped by another device needs approval and is not run.
#[cfg(unix)]
#[tokio::test]
async fn t12_approval_gate() {
    let dir = std::env::temp_dir().join(format!("sverb-m2-06-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("ran");
    let _ = std::fs::remove_file(&marker);
    let here = DeviceId::from_bytes([1; 16]);
    let other = DeviceId::from_bytes([2; 16]);
    let item = Some(ItemId::from_bytes([7; 16]));
    let command = format!("touch {} && cat", marker.display());
    let synced = ProxyConfig::Command {
        command: command.clone(),
        origin: ValueOrigin {
            item_id: item,
            written_by: Some(other),
            this_device: Some(here),
        },
    };
    let err = open_first_hop(&synced, target("db", 22), WAIT, &StampApprovals)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, crate::ssh::SshError::NeedsApproval { command: c, .. } if *c == command)
    );
    assert_eq!(
        err.message(),
        "host \"db\" uses a local command that has not been approved on this device. Run: sverb approve db"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!marker.exists(), "an unapproved ProxyCommand ran");

    // A stamp without a known local device is not trusted either.
    let unknown = ValueOrigin {
        item_id: item,
        written_by: Some(here),
        this_device: None,
    };
    assert_eq!(
        StampApprovals.check(COMMAND_FIELD, &command, &unknown),
        Approval::NeedsApproval
    );

    // Typed here → runs.
    let local = ProxyConfig::Command {
        command,
        origin: ValueOrigin {
            item_id: item,
            written_by: Some(here),
            this_device: Some(here),
        },
    };
    let hop = open_first_hop(&local, target("db", 22), WAIT, &StampApprovals)
        .await
        .unwrap();
    let deadline = Instant::now() + WAIT;
    while !marker.exists() {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(hop);
    let _ = std::fs::remove_dir_all(&dir);
}

/// M2-10 T-04/T-05/T-10 (connector level): with the device's explicit approvals, a
/// stored ProxyCommand runs only with a row for its exact value, whoever stamped it;
/// a remote change asks again; a session denial fails with "blocked by approval
/// policy".
#[cfg(unix)]
#[tokio::test]
async fn m2_10_device_approvals_gate() {
    use sverb_core::resolve::approval::DeviceApprovals;
    let dir = std::env::temp_dir().join(format!("sverb-m2-10-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("ran");
    let _ = std::fs::remove_file(&marker);
    let here = DeviceId::from_bytes([1; 16]);
    let item = ItemId::from_bytes([7; 16]);
    let command = format!("touch {} && cat", marker.display());
    // Stamped by this device, but no row: the stamp alone is not trusted.
    let config = |command: &str| ProxyConfig::Command {
        command: command.to_owned(),
        origin: ValueOrigin {
            item_id: Some(item),
            written_by: Some(here),
            this_device: Some(here),
        },
    };
    let approvals = DeviceApprovals::new();
    let err = open_first_hop(&config(&command), target("db", 22), WAIT, &approvals)
        .await
        .unwrap_err();
    assert!(matches!(err, crate::ssh::SshError::NeedsApproval { .. }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!marker.exists(), "an unapproved ProxyCommand ran");

    // Denied for the session: blocked, not asked.
    approvals.deny(item, COMMAND_FIELD, &command);
    let err = open_first_hop(&config(&command), target("db", 22), WAIT, &approvals)
        .await
        .unwrap_err();
    assert_eq!(
        err.message(),
        "proxy: the ProxyCommand was blocked by approval policy"
    );

    // Allowed: runs.
    approvals.approve(item, COMMAND_FIELD, &command);
    let hop = open_first_hop(&config(&command), target("db", 22), WAIT, &approvals)
        .await
        .unwrap();
    let deadline = Instant::now() + WAIT;
    while !marker.exists() {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(hop);

    // Changed remotely: asks again.
    let changed = format!("{command} # changed");
    let err = open_first_hop(&config(&changed), target("db", 22), WAIT, &approvals)
        .await
        .unwrap_err();
    assert!(matches!(err, crate::ssh::SshError::NeedsApproval { .. }));

    // An unsaved target (no item, typed into this process) needs no row.
    let typed = ProxyConfig::Command {
        command: "cat".into(),
        origin: ValueOrigin::default(),
    };
    assert_eq!(
        approvals.check(COMMAND_FIELD, "cat", &ValueOrigin::default()),
        Approval::Approved
    );
    drop(typed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn proxy_addresses() {
    assert_eq!(split_host_port("proxy:1080"), Some(("proxy".into(), 1080)));
    assert_eq!(split_host_port("[::1]:3128"), Some(("::1".into(), 3128)));
    assert_eq!(split_host_port("proxy"), None);
    assert_eq!(split_host_port("::1:80"), None);
    assert_eq!(split_host_port("proxy:0"), None);
    assert!(validate_proxy_addr("10.0.0.1:8080").is_ok());
    assert!(validate_proxy_addr("10.0.0.1").is_err());
    let c = creds("u", "hunter2");
    assert!(!format!("{c:?}").contains("hunter2"));
}

// ------------------------------------------------------------- SSH through proxies

/// A client that accepts any host key (the stream is what is tested here).
struct AnyKey;

impl russh::client::Handler for AnyKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Handshake and password auth over `hop` against the in-process server.
async fn ssh_over(hop: FirstHop) {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = tokio::time::timeout(
        WAIT,
        russh::client::connect_stream(config, hop.stream, AnyKey),
    )
    .await
    .unwrap()
    .unwrap();
    let auth = handle
        .authenticate_password("sverb", "secret")
        .await
        .unwrap();
    assert!(auth.success(), "{auth:?}");
}

/// SSH through the mock SOCKS5 proxy, by name (the proxy "resolves" it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_through_socks5() {
    let (server, _) = start_server().await;
    let (proxy, log) = socks_mock(SocksMock {
        creds: None,
        reply: 0,
        upstream: Some(server),
    })
    .await;
    let config = ProxyConfig::Socks5 {
        addr: proxy.to_string(),
        auth: None,
    };
    let hop = open_first_hop(
        &config,
        target("ssh.only-the-proxy-knows.invalid", 22),
        WAIT,
        &StampApprovals,
    )
    .await
    .unwrap();
    assert_eq!(hop.peer, format!("socks5 {proxy}"));
    ssh_over(hop).await;
    assert_eq!(
        log.lock().unwrap()[0].host,
        "ssh.only-the-proxy-knows.invalid"
    );
}

/// A minimal HTTP CONNECT proxy to `upstream` that sends `early` right after its
/// headers when asked to, and checks basic auth when `auth` is set.
async fn http_proxy(upstream: SocketAddr, auth: Option<&'static str>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut b = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap() == 0 {
                        return;
                    }
                    buf.push(b[0]);
                }
                let head = String::from_utf8(buf).unwrap();
                if let Some(token) = auth
                    && !head.contains(&format!("Proxy-Authorization: Basic {token}\r\n"))
                {
                    let _ = s
                        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        .await;
                    return;
                }
                let mut up = TcpStream::connect(upstream).await.unwrap();
                // Read the server's banner first and send it in the same write as the
                // response headers: the early-data case.
                let mut banner = vec![0u8; 256];
                let n = up.read(&mut banner).await.unwrap();
                let mut reply = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
                reply.extend_from_slice(&banner[..n]);
                s.write_all(&reply).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    addr
}

/// SSH through HTTP CONNECT with basic auth; the server's banner arrives in the same
/// packet as the 200 (early data). A wrong password → the 407 message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_through_http_connect() {
    let (server, _) = start_server().await;
    // base64("alice:pw")
    let proxy = http_proxy(server, Some("YWxpY2U6cHc=")).await;
    let config = ProxyConfig::Http {
        addr: proxy.to_string(),
        auth: Some(creds("alice", "pw")),
    };
    let hop = open_first_hop(&config, target("127.0.0.1", 22), WAIT, &StampApprovals)
        .await
        .unwrap();
    ssh_over(hop).await;

    let wrong = ProxyConfig::Http {
        addr: proxy.to_string(),
        auth: Some(creds("alice", "nope")),
    };
    let err = open_first_hop(&wrong, target("127.0.0.1", 22), WAIT, &StampApprovals)
        .await
        .unwrap_err();
    assert_eq!(err.message(), "proxy: authentication failed (407)");
}

/// SSH through a ProxyCommand (`socat - TCP:%h:%p`) when socat is installed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_through_proxy_command() {
    if std::process::Command::new("socat")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("socat not installed; skipping");
        return;
    }
    let (server, _) = start_server().await;
    let config = ProxyConfig::Command {
        command: "socat - TCP:%h:%p".into(),
        origin: ValueOrigin::default(),
    };
    let port = server.port();
    let hop = open_first_hop(&config, target("127.0.0.1", port), WAIT, &StampApprovals)
        .await
        .unwrap();
    ssh_over(hop).await;
}

// ------------------------------------------------------------- Docker (M1-18)

/// T-09: SOCKS5 via a `microsocks`/`dante` container → SSH connects through it.
#[test]
#[ignore = "needs Docker (M1-18 harness)"]
fn t09_e2e_socks5_container() {}

/// T-10: HTTP CONNECT via `tinyproxy` with basic auth; wrong password → 407 message.
#[test]
#[ignore = "needs Docker (M1-18 harness)"]
fn t10_e2e_http_connect_container() {}

/// T-11: ProxyCommand `nc %h %p` from the test image → connects.
#[test]
#[ignore = "needs Docker (M1-18 harness)"]
fn t11_e2e_proxy_command_container() {}
