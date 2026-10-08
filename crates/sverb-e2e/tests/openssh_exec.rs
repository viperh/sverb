//! M2-04 T-01 (property) and T-02…T-09 against OpenSSH in Docker (the M1-18 harness).
//! The loopback versions run without Docker in `sverb-conn`'s `ssh::exec_tests`.
//!
//! `#[ignore]`d: `SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_exec -- --ignored`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use sverb_conn::{
    SshSpec,
    ssh::{
        HostResolver, InsecureAcceptAnyHostKey, SshConnector, SshError, SshTarget,
        exec::{ExecOpts, ExecPrompts, OUTPUT_CAP, SshConnection, TIMEOUT_SIGNAL, exec},
        install_key::{InstallOutcome, install_command, install_on},
        test_keys,
    },
};
use sverb_core::shell_quote::posix_single_quote;
use sverb_e2e::{Login, Profile, Sshd, require_docker};

#[derive(Debug)]
struct Fixed(Login);

#[async_trait]
impl HostResolver for Fixed {
    async fn resolve(&self, _spec: &SshSpec) -> Result<SshTarget, SshError> {
        Ok(self.0.target())
    }
}

async fn open(login: Login) -> SshConnection {
    let connector = SshConnector::new(Arc::new(Fixed(login)))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
    SshConnection::open(&connector, &SshSpec::default(), ExecPrompts::none())
        .await
        .expect("connects")
}

fn secs(n: u64) -> ExecOpts {
    ExecOpts::with_timeout(Duration::from_secs(n))
}

async fn install(sshd: &Sshd, public: &str) -> InstallOutcome {
    let conn = open(Login::sshd_password(sshd)).await;
    let out = install_on(
        &conn,
        &install_command(public).unwrap(),
        Duration::from_secs(30),
    )
    .await;
    conn.close().await;
    out
}

/// T-01 (property): `sh -c "printf %s <quoted>"` round-trips 200 strings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t01_quote_roundtrip_in_container() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let conn = open(Login::sshd_password(&sshd)).await;
    let alphabet: Vec<char> = "aZ0 '\"\\$`\n\t*?~#;&|()<>!{}%é✓".chars().collect();
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for _ in 0..200 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = usize::try_from(state % 20).unwrap();
        let s: String = (0..len)
            .map(|i| alphabet[usize::try_from((state >> (i % 50)) % 31).unwrap() % alphabet.len()])
            .collect();
        let r = exec(
            &conn,
            &format!("printf %s {}", posix_single_quote(&s).unwrap()),
            secs(10),
        )
        .await
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&r.stdout), s);
    }
    conn.close().await;
}

/// T-02…T-05: basic exec, output cap, timeout, PTY merge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t02_t05_exec() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let conn = open(Login::sshd_password(&sshd)).await;
    let r = exec(&conn, "echo hi; echo err >&2; exit 3", secs(10))
        .await
        .unwrap();
    assert_eq!(
        (&r.stdout[..], &r.stderr[..], r.exit),
        (&b"hi\n"[..], &b"err\n"[..], Some(3))
    );

    let r = exec(&conn, "head -c 3000000 /dev/zero", secs(60))
        .await
        .unwrap();
    assert_eq!(r.stdout.len(), OUTPUT_CAP);
    assert!(r.truncated);
    assert_eq!(r.exit, Some(0));

    let started = std::time::Instant::now();
    let r = exec(&conn, "sleep 100", secs(1)).await.unwrap();
    assert_eq!(r.signal.as_deref(), Some(TIMEOUT_SIGNAL));
    assert!(started.elapsed() < Duration::from_secs(4));

    let r = exec(
        &conn,
        "echo a; echo b >&2",
        ExecOpts {
            request_pty: Some(true),
            ..secs(10)
        },
    )
    .await
    .unwrap();
    let out = String::from_utf8_lossy(&r.stdout);
    assert!(out.contains('a') && out.contains('b'), "{out:?}");
    assert!(r.stderr.is_empty());
    conn.close().await;
}

/// T-06, T-07, T-09: installed, already present, key auth works; a quote in the
/// comment; `~/.ssh` 700 and `authorized_keys` 600.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t06_t07_t09_install() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    assert_eq!(
        install(&sshd, test_keys::ED25519_PUB).await,
        InstallOutcome::Installed
    );
    assert_eq!(
        install(&sshd, test_keys::ED25519_PUB).await,
        InstallOutcome::AlreadyPresent
    );
    let conn = open(Login {
        password: None,
        key: Some(test_keys::ED25519.to_owned()),
        ..Login::sshd_password(&sshd)
    })
    .await;
    assert_eq!(
        &exec(&conn, "echo ok", secs(10)).await.unwrap().stdout[..],
        b"ok\n"
    );
    conn.close().await;

    let quoted = test_keys::ED25519_ENCRYPTED_PUB.replace("enc@test", "bob's key");
    assert_eq!(install(&sshd, &quoted).await, InstallOutcome::Installed);
    let keys = sshd.exec("cat ~/.ssh/authorized_keys").await.unwrap();
    assert!(keys.stdout.lines().any(|l| l == quoted), "{}", keys.stdout);

    let modes = sshd
        .exec("stat -c %a ~/.ssh ~/.ssh/authorized_keys")
        .await
        .unwrap();
    assert_eq!(
        modes.stdout.split_whitespace().collect::<Vec<_>>(),
        ["700", "600"]
    );
}

/// T-08: the Windows-like profile is reported as unsupported.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t08_windows_like() {
    require_docker!();
    let sshd = Sshd::start(Profile::WindowsLike).await.unwrap();
    assert_eq!(
        install(&sshd, test_keys::ED25519_PUB).await,
        InstallOutcome::Unsupported
    );
}
