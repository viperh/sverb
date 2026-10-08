//! M1-14 T-11…T-17 against OpenSSH in Docker (the M1-18 harness). The loopback
//! versions run without Docker in `sverb-conn`'s `ssh::auth_loopback`.
//!
//! `#[ignore]`d: `SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_auth -- --ignored`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::Arc,
    time::{Duration, Instant},
};

use sverb_conn::{
    AuthMethod, DisconnectReason, PromptKind, SessionEvent, SessionState,
    agent_client::SocketAgent,
    ssh::{Authenticator, ChainAuthenticator},
};
use sverb_e2e::{
    Headless, HeadlessOptions, Login, Profile, Sshd,
    keys::{self, FixtureKey},
    require_docker, timeout,
};

/// Connected, or the whole event log.
async fn assert_connects(mut s: Headless) {
    s.wait_connected().await.unwrap();
    s.wait_for_text("$", timeout()).await.unwrap();
    s.close().await;
}

/// T-11: password auth.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t11_password() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    assert_connects(Headless::connect(Login::sshd_password(&sshd))).await;
}

/// T-12: ed25519 and ecdsa keys; RSA 4096 signs with `rsa-sha2-512` (server log).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t12_key_auth() {
    require_docker!();
    let sshd = Sshd::start(Profile::Key).await.unwrap();
    for key in [
        FixtureKey::Ed25519,
        FixtureKey::EcdsaP256,
        FixtureKey::Rsa4096,
    ] {
        assert_connects(Headless::connect(Login::sshd_key(&sshd, key))).await;
    }
    let logs = sshd.logs().await.unwrap();
    assert!(logs.contains("rsa-sha2-512"), "{logs}");
}

/// T-13: an encrypted key prompts for its passphrase; with the stored passphrase
/// there is no prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t13_encrypted_key() {
    require_docker!();
    let sshd = Sshd::start(Profile::Key).await.unwrap();
    let mut s = Headless::connect(Login {
        passphrase: None,
        ..Login::sshd_key(&sshd, FixtureKey::Ed25519Encrypted)
    });
    let prompt = s
        .wait_event("passphrase prompt", |e| {
            matches!(e, SessionEvent::Prompt(_))
        })
        .await
        .unwrap();
    let SessionEvent::Prompt(prompt) = prompt else {
        unreachable!()
    };
    assert!(
        matches!(prompt.kind, PromptKind::Passphrase { .. }),
        "{prompt:?}"
    );
    s.answer(&[keys::PASSPHRASE]).await;
    assert_connects(s).await;

    // Stored passphrase: no prompt.
    let mut s = Headless::connect(Login::sshd_key(&sshd, FixtureKey::Ed25519Encrypted));
    s.wait_connected().await.unwrap();
    assert!(
        !s.events()
            .iter()
            .any(|e| matches!(e, SessionEvent::Prompt(_))),
        "{:?}",
        s.events()
    );
    s.close().await;
}

/// T-14: certificate auth (`TrustedUserCAKeys`); the key alone is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t14_certificate() {
    require_docker!();
    let sshd = Sshd::start(Profile::Cert).await.unwrap();
    assert_connects(Headless::connect(Login::sshd_key(&sshd, FixtureKey::Cert))).await;
    let logs = sshd.logs().await.unwrap();
    assert!(
        logs.contains("Accepted publickey") || logs.contains("Accepted certificate"),
        "{logs}"
    );

    let mut s = Headless::connect(Login {
        certificates: Vec::new(),
        ..Login::sshd_key(&sshd, FixtureKey::Cert)
    });
    let state = s
        .wait_state("Disconnected", |st| {
            matches!(
                st,
                SessionState::Disconnected { .. } | SessionState::Connected { .. }
            )
        })
        .await
        .unwrap();
    assert!(
        matches!(
            state,
            SessionState::Disconnected {
                reason: DisconnectReason::Auth,
                ..
            }
        ),
        "{state:?}"
    );
    s.close().await;
}

/// T-15: keyboard-interactive through PAM: the prompt round completes with the OTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t15_keyboard_interactive() {
    require_docker!();
    let sshd = Sshd::start(Profile::Kbd).await.unwrap();
    let mut s = Headless::connect(Login {
        password: None,
        ..Login::sshd_password(&sshd)
    });
    let ev = s
        .wait_event("kbd prompt", |e| matches!(e, SessionEvent::Prompt(_)))
        .await
        .unwrap();
    let SessionEvent::Prompt(prompt) = ev else {
        unreachable!()
    };
    assert_eq!(prompt.method, AuthMethod::KeyboardInteractive, "{prompt:?}");
    assert_eq!(prompt.prompts.len(), 1, "{prompt:?}");
    s.answer(&[keys::OTP]).await;
    assert_connects(s).await;
}

// ---------------------------------------------------------------- a real ssh-agent

/// `ssh-agent -D -a <dir>/agent.sock` with its own socket (never the user's agent).
struct TestAgent {
    dir: PathBuf,
    child: Child,
}

impl TestAgent {
    fn start() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("sverb-e2e-agent-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("agent.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .env_remove("SSH_AUTH_SOCK")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("ssh-agent");
        let deadline = Instant::now() + timeout();
        while !sock.exists() {
            assert!(Instant::now() < deadline, "ssh-agent did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { dir, child }
    }

    fn sock(&self) -> PathBuf {
        self.dir.join("agent.sock")
    }

    /// Generate a throwaway key and add it; or add `private` (a key file).
    fn add(&self, private: Option<&Path>) {
        let path = match private {
            Some(p) => {
                let dst = self.dir.join(p.file_name().unwrap());
                std::fs::copy(p, &dst).unwrap();
                set_private(&dst);
                dst
            }
            None => {
                let n = std::fs::read_dir(&self.dir).unwrap().count();
                let p = self.dir.join(format!("throwaway{n}"));
                let ok = Command::new("ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(&p)
                    .status()
                    .unwrap()
                    .success();
                assert!(ok, "ssh-keygen");
                p
            }
        };
        let ok = Command::new("ssh-add")
            .arg(&path)
            .env("SSH_AUTH_SOCK", self.sock())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "ssh-add {}", path.display());
    }

    fn authenticator(&self) -> Arc<dyn Authenticator> {
        Arc::new(ChainAuthenticator::new().with_agent(Arc::new(SocketAgent { path: self.sock() })))
    }
}

fn set_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn with_agent(agent: &TestAgent) -> HeadlessOptions {
    HeadlessOptions {
        authenticator: Some(agent.authenticator()),
        ..HeadlessOptions::default()
    }
}

/// T-16: `MaxAuthTries 2` with five agent identities and no configured key → fails
/// gracefully; with a configured key → succeeds without asking the agent
/// (IdentitiesOnly).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t16_max_auth_tries() {
    require_docker!();
    let sshd = Sshd::start(Profile::MaxAuth2).await.unwrap();
    let agent = TestAgent::start();
    for _ in 0..4 {
        agent.add(None);
    }
    agent.add(Some(&keys::keys_dir().join("id_ed25519")));
    let login = Login {
        password: None,
        ..Login::sshd_password(&sshd)
    };
    let mut s = Headless::connect_with(login, with_agent(&agent));
    let state = s
        .wait_state("Disconnected", |st| {
            matches!(
                st,
                SessionState::Disconnected { .. } | SessionState::Connected { .. }
            )
        })
        .await
        .unwrap();
    assert!(
        matches!(
            state,
            SessionState::Disconnected {
                reason: DisconnectReason::Auth,
                ..
            }
        ),
        "{state:?}"
    );
    let err = s
        .events()
        .iter()
        .find_map(|e| match e {
            SessionEvent::Error(r) => Some(r.short.clone()),
            _ => None,
        })
        .unwrap_or_default();
    assert!(err.contains("Permission denied"), "{err}");
    s.close().await;

    let s = Headless::connect_with(
        Login::sshd_key(&sshd, FixtureKey::Ed25519),
        with_agent(&agent),
    );
    assert_connects(s).await;
}

/// T-17: a real `ssh-agent` holding the authorized key, no key configured → success
/// through the agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t17_agent_auth() {
    require_docker!();
    let sshd = Sshd::start(Profile::Key).await.unwrap();
    let agent = TestAgent::start();
    agent.add(Some(&keys::keys_dir().join("id_ed25519")));
    let login = Login {
        password: None,
        ..Login::sshd_password(&sshd)
    };
    let mut s = Headless::connect_with(login, with_agent(&agent));
    s.wait_connected().await.unwrap();
    assert!(s.events().iter().any(|e| matches!(
        e,
        SessionEvent::State(SessionState::Authenticating {
            method: AuthMethod::Agent,
            ..
        })
    )));
    s.close().await;
}
