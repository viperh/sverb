//! ([`Fake`], an [`AuthBackend`]) and a scripted user ([`User`], an [`AuthIo`]).
//! Loopback tests against the in-process russh server are in `ssh/auth_loopback.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use pretty_assertions::assert_eq;
use russh::keys::{
    Certificate, HashAlg, PrivateKey, PublicKey, agent::AgentIdentity,
    ssh_key::private::Ed25519Keypair,
};
use sverb_core::{model::ItemId, secret::SecretString};

use super::{
    auth::*,
    auth_stub::AuthOutcome,
    errors::SshError,
    resolved::{AuthMaterial, KeyMaterial},
    test_keys,
};
use crate::{
    agent_client::{Agent, AgentConnector, AgentError},
    session::{AuthMethod, AuthPrompt, PromptKind, PromptLine},
};

// ---------------------------------------------------------------- the fake server

/// A scripted server. Every request is recorded in `calls`.
struct Fake {
    /// The method list sent with every failure.
    methods: Vec<&'static str>,
    calls: Vec<String>,
    password: Option<&'static str>,
    accept_key: bool,
    accept_cert: bool,
    accept_agent: Option<&'static str>,
    rsa: RsaSigSupport,
    /// Replies to `kbd_start` / `kbd_respond`, in order.
    kbd: VecDeque<KbdReply>,
    kbd_answers: Vec<Vec<String>>,
}

impl Fake {
    fn new(methods: &[&'static str]) -> Self {
        Self {
            methods: methods.to_vec(),
            calls: Vec::new(),
            password: None,
            accept_key: false,
            accept_cert: false,
            accept_agent: None,
            rsa: RsaSigSupport::Sha512,
            kbd: VecDeque::new(),
            kbd_answers: Vec::new(),
        }
    }

    fn fail(&self) -> AuthOutcome {
        AuthOutcome::Failure {
            remaining: self.methods.clone(),
            partial: false,
        }
    }

    fn verdict(&self, ok: bool) -> AuthOutcome {
        if ok {
            AuthOutcome::Success
        } else {
            self.fail()
        }
    }

    fn next_kbd(&mut self) -> KbdReply {
        self.kbd.pop_front().unwrap_or_else(|| KbdReply::Failure {
            remaining: self.methods.clone(),
            partial: false,
        })
    }
}

fn hash_name(hash: Option<HashAlg>) -> &'static str {
    match hash {
        Some(HashAlg::Sha512) => "rsa-sha2-512",
        Some(HashAlg::Sha256) => "rsa-sha2-256",
        None => "default",
        _ => "other",
    }
}

#[async_trait]
impl AuthBackend for Fake {
    async fn none(&mut self, _user: &str) -> Result<AuthOutcome, SshError> {
        self.calls.push("none".into());
        Ok(self.fail())
    }

    async fn password(
        &mut self,
        _user: &str,
        password: &SecretString,
    ) -> Result<AuthOutcome, SshError> {
        self.calls.push(format!("password:{}", password.expose()));
        Ok(self.verdict(self.password == Some(password.expose())))
    }

    async fn publickey(
        &mut self,
        _user: &str,
        key: Arc<PrivateKey>,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        let alg = if key.algorithm().is_rsa() {
            hash_name(hash).to_owned()
        } else {
            key.algorithm().as_str().to_owned()
        };
        self.calls.push(format!("publickey:{alg}"));
        Ok(self.verdict(self.accept_key))
    }

    async fn certificate(
        &mut self,
        _user: &str,
        _key: Arc<PrivateKey>,
        cert: Certificate,
    ) -> Result<AuthOutcome, SshError> {
        self.calls.push(format!("cert:{}", cert.key_id()));
        Ok(self.verdict(self.accept_cert))
    }

    async fn agent_identity(
        &mut self,
        _user: &str,
        _agent: &mut dyn Agent,
        identity: &AgentIdentity,
        _hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        self.calls.push(format!("agent:{}", identity.comment()));
        Ok(self.verdict(self.accept_agent == Some(identity.comment())))
    }

    async fn kbd_start(&mut self, _user: &str) -> Result<KbdReply, SshError> {
        self.calls.push("kbd".into());
        Ok(self.next_kbd())
    }

    async fn kbd_respond(&mut self, answers: &[SecretString]) -> Result<KbdReply, SshError> {
        self.kbd_answers
            .push(answers.iter().map(|a| a.expose().to_owned()).collect());
        Ok(self.next_kbd())
    }

    async fn rsa_support(&mut self) -> RsaSigSupport {
        self.rsa
    }
}

// ---------------------------------------------------------------- the fake user

/// Answers prompts from a script (`None`: cancel; script empty: cancel).
#[derive(Default)]
struct User {
    answers: VecDeque<Option<Vec<&'static str>>>,
    prompts: Vec<AuthPrompt>,
    started: Vec<AuthMethod>,
    accepted: Vec<PromptKind>,
}

impl User {
    fn answering(answers: &[Option<&[&'static str]>]) -> Self {
        Self {
            answers: answers.iter().map(|a| a.map(<[_]>::to_vec)).collect(),
            ..Self::default()
        }
    }
}

#[async_trait]
impl AuthIo for User {
    fn started(&mut self, method: AuthMethod) -> Result<(), SshError> {
        if self.started.last() != Some(&method) {
            self.started.push(method);
        }
        Ok(())
    }

    async fn ask(&mut self, prompt: AuthPrompt) -> Result<Option<Vec<SecretString>>, SshError> {
        self.prompts.push(prompt);
        Ok(self
            .answers
            .pop_front()
            .flatten()
            .map(|a| a.into_iter().map(SecretString::from).collect()))
    }

    fn accepted(&mut self, kind: PromptKind) {
        self.accepted.push(kind);
    }
}

// ---------------------------------------------------------------- the fake agent

#[derive(Debug, Default)]
struct FakeAgent {
    comments: Vec<&'static str>,
    connects: AtomicUsize,
}

struct FakeAgentConn(Vec<AgentIdentity>);

#[async_trait]
impl Agent for FakeAgentConn {
    async fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        Ok(self.0.clone())
    }

    async fn sign(
        &mut self,
        _identity: &AgentIdentity,
        _hash: Option<HashAlg>,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        Ok(Vec::new())
    }
}

fn ed25519_public(seed: u8) -> PublicKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
        .public_key()
        .clone()
}

#[async_trait]
impl AgentConnector for FakeAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let ids = self
            .comments
            .iter()
            .zip(1_u8..)
            .map(|(c, seed)| AgentIdentity::PublicKey {
                key: ed25519_public(seed),
                comment: (*c).to_owned(),
            })
            .collect();
        Ok(Box::new(FakeAgentConn(ids)))
    }
}

fn agent(comments: &[&'static str]) -> Arc<FakeAgent> {
    Arc::new(FakeAgent {
        comments: comments.to_vec(),
        connects: AtomicUsize::new(0),
    })
}

// ---------------------------------------------------------------- helpers

const KEY_ID: ItemId = ItemId::from_bytes([7; 16]);
const HOST_ID: ItemId = ItemId::from_bytes([3; 16]);

fn key(private: &str, certs: &[&str]) -> KeyMaterial {
    KeyMaterial {
        key_id: Some(KEY_ID),
        label: "work".into(),
        private_key: SecretString::from(private),
        passphrase: None,
        certificates: certs.iter().map(|c| (*c).to_owned()).collect(),
    }
}

fn material(key: Option<KeyMaterial>, password: Option<&str>) -> AuthMaterial {
    AuthMaterial {
        password: password.map(SecretString::from),
        key_id: key.as_ref().and_then(|k| k.key_id),
        key,
        max_attempts: 10,
        ..AuthMaterial::default()
    }
}

fn target(auth: &AuthMaterial) -> ChainTarget<'_> {
    ChainTarget {
        user: "deploy",
        label: "db",
        user_at_host: "deploy@db.example".into(),
        host_id: Some(HOST_ID),
        auth,
    }
}

async fn run(
    auth: &AuthMaterial,
    fake: &mut Fake,
    user: &mut User,
    agent: Option<Arc<FakeAgent>>,
) -> Result<(), SshError> {
    let agent = agent.map(|a| a as Arc<dyn AgentConnector>);
    run_chain(&target(auth), fake, user, agent).await
}

fn info(prompts: &[(&str, bool)]) -> KbdReply {
    KbdReply::Info {
        name: String::new(),
        instruction: String::new(),
        prompts: prompts
            .iter()
            .map(|(t, e)| PromptLine {
                text: (*t).to_owned(),
                echo: *e,
            })
            .collect(),
    }
}

const ALL: &[&str] = &[PUBLICKEY, PASSWORD, KEYBOARD_INTERACTIVE];

// ---------------------------------------------------------------- tests

/// Key + cert + password + agent → cert, key, password; the agent is skipped
/// because a key is configured.
#[tokio::test]
async fn t01_order_cert_key_password() {
    let auth = material(
        Some(key(test_keys::ED25519, &[test_keys::ED25519_CERT])),
        Some("stored"),
    );
    let mut fake = Fake::new(&[PUBLICKEY, PASSWORD]);
    let mut user = User::default();
    let agent = agent(&["a", "b"]);
    let err = run(&auth, &mut fake, &mut user, Some(Arc::clone(&agent)))
        .await
        .unwrap_err();
    assert_eq!(
        fake.calls,
        [
            "none",
            "cert:testcert",
            "publickey:ssh-ed25519",
            "password:stored"
        ]
    );
    assert_eq!(agent.connects.load(Ordering::SeqCst), 0);
    // The stored password failed: the user was asked (and cancelled).
    assert_eq!(user.prompts.len(), 1);
    assert_eq!(
        user.prompts[0].kind,
        PromptKind::Password {
            host: Some(HOST_ID)
        }
    );
    assert_eq!(
        err.message(),
        "Permission denied (methods tried: publickey, password)"
    );
    assert_eq!(
        user.started,
        [
            AuthMethod::None,
            AuthMethod::PublicKey,
            AuthMethod::Password
        ]
    );
}

/// No configured key → agent identities after the key steps; a configured key →
/// no agent attempts at all.
#[tokio::test]
async fn t02_identities_only() {
    let auth = material(None, Some("stored"));
    let mut fake = Fake::new(&[PUBLICKEY, PASSWORD]);
    fake.password = Some("stored");
    let mut user = User::default();
    run(&auth, &mut fake, &mut user, Some(agent(&["a", "b"])))
        .await
        .unwrap();
    assert_eq!(
        fake.calls,
        ["none", "agent:a", "agent:b", "password:stored"]
    );

    let auth = material(Some(key(test_keys::ED25519, &[])), None);
    let mut fake = Fake::new(&[PUBLICKEY]);
    let fake_agent = agent(&["a", "b"]);
    let _ = run(
        &auth,
        &mut fake,
        &mut User::default(),
        Some(Arc::clone(&fake_agent)),
    )
    .await;
    assert_eq!(fake.calls, ["none", "publickey:ssh-ed25519"]);
    assert_eq!(fake_agent.connects.load(Ordering::SeqCst), 0);

    // A configured key that couldn't be read keeps the agent off too.
    let mut auth = material(None, None);
    auth.key_id = Some(KEY_ID);
    let mut fake = Fake::new(&[PUBLICKEY]);
    let _ = run(&auth, &mut fake, &mut User::default(), Some(agent(&["a"]))).await;
    assert_eq!(fake.calls, ["none"]);

    // `ssh.use_system_agent = false`.
    let mut auth = material(None, None);
    auth.use_system_agent = false;
    let mut fake = Fake::new(&[PUBLICKEY]);
    let _ = run(&auth, &mut fake, &mut User::default(), Some(agent(&["a"]))).await;
    assert_eq!(fake.calls, ["none"]);
}

/// The server lists only publickey and keyboard-interactive → password is never
/// tried (not even the stored one).
#[tokio::test]
async fn t03_skips_unlisted_methods() {
    let auth = material(Some(key(test_keys::ED25519, &[])), Some("stored"));
    let mut fake = Fake::new(&[PUBLICKEY, KEYBOARD_INTERACTIVE]);
    fake.kbd.push_back(info(&[("Verification code:", true)]));
    let mut user = User::default();
    let _ = run(&auth, &mut fake, &mut user, None).await;
    assert_eq!(fake.calls, ["none", "publickey:ssh-ed25519", "kbd"]);
    assert!(
        user.prompts
            .iter()
            .all(|p| p.kind == PromptKind::KeyboardInteractive)
    );
}

/// RSA signature hash from `server-sig-algs`; SHA-1 only with the legacy opt-in.
#[tokio::test]
async fn t04_rsa_signature_algorithm() {
    let cases = [
        (RsaSigSupport::Sha512, false, Some("publickey:rsa-sha2-512")),
        (RsaSigSupport::Sha256, false, Some("publickey:rsa-sha2-256")),
        (RsaSigSupport::SshRsaOnly, false, None),
        (RsaSigSupport::Unknown, false, None),
        (RsaSigSupport::SshRsaOnly, true, Some("publickey:default")),
        (RsaSigSupport::Unknown, true, Some("publickey:default")),
    ];
    for (support, legacy, expect) in cases {
        let mut auth = material(Some(key(test_keys::RSA_2048, &[])), None);
        auth.allow_ssh_rsa = legacy;
        let mut fake = Fake::new(&[PUBLICKEY]);
        fake.rsa = support;
        let _ = run(&auth, &mut fake, &mut User::default(), None).await;
        let mut want = vec!["none".to_owned()];
        want.extend(expect.map(str::to_owned));
        assert_eq!(fake.calls, want, "{support:?} legacy={legacy}");
    }
    assert_eq!(
        rsa_hash(RsaSigSupport::Sha256, false),
        Some(Some(HashAlg::Sha256))
    );
    assert_eq!(rsa_hash(RsaSigSupport::Unknown, false), None);
    assert_eq!(rsa_hash(RsaSigSupport::Unknown, true), Some(None));
    // Legacy opt-in: `algorithms.host_key` lists `ssh-rsa`.
    let mut o = sverb_core::model::AlgoOverrides::default();
    assert!(!super::allows_ssh_rsa(&o));
    o.host_key = Some(vec!["ssh-rsa".into()]);
    assert!(super::allows_ssh_rsa(&o));
}

/// `max_auth_attempts = 2` with 4 agent identities → exactly 2 attempts, then an
/// `Auth` failure listing the methods tried (the stored password is never sent).
#[tokio::test]
async fn t05_attempt_cap() {
    let mut auth = material(None, Some("stored"));
    auth.max_attempts = 2;
    let mut fake = Fake::new(ALL);
    let mut user = User::default();
    let err = run(
        &auth,
        &mut fake,
        &mut user,
        Some(agent(&["a", "b", "c", "d"])),
    )
    .await
    .unwrap_err();
    assert_eq!(fake.calls, ["none", "agent:a", "agent:b"]);
    assert!(matches!(&err, SshError::Auth { tried } if tried == &["publickey"]));
    assert_eq!(
        err.message(),
        "Permission denied (methods tried: publickey)"
    );
    assert_eq!(err.reason(), crate::DisconnectReason::Auth);
    assert!(user.prompts.is_empty());
}

/// One non-echo "Password:" prompt + a stored password → answered once without a
/// dialog; the same request again in this connection → a dialog.
#[tokio::test]
async fn t06_kbd_auto_answer_once() {
    let auth = material(None, Some("pw"));
    let mut fake = Fake::new(&[KEYBOARD_INTERACTIVE]);
    fake.kbd.push_back(info(&[("Password:", false)]));
    fake.kbd.push_back(info(&[("Password:", false)]));
    fake.kbd.push_back(KbdReply::Success);
    let mut user = User::answering(&[Some(&["typed"])]);
    run(&auth, &mut fake, &mut user, None).await.unwrap();
    assert_eq!(fake.kbd_answers, [vec!["pw"], vec!["typed"]]);
    assert_eq!(user.prompts.len(), 1);
    assert_eq!(user.prompts[0].kind, PromptKind::KeyboardInteractive);
    assert_eq!(user.prompts[0].prompts[0].text, "Password:");
    // keyboard-interactive answers are never offered for saving.
    assert!(user.accepted.is_empty());
}

/// An OTP prompt is always shown, even with a stored password.
#[tokio::test]
async fn t07_kbd_otp_shows_a_dialog() {
    let auth = material(None, Some("pw"));
    let mut fake = Fake::new(&[KEYBOARD_INTERACTIVE]);
    fake.kbd.push_back(info(&[("Verification code:", false)]));
    fake.kbd.push_back(KbdReply::Success);
    let mut user = User::answering(&[Some(&["123456"])]);
    run(&auth, &mut fake, &mut user, None).await.unwrap();
    assert_eq!(user.prompts.len(), 1);
    assert_eq!(fake.kbd_answers, [vec!["123456"]]);
    // Two prompts (password + OTP) are not auto-answered either.
    assert!(!is_password_request(&[
        PromptLine {
            text: "Password:".into(),
            echo: false
        },
        PromptLine {
            text: "OTP:".into(),
            echo: false
        },
    ]));
    assert!(is_password_request(&[PromptLine {
        text: "deploy's PASSWORD: ".into(),
        echo: false
    }]));
    assert!(!is_password_request(&[PromptLine {
        text: "Password:".into(),
        echo: true
    }]));
}

/// Server text is stripped of escape sequences and control characters and capped
/// at 512 characters, in the dialog too.
#[tokio::test]
async fn t08_server_text_is_sanitized() {
    let evil = format!("\x1b[2J\x1b]0;pwned\x07{}\r\x07", "A".repeat(2000));
    let clean = sanitize_server_text(&evil);
    assert!(!clean.contains('\x1b') && !clean.contains("[2J") && !clean.contains("pwned"));
    assert_eq!(clean.chars().count(), MAX_SERVER_TEXT + 1);
    assert!(clean.ends_with('…'));
    assert_eq!(
        sanitize_server_text("Line 1\nLine\t2\u{202e}x"),
        "Line 1\nLine 2x"
    );
    assert_eq!(sanitize_server_text("a\u{9b}31mb"), "ab");

    let auth = material(None, None);
    let mut fake = Fake::new(&[KEYBOARD_INTERACTIVE]);
    fake.kbd.push_back(KbdReply::Info {
        name: "\x1b[31mDuo\x1b[0m".into(),
        instruction: evil.clone(),
        prompts: vec![PromptLine {
            text: "\x1b[1mCode:\x1b[0m ".into(),
            echo: true,
        }],
    });
    let mut user = User::default();
    let _ = run(&auth, &mut fake, &mut user, None).await;
    let p = &user.prompts[0];
    assert_eq!(p.name, "Duo");
    assert_eq!(p.instruction, clean);
    assert_eq!(p.prompts[0].text, "Code:");
    assert_eq!(p.title, "Authenticate to db");
}

/// Answer buffers are dropped once the request using them returns.
#[tokio::test(flavor = "current_thread")]
async fn t18_answer_buffers_are_dropped() {
    let before = ANSWERS_DROPPED.with(std::cell::Cell::get);
    let auth = material(None, None);
    let mut fake = Fake::new(&[PASSWORD, KEYBOARD_INTERACTIVE]);
    fake.kbd.push_back(info(&[("Code:", false)]));
    fake.kbd.push_back(KbdReply::Success);
    // Two password prompts (wrong), one cancel, then the OTP.
    let mut user = User::answering(&[Some(&["a"]), Some(&["b"]), None, Some(&["otp"])]);
    run(&auth, &mut fake, &mut user, None).await.unwrap();
    let after = ANSWERS_DROPPED.with(std::cell::Cell::get);
    assert_eq!(after - before, 3);
}

// ---------------------------------------------------------------- more behaviour

/// Passwords: the stored one, then prompts; a typed password is reported as accepted
/// only when authentication succeeds (T-10's connector side).
#[tokio::test]
async fn typed_passwords_are_accepted_only_on_success() {
    let auth = material(None, None);
    let mut fake = Fake::new(&[PASSWORD]);
    fake.password = Some("right");
    let mut user = User::answering(&[Some(&["wrong"]), Some(&["right"])]);
    run(&auth, &mut fake, &mut user, None).await.unwrap();
    assert_eq!(fake.calls, ["none", "password:wrong", "password:right"]);
    assert_eq!(
        user.prompts[0].instruction,
        "Password for deploy@db.example"
    );
    assert!(user.prompts[1].instruction.contains("please try again"));
    assert_eq!(
        user.accepted,
        [PromptKind::Password {
            host: Some(HOST_ID)
        }]
    );

    // Three wrong passwords: no success, nothing accepted.
    let mut fake = Fake::new(&[PASSWORD]);
    let mut user = User::answering(&[Some(&["a"]), Some(&["b"]), Some(&["c"])]);
    let err = run(&auth, &mut fake, &mut user, None).await.unwrap_err();
    assert_eq!(fake.calls.len(), 1 + PASSWORD_PROMPTS);
    assert!(user.accepted.is_empty());
    assert_eq!(err.message(), "Permission denied (methods tried: password)");
}

/// Encrypted keys: the stored passphrase; else a prompt (re-asked on a wrong one, the
/// key skipped after three); a typed passphrase is accepted with the key's success.
#[tokio::test]
async fn encrypted_keys_prompt_for_the_passphrase() {
    // Wrong, then right: the key is used and the passphrase reported.
    let auth = material(Some(key(test_keys::ED25519_ENCRYPTED, &[])), None);
    let mut fake = Fake::new(&[PUBLICKEY]);
    fake.accept_key = true;
    let mut user = User::answering(&[Some(&["nope"]), Some(&[test_keys::PASSPHRASE])]);
    run(&auth, &mut fake, &mut user, None).await.unwrap();
    assert_eq!(fake.calls, ["none", "publickey:ssh-ed25519"]);
    assert_eq!(user.prompts.len(), 2);
    let kind = PromptKind::Passphrase {
        key: Some(KEY_ID),
        label: "work".into(),
    };
    assert_eq!(user.prompts[0].kind, kind);
    assert!(user.prompts[1].instruction.contains("Wrong passphrase"));
    assert_eq!(user.accepted, std::slice::from_ref(&kind));

    // Three wrong passphrases: the key is skipped.
    let mut fake = Fake::new(&[PUBLICKEY]);
    let mut user = User::answering(&[Some(&["a"]), Some(&["b"]), Some(&["c"])]);
    let _ = run(&auth, &mut fake, &mut user, None).await;
    assert_eq!(fake.calls, ["none"]);
    assert_eq!(user.prompts.len(), PASSPHRASE_TRIES);

    // A stored passphrase: no prompt, nothing to save.
    let mut km = key(test_keys::ED25519_ENCRYPTED, &[]);
    km.passphrase = Some(SecretString::from(test_keys::PASSPHRASE));
    let auth = material(Some(km), None);
    let mut fake = Fake::new(&[PUBLICKEY]);
    fake.accept_key = true;
    let mut user = User::default();
    run(&auth, &mut fake, &mut user, None).await.unwrap();
    assert!(user.prompts.is_empty() && user.accepted.is_empty());

    // The key was accepted but the server wants more and nothing else works: not saved.
    let auth = material(Some(key(test_keys::ED25519_ENCRYPTED, &[])), None);
    let mut fake = Fake::new(&[PUBLICKEY]);
    let mut user = User::answering(&[Some(&[test_keys::PASSPHRASE])]);
    assert!(run(&auth, &mut fake, &mut user, None).await.is_err());
    assert!(user.accepted.is_empty());

    // No passphrase prompt when the server doesn't take public keys.
    let mut fake = Fake::new(&[PASSWORD]);
    let mut user = User::default();
    let _ = run(&auth, &mut fake, &mut user, None).await;
    assert!(
        user.prompts
            .iter()
            .all(|p| matches!(p.kind, PromptKind::Password { .. }))
    );
}

/// Certificates: an expired one or one for another key is skipped; a valid one is tried
/// first and its success ends the chain.
#[tokio::test]
async fn certificates_are_checked_and_tried_first() {
    let auth = material(
        Some(key(
            test_keys::ED25519,
            &[
                test_keys::ED25519_CERT_EXPIRED,
                test_keys::ED25519_ENCRYPTED_CERT_EXPIRED,
                "garbage",
                test_keys::ED25519_CERT,
            ],
        )),
        None,
    );
    let mut fake = Fake::new(&[PUBLICKEY]);
    fake.accept_cert = true;
    run(&auth, &mut fake, &mut User::default(), None)
        .await
        .unwrap();
    assert_eq!(fake.calls, ["none", "cert:testcert"]);

    let key = PrivateKey::from_openssh(test_keys::ED25519).unwrap();
    let cert = Certificate::from_openssh(test_keys::ED25519_CERT).unwrap();
    assert!(cert_usable(&cert, &key, cert.valid_after() + 1));
    assert!(!cert_usable(&cert, &key, cert.valid_before()));
    let other = PrivateKey::from_openssh(test_keys::RSA_2048).unwrap();
    assert!(!cert_usable(&cert, &other, cert.valid_after() + 1));
}

/// Cancelling the password prompt goes on with keyboard-interactive; cancelling that
/// ends the chain.
#[tokio::test]
async fn cancel_skips_the_method() {
    let auth = material(None, None);
    let mut fake = Fake::new(&[PASSWORD, KEYBOARD_INTERACTIVE]);
    fake.kbd.push_back(info(&[("Code:", false)]));
    let mut user = User::answering(&[None, None]);
    let err = run(&auth, &mut fake, &mut user, None).await.unwrap_err();
    assert_eq!(fake.calls, ["none", "kbd"]);
    assert_eq!(user.prompts.len(), 2);
    assert_eq!(
        err.message(),
        "Permission denied (methods tried: keyboard-interactive)"
    );
}

/// Partial success (publickey, then a second factor) continues with the listed method.
#[tokio::test]
async fn partial_success_continues() {
    struct TwoFactor(Fake);
    #[async_trait]
    impl AuthBackend for TwoFactor {
        async fn none(&mut self, u: &str) -> Result<AuthOutcome, SshError> {
            self.0.none(u).await
        }
        async fn password(&mut self, u: &str, p: &SecretString) -> Result<AuthOutcome, SshError> {
            self.0.password(u, p).await
        }
        async fn publickey(
            &mut self,
            u: &str,
            k: Arc<PrivateKey>,
            h: Option<HashAlg>,
        ) -> Result<AuthOutcome, SshError> {
            self.0.publickey(u, k, h).await?;
            Ok(AuthOutcome::Failure {
                remaining: vec![KEYBOARD_INTERACTIVE],
                partial: true,
            })
        }
        async fn certificate(
            &mut self,
            u: &str,
            k: Arc<PrivateKey>,
            c: Certificate,
        ) -> Result<AuthOutcome, SshError> {
            self.0.certificate(u, k, c).await
        }
        async fn agent_identity(
            &mut self,
            u: &str,
            a: &mut dyn Agent,
            i: &AgentIdentity,
            h: Option<HashAlg>,
        ) -> Result<AuthOutcome, SshError> {
            self.0.agent_identity(u, a, i, h).await
        }
        async fn kbd_start(&mut self, u: &str) -> Result<KbdReply, SshError> {
            self.0.kbd_start(u).await
        }
        async fn kbd_respond(&mut self, a: &[SecretString]) -> Result<KbdReply, SshError> {
            self.0.kbd_respond(a).await
        }
        async fn rsa_support(&mut self) -> RsaSigSupport {
            self.0.rsa
        }
    }
    let auth = material(Some(key(test_keys::ED25519_ENCRYPTED, &[])), Some("stored"));
    let mut fake = Fake::new(&[PUBLICKEY, PASSWORD, KEYBOARD_INTERACTIVE]);
    fake.kbd.push_back(info(&[("OTP:", false)]));
    fake.kbd.push_back(KbdReply::Success);
    let mut two = TwoFactor(fake);
    let mut user = User::answering(&[Some(&[test_keys::PASSPHRASE]), Some(&["42"])]);
    run_chain(&target(&auth), &mut two, &mut user, None)
        .await
        .unwrap();
    // The password isn't listed after the partial success.
    assert_eq!(two.0.calls, ["none", "publickey:ssh-ed25519", "kbd"]);
    // The passphrase counted towards the success: offered for saving.
    assert_eq!(user.accepted.len(), 1);
}

/// An agent / hardware reference key (its public line in `private_key`): only that
/// identity of the system agent is used; nothing else from the agent is offered, and a
/// missing identity skips the key.
#[tokio::test]
async fn m2_03_agent_reference_key_signs_through_the_agent() {
    let public = ed25519_public(2).to_openssh().unwrap();
    let km = key(&public, &[]);
    assert!(super::auth::agent_reference(&km).is_some());
    assert!(super::auth::agent_reference(&key(test_keys::ED25519, &[])).is_none());

    let auth = material(Some(km), None);
    let mut fake = Fake::new(&[PUBLICKEY]);
    fake.accept_agent = Some("b");
    run(
        &auth,
        &mut fake,
        &mut User::default(),
        Some(agent(&["a", "b", "c"])),
    )
    .await
    .unwrap();
    assert_eq!(fake.calls, ["none", "agent:b"]);

    // The agent doesn't hold it: skipped, and no other agent identity is offered.
    let auth = material(
        Some(key(&ed25519_public(9).to_openssh().unwrap(), &[])),
        None,
    );
    let mut fake = Fake::new(&[PUBLICKEY]);
    let err = run(
        &auth,
        &mut fake,
        &mut User::default(),
        Some(agent(&["a", "b"])),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SshError::Auth { .. }));
    assert_eq!(fake.calls, ["none"]);
}
