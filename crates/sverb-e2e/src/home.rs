//! [`TestHome`]: a temporary `SVERB_HOME` with an initialized vault.
//!
//! The vault uses the cheapest Argon2 parameters (`Argon2Cost::TEST`) and no OS
//! keyring; run the binary with [`TestHome::env`] (`SVERB_HOME`, `SVERB_KEYRING=off`).
//! Hosts, keys and known hosts are written through the item service, exactly as the
//! TUI and the CLI write them.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use sverb_core::{
    model::{
        HlcClock, Host, ItemBody, ItemId, ItemKind, Key, KeyAlgorithm, KnownHost, KnownHostMarker,
        UnixMillis, ValidationError,
    },
    paths::{DirKind, MapEnv, Paths},
    secret::SecretString,
    vault::{Argon2Cost, NoKeyring},
};
use sverb_store::Store;
use sverb_tui::services::vault::{VaultEngine, items::ItemOps};

use crate::{E2eError, Result, diag, keys::FixtureKey};

/// The master password of every [`TestHome`].
pub const MASTER_PASSWORD: &str = "correct horse battery staple violin";

/// A temporary `SVERB_HOME` with an initialized vault. Deleted on drop (kept, and its
/// path printed, when the test is failing).
#[derive(Debug)]
pub struct TestHome {
    dir: PathBuf,
    paths: Paths,
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "sverb-e2e-home-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn err(e: impl std::fmt::Display) -> E2eError {
    E2eError::new(e.to_string())
}

impl TestHome {
    /// A new home with an initialized vault (password [`MASTER_PASSWORD`]). The
    /// first-run leader notice is marked as seen.
    ///
    /// # Errors
    /// Creating the directory, the database or the vault failed.
    pub async fn new() -> Result<Self> {
        let dir = unique_dir();
        std::fs::create_dir_all(&dir)?;
        let paths = Paths::resolve(&MapEnv::new().var("SVERB_HOME", &dir)).map_err(err)?;
        paths.ensure(DirKind::Data).map_err(err)?;
        let home = Self { dir, paths };
        let engine = home.engine()?;
        engine
            .initialize(MASTER_PASSWORD, false)
            .await
            .map_err(err)?;
        engine
            .store()
            .set_meta("seen_leader_notice", vec![1])
            .await
            .map_err(err)?;
        Ok(home)
    }

    /// [`TestHome::new`] outside a Tokio runtime (synchronous tests such as
    /// [`PtyApp`](crate::PtyApp) ones). Panics inside a runtime.
    ///
    /// # Errors
    /// As [`TestHome::new`].
    pub fn new_blocking() -> Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(Self::new())
    }

    /// The `SVERB_HOME` directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The resolved paths.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Environment for the `sverb` binary: this home, no OS keyring.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("SVERB_HOME".into(), self.dir.display().to_string()),
            ("SVERB_KEYRING".into(), "off".into()),
        ]
    }

    fn engine(&self) -> Result<VaultEngine> {
        let store = Store::open(&self.paths).map_err(err)?;
        Ok(VaultEngine::new(
            store,
            Arc::new(NoKeyring),
            Argon2Cost::TEST,
        ))
    }

    /// Item operations on the unlocked vault.
    ///
    /// # Errors
    /// The vault did not unlock.
    pub async fn items(&self) -> Result<ItemOps> {
        let engine = self.engine()?;
        let vault = engine
            .unlock_with_password(MASTER_PASSWORD)
            .await
            .map_err(err)?;
        Ok(ItemOps::new(engine, Arc::new(vault)))
    }

    async fn add(
        &self,
        kind: ItemKind,
        apply: impl FnOnce(&mut ItemBody, &mut HlcClock, sverb_core::model::DeviceId) + Send,
    ) -> Result<ItemId> {
        let ops = self.items().await?;
        let written = ops
            .save(kind, None, None, move |body, clock, device| {
                apply(body, clock, device);
                Ok::<(), Vec<ValidationError>>(())
            })
            .await
            .map_err(err)?;
        Ok(written.id)
    }

    /// Save `host` (validated like a form save). Returns its id.
    ///
    /// # Errors
    /// Invalid host or storage failure.
    pub async fn add_host(&self, host: Host) -> Result<ItemId> {
        self.add(ItemKind::Host, move |b, c, d| host.apply_to(b, c, d))
            .await
    }

    /// Save `key`. Returns its id.
    ///
    /// # Errors
    /// Storage failure.
    pub async fn add_key(&self, key: Key) -> Result<ItemId> {
        self.add(ItemKind::Key, move |b, c, d| key.apply_to(b, c, d))
            .await
    }

    /// Save a fixture key (with its stored passphrase, if it has one).
    ///
    /// # Errors
    /// Storage failure.
    pub async fn add_fixture_key(&self, key: FixtureKey) -> Result<ItemId> {
        let algorithm = match key {
            FixtureKey::EcdsaP256 => KeyAlgorithm::EcdsaP256,
            FixtureKey::Rsa4096 => KeyAlgorithm::Rsa4096,
            _ => KeyAlgorithm::Ed25519,
        };
        self.add_key(Key {
            label: format!("fixture {}", key.file_name()),
            algorithm,
            private_key: SecretString::from(key.private()),
            public_key: key.public(),
            passphrase: key.passphrase().map(SecretString::from),
            certificate_ids: Vec::new(),
            agent_forwardable: false,
            confirm_on_use: false,
            read_only: false,
        })
        .await
    }

    /// Save a known-hosts entry. Returns its id.
    ///
    /// # Errors
    /// Storage failure.
    pub async fn add_known_host(&self, entry: KnownHost) -> Result<ItemId> {
        self.add(ItemKind::KnownHost, move |b, c, d| entry.apply_to(b, c, d))
            .await
    }

    /// Trust `public_key` (`type base64`) for `host_pattern` (`host` or `[host]:port`).
    ///
    /// # Errors
    /// Malformed key or storage failure.
    pub async fn trust_host_key(&self, host_pattern: &str, public_key: &str) -> Result<ItemId> {
        let mut parts = public_key.split_whitespace();
        let (Some(key_type), Some(b64)) = (parts.next(), parts.next()) else {
            return Err(E2eError::new(format!("not a public key: {public_key:?}")));
        };
        self.add_known_host(KnownHost {
            host_pattern: host_pattern.to_owned(),
            key_type: key_type.to_owned(),
            public_key: b64.to_owned(),
            added_at: UnixMillis::now(),
            comment: Some("sverb-e2e".into()),
            marker: KnownHostMarker::None,
            read_only: false,
        })
        .await
    }

    /// Every live item of `kinds` (all kinds when empty), decrypted.
    ///
    /// # Errors
    /// The vault did not unlock or storage failed.
    pub async fn list(&self, kinds: &[ItemKind]) -> Result<Vec<(ItemId, ItemBody)>> {
        let ops = self.items().await?;
        Ok(ops
            .list(kinds)
            .await
            .map_err(err)?
            .into_iter()
            .map(|l| (l.id, l.body))
            .collect())
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        if diag::failing() {
            diag::dump("SVERB_HOME (kept)", &self.dir.display().to_string());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
