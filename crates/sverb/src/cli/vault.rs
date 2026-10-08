//! M0-07 / M1-04: `sverb lock | unlock`, and vault access for headless commands.
//!
//! [`require_unlocked`] is the one way a headless command gets the vault: keyring
//! unlock (if enabled) → master-password prompt on the terminal (only when stdin and
//! stderr are TTYs; no echo; with the persisted backoff) → otherwise exit 3 with
//! [`VAULT_LOCKED_NO_TTY`](super::exit::VAULT_LOCKED_NO_TTY). It never reads a
//! non-TTY stdin, so piped or cron invocations cannot hang. A database that was
//! never initialized fails at once with "sverb is not initialized; run `sverb` once
//! to set a master password" (exit 3). Unlocking never contacts a server.
//!
//! There is no daemon in v1: `sverb unlock` only validates the password (useful to
//! check the backoff state; on a fresh home it runs first-run setup on the TTY), and
//! the unlocked state lives only as long as the command.

use std::io::{self, Write};
use std::sync::Arc;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use sverb_core::error_report::ErrorReport;
use sverb_core::vault::{Argon2Cost, KeyringStore, VaultError, check_strength};
use sverb_store::Store;
use sverb_tui::services::vault::{UnlockedVault, VaultEngine, keyring_from_env};
use zeroize::Zeroizing;

use super::{CliError, Ctx};

/// Password prompts before giving up.
const MAX_ATTEMPTS: u32 = 3;

/// The unlocked vault for a headless command. Dropping it zeroizes the keys.
#[derive(Debug)]
#[allow(dead_code)] // M1-07+: vault-backed commands read items through it.
pub(crate) struct Unlocked {
    pub(crate) engine: VaultEngine,
    pub(crate) vault: UnlockedVault,
}

fn vault_error(err: VaultError) -> CliError {
    CliError::UnlockFailed(ErrorReport::msg(err.to_string()))
}

/// Open the store with the binary's keyring. `None` when there is no database yet
/// (a fresh home is never created by a headless command).
async fn open_engine(
    ctx: &Ctx,
    keyring: Arc<dyn KeyringStore>,
) -> Result<Option<VaultEngine>, CliError> {
    if !ctx.paths.db_file().exists() {
        return Ok(None);
    }
    let paths = ctx.paths.clone();
    let store = tokio::task::spawn_blocking(move || Store::open(&paths))
        .await
        .map_err(|e| CliError::failure(&e))?
        .map_err(|e| CliError::failure(&e))?;
    Ok(Some(VaultEngine::new(
        store,
        keyring,
        Argon2Cost::PRODUCTION,
    )))
}

/// Unlock the vault for a headless command, or fail without blocking.
#[allow(dead_code)] // M1-07+: called by every vault-backed command.
pub(crate) async fn require_unlocked(ctx: &Ctx) -> Result<Unlocked, CliError> {
    let Some(engine) = open_engine(ctx, keyring_from_env()).await? else {
        return Err(vault_error(VaultError::NotInitialized));
    };
    let status = engine.status().await.map_err(vault_error)?;
    if !status.initialized {
        return Err(vault_error(VaultError::NotInitialized));
    }
    if status.keyring_enabled {
        match engine.unlock_with_keyring().await {
            Ok(vault) => return Ok(Unlocked { engine, vault }),
            Err(e) => {
                tracing::info!(error = %e, "keyring unlock failed; falling back to the prompt")
            }
        }
    }
    if !(ctx.tty.stdin && ctx.tty.stderr) {
        return Err(CliError::VaultLocked);
    }
    let vault = prompt_until(&engine, |pw| {
        let engine = engine.clone();
        async move { engine.unlock_with_password(&pw).await }
    })
    .await?;
    Ok(Unlocked { engine, vault })
}

// M2-08
/// [`require_unlocked`] that also returns the master password when it was typed (not
/// when the keyring unlocked), so `sverb forward --detach` can hand it to its
/// background process over a pipe.
pub(crate) async fn require_unlocked_with_password(
    ctx: &Ctx,
) -> Result<(Unlocked, Option<Zeroizing<String>>), CliError> {
    let Some(engine) = open_engine(ctx, keyring_from_env()).await? else {
        return Err(vault_error(VaultError::NotInitialized));
    };
    let status = engine.status().await.map_err(vault_error)?;
    if !status.initialized {
        return Err(vault_error(VaultError::NotInitialized));
    }
    if status.keyring_enabled {
        match engine.unlock_with_keyring().await {
            Ok(vault) => return Ok((Unlocked { engine, vault }, None)),
            Err(e) => {
                tracing::info!(error = %e, "keyring unlock failed; falling back to the prompt")
            }
        }
    }
    if !(ctx.tty.stdin && ctx.tty.stderr) {
        return Err(CliError::VaultLocked);
    }
    let (vault, password) = prompt_until(&engine, |pw| {
        let engine = engine.clone();
        async move {
            let vault = engine.unlock_with_password(&pw).await?;
            Ok((vault, pw))
        }
    })
    .await?;
    Ok((Unlocked { engine, vault }, Some(password)))
}

// M2-08
/// Unlock with a password handed over by a parent `sverb` process (keyring first).
pub(crate) async fn unlock_with_handoff(
    ctx: &Ctx,
    password: Option<Zeroizing<String>>,
) -> Result<Unlocked, CliError> {
    let Some(engine) = open_engine(ctx, keyring_from_env()).await? else {
        return Err(vault_error(VaultError::NotInitialized));
    };
    if let Some(pw) = password {
        let vault = engine
            .unlock_with_password(&pw)
            .await
            .map_err(vault_error)?;
        return Ok(Unlocked { engine, vault });
    }
    let vault = engine.unlock_with_keyring().await.map_err(vault_error)?;
    Ok(Unlocked { engine, vault })
}

// M2-08
/// [`read_password`] for other headless commands (SSH passwords, passphrases).
pub(crate) fn read_secret(prompt: &str) -> io::Result<Zeroizing<String>> {
    read_password(prompt)
}

/// Ask for the password (up to [`MAX_ATTEMPTS`]), waiting out backoff delays.
async fn prompt_until<T, F, Fut>(engine: &VaultEngine, attempt: F) -> Result<T, CliError>
where
    F: Fn(Zeroizing<String>) -> Fut,
    Fut: std::future::Future<Output = Result<T, VaultError>>,
{
    let mut last = VaultError::Locked;
    for _ in 0..MAX_ATTEMPTS {
        if let Some(wait) = engine.status().await.map_err(vault_error)?.retry_after {
            eprintln!(
                "Too many failed attempts; waiting {}s…",
                wait.as_secs().max(1)
            );
            tokio::time::sleep(wait).await;
        }
        let pw = read_password("Master password: ").map_err(|e| CliError::failure(&e))?;
        match attempt(pw).await {
            Ok(v) => return Ok(v),
            Err(e @ (VaultError::WrongPassword { .. } | VaultError::Backoff { .. })) => {
                eprintln!("{e}");
                last = e;
            }
            Err(e) => return Err(vault_error(e)),
        }
    }
    Err(vault_error(last))
}

/// Read a password from the terminal without echo (raw mode; prompt on stderr).
/// Ctrl-C / Ctrl-D / Esc abort.
fn read_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    let mut err = io::stderr();
    // Raw mode first, then the prompt: a password typed right after the prompt
    // appears is never echoed by the cooked tty, and its line end can't arrive as
    // `\n` (which raw mode reads as ctrl-j, not Enter).
    crossterm::terminal::enable_raw_mode()?;
    if let Err(e) = write!(err, "{prompt}").and_then(|()| err.flush()) {
        let _ = crossterm::terminal::disable_raw_mode();
        return Err(e);
    }
    let result = (|| {
        let mut pw = Zeroizing::new(String::new());
        loop {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind == KeyEventKind::Release {
                continue;
            }
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Enter => return Ok(pw),
                // Line ends typed ahead in cooked mode (`\n`, `\r`).
                KeyCode::Char('j' | 'm') if ctrl => return Ok(pw),
                KeyCode::Char('c' | 'd') if ctrl => {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                KeyCode::Esc => {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                KeyCode::Backspace => {
                    pw.pop();
                }
                KeyCode::Char(c) if !ctrl => pw.push(c),
                _ => {}
            }
        }
    })();
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = writeln!(err, "\r");
    result
}

/// `sverb lock`. M2-07: the running TUI is locked over its control socket
/// (`super::agent::lock`); without one there is nothing to lock (exit 0). Headless
/// commands never keep the vault unlocked.
pub(crate) async fn lock(ctx: &Ctx) -> Result<u8, CliError> {
    super::agent::lock(ctx).await
}

/// `sverb unlock`: validate the master password (no unlocked state is kept). On a
/// fresh home with a terminal, set the master password (first run).
pub(crate) async fn unlock(ctx: &Ctx) -> Result<u8, CliError> {
    let tty = ctx.tty.stdin && ctx.tty.stderr;
    let engine = match open_engine(ctx, keyring_from_env()).await? {
        Some(engine) => engine,
        None if tty => {
            ctx.paths
                .ensure(sverb_core::paths::DirKind::Data)
                .map_err(|e| CliError::failure(&e))?;
            open_engine(ctx, keyring_from_env())
                .await?
                .ok_or_else(|| vault_error(VaultError::NotInitialized))?
        }
        None => return Err(vault_error(VaultError::NotInitialized)),
    };
    let status = engine.status().await.map_err(vault_error)?;
    if !status.initialized {
        if !tty {
            return Err(vault_error(VaultError::NotInitialized));
        }
        return first_run(&engine).await;
    }
    if !tty {
        return Err(CliError::VaultLocked);
    }
    prompt_until(&engine, |pw| {
        let engine = engine.clone();
        async move { engine.verify_password(&pw).await }
    })
    .await?;
    eprintln!("Password OK.");
    Ok(super::exit::OK)
}

/// First-run setup on the TTY (same rules as the TUI: zxcvbn score ≥ 3).
async fn first_run(engine: &VaultEngine) -> Result<u8, CliError> {
    eprintln!("sverb is not initialized. Choose a master password.");
    eprintln!("{}", sverb_core::vault::password::NO_RECOVERY_WARNING);
    for _ in 0..MAX_ATTEMPTS {
        let pw = read_password("New master password: ").map_err(|e| CliError::failure(&e))?;
        if let Err(weak) = check_strength(&pw, &["sverb"]) {
            eprintln!("{weak}");
            continue;
        }
        let confirm = read_password("Confirm: ").map_err(|e| CliError::failure(&e))?;
        if *confirm != *pw {
            eprintln!("The passwords do not match.");
            continue;
        }
        engine.initialize(&pw, false).await.map_err(vault_error)?;
        eprintln!("Vault created.");
        return Ok(super::exit::OK);
    }
    Err(vault_error(VaultError::NotInitialized))
}
