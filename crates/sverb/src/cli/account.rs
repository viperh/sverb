//! M0-07: `sverb login | logout | register | sync` (sync builds only). M4-08:
//! `login`, `logout`, `register` run the account flows of
//! `sverb_sync::account` with TTY prompts. M4-07: `sverb sync [--now|--status]`
//! runs one headless engine cycle / prints the local sync state.
//!
//! The recovery phrase is only ever written to a terminal: `sverb register`
//! without one fails at once (exit 2), so the words never reach a log or pipe.
#![cfg(feature = "sync")]

use std::io::{self, BufRead, Write};

use clap::Args;

use std::sync::Arc;

use sverb_core::error_report::ErrorReport;
use sverb_core::model::UnixMillis;
use sverb_core::vault::{Argon2Cost, VaultError};
use sverb_crypto::Key32;
use sverb_store::Store;
use sverb_store::VaultKind;
use sverb_sync::account::{
    self as acct, AccountConfig, AccountError, DuplicateChoice, LoginRequest, RecoveryConfirm,
    RegistrationToken,
};
use sverb_sync::{
    EngineConfig, LocalSyncInfo, NoKeySource, SyncEngine, SyncError, SyncStatus, VaultKeySource,
    shared_hlc,
};
use sverb_tui::services::vault::{VaultEngine, keyring_from_env, vault_display_name};
use sverb_tui::views::logs::list::format_time;
use zeroize::Zeroizing;

use super::output::write_json;
use super::vault::{read_secret, require_unlocked};
use super::{CliError, Ctx, exit, write_out};

/// `sverb login …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct LoginArgs {
    /// Sync server URL
    #[arg(long, value_name = "URL")]
    pub server: Option<String>,
    // M4-08
    /// Account email
    #[arg(long, value_name = "EMAIL")]
    pub email: Option<String>,
}

/// `sverb logout …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct LogoutArgs {
    /// Keep the local vault copy
    #[arg(long)]
    pub keep_local: bool,
}

// M4-08
/// `sverb register …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct RegisterArgs {
    /// Sync server URL
    #[arg(long, value_name = "URL")]
    pub server: Option<String>,
    /// Account email
    #[arg(long, value_name = "EMAIL")]
    pub email: Option<String>,
}

/// `sverb sync …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct SyncArgs {
    /// Sync immediately
    #[arg(long)]
    pub now: bool,
    /// Show the sync status (the default)
    #[arg(long)]
    pub status: bool,
    // M4-09
    /// Machine-readable output
    #[arg(long)]
    pub json: bool,
}

// ------------------------------------------------------------------- M4-08

const NEEDS_TTY: &str = "needs an interactive terminal (passwords are only read from a TTY)";

pub(crate) fn account_config() -> AccountConfig {
    let name = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "sverb CLI".to_owned());
    AccountConfig::new(name)
}

pub(crate) fn account_error(e: AccountError) -> CliError {
    match e {
        e if e.is_offline() => CliError::Network(ErrorReport::msg(e.to_string())),
        e @ (AccountError::IncompatibleServer(_) | AccountError::Sync(_)) => {
            CliError::Network(ErrorReport::msg(e.to_string()))
        }
        e @ (AccountError::WrongLocalPassword | AccountError::LoginFailed) => {
            CliError::UnlockFailed(ErrorReport::msg(e.to_string()))
        }
        e => CliError::Failure(ErrorReport::msg(e.to_string())),
    }
}

fn io_failure(e: &io::Error) -> CliError {
    CliError::failure(e)
}

/// A visible line from the terminal (prompt on stderr).
fn read_line(prompt: &str) -> Result<String, CliError> {
    let mut err = io::stderr();
    write!(err, "{prompt}").map_err(|e| io_failure(&e))?;
    err.flush().map_err(|e| io_failure(&e))?;
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| io_failure(&e))?;
    Ok(line.trim().to_owned())
}

fn ask(given: Option<String>, prompt: &str) -> Result<String, CliError> {
    match given.filter(|s| !s.trim().is_empty()) {
        Some(v) => Ok(v.trim().to_owned()),
        None => {
            let v = read_line(prompt)?;
            if v.is_empty() {
                return Err(CliError::Usage(format!(
                    "{} is required",
                    prompt.trim_end_matches([':', ' '])
                )));
            }
            Ok(v)
        }
    }
}

fn confirm(prompt: &str, default_yes: bool) -> Result<bool, CliError> {
    let a = read_line(prompt)?.to_ascii_lowercase();
    Ok(if a.is_empty() {
        default_yes
    } else {
        a == "y" || a == "yes"
    })
}

fn secret(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    read_secret(prompt).map_err(|e| io_failure(&e))
}

async fn open_store(ctx: &Ctx) -> Result<Option<Store>, CliError> {
    if !ctx.paths.db_file().exists() {
        return Ok(None);
    }
    let paths = ctx.paths.clone();
    let store = tokio::task::spawn_blocking(move || Store::open(&paths))
        .await
        .map_err(|e| CliError::failure(&e))?
        .map_err(|e| CliError::failure(&e))?;
    Ok(Some(store))
}

/// One sync cycle after a login / registration (the upload of §2.1.6).
async fn first_sync(store: &Store, lmk: &Key32, ctx: &Ctx) -> SyncStatus {
    let source: Arc<dyn VaultKeySource> = match acct::load_account_keys(store, lmk).await {
        Ok(Some((a, k))) => Arc::new(acct::GrantKeySource::new(a.user_id, k)),
        _ => Arc::new(NoKeySource),
    };
    let config = EngineConfig {
        websocket: false,
        ..EngineConfig::from_config(&ctx.config)
    };
    match SyncEngine::new(
        store.clone(),
        lmk.clone(),
        shared_hlc(sverb_core::model::HlcClock::default()),
        source,
        config,
        None,
    )
    .await
    {
        Ok(mut e) => e.sync_once().await,
        Err(e) => SyncStatus::Error {
            message: e.to_string(),
        },
    }
}

fn print_words(words: &[&str]) {
    eprintln!();
    eprintln!("Your recovery phrase (write it down; it is shown only now):");
    eprintln!();
    for (row, chunk) in words.chunks(4).enumerate() {
        let line: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{:>2}. {w:<10}", row * 4 + i + 1))
            .collect();
        eprintln!("  {}", line.join("  "));
    }
    eprintln!();
    eprintln!("{}", acct::RECOVERY_WARNING);
    eprintln!();
}

/// `sverb register [--server URL] [--email E]` (§2.1).
pub(crate) async fn register(args: RegisterArgs, ctx: &Ctx) -> Result<u8, CliError> {
    // T-11: the recovery words are only ever shown on a terminal.
    if !(ctx.tty.stdin && ctx.tty.stdout && ctx.tty.stderr) {
        return Err(CliError::Usage(format!(
            "`sverb register` {NEEDS_TTY}; the recovery phrase is only shown on a terminal"
        )));
    }
    let Some(store) = open_store(ctx).await? else {
        return Err(CliError::UnlockFailed(ErrorReport::msg(
            VaultError::NotInitialized.to_string(),
        )));
    };
    let cfg = account_config();
    let server = ask(args.server, "Server URL: ")?;
    let email = ask(args.email, "Email: ")?;
    eprintln!("Your current master password becomes the account password.");
    let password = secret("Master password: ")?;
    let prepared = acct::prepare_registration(&store, &server, &email, &password, &cfg)
        .await
        .map_err(account_error)?;
    drop(password);
    let words = prepared.recovery_words();
    loop {
        print_words(&words);
        read_line("Press Enter once you have written the phrase down…")?;
        // Clear the words from the screen before asking for them.
        eprint!("\x1b[2J\x1b[H");
        let mut c = RecoveryConfirm::with_random_positions(&words);
        for (slot, n) in c.word_numbers().iter().enumerate() {
            let w = read_line(&format!("Word #{n}: "))?;
            c.set_input(slot, &w);
        }
        if c.submit() {
            break;
        }
        eprintln!("{}", c.error().unwrap_or("The words do not match."));
        if !confirm("Show the phrase again? [Y/n] ", true)? {
            return Err(CliError::Usage("registration cancelled".into()));
        }
    }
    let mut token = None;
    let done = loop {
        match acct::finish_registration(&store, &prepared, token.as_ref(), &cfg).await {
            Ok(r) => break r,
            Err(AccountError::InviteRequired(msg)) if token.is_none() => {
                eprintln!("{msg}");
                let t = secret("Invite or setup token: ")?;
                let setup = confirm(
                    "Is this the server's first-admin setup token? [y/N] ",
                    false,
                )?;
                token = Some(if setup {
                    RegistrationToken::Setup(t.to_string())
                } else {
                    RegistrationToken::Invite(t.to_string())
                });
            }
            Err(e) => return Err(account_error(e)),
        }
    };
    eprintln!("Account created. Uploading {} item(s)…", done.queued);
    let st = first_sync(&store, prepared.lmk(), ctx).await;
    eprintln!("Sync: {st}");
    Ok(exit::OK)
}

/// `sverb login [--server URL] [--email E]` (§2.2, §2.3, §2.5).
pub(crate) async fn login(args: LoginArgs, ctx: &Ctx) -> Result<u8, CliError> {
    if !(ctx.tty.stdin && ctx.tty.stderr) {
        return Err(CliError::Usage(format!("`sverb login` {NEEDS_TTY}")));
    }
    let cfg = account_config();
    let server = ask(args.server, "Server URL: ")?;
    let email = ask(args.email, "Email: ")?;
    let (store, lmk, password) = match open_store(ctx).await? {
        // §2.3: a new device: the account password becomes the master password.
        None => {
            ctx.paths
                .ensure(sverb_core::paths::DirKind::Data)
                .map_err(|e| CliError::failure(&e))?;
            let store = open_store(ctx).await?.ok_or_else(|| {
                CliError::Failure(ErrorReport::msg("cannot create the database".to_owned()))
            })?;
            let password = secret("Account password: ")?;
            let engine =
                VaultEngine::new(store.clone(), keyring_from_env(), Argon2Cost::PRODUCTION);
            let init = engine
                .initialize(&password, false)
                .await
                .map_err(|e| CliError::UnlockFailed(ErrorReport::msg(e.to_string())))?;
            let lmk = init.vault.lmk().clone();
            (store, lmk, password)
        }
        Some(_) => {
            let unlocked = require_unlocked(ctx).await?;
            let store = unlocked.engine.store().clone();
            let lmk = unlocked.vault.lmk().clone();
            drop(unlocked);
            let password = secret("Account password: ")?;
            (store, lmk, password)
        }
    };
    let mut req = LoginRequest {
        server_url: server,
        email,
        password,
        totp: None,
    };
    let mut session = match acct::start_login(&store, &lmk, &req, &cfg).await {
        Err(AccountError::TotpRequired) => {
            req.totp = Some(read_line("TOTP code: ")?);
            acct::start_login(&store, &lmk, &req, &cfg).await
        }
        other => other,
    }
    .map_err(account_error)?;
    if session.password_differs() {
        eprintln!("{}.", acct::PASSWORD_ADOPT_WARNING);
        if !confirm("Continue? [y/N] ", false)? {
            return Err(CliError::Usage("login cancelled".into()));
        }
    }
    if session.will_import() {
        let preview = session.preview().clone();
        eprint!("{}", preview.render());
        if !preview.duplicates.is_empty() {
            let choice =
                read_line("Likely duplicates: keep [b]oth, keep [l]ocal or keep [a]ccount? [b] ")?;
            let choice = match choice.to_ascii_lowercase().as_str() {
                "l" | "local" => DuplicateChoice::KeepLocal,
                "a" | "account" => DuplicateChoice::KeepAccount,
                _ => DuplicateChoice::KeepBoth,
            };
            session.preview_mut().set_all(choice);
        }
        let n = session.preview().imported_count();
        if !confirm(
            &format!("Import {n} local item(s) into the account? [Y/n] "),
            true,
        )? {
            return Err(CliError::Usage("login cancelled".into()));
        }
    }
    let done = session.commit(&store).await.map_err(account_error)?;
    if done.imported > 0 {
        eprintln!("Imported {} item(s).", done.imported);
    }
    let st = first_sync(&store, &lmk, ctx).await;
    eprintln!("Logged in. Sync: {st}");
    Ok(exit::OK)
}

/// `sverb logout [--keep-local]` (§2.8).
pub(crate) async fn logout(args: LogoutArgs, ctx: &Ctx) -> Result<u8, CliError> {
    if !args.keep_local {
        if !(ctx.tty.stdin && ctx.tty.stderr) {
            return Err(CliError::Usage(
                "`sverb logout` without --keep-local deletes all local data and must be \
                 confirmed on a terminal"
                    .into(),
            ));
        }
        eprintln!(
            "This logs out and deletes ALL local data (hosts, keys, snippets, history) from \
             this device."
        );
        if read_line("Type 'delete' to confirm: ")? != "delete" {
            return Err(CliError::Usage("logout cancelled".into()));
        }
    }
    let unlocked = require_unlocked(ctx).await?;
    let store = unlocked.engine.store().clone();
    let lmk = unlocked.vault.lmk().clone();
    drop(unlocked);
    let report = acct::logout(&store, &lmk, &account_config())
        .await
        .map_err(account_error)?;
    if let Some(why) = &report.revoke_error {
        eprintln!("warning: the server did not revoke this device ({why})");
    }
    if report.shared_removed > 0 {
        eprintln!(
            "Removed {} shared vault(s) from this device.",
            report.shared_removed
        );
    }
    if args.keep_local {
        eprintln!(
            "Logged out. {} personal item(s) kept locally.",
            report.kept_items
        );
        return Ok(exit::OK);
    }
    drop(store);
    let db = ctx.paths.db_file();
    for suffix in ["", "-wal", "-shm"] {
        let mut p = db.clone().into_os_string();
        p.push(suffix);
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(CliError::failure(&e)),
        }
    }
    eprintln!("Logged out. Local data deleted.");
    Ok(exit::OK)
}

// M4-07, M4-09
/// `sverb sync`: without `--now` (or with `--status` alone) prints the local
/// state (server, account, last sync, pending changes per vault) without
/// unlocking or contacting the server. `--now` unlocks and runs one full cycle
/// (vault list, pull, push, pull) headlessly: exit 0 when it worked, 6 when the
/// server can't be reached; `--now --status` prints the state afterwards too.
pub(crate) async fn sync(args: SyncArgs, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    if !args.now {
        return status(ctx, args.json, out).await;
    }
    let unlocked = require_unlocked(ctx).await?;
    let store = unlocked.engine.store().clone();
    let lmk = unlocked.vault.lmk().clone();
    let hlc = unlocked.vault.hlc();
    drop(unlocked);
    let res = sync_now(&store, &lmk, hlc, ctx, args.json, out).await;
    if res.is_ok() && args.status {
        let info = sverb_sync::local_info(&store)
            .await
            .map_err(|e| CliError::failure(&e))?;
        write_status(&info, args.json, out)?;
    }
    res
}

// M4-09: GrantKeySource like the TUI, so new vault keys (rotation) open headlessly too.
async fn key_source(store: &Store, lmk: &Key32) -> Arc<dyn VaultKeySource> {
    match acct::load_account_keys(store, lmk).await {
        Ok(Some((a, k))) => Arc::new(acct::GrantKeySource::new(a.user_id, k)),
        _ => Arc::new(NoKeySource),
    }
}

/// One headless cycle with the unlocked vault's `store` and `lmk`.
pub(crate) async fn sync_now(
    store: &Store,
    lmk: &Key32,
    hlc: sverb_core::model::HlcClock,
    ctx: &Ctx,
    json: bool,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let config = EngineConfig {
        websocket: false,
        ..EngineConfig::from_config(&ctx.config)
    };
    let engine = SyncEngine::new(
        store.clone(),
        lmk.clone(),
        shared_hlc(hlc),
        key_source(store, lmk).await,
        config,
        None,
    )
    .await;
    let mut engine = match engine {
        Ok(e) => e,
        Err(SyncError::NotConfigured(why)) => {
            return Err(CliError::Usage(format!(
                "sync is not set up on this device ({why}); sign in with `sverb login`"
            )));
        }
        Err(SyncError::NeedsLogin) => {
            return Err(CliError::Network(ErrorReport::msg(
                "sign-in required: run `sverb login`".to_owned(),
            )));
        }
        Err(e) => return Err(CliError::failure(&e)),
    };
    let st = engine.sync_once().await;
    if json {
        #[derive(serde::Serialize)]
        struct Now {
            status: String,
            pending: u64,
            error: Option<String>,
        }
        let (pending, error) = match &st {
            SyncStatus::Offline { pending } => (*pending, None),
            SyncStatus::Error { message } => (0, Some(message.clone())),
            _ => (0, None),
        };
        write_json(
            out,
            &Now {
                status: st.short(),
                pending,
                error,
            },
        )?;
    } else {
        write_out(out, &format!("{st}\n"))?;
    }
    match st {
        SyncStatus::Synced | SyncStatus::Syncing | SyncStatus::Disabled => Ok(exit::OK),
        SyncStatus::Offline { .. } => Err(CliError::Network(ErrorReport::msg(format!(
            "{st}: the server is unreachable; changes stay queued"
        )))),
        SyncStatus::NeedsLogin => Err(CliError::Network(ErrorReport::msg(
            "sign-in required: run `sverb login`".to_owned(),
        ))),
        SyncStatus::Error { message } => Err(CliError::Failure(ErrorReport::msg(message))),
    }
}

// M4-07, M4-09
async fn status(ctx: &Ctx, json: bool, out: &mut dyn Write) -> Result<u8, CliError> {
    // A fresh home has no database: local-only, and nothing is created.
    let info = match open_store(ctx).await? {
        Some(store) => sverb_sync::local_info(&store)
            .await
            .map_err(|e| CliError::failure(&e))?,
        None => LocalSyncInfo::default(),
    };
    write_status(&info, json, out)?;
    Ok(exit::OK)
}

/// `sync --status --json` data (`docs/cli-json.md`).
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub(crate) struct StatusJson {
    /// Sync is set up (`false`: local-only).
    pub connected: bool,
    pub server: Option<String>,
    pub signed_in: bool,
    pub email: Option<String>,
    /// RFC 3339 (UTC), `null` before the first successful sync.
    pub last_sync: Option<String>,
    pub pending_total: u64,
    pub pending: Vec<PendingJson>,
}

/// Pending changes of one vault.
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub(crate) struct PendingJson {
    pub vault: String,
    /// `personal`, `shared` or `unknown`.
    pub kind: &'static str,
    pub pending: u64,
}

fn rfc3339(ms: i64) -> String {
    format_time(UnixMillis(ms), "%Y-%m-%dT%H:%M:%SZ", Some(0))
}

impl StatusJson {
    pub(crate) fn from_info(info: &LocalSyncInfo) -> Self {
        Self {
            connected: info.connected(),
            server: info.server_url.clone(),
            signed_in: info.signed_in,
            email: info.email.clone(),
            last_sync: info.last_sync_ms.map(rfc3339),
            pending_total: info.pending_total(),
            pending: info
                .pending
                .iter()
                .map(|p| PendingJson {
                    vault: p.vault.uuid().to_string(),
                    kind: match p.kind {
                        Some(VaultKind::Personal) => "personal",
                        Some(VaultKind::Shared) => "shared",
                        None => "unknown",
                    },
                    pending: p.pending,
                })
                .collect(),
        }
    }
}

/// The text of `sverb sync --status`.
pub(crate) fn status_text(info: &LocalSyncInfo) -> String {
    use std::fmt::Write as _;
    let Some(server) = &info.server_url else {
        return "local-only: not connected to a sync server (`sverb login` or `sverb register`)\n"
            .to_owned();
    };
    let mut t = String::new();
    let _ = writeln!(t, "server:     {server}");
    if let Some(email) = &info.email {
        let _ = writeln!(t, "account:    {email}");
    }
    let signed_in = if info.signed_in {
        "yes"
    } else {
        "no (run `sverb login`)"
    };
    let _ = writeln!(t, "signed in:  {signed_in}");
    let last = info.last_sync_ms.map_or_else(
        || "never".to_owned(),
        |ms| format_time(UnixMillis(ms), "%Y-%m-%d %H:%M:%S UTC", Some(0)),
    );
    let _ = writeln!(t, "last sync:  {last}");
    let _ = writeln!(t, "pending:    {}", info.pending_total());
    for p in &info.pending {
        let name = match p.kind {
            Some(kind) => vault_display_name(p.vault, kind),
            None => format!("vault {}", p.vault.short()),
        };
        let _ = writeln!(t, "  {name}: {}", p.pending);
    }
    t
}

fn write_status(info: &LocalSyncInfo, json: bool, out: &mut dyn Write) -> Result<(), CliError> {
    if json {
        write_json(out, &StatusJson::from_info(info))
    } else {
        write_out(out, &status_text(info))
    }
}
