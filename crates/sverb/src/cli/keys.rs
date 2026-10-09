//! `sverb keys list | generate | import | export` and
//! `sverb keys --dump` (the effective keymap).
//!
//! SPEC §16 uses `sverb keys` for both SSH keys and the keymap dump; the hidden
//!
//! ([`require_unlocked`]); writes go through the TUI's item service.
//! - `list [--json]`: label, algorithm, fingerprint and certificate status. Never any
//!   private material.
//! - `generate [--type ed25519] [--label L] [--comment C] [--no-passphrase]`: prints
//!   the public key, then the new id. The passphrase prompt is TTY-only; without a
//!   terminal (or with `--no-passphrase`) the key is stored without one (the vault
//!   still encrypts it).
//! - `import <file> [--label L]`: every keychain format. An encrypted key asks for its
//!   passphrase on a TTY (3 tries); without one it exits 3. A `.pub` alone becomes a
//!   hardware / agent reference (confirmed on a TTY). A key already in the keychain is
//!   not duplicated (its id is printed).
//! - `export <key> [--public] [--output F]`: `--public` prints the public key. The
//!   private key goes to `--output` (mode 0600, never overwritten silently) or to
//!   stdout **only when stdout is not a terminal**.

use std::{
    io::{BufRead, Write},
    path::PathBuf,
    sync::Arc,
};

use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use sverb_core::{
    error_report::ErrorReport,
    keychain::{
        KeychainError, algorithm_name,
        cert::{ExpiryBadge, expiry_badge, now_secs, parse_cert},
        export::{self as kexport, PrivateExport},
        generate::{GenerateRequest, default_comment, default_label, generate},
        import::{self as kimport, ImportOptions},
    },
    model::{ItemId, KeyAlgorithm},
    secret::SecretString,
};
use sverb_tui::keymap::Keymap;
use sverb_tui::services::vault::items::{ItemError, ItemOps};
use zeroize::Zeroizing;

use super::{CliError, Ctx, vault::require_unlocked};

/// `sverb keys [--dump [--json]] [<subcommand>]`
#[derive(Args, Debug, PartialEq, Eq)]
#[command(args_conflicts_with_subcommands = true, arg_required_else_help = true)]
pub(crate) struct KeysArgs {
    /// Print the effective keymap (built-ins and config overrides)
    #[arg(long)]
    pub dump: bool,
    /// With --dump: print JSON (`{"version":1,"data":…}`)
    #[arg(long, requires = "dump")]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Option<KeysCmd>,
}

/// `sverb keymap --dump [--json]` (hidden alias).
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct KeymapArgs {
    /// Print the effective keymap
    #[arg(long, required = true)]
    pub dump: bool,
    /// Print JSON (`{"version":1,"data":…}`)
    #[arg(long)]
    pub json: bool,
}

/// SSH key subcommands.
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum KeysCmd {
    /// List keys in the vault (no private material)
    List {
        /// Print JSON (`{"version":1,"data":…}`)
        #[arg(long)]
        json: bool,
    },
    /// Generate a key
    Generate {
        /// Key algorithm
        #[arg(long = "type", value_enum, default_value_t = KeyType::Ed25519)]
        key_type: KeyType,
        /// Label for the key
        #[arg(long)]
        label: Option<String>,
        /// Key comment (default `user@hostname-sverb`)
        #[arg(long)]
        comment: Option<String>,
        /// Do not ask for a passphrase (scripts)
        #[arg(long)]
        no_passphrase: bool,
    },
    /// Import a key file (OpenSSH, PEM, PKCS#8, or a .pub agent / hardware key)
    Import {
        /// The key file
        file: PathBuf,
        /// Label for the key (default: its comment, else the file name)
        #[arg(long)]
        label: Option<String>,
    },
    /// Export a key
    Export {
        /// Key label or id
        key: String,
        /// Export only the public key
        #[arg(long)]
        public: bool,
        /// Write to this file (private keys: mode 0600)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

/// `--type` values for `sverb keys generate`.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyType {
    #[value(name = "ed25519")]
    Ed25519,
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    #[value(name = "ecdsa-p384")]
    EcdsaP384,
    #[value(name = "ecdsa-p521")]
    EcdsaP521,
    #[value(name = "rsa-2048")]
    Rsa2048,
    #[value(name = "rsa-3072")]
    Rsa3072,
    #[value(name = "rsa-4096")]
    Rsa4096,
}

impl KeyType {
    fn algorithm(self) -> KeyAlgorithm {
        match self {
            Self::Ed25519 => KeyAlgorithm::Ed25519,
            Self::EcdsaP256 => KeyAlgorithm::EcdsaP256,
            Self::EcdsaP384 => KeyAlgorithm::EcdsaP384,
            Self::EcdsaP521 => KeyAlgorithm::EcdsaP521,
            Self::Rsa2048 => KeyAlgorithm::Rsa2048,
            Self::Rsa3072 => KeyAlgorithm::Rsa3072,
            Self::Rsa4096 => KeyAlgorithm::Rsa4096,
        }
    }
}

pub(crate) async fn run(args: KeysArgs, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    if args.dump {
        return run_dump(args.json, ctx, out);
    }
    let Some(cmd) = args.cmd else {
        // `arg_required_else_help` makes clap print help instead.
        return Err(CliError::Usage(
            "`sverb keys` needs a subcommand or --dump".to_owned(),
        ));
    };
    let unlocked = require_unlocked(ctx).await?;
    let ops = ItemOps::new(unlocked.engine, Arc::new(unlocked.vault));
    let mut io = KeysIo {
        prompt_tty: ctx.tty.stdin && ctx.tty.stderr,
        stdout_tty: ctx.tty.stdout,
        read_secret: &mut |prompt| super::vault::read_secret(prompt).ok(),
        read_yes: &mut read_yes,
    };
    run_with(cmd, &ops, &mut io, out).await
}

/// `sverb keys --dump [--json]`: the effective keymap (built-ins + config overrides) as
/// `MODE KEYS ACTION DESCRIPTION SOURCE`, or JSON `{"version":1,"data":[…]}`.
pub(crate) fn run_dump(json: bool, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let rows = Keymap::effective(&ctx.config);
    if json {
        super::output::write_json(out, &rows)?;
    } else {
        super::write_out(out, &sverb_tui::keymap::dump::render_text(&rows))?;
    }
    Ok(0)
}

/// The terminal and the prompts of a `keys` command (injected by tests).
pub(crate) struct KeysIo<'a> {
    /// Prompts can be shown and answered (stdin and stderr are terminals).
    pub prompt_tty: bool,
    /// stdout is a terminal (no private key is printed there).
    pub stdout_tty: bool,
    /// Ask for a secret (`None`: cancelled).
    pub read_secret: &'a mut dyn FnMut(&str) -> Option<Zeroizing<String>>,
    /// Ask y/N.
    pub read_yes: &'a mut dyn FnMut() -> bool,
}

/// `y`/`yes` on stdin.
fn read_yes() -> bool {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn item_error(e: ItemError) -> CliError {
    match e {
        ItemError::NotFound => CliError::NotFound(e.to_string()),
        other => CliError::Failure(ErrorReport::msg(other.to_string())),
    }
}

fn key_error(e: KeychainError) -> CliError {
    match e {
        KeychainError::Read(_) => CliError::NotFound(e.to_string()),
        other => CliError::Failure(ErrorReport::msg(other.to_string())),
    }
}

/// One `keys list --json` entry: public data only.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct KeyJson {
    id: String,
    label: String,
    algorithm: String,
    fingerprint: String,
    /// `none`, `valid`, `expiring`, `expired`, `not-yet-valid`.
    certificate: String,
    certificates: usize,
    agent_ref: bool,
    encrypted: bool,
    agent_forwardable: bool,
}

fn cert_status(badges: &[ExpiryBadge]) -> String {
    if badges.is_empty() {
        return "none".to_owned();
    }
    match badges
        .iter()
        .copied()
        .fold(ExpiryBadge::None, ExpiryBadge::worst)
    {
        ExpiryBadge::None => "valid",
        ExpiryBadge::Expiring => "expiring",
        ExpiryBadge::Expired => "expired",
        ExpiryBadge::NotYetValid => "not-yet-valid",
    }
    .to_owned()
}

async fn key_rows(ops: &ItemOps) -> Result<Vec<KeyJson>, CliError> {
    let keys = ops.keys().await.map_err(item_error)?;
    let certs = ops.certificates().await.map_err(item_error)?;
    let now = now_secs();
    let mut rows: Vec<KeyJson> = keys
        .into_iter()
        .map(|(l, k)| {
            let badges: Vec<ExpiryBadge> = certs
                .iter()
                .filter(|(cl, c)| k.certificate_ids.contains(&cl.id) || c.key_id == Some(l.id))
                .filter_map(|(_, c)| parse_cert(&c.cert).ok())
                .map(|i| expiry_badge(&i, now))
                .collect();
            KeyJson {
                id: l.id.to_string(),
                label: k.label.clone(),
                algorithm: algorithm_name(k.algorithm).to_owned(),
                fingerprint: sverb_core::keychain::fingerprint(&k.public_key).unwrap_or_default(),
                certificate: cert_status(&badges),
                certificates: badges.len(),
                agent_ref: k.is_agent_ref(),
                encrypted: !k.is_agent_ref() && kexport::is_encrypted(&k),
                agent_forwardable: k.agent_forwardable,
            }
        })
        .collect();
    rows.sort_by_key(|r| r.label.to_lowercase());
    Ok(rows)
}

/// Resolve `<key>`: an id (or a unique id prefix), else a label (case-insensitive).
async fn resolve_key(ops: &ItemOps, arg: &str) -> Result<ItemId, CliError> {
    let keys = ops.keys().await.map_err(item_error)?;
    let arg = arg.trim();
    if let Some((l, _)) = keys.iter().find(|(l, _)| l.id.to_string() == arg) {
        return Ok(l.id);
    }
    let by_label: Vec<_> = keys
        .iter()
        .filter(|(_, k)| k.label.eq_ignore_ascii_case(arg))
        .collect();
    if let [(l, _)] = by_label.as_slice() {
        return Ok(l.id);
    }
    let by_prefix: Vec<_> = keys
        .iter()
        .filter(|(l, _)| arg.len() >= 4 && l.id.to_string().starts_with(arg))
        .collect();
    match (by_label.len(), by_prefix.as_slice()) {
        (0, [(l, _)]) => Ok(l.id),
        (0, []) => Err(CliError::NotFound(format!("no key named `{arg}`"))),
        _ => Err(CliError::NotFound(format!(
            "`{arg}` matches several keys; use its id (`sverb keys list`)"
        ))),
    }
}

/// `YYYY-MM-DD` (UTC) of a UNIX time (the default label's date).
fn utc_date(secs: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn line(out: &mut dyn Write, text: &str) -> Result<(), CliError> {
    writeln!(out, "{text}").map_err(|e| CliError::failure(&e))
}

/// Run a `keys` subcommand with `ops` and `io`.
pub(crate) async fn run_with(
    cmd: KeysCmd,
    ops: &ItemOps,
    io: &mut KeysIo<'_>,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    match cmd {
        KeysCmd::List { json } => {
            let rows = key_rows(ops).await?;
            if json {
                super::output::write_json(out, &rows)?;
            } else if rows.is_empty() {
                line(out, "No keys.")?;
            } else {
                for r in &rows {
                    let mut flags = Vec::new();
                    if r.agent_ref {
                        flags.push("agent");
                    }
                    if r.encrypted {
                        flags.push("encrypted");
                    }
                    let cert = if r.certificate == "none" {
                        String::new()
                    } else {
                        format!("cert:{}", r.certificate)
                    };
                    line(
                        out,
                        format!(
                            "{:<24} {:<12} {} {} {}",
                            r.label,
                            r.algorithm,
                            r.fingerprint,
                            flags.join(","),
                            cert
                        )
                        .trim_end(),
                    )?;
                }
            }
            Ok(0)
        }
        KeysCmd::Generate {
            key_type,
            label,
            comment,
            no_passphrase,
        } => {
            let algorithm = key_type.algorithm();
            let passphrase = if no_passphrase || !io.prompt_tty {
                None
            } else {
                let first = (io.read_secret)("Passphrase (empty for none): ")
                    .ok_or_else(|| CliError::Usage("cancelled".to_owned()))?;
                if first.is_empty() {
                    None
                } else {
                    let again = (io.read_secret)("Confirm passphrase: ")
                        .ok_or_else(|| CliError::Usage("cancelled".to_owned()))?;
                    if *again != *first {
                        return Err(CliError::Usage("the passphrases do not match".to_owned()));
                    }
                    Some(SecretString::from(first.as_str()))
                }
            };
            let req = GenerateRequest {
                algorithm,
                comment: comment.unwrap_or_else(default_comment),
                passphrase,
            };
            let pass = req
                .passphrase
                .as_ref()
                .map(|p| SecretString::from(p.expose()));
            let generated = tokio::task::spawn_blocking(move || generate(&req))
                .await
                .map_err(|e| CliError::failure(&e))?
                .map_err(key_error)?;
            let today = utc_date(now_secs());
            let label = label.unwrap_or_else(|| default_label(algorithm, &today));
            let public = generated.public_key.clone();
            let written = ops
                .create_key(generated.into_key(label, pass, true))
                .await
                .map_err(item_error)?;
            line(out, &public)?;
            line(out, &written.id.to_string())?;
            Ok(0)
        }
        KeysCmd::Import { file, label } => {
            let path = file.to_string_lossy().into_owned();
            let text = kimport::read_key_file(&path).map_err(key_error)?;
            let imported = if kimport::needs_passphrase(text.expose()) {
                if !io.prompt_tty {
                    return Err(CliError::UnlockFailed(ErrorReport::msg(
                        "the key is encrypted and no terminal is available to enter its passphrase",
                    )));
                }
                kimport::import_with_prompt(text.expose(), ImportOptions::default(), |_, last| {
                    if last.is_some() {
                        eprintln!("Wrong passphrase.");
                    }
                    (io.read_secret)("Key passphrase: ").map(|p| SecretString::from(p.as_str()))
                })
                .map_err(key_error)?
            } else {
                kimport::import_text(text.expose(), None, ImportOptions::default())
                    .map_err(key_error)?
            };
            if imported.is_agent_ref() {
                if io.prompt_tty {
                    eprint!(
                        "{path} is a public key only. Create a hardware / agent key reference \
                         (the system agent signs with it)? [y/N] "
                    );
                    if !(io.read_yes)() {
                        return Err(CliError::Usage("cancelled".to_owned()));
                    }
                } else {
                    eprintln!(
                        "note: {path} is a public key only: stored as an agent key reference"
                    );
                }
            }
            if let Some((existing, name)) = ops
                .duplicate_key(&imported.public_key)
                .await
                .map_err(item_error)?
            {
                eprintln!("This key is already in the keychain as \"{name}\"; using it.");
                line(out, &existing.to_string())?;
                return Ok(0);
            }
            let label = label
                .filter(|l| !l.trim().is_empty())
                .unwrap_or_else(|| imported.suggested_label(kimport::file_stem(&path).as_deref()));
            let written = ops
                .create_key(imported.into_key(label))
                .await
                .map_err(item_error)?;
            line(out, &written.id.to_string())?;
            Ok(0)
        }
        KeysCmd::Export {
            key,
            public,
            output,
        } => {
            let id = resolve_key(ops, &key).await?;
            let k = ops.load_key(id).await.map_err(item_error)?;
            if public {
                let text = kexport::public_export(&k);
                return match output {
                    Some(path) => {
                        kexport::write_public_file(&path, &text, false).map_err(key_error)?;
                        Ok(0)
                    }
                    None => {
                        line(out, &text)?;
                        Ok(0)
                    }
                };
            }
            let text =
                kexport::private_export(&k, &PrivateExport::Keep, None).map_err(key_error)?;
            match output {
                Some(path) => {
                    let exists = path.exists();
                    if exists {
                        if !io.prompt_tty {
                            return Err(key_error(KeychainError::Exists(
                                path.display().to_string(),
                            )));
                        }
                        eprint!("{} exists. Overwrite? [y/N] ", path.display());
                        if !(io.read_yes)() {
                            return Err(CliError::Usage("cancelled".to_owned()));
                        }
                    }
                    kexport::write_private_file(&path, &text, exists).map_err(key_error)?;
                    eprintln!("Private key written to {} (mode 0600)", path.display());
                    Ok(0)
                }
                None if io.stdout_tty => Err(CliError::Failure(ErrorReport::msg(
                    "refusing to print a private key to the terminal; use --output <file> or \
                     pipe the output",
                ))),
                None => {
                    line(out, text.expose())?;
                    Ok(0)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! T-11 (no private material in `keys list --json`), T-12 (private export
    //! refused on a terminal, printed when piped), generate / import / duplicates.

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::Path;

    use sverb_core::paths::{MapEnv, Paths};
    use sverb_core::vault::{Argon2Cost, NoKeyring};
    use sverb_tui::services::vault::VaultEngine;

    use super::*;

    const PW: &str = "correct horse battery staple violin";

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/keys")
            .join(name)
    }

    struct Home(PathBuf);

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn ops(tag: &str) -> (Home, ItemOps) {
        let home =
            std::env::temp_dir().join(format!("sverb-m2-03-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let paths = Paths::resolve(&MapEnv::new().var("SVERB_HOME", &home)).unwrap();
        paths.ensure(sverb_core::paths::DirKind::Data).unwrap();
        let store = sverb_store::Store::open(&paths).unwrap();
        let engine = VaultEngine::new(store, Arc::new(NoKeyring), Argon2Cost::TEST);
        engine.initialize(PW, false).await.unwrap();
        let vault = engine.unlock_with_password(PW).await.unwrap();
        (Home(home), ItemOps::new(engine, Arc::new(vault)))
    }

    async fn exec(
        ops: &ItemOps,
        cmd: KeysCmd,
        prompt_tty: bool,
        stdout_tty: bool,
        secrets: &[&str],
    ) -> (Result<u8, CliError>, String) {
        let mut answers: Vec<String> = secrets.iter().rev().map(|s| (*s).to_owned()).collect();
        let mut secret = |_: &str| answers.pop().map(Zeroizing::new);
        let mut yes = || true;
        let mut io = KeysIo {
            prompt_tty,
            stdout_tty,
            read_secret: &mut secret,
            read_yes: &mut yes,
        };
        let mut out = Vec::new();
        let res = run_with(cmd, ops, &mut io, &mut out).await;
        (res, String::from_utf8(out).unwrap())
    }

    fn import(file: &str) -> KeysCmd {
        KeysCmd::Import {
            file: fixture(file),
            label: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn t11_list_json_has_no_private_material() {
        let (_h, ops) = ops("t11").await;
        let gen_cmd = KeysCmd::Generate {
            key_type: KeyType::Ed25519,
            label: Some("work".into()),
            comment: Some("me@host-sverb".into()),
            no_passphrase: true,
        };
        let (res, out) = exec(&ops, gen_cmd, false, false, &[]).await;
        assert_eq!(res, Ok(0));
        assert!(out.starts_with("ssh-ed25519 "), "{out}");
        assert!(!out.contains("PRIVATE KEY"));
        // Encrypted import on a "TTY".
        let (res, _) = exec(
            &ops,
            import("openssh_ed25519_enc"),
            true,
            false,
            &["sverb-test"],
        )
        .await;
        assert_eq!(res, Ok(0));
        let (res, _) = exec(&ops, import("agent_ref.pub"), true, false, &[]).await;
        assert_eq!(res, Ok(0));
        let (res, out) = exec(&ops, KeysCmd::List { json: true }, false, false, &[]).await;
        assert_eq!(res, Ok(0));
        assert!(!out.contains("PRIVATE KEY"), "{out}");
        assert!(!out.contains("sverb-test"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let data = v["data"].as_array().unwrap();
        assert_eq!(data.len(), 3);
        let labels: Vec<&str> = data.iter().map(|d| d["label"].as_str().unwrap()).collect();
        assert_eq!(labels, ["enc@sverb", "hw@sverb", "work"]);
        assert_eq!(data[0]["encrypted"], true);
        assert_eq!(data[1]["agent_ref"], true);
        assert!(
            data[2]["fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("SHA256:")
        );
        assert_eq!(data[2]["certificate"], "none");
        let (res, out) = exec(&ops, KeysCmd::List { json: false }, false, false, &[]).await;
        assert_eq!(res, Ok(0));
        assert!(out.contains("work") && !out.contains("PRIVATE KEY"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn t12_private_export_refused_on_a_terminal() {
        let (_h, ops) = ops("t12").await;
        let (res, _) = exec(&ops, import("openssh_ed25519"), false, false, &[]).await;
        assert_eq!(res, Ok(0));
        let export = |public: bool, output: Option<PathBuf>| KeysCmd::Export {
            key: "fixture@sverb".into(),
            public,
            output,
        };
        let (res, out) = exec(&ops, export(false, None), false, true, &[]).await;
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("--output"));
        assert!(out.is_empty());
        // Piped: the key.
        let (res, out) = exec(&ops, export(false, None), false, false, &[]).await;
        assert_eq!(res, Ok(0));
        assert!(out.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        // --public on a terminal is fine.
        let (res, out) = exec(&ops, export(true, None), false, true, &[]).await;
        assert_eq!(res, Ok(0));
        assert!(out.starts_with("ssh-ed25519 ") && out.trim_end().ends_with("fixture@sverb"));
        // --output: mode 0600; no silent overwrite without a terminal.
        let dir = std::env::temp_dir().join(format!("sverb-m2-03-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("id");
        let (res, _) = exec(&ops, export(false, Some(file.clone())), false, true, &[]).await;
        assert_eq!(res, Ok(0));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let (res, _) = exec(&ops, export(false, Some(file.clone())), false, true, &[]).await;
        assert_eq!(res.unwrap_err().exit_code(), 1);
        let _ = std::fs::remove_dir_all(&dir);
        // Unknown key.
        let (res, _) = exec(
            &ops,
            KeysCmd::Export {
                key: "nope".into(),
                public: true,
                output: None,
            },
            false,
            false,
            &[],
        )
        .await;
        assert_eq!(res.unwrap_err().exit_code(), 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn import_without_terminal_and_duplicates() {
        let (_h, ops) = ops("import").await;
        // Encrypted, no terminal: exit 3, nothing saved.
        let (res, _) = exec(&ops, import("pkcs8_rsa_enc.pem"), false, false, &[]).await;
        assert_eq!(res.unwrap_err().exit_code(), 3);
        // Three wrong passphrases: aborted.
        let (res, _) = exec(
            &ops,
            import("pkcs8_rsa_enc.pem"),
            true,
            false,
            &["a", "b", "c"],
        )
        .await;
        assert!(res.unwrap_err().to_string().contains("import aborted"));
        assert!(ops.keys().await.unwrap().is_empty());
        let (res, first) = exec(&ops, import("pkcs1_rsa.pem"), false, false, &[]).await;
        assert_eq!(res, Ok(0));
        // The same key again: the existing id.
        let (res, again) = exec(&ops, import("pkcs8_rsa.pem"), false, false, &[]).await;
        assert_eq!(res, Ok(0));
        assert_eq!(first, again);
        assert_eq!(ops.keys().await.unwrap().len(), 1);
        // Generated with a passphrase typed twice.
        let (res, out) = exec(
            &ops,
            KeysCmd::Generate {
                key_type: KeyType::EcdsaP256,
                label: None,
                comment: None,
                no_passphrase: false,
            },
            true,
            false,
            &["pp", "pp"],
        )
        .await;
        assert_eq!(res, Ok(0));
        assert!(out.starts_with("ecdsa-sha2-nistp256 "), "{out}");
        let keys = ops.keys().await.unwrap();
        let k = keys
            .iter()
            .find(|(_, k)| k.label.starts_with("ECDSA P-256 "))
            .unwrap();
        assert!(kexport::is_encrypted(&k.1));
        assert_eq!(k.1.passphrase.as_ref().map(|p| p.expose()), Some("pp"));
    }
}
