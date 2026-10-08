//! M0-07: `sverb devices list | revoke <id>` (sync builds only). M4-09: the
//! bodies, over `sverb_sync::account::{list_devices, revoke_device}`.
//!
//! - `list [--json]`: id, name, platform, created, last seen; `*` marks this
//!   device. Revoked devices are not listed.
//! - `revoke <id>`: a full id or a unique prefix of a listed one. Revoking this
//!   device logs it out (personal data kept, like `sverb logout --keep-local`).
#![cfg(feature = "sync")]

use std::io::Write;

use clap::Subcommand;
use sverb_proto::auth::DeviceView;
use sverb_sync::account::{self as acct, AccountError, Revoked};

use super::account::{account_config, account_error};
use super::output::write_json;
use super::vault::require_unlocked;
use super::{CliError, Ctx, exit, write_out};

/// `sverb devices …`
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum DevicesCmd {
    /// List this account's devices
    List {
        // M4-09
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Revoke a device
    Revoke {
        /// Device id
        id: String,
    },
}

/// One `devices list --json` entry.
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub(crate) struct DeviceJson {
    pub id: String,
    pub name: Option<String>,
    pub platform: Option<String>,
    pub created_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub current: bool,
}

fn rfc3339(t: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    t.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

impl From<&DeviceView> for DeviceJson {
    fn from(d: &DeviceView) -> Self {
        Self {
            id: d.id.to_string(),
            name: d.name.clone(),
            platform: d.platform.clone(),
            created_at: rfc3339(d.created_at),
            last_seen_at: rfc3339(d.last_seen_at),
            current: d.current,
        }
    }
}

/// The `devices list` table.
pub(crate) fn table(devices: &[DeviceView]) -> String {
    use std::fmt::Write as _;
    let day = |t: Option<chrono::DateTime<chrono::Utc>>| {
        t.map_or_else(
            || "-".to_owned(),
            |t| t.format("%Y-%m-%d %H:%M").to_string(),
        )
    };
    let rows: Vec<[String; 5]> = devices
        .iter()
        .map(|d| {
            [
                format!("{}{}", if d.current { "* " } else { "  " }, d.id),
                d.name.clone().unwrap_or_else(|| "-".into()),
                d.platform.clone().unwrap_or_else(|| "-".into()),
                day(d.created_at),
                day(d.last_seen_at),
            ]
        })
        .collect();
    let head = ["  ID", "NAME", "PLATFORM", "CREATED", "LAST SEEN"];
    let mut w = head.map(str::len);
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let mut out = String::new();
    let line = |out: &mut String, cells: [&str; 5]| {
        let mut l = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                l.push_str(c);
            } else {
                let _ = write!(l, "{c:<width$}  ", width = w[i]);
            }
        }
        let _ = writeln!(out, "{}", l.trim_end());
    };
    line(&mut out, head);
    for r in &rows {
        line(&mut out, [&r[0], &r[1], &r[2], &r[3], &r[4]]);
    }
    if devices.iter().any(|d| d.current) {
        out.push_str("(* this device)\n");
    }
    out
}

/// The device `query` names: a full id or a unique prefix.
pub(crate) fn pick<'a>(devices: &'a [DeviceView], query: &str) -> Result<&'a DeviceView, CliError> {
    let q = query.trim().to_ascii_lowercase();
    let hits: Vec<_> = devices
        .iter()
        .filter(|d| !q.is_empty() && d.id.to_string().starts_with(&q))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => Err(CliError::NotFound(format!(
            "no device `{query}` (see `sverb devices list`)"
        ))),
        _ => Err(CliError::NotFound(format!(
            "`{query}` matches {} devices; use more of the id",
            hits.len()
        ))),
    }
}

/// `sverb devices …` (unlocks the vault: the tokens are sealed under the LMK).
pub(crate) async fn run(cmd: DevicesCmd, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let unlocked = require_unlocked(ctx).await?;
    let store = unlocked.engine.store().clone();
    let lmk = unlocked.vault.lmk().clone();
    drop(unlocked);
    let cfg = account_config();
    let devices = acct::list_devices(&store, &lmk, &cfg)
        .await
        .map_err(not_signed_in)?;
    match cmd {
        DevicesCmd::List { json } => {
            if json {
                let list: Vec<DeviceJson> = devices.iter().map(DeviceJson::from).collect();
                write_json(out, &list)?;
            } else {
                write_out(out, &table(&devices))?;
            }
            Ok(exit::OK)
        }
        DevicesCmd::Revoke { id } => {
            let device = pick(&devices, &id)?;
            match acct::revoke_device(&store, &lmk, &cfg, device.id)
                .await
                .map_err(not_signed_in)?
            {
                Revoked::Other => {
                    write_out(out, &format!("Revoked device {}.\n", device.id))?;
                }
                Revoked::ThisDevice(report) => {
                    write_out(
                        out,
                        &format!(
                            "Revoked this device and logged out. {} personal item(s) kept locally.\n",
                            report.kept_items
                        ),
                    )?;
                }
            }
            Ok(exit::OK)
        }
    }
}

fn not_signed_in(e: AccountError) -> CliError {
    match e {
        AccountError::NotSignedIn => CliError::Usage(
            "this device is not signed in to a sync server; run `sverb login`".into(),
        ),
        AccountError::Sync(ref s) if s.is_status(404) => {
            CliError::NotFound("no such device".to_owned())
        }
        e => account_error(e),
    }
}
