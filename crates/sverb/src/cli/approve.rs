//! `sverb approve <host> [--all] [--yes]` (SPEC §16, §17.1).
//!
//! Lists every value of the host that acts on this machine (resolved through its
//! groups and the vault defaults, plus its forwarding rules) with its status
//! (`approved`, `needs approval`, `changed since approval`) and the full value, then:
//!
//! - on a terminal: asks `[y/N]` for each value that is not approved (`--all`: one
//!   question for all of them);
//! - `--yes` (scripts): approves every value that is not approved and prints what it
//!   approved;
//! - without a terminal and without `--yes`: exit 2 (nothing is approved).
//!
//! Approvals are rows in the device-local `local_approvals` table (never synced).

use std::io::{BufRead, Write};

use clap::Args;
use sverb_core::{
    host_arg::{HostCandidate, resolve_host_arg},
    model::{Host, ItemKind},
    resolve::approval::{ApprovalStatus, LocalAction, PendingApproval, review},
};
use sverb_tui::services::vault::VaultService;

use super::{CliError, Ctx, exit, vault::require_unlocked, write_out};

/// `sverb approve …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct ApproveArgs {
    /// Label, address or unique fuzzy match
    pub host: String,
    /// Approve every listed value with one question
    #[arg(long)]
    pub all: bool,
    /// Approve without asking (scripts; required without a terminal)
    #[arg(long)]
    pub yes: bool,
}

/// How `sverb approve` answers (the `--all` / `--yes` flags).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ApproveOptions {
    /// One question for every value instead of one per value.
    pub all: bool,
    /// Approve without asking (scripts).
    pub yes: bool,
}

/// `sverb approve <host>`.
pub(crate) async fn run_async(
    host: &str,
    opts: ApproveOptions,
    ctx: &Ctx,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let interactive = ctx.tty.stdin && ctx.tty.stderr;
    let unlocked = require_unlocked(ctx).await?;
    let vault = VaultService::from_unlocked(unlocked.engine, unlocked.vault);
    let ops = vault.item_ops().ok_or(CliError::VaultLocked)?;
    let hosts = ops
        .list(&[ItemKind::Host])
        .await
        .map_err(|e| CliError::Failure(e.report()))?;
    let candidates: Vec<HostCandidate<_>> = hosts
        .iter()
        .filter_map(|i| {
            let h = Host::try_from(&i.body).ok()?;
            Some(HostCandidate {
                id: i.id,
                label: h.label.clone(),
                address: h.address.clone(),
            })
        })
        .collect();
    let (found, _) = resolve_host_arg(host, &candidates)?;
    let (label, actions) = ops
        .host_local_actions(found.id)
        .await
        .map_err(|e| CliError::Failure(e.report()))?;
    let store = vault.store().clone();
    let pending = review(actions, &*store.device_approvals());

    if pending.is_empty() {
        write_out(
            out,
            &format!("host \"{label}\" has no settings that act on this machine\n"),
        )?;
        return Ok(exit::OK);
    }
    write_out(out, &listing(&label, &pending))?;
    let open: Vec<&PendingApproval> = pending
        .iter()
        .filter(|p| p.status != ApprovalStatus::Approved)
        .collect();
    if open.is_empty() {
        write_out(out, "everything is approved\n")?;
        return Ok(exit::OK);
    }

    let chosen = choose(&open, opts, interactive, ask_yes)?;
    store
        .approve_all_local(&chosen)
        .await
        .map_err(|e| CliError::failure(&e))?;
    let mut text = String::new();
    for a in &chosen {
        text.push_str(&format!("approved: {}: {}\n", a.kind.label(), a.value));
    }
    let skipped = open.len() - chosen.len();
    if skipped > 0 {
        text.push_str(&format!("{skipped} value(s) left unapproved\n"));
    }
    write_out(out, &text)?;
    Ok(exit::OK)
}

/// Which of the `open` (not approved) values to approve: all with `--yes`; else on a
/// terminal one question each (or one for all with `--all`); without a terminal,
/// a usage error (exit 2).
pub(crate) fn choose(
    open: &[&PendingApproval],
    opts: ApproveOptions,
    interactive: bool,
    mut ask: impl FnMut(&str) -> bool,
) -> Result<Vec<LocalAction>, CliError> {
    let all = || open.iter().map(|p| p.action.clone()).collect();
    if opts.yes {
        Ok(all())
    } else if !interactive {
        Err(CliError::Usage(
            "no terminal to ask on: review the values above and run `sverb approve <host> --all --yes`"
                .to_owned(),
        ))
    } else if opts.all {
        Ok(
            if ask(&format!("Approve all {} values above?", open.len())) {
                all()
            } else {
                Vec::new()
            },
        )
    } else {
        Ok(open
            .iter()
            .filter(|p| ask(&p.action.question()))
            .map(|p| p.action.clone())
            .collect())
    }
}

/// The listing: one line per value with its status and the full value.
pub(crate) fn listing(label: &str, pending: &[PendingApproval]) -> String {
    let mut text = format!("host \"{label}\": settings that act on this machine\n");
    for p in pending {
        text.push_str(&format!(
            "  [{}] {}: {}  (item {})\n",
            p.status,
            p.action.kind.label(),
            p.action.value,
            p.action.item_id.short()
        ));
    }
    text
}

/// `y`/`yes` on the terminal.
fn ask_yes(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use sverb_core::model::ItemId;
    use sverb_core::resolve::approval::ActionKind;

    use super::*;

    #[test]
    fn listing_shows_status_and_full_value() {
        let id = ItemId::from_bytes([0xab; 16]);
        let text = listing(
            "db",
            &[
                PendingApproval {
                    action: LocalAction::new(id, ActionKind::ProxyCommand, "ssh -W %h:%p bastion"),
                    status: ApprovalStatus::ChangedSinceApproval,
                },
                PendingApproval {
                    action: LocalAction::new(id, ActionKind::SystemAgent, "system"),
                    status: ApprovalStatus::Approved,
                },
            ],
        );
        assert!(text.contains("[changed since approval] ProxyCommand: ssh -W %h:%p bastion"));
        assert!(text.contains("[approved] system agent forwarding: system"));
    }

    // T-07 (unit half): `--all --yes` approves everything without asking; no
    // terminal and no `--yes` → exit 2; interactive asks per value or once (`--all`).
    #[test]
    fn choose_answers() {
        let id = ItemId::from_bytes([1; 16]);
        let p = |kind, v: &str| PendingApproval {
            action: LocalAction::new(id, kind, v),
            status: ApprovalStatus::NeedsApproval,
        };
        let a = p(ActionKind::ProxyCommand, "nc %h %p");
        let b = p(ActionKind::ForwardBind, "0.0.0.0:8080");
        let open = [&a, &b];
        let never = |_: &str| -> bool { panic!("asked") };
        let yes = ApproveOptions {
            all: true,
            yes: true,
        };
        assert_eq!(choose(&open, yes, false, never).unwrap().len(), 2);
        let err = choose(&open, ApproveOptions::default(), false, never).unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
        let mut asked = Vec::new();
        let got = choose(&open, ApproveOptions::default(), true, |q: &str| {
            asked.push(q.to_owned());
            q.contains("local command")
        })
        .unwrap();
        assert_eq!(got, std::slice::from_ref(&a.action));
        assert_eq!(asked.len(), 2);
        let all = ApproveOptions {
            all: true,
            yes: false,
        };
        let mut n = 0;
        assert_eq!(
            choose(&open, all, true, |_: &str| {
                n += 1;
                true
            })
            .unwrap()
            .len(),
            2
        );
        assert_eq!(n, 1);
    }
}
