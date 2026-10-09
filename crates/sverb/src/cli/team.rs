//! `sverb team list | invite <email> | verify <user>` (sync builds only).
//!
//! `team list [--json]` prints each org with its members and roles;
//! `team invite <email> [--org O] [--role member]` creates an invite and prints the
//! link when the server has no SMTP (otherwise it says the mail went out);
//! `team create <name>` and `team accept <link>` create and join orgs. `--org`
//! takes a name or an id; it may be left out when the account is in one org.
//!
//! `sverb team verify <user>` prints the 60-digit safety number between this
//! account and a pinned member (12 groups of 5 digits, the same on both devices,
//! §13.3) and asks "Mark as verified? [y/N]". After a key change it warns and asks
//! "Accept new key? [y/N]" instead. Pins and verification are device-local
//! (`pinned_keys`), never synced. Without a terminal the number is printed and
//! nothing is marked.
#![cfg(feature = "sync")]

use std::io::{BufRead, Write};

use clap::Subcommand;
use sverb_store::pins::find_pin;
use sverb_store::{PinState, Store};
use sverb_tui::services::vault::VaultService;

use sverb_proto::orgs::{InviteCreated, MemberView, OrgView, Role};
use sverb_sync::account::{AccountError, teams};

use super::account::{account_config, account_error};
use super::output::write_json;
use super::{CliError, Ctx, exit, vault::require_unlocked, write_out};

/// `sverb team …`
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum TeamCmd {
    /// List team members
    List {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Invite someone by email
    Invite {
        /// Email address
        email: String,
        /// Org name or id (needed when you are in several)
        #[arg(long, value_name = "ORG")]
        org: Option<String>,
        /// Role to grant: member, admin or owner
        #[arg(long, default_value = "member", value_parser = parse_role)]
        role: Role,
    },
    /// Create an org (you become its owner)
    Create {
        /// Org name
        name: String,
    },
    /// Join an org with an invite link
    Accept {
        /// The invite link (or token)
        link: String,
    },
    /// Verify a member's safety number
    Verify {
        /// User name or email
        user: String,
    },
}

fn parse_role(s: &str) -> Result<Role, String> {
    Role::parse(&s.to_ascii_lowercase())
        .ok_or_else(|| format!("unknown role `{s}` (member, admin, owner)"))
}

/// The org `query` names (name, case-insensitive, or id), or the only one.
pub(crate) fn pick_org<'a>(
    orgs: &'a [OrgView],
    query: Option<&str>,
) -> Result<&'a OrgView, CliError> {
    match query {
        None => match orgs {
            [one] => Ok(one),
            [] => Err(CliError::Usage(
                "you are not in any org: create one with `sverb team create <name>`".into(),
            )),
            _ => Err(CliError::Usage(format!(
                "you are in {} orgs: pick one with --org ({})",
                orgs.len(),
                orgs.iter()
                    .map(|o| o.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        },
        Some(q) => {
            let q = q.trim();
            let hits: Vec<_> = orgs
                .iter()
                .filter(|o| o.id.to_string() == q || o.name.eq_ignore_ascii_case(q))
                .collect();
            match hits.as_slice() {
                [one] => Ok(one),
                [] => Err(CliError::NotFound(format!(
                    "no org `{q}` (see `sverb team list`)"
                ))),
                _ => Err(CliError::Usage(format!(
                    "`{q}` names several orgs: use its id"
                ))),
            }
        }
    }
}

/// What `team invite` prints.
pub(crate) fn invite_text(inv: &InviteCreated, org: &str) -> String {
    let who = inv.email.as_deref().unwrap_or("anyone with the link");
    let mut t = format!("Invited {who} to {org} as {}.\n", inv.role);
    match &inv.link {
        Some(link) => {
            t.push_str("Send them this link (single use, expires in 7 days):\n");
            t.push_str(link);
            t.push('\n');
        }
        None if inv.emailed => t.push_str("The invite link was sent by email.\n"),
        None => {}
    }
    t
}

/// What `team list` prints.
pub(crate) fn list_text(orgs: &[(OrgView, Vec<MemberView>)]) -> String {
    use std::fmt::Write as _;
    if orgs.is_empty() {
        return "You are not in any org. Create one with `sverb team create <name>`.\n".into();
    }
    let mut t = String::new();
    for (org, members) in orgs {
        let _ = writeln!(t, "{} (you: {})", org.name, org.role);
        for m in members {
            let _ = writeln!(t, "  {:<6} {}", m.role.as_str(), m.email);
        }
    }
    t
}

/// The `team list --json` entries.
#[derive(serde::Serialize)]
struct OrgJson<'a> {
    id: uuid::Uuid,
    name: &'a str,
    role: Role,
    members: &'a [MemberView],
}

fn account_failure(e: AccountError) -> CliError {
    match e {
        AccountError::NotSignedIn => CliError::Usage(
            "this device is not signed in to a sync server; run `sverb login`".into(),
        ),
        AccountError::Sync(ref s) if s.is_status(404) => {
            CliError::NotFound("no such org or invite (or it expired or was used)".into())
        }
        AccountError::Sync(ref s) if s.is_status(403) => {
            CliError::Failure(sverb_core::error_report::ErrorReport::msg(e.to_string()))
        }
        e => account_error(e),
    }
}

// List, invite, create, accept.
async fn run_remote(cmd: TeamCmd, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let unlocked = require_unlocked(ctx).await?;
    let store = unlocked.engine.store().clone();
    let lmk = unlocked.vault.lmk().clone();
    drop(unlocked);
    let cfg = account_config();
    match cmd {
        TeamCmd::List { json } => {
            let orgs = teams::list_orgs(&store, &lmk, &cfg)
                .await
                .map_err(account_failure)?;
            let mut full = Vec::new();
            for o in orgs {
                let m = teams::members(&store, &lmk, &cfg, o.id)
                    .await
                    .map_err(account_failure)?;
                full.push((o, m));
            }
            if json {
                let data: Vec<OrgJson<'_>> = full
                    .iter()
                    .map(|(o, m)| OrgJson {
                        id: o.id,
                        name: &o.name,
                        role: o.role,
                        members: m,
                    })
                    .collect();
                write_json(out, &data)?;
            } else {
                write_out(out, &list_text(&full))?;
            }
        }
        TeamCmd::Invite { email, org, role } => {
            let orgs = teams::list_orgs(&store, &lmk, &cfg)
                .await
                .map_err(account_failure)?;
            let target = pick_org(&orgs, org.as_deref())?;
            let inv = teams::invite(&store, &lmk, &cfg, target.id, Some(&email), role)
                .await
                .map_err(account_failure)?;
            write_out(out, &invite_text(&inv, &target.name))?;
        }
        TeamCmd::Create { name } => {
            let org = teams::create_org(&store, &lmk, &cfg, &name)
                .await
                .map_err(account_failure)?;
            write_out(
                out,
                &format!("Created {} ({}). You are its owner.\n", org.name, org.id),
            )?;
        }
        TeamCmd::Accept { link } => {
            let joined = teams::accept_invite(&store, &lmk, &cfg, &link)
                .await
                .map_err(account_failure)?;
            let orgs = teams::list_orgs(&store, &lmk, &cfg)
                .await
                .map_err(account_failure)?;
            let name = orgs
                .iter()
                .find(|o| o.id == joined.org_id)
                .map_or_else(|| joined.org_id.to_string(), |o| o.name.clone());
            write_out(out, &format!("Joined {name} as {}.\n", joined.role))?;
        }
        TeamCmd::Verify { .. } => unreachable!("handled by run_async"),
    }
    Ok(exit::OK)
}

// `cli/mod.rs` dispatches `team` here (async: `verify` opens the store).
pub(crate) async fn run_async(
    cmd: TeamCmd,
    ctx: &Ctx,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    match cmd {
        TeamCmd::Verify { user } => {
            let interactive = ctx.tty.stdin && ctx.tty.stderr;
            let unlocked = require_unlocked(ctx).await?;
            let vault = VaultService::from_unlocked(unlocked.engine, unlocked.vault);
            let store = vault.store().clone();
            verify(&store, &user, interactive, ask_yes, out).await
        }
        other => run_remote(other, ctx, out).await,
    }
}

/// `sverb team verify <user>` on `store`; `ask` answers the `[y/N]` question
/// (only called when `interactive`).
pub(crate) async fn verify(
    store: &Store,
    user: &str,
    interactive: bool,
    mut ask: impl FnMut(&str) -> bool,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let pins = store.list_pins().await.map_err(|e| CliError::failure(&e))?;
    let mine = pins.iter().find(|p| p.is_self).cloned().ok_or_else(|| {
        CliError::Usage(
            "this device has no account keys pinned yet: log in to the sync server first"
                .to_owned(),
        )
    })?;
    let theirs = find_pin(&pins, user).map_err(CliError::NotFound)?.clone();
    if theirs.is_self {
        return Err(CliError::Usage(
            "that is your own account: compare the number on the other member's device".into(),
        ));
    }
    let label = theirs.label.clone().unwrap_or_else(|| user.to_owned());
    let number = mine.safety_number_with(&theirs);
    let groups: Vec<&str> = number.split(' ').collect();
    let mut text = String::new();
    if theirs.state() == PinState::KeyChanged {
        text.push_str(&format!(
            "WARNING: the public key of {label} CHANGED since it was first seen.\n\
             This only happens when the account was re-created, or when the server\n\
             substituted the key. Vault access granted to or by {label} is blocked\n\
             until you compare the NEW safety number below and accept the new key.\n\n"
        ));
    }
    text.push_str(&format!("Safety number with {label}:\n\n"));
    for row in groups.chunks(4) {
        text.push_str(&format!("    {}\n", row.join(" ")));
    }
    text.push_str(&format!(
        "\nCompare it with the number {label} sees for you (in person or on a trusted call).\n"
    ));
    write_out(out, &text)?;

    let (question, done) = match theirs.state() {
        PinState::Verified => {
            write_out(out, &format!("{label} is already verified ✓\n"))?;
            return Ok(exit::OK);
        }
        PinState::Pinned => ("Mark as verified?", "verified ✓"),
        PinState::KeyChanged => ("Accept new key?", "new key accepted and verified ✓"),
    };
    if !interactive {
        write_out(out, "not marked: run on a terminal to confirm\n")?;
        return Ok(exit::OK);
    }
    if !ask(question) {
        write_out(out, "not marked\n")?;
        return Ok(exit::OK);
    }
    match theirs.state() {
        PinState::KeyChanged => {
            store
                .accept_new_key(theirs.user_id, true)
                .await
                .map_err(|e| CliError::failure(&e))?;
        }
        _ => {
            store
                .set_pin_verified(theirs.user_id, true)
                .await
                .map_err(|e| CliError::failure(&e))?;
        }
    }
    write_out(out, &format!("{label}: {done}\n"))?;
    Ok(exit::OK)
}

/// `y`/`yes` on the terminal.
fn ask_yes(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

// `team invite` output and org picking.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod team_tests {
    use super::*;

    fn org(name: &str) -> OrgView {
        OrgView {
            id: uuid::Uuid::now_v7(),
            name: name.into(),
            role: Role::Owner,
            created_at: None,
        }
    }

    #[test]
    fn t09_invite_prints_the_link_without_smtp() {
        let inv = InviteCreated {
            id: uuid::Uuid::nil(),
            org_id: uuid::Uuid::nil(),
            email: Some("bob@example.test".into()),
            role: Role::Member,
            expires_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            link: Some("https://sync.example.test/invite/tok".into()),
            emailed: false,
        };
        let t = invite_text(&inv, "Acme");
        assert_eq!(
            t,
            "Invited bob@example.test to Acme as member.\n\
             Send them this link (single use, expires in 7 days):\n\
             https://sync.example.test/invite/tok\n"
        );
        let mailed = InviteCreated {
            link: None,
            emailed: true,
            ..inv
        };
        assert!(invite_text(&mailed, "Acme").ends_with("The invite link was sent by email.\n"));
    }

    #[test]
    fn org_picking() {
        let one = [org("Acme")];
        assert_eq!(pick_org(&one, None).unwrap().name, "Acme");
        assert_eq!(pick_org(&one, Some("acme")).unwrap().name, "Acme");
        assert_eq!(
            pick_org(&one, Some(&one[0].id.to_string())).unwrap().name,
            "Acme"
        );
        assert_eq!(
            pick_org(&one, Some("nope")).unwrap_err().exit_code(),
            exit::NOT_FOUND
        );
        let two = [org("Acme"), org("Beta")];
        assert_eq!(pick_org(&two, None).unwrap_err().exit_code(), exit::USAGE);
        assert_eq!(pick_org(&[], None).unwrap_err().exit_code(), exit::USAGE);
        assert!(list_text(&[]).starts_with("You are not in any org"));
        let members = vec![MemberView {
            user_id: uuid::Uuid::nil(),
            email: "a@example.test".into(),
            role: Role::Owner,
        }];
        assert_eq!(
            list_text(&[(org("Acme"), members)]),
            "Acme (you: owner)\n  owner  a@example.test\n"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use sverb_store::ManualClock;

    use super::*;

    const ALICE: [u8; 16] = [0xa1; 16];
    const BOB: [u8; 16] = [0xb0; 16];

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn store_with_pins(tag: &str) -> (Dir, Store) {
        let dir = std::env::temp_dir().join(format!(
            "sverb-team-verify-cli-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store =
            Store::open_at(dir.join("sverb.db"), Arc::new(ManualClock::new(1_000))).unwrap();
        store
            .observe_pin(
                ALICE,
                Some("alice@example.com".into()),
                [1; 32],
                [2; 32],
                true,
            )
            .await
            .unwrap();
        store
            .observe_pin(BOB, Some("bob@example.com".into()), [3; 32], [4; 32], false)
            .await
            .unwrap();
        (Dir(dir), store)
    }

    fn digit_groups(text: &str) -> Vec<String> {
        text.split_whitespace()
            .filter(|w| w.len() == 5 && w.bytes().all(|b| b.is_ascii_digit()))
            .map(ToOwned::to_owned)
            .collect()
    }

    // `team verify bob` prints 12 groups of 5 digits and marks verified on `y`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t06_team_verify_bob() {
        let (_dir, store) = store_with_pins("t06").await;
        let mut out = Vec::new();
        let mut asked = Vec::new();
        let code = verify(
            &store,
            "bob",
            true,
            |q| {
                asked.push(q.to_owned());
                true
            },
            &mut out,
        )
        .await
        .unwrap();
        assert_eq!(code, exit::OK);
        let text = String::from_utf8(out).unwrap();
        let groups = digit_groups(&text);
        assert_eq!(groups.len(), 12, "{text}");
        // The same number Bob's device computes (symmetry: sverb-sync T-03).
        let expected = store
            .get_pin(BOB)
            .await
            .unwrap()
            .unwrap()
            .safety_number_with(&store.get_pin(ALICE).await.unwrap().unwrap());
        assert_eq!(groups.join(" "), expected);
        assert_eq!(asked, ["Mark as verified?"]);
        assert!(text.contains("bob@example.com: verified ✓"), "{text}");
        let pin = store.get_pin(BOB).await.unwrap().unwrap();
        assert!(pin.verified);

        // Again: already verified, no question.
        let mut out = Vec::new();
        verify(
            &store,
            "bob@example.com",
            true,
            |_| panic!("asked"),
            &mut out,
        )
        .await
        .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("already verified ✓")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn decline_non_tty_and_key_change() {
        let (_dir, store) = store_with_pins("misc").await;
        // `n` → not marked.
        let mut out = Vec::new();
        verify(&store, "bob", true, |_| false, &mut out)
            .await
            .unwrap();
        assert!(!store.get_pin(BOB).await.unwrap().unwrap().verified);
        // No terminal → printed, not marked, never asked.
        let mut out = Vec::new();
        verify(&store, "bob", false, |_| panic!("asked"), &mut out)
            .await
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(digit_groups(&text).len(), 12);
        assert!(!store.get_pin(BOB).await.unwrap().unwrap().verified);

        // Key change → warning, "Accept new key?", the new key is pinned.
        store
            .observe_pin(BOB, None, [9; 32], [4; 32], false)
            .await
            .unwrap();
        let mut out = Vec::new();
        let mut asked = String::new();
        verify(
            &store,
            "bob",
            true,
            |q| {
                asked = q.to_owned();
                true
            },
            &mut out,
        )
        .await
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("CHANGED"), "{text}");
        assert_eq!(asked, "Accept new key?");
        let pin = store.get_pin(BOB).await.unwrap().unwrap();
        assert_eq!((pin.x25519_pub, pin.state()), ([9; 32], PinState::Verified));

        // Unknown user and self.
        let mut out = Vec::new();
        assert!(matches!(
            verify(&store, "zed", true, |_| true, &mut out).await,
            Err(CliError::NotFound(_))
        ));
        assert!(matches!(
            verify(&store, "alice", true, |_| true, &mut out).await,
            Err(CliError::Usage(_))
        ));
    }
}
