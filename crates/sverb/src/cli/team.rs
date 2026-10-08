//! M0-07: `sverb team list | invite <email> | verify <user>` (sync builds only).
//! `list` / `invite` land in M5-01.
//!
//! M5-03: `sverb team verify <user>` prints the 60-digit safety number between this
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

use super::{CliError, Ctx, exit, not_implemented, vault::require_unlocked, write_out};

/// `sverb team …`
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum TeamCmd {
    /// List team members
    List,
    /// Invite someone by email
    Invite {
        /// Email address
        email: String,
    },
    /// Verify a member's safety number
    Verify {
        /// User name or email
        user: String,
    },
}

pub(crate) fn run(cmd: TeamCmd, _ctx: &Ctx, _out: &mut dyn Write) -> Result<u8, CliError> {
    match cmd {
        TeamCmd::List => not_implemented("team list", "M5-01"),
        TeamCmd::Invite { .. } => not_implemented("team invite", "M5-01"),
        // M5-03: `cli/mod.rs` dispatches through `run_async`, which handles `verify`.
        TeamCmd::Verify { .. } => unreachable!("`team verify` is handled by `run_async`"),
    }
}

// M5-03: `cli/mod.rs` dispatches `team` here (async: `verify` opens the store).
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
        other => run(other, ctx, out),
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

    // T-06: `team verify bob` prints 12 groups of 5 digits and marks verified on `y`.
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
