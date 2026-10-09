//! Tests for `views::settings::team_verify`. They live outside `views/`
//! because they open a temp store with `tokio` and `std::fs`, which the reducer
//! no-I/O scan (`testing::t02`) forbids in view code.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ratatui::style::Color;
use sverb_crypto::account::generate_account_keys;
use sverb_crypto::random::os_rng;
use sverb_store::ManualClock;

use super::*;
use crate::widgets::test_util::{draw, keys, text};

const ALICE: UserId = [0xa1; 16];
const BOB: UserId = [0xb0; 16];

fn open(dir: &std::path::Path) -> Store {
    Store::open_at(dir.join("sverb.db"), Arc::new(ManualClock::new(1_000))).unwrap()
}

fn line_of<'a>(screen: &'a str, needle: &str) -> &'a str {
    screen
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?} in\n{screen}"))
}

// Verify flow → ✓ shown and persisted; after a key change the ✓ is
// cleared and the warning shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_verify_flow_and_key_change() {
    let dir = tempfile_dir();
    let store = open(dir.path());
    let alice = generate_account_keys(&mut os_rng()).public();
    let bob = generate_account_keys(&mut os_rng()).public();
    store
        .observe_pin(
            ALICE,
            Some("alice@example.com".into()),
            alice.x25519,
            alice.ed25519,
            true,
        )
        .await
        .unwrap();
    store
        .observe_pin(
            BOB,
            Some("bob@example.com".into()),
            bob.x25519,
            bob.ed25519,
            false,
        )
        .await
        .unwrap();

    let mut view = TeamVerifyView::default();
    view.set_pins(&store.list_pins().await.unwrap());
    assert!(view.dialog.is_none());
    let screen = text(&draw(&view, 80, 20, false));
    assert!(line_of(&screen, "bob@example.com").contains("not verified"));
    assert!(line_of(&screen, "alice@example.com").contains("(you)"));

    // Select Bob, open the safety number, confirm.
    keys(&mut view, "j v");
    let expected = safety_number(&alice.fingerprint(), &bob.fingerprint());
    match &view.dialog {
        Some(TeamVerifyDialog::Verify {
            safety_number,
            key_changed: false,
            ..
        }) => assert_eq!(safety_number, &expected),
        other => panic!("{other:?}"),
    }
    let screen = text(&draw(&view, 80, 20, false));
    for l in safety_number_lines(&expected) {
        assert!(screen.contains(&l), "{screen}");
    }
    assert!(screen.contains("Mark as verified? [y/N]"));
    keys(&mut view, "y");
    assert!(view.dialog.is_none());
    let req = view.take_request().unwrap();
    assert_eq!(req, TeamVerifyRequest::MarkVerified(BOB));
    view.set_pins(&execute(&store, req).await.unwrap());
    let screen = text(&draw(&view, 80, 20, false));
    assert!(
        line_of(&screen, "bob@example.com").contains('✓'),
        "{screen}"
    );

    // Persisted: a fresh store on the same file still says verified.
    drop(store);
    let store = open(dir.path());
    let mut fresh = TeamVerifyView::default();
    fresh.set_pins(&store.list_pins().await.unwrap());
    assert_eq!(fresh.row(&BOB).unwrap().state, PinState::Verified);

    // Bob's key changes: ✓ cleared, red warning modal, row marked.
    let new_bob = generate_account_keys(&mut os_rng()).public();
    store
        .observe_pin(BOB, None, new_bob.x25519, new_bob.ed25519, false)
        .await
        .unwrap();
    view.set_pins(&store.list_pins().await.unwrap());
    assert_eq!(view.row(&BOB).unwrap().state, PinState::KeyChanged);
    assert!(matches!(
        view.dialog,
        Some(TeamVerifyDialog::KeyChanged { user_id: BOB, .. })
    ));
    let buf = draw(&view, 80, 24, false);
    let screen = text(&buf);
    assert!(screen.contains("KEY CHANGED"), "{screen}");
    assert!(!screen.contains('✓'), "{screen}");
    // The warning is red.
    let theme = crate::widgets::test_util::theme(false);
    let red = theme.error.fg.unwrap_or(Color::Red);
    assert!(
        buf.content()
            .iter()
            .any(|c| c.symbol() == "⚠" && c.fg == red)
    );

    // Dismiss: the list marks Bob; the same change is not warned twice.
    keys(&mut view, "esc");
    let screen = text(&draw(&view, 80, 20, false));
    assert!(line_of(&screen, "bob@example.com").contains("⚠ key changed"));
    view.set_pins(&store.list_pins().await.unwrap());
    assert!(view.dialog.is_none());

    // Compare the new safety number and accept the new key → ✓ again.
    keys(&mut view, "v");
    match &view.dialog {
        Some(TeamVerifyDialog::Verify {
            safety_number,
            key_changed: true,
            ..
        }) => assert_eq!(
            safety_number,
            &safety_number_of(&alice.fingerprint(), &new_bob.fingerprint())
        ),
        other => panic!("{other:?}"),
    }
    assert!(text(&draw(&view, 80, 20, false)).contains("Accept new key? [y/N]"));
    keys(&mut view, "y");
    let req = view.take_request().unwrap();
    assert_eq!(req, TeamVerifyRequest::AcceptNewKey(BOB));
    view.set_pins(&execute(&store, req).await.unwrap());
    assert_eq!(view.row(&BOB).unwrap().state, PinState::Verified);
    let pin = store.get_pin(BOB).await.unwrap().unwrap();
    assert_eq!(pin.x25519_pub, new_bob.x25519);
}

#[test]
fn decline_and_self_and_empty() {
    let mut view = TeamVerifyView::default();
    // Empty and tiny areas render.
    let _ = draw(&view, 0, 0, true);
    let _ = draw(&view, 1, 1, true);
    assert!(text(&draw(&view, 80, 5, true)).contains("No team members"));
    let mk = |id: UserId, label: &str, is_self: bool| PinnedKey {
        user_id: id,
        label: Some(label.into()),
        fingerprint: [id[0]; 32],
        x25519_pub: [0; 32],
        ed25519_pub: [0; 32],
        first_seen_at: 0,
        verified: false,
        verified_at: None,
        is_self,
        changed: None,
    };
    view.set_pins(&[mk(BOB, "bob", false), mk(ALICE, "alice", true)]);
    assert!(view.rows[0].is_self);
    // Self: no dialog.
    keys(&mut view, "v");
    assert!(view.dialog.is_none());
    // Bob: decline.
    keys(&mut view, "j v n");
    assert!(view.dialog.is_none());
    assert!(view.take_request().is_none());
    // Without an own pin there is no safety number and `y` does nothing.
    view.set_pins(&[mk(BOB, "bob", false)]);
    keys(&mut view, "v y");
    assert!(view.take_request().is_none());
    let _ = draw(&view, 3, 3, true);
}

fn safety_number_of(a: &[u8; 32], b: &[u8; 32]) -> String {
    safety_number(a, b)
}

fn tempfile_dir() -> TempDir {
    TempDir::new()
}

/// A temp directory under the system temp dir, removed on drop (sverb-tui
/// has no `tempfile` dev-dependency).
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "sverb-team-verify-{}-{}",
            std::process::id(),
            fastrand_suffix()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fastrand_suffix() -> String {
    let b = sverb_crypto::random::random_salt16(&mut os_rng());
    b.iter().map(|x| format!("{x:02x}")).collect()
}
