//! T-21 / K-07: `docs/keybindings.md` is generated from the keymap registry.
//!
//! Regenerate with `SVERB_BLESS=1 cargo test -p sverb-tui --test keybindings_doc`.

use std::path::Path;

#[test]
fn keybindings_doc_is_up_to_date() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/keybindings.md");
    let want = sverb_tui::keymap::dump::markdown();
    if std::env::var_os("SVERB_BLESS").is_some() {
        if let Err(e) = std::fs::write(&path, &want) {
            panic!("cannot write {}: {e}", path.display());
        }
        return;
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        have == want,
        "docs/keybindings.md is stale; run `SVERB_BLESS=1 cargo test -p sverb-tui --test keybindings_doc`"
    );
    // K-07: the static rules and the leader rationale are included.
    assert!(have.contains("Pass-through guarantee"));
    assert!(have.contains("Why `ctrl-\\` is the leader"));
}
