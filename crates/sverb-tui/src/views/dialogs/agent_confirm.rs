//! The `confirm_on_use` modal (SPEC §6.1.6): "**`<host>`** requests a signature
//! with key **`<key>`**" — `[a]llow once` / `[d]eny`. Esc denies; after the prompt's
//! timeout (60 s) it denies. Each answer becomes `Effect::AgentConfirm`. Prompts come
//! one at a time from the agent's queue, so concurrent requests wait their turn.

use std::collections::BTreeMap;

use sverb_conn::agent::AgentConfirmRequest;

use super::ModalDialog;
use crate::{
    app::Effect,
    widgets::dialog::{Button, Modal, ModalAnswer},
};

/// The modal for `prompt`.
pub fn dialog(prompt: &AgentConfirmRequest) -> ModalDialog {
    let req = &prompt.request;
    let body = format!(
        "{} requests a signature with key {} ({}).",
        req.requester, req.key_label, req.fingerprint
    );
    let modal = Modal::confirm(
        "Agent signature",
        &body,
        vec![
            Button::new("allow", "Allow once", 'a'),
            Button::new("deny", "Deny", 'd').safe(),
        ],
        1,
        true,
    )
    .with_timeout(prompt.timeout, ModalAnswer::TimedOut);
    let answer = |allow| {
        vec![Effect::AgentConfirm {
            id: prompt.id,
            allow,
        }]
    };
    let mut on_answer = BTreeMap::new();
    on_answer.insert("button:allow".to_owned(), answer(true));
    for key in ["button:deny", "cancelled", "timed-out"] {
        on_answer.insert(key.to_owned(), answer(false));
    }
    ModalDialog { modal, on_answer }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use sverb_conn::agent::{ConfirmRequest, Requester};
    use sverb_core::config::Config;

    use crate::{
        app::{Effect, UiEvent},
        testing::AppHarness,
    };

    fn prompt(id: u64) -> super::AgentConfirmRequest {
        super::AgentConfirmRequest {
            id,
            request: ConfirmRequest {
                requester: Requester::Session {
                    host: "db-prod".into(),
                    session: "7".into(),
                },
                key_label: "deploy".into(),
                fingerprint: "SHA256:abc".into(),
            },
            timeout: Duration::from_secs(60),
        }
    }

    fn answers(h: &mut AppHarness) -> Vec<(u64, bool)> {
        h.take_effects()
            .into_iter()
            .filter_map(|e| match e {
                Effect::AgentConfirm { id, allow } => Some((id, allow)),
                _ => None,
            })
            .collect()
    }

    /// T-06 (reducer): allow → `allow = true`, deny / Esc → `false`, 60 s → `false`.
    #[test]
    fn t06_allow_deny_timeout() {
        let mut h = AppHarness::new(Config::default());
        h.send(UiEvent::AgentConfirm(prompt(1)));
        let screen = h.render(100, 24);
        assert!(
            screen.contains("db-prod requests a signature with key deploy"),
            "{screen}"
        );
        h.keys("a");
        assert_eq!(answers(&mut h), vec![(1, true)]);

        h.send(UiEvent::AgentConfirm(prompt(2)));
        h.keys("d");
        assert_eq!(answers(&mut h), vec![(2, false)]);

        h.send(UiEvent::AgentConfirm(prompt(3)));
        h.keys("esc");
        assert_eq!(answers(&mut h), vec![(3, false)]);

        h.send(UiEvent::AgentConfirm(prompt(4)));
        h.advance(59_000);
        assert_eq!(answers(&mut h), Vec::new());
        h.advance(1_000);
        assert_eq!(answers(&mut h), vec![(4, false)]);
        // Nothing left open.
        h.keys("a");
        assert_eq!(answers(&mut h), Vec::new());
    }

    /// Enter on the default button denies (the safe choice is focused).
    #[test]
    fn enter_denies() {
        let mut h = AppHarness::new(Config::default());
        h.send(UiEvent::AgentConfirm(prompt(5)));
        h.keys("enter");
        assert_eq!(answers(&mut h), vec![(5, false)]);
    }
}
