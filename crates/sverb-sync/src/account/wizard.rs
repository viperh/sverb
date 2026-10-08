//! UI-agnostic wizard state machines for the account flows (Settings → Sync
//! and the CLI). Pure reducers: inputs in, effects out; the caller runs the
//! effects ([`super::prepare_registration`], [`super::finish_registration`])
//! and feeds the results back.
//!
//! The recovery confirmation (§11.2: shown once, confirmed) blocks the
//! registration until three randomly chosen words are re-typed correctly.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use super::RECOVERY_WARNING;

/// How many words the user must re-type.
pub const CONFIRM_WORDS: usize = 3;

/// The "re-type 3 random words" step.
pub struct RecoveryConfirm {
    words: Vec<Zeroizing<String>>,
    /// 0-based positions asked for, ascending.
    positions: [usize; CONFIRM_WORDS],
    inputs: [Zeroizing<String>; CONFIRM_WORDS],
    error: Option<String>,
    confirmed: bool,
}

impl fmt::Debug for RecoveryConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryConfirm")
            .field("positions", &self.positions)
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

impl RecoveryConfirm {
    /// Asks for the words at `positions` (0-based, distinct, in range).
    ///
    /// # Panics
    /// Never for valid input; invalid positions are clamped and de-duplicated
    /// by [`Self::with_random_positions`] instead.
    #[must_use]
    pub fn new(words: &[&str], mut positions: [usize; CONFIRM_WORDS]) -> Self {
        positions.sort_unstable();
        Self {
            words: words
                .iter()
                .map(|w| Zeroizing::new((*w).to_owned()))
                .collect(),
            positions,
            inputs: Default::default(),
            error: None,
            confirmed: false,
        }
    }

    /// Asks for three distinct random positions.
    #[must_use]
    pub fn with_random_positions(words: &[&str]) -> Self {
        let n = words.len().max(CONFIRM_WORDS);
        let mut picked: Vec<usize> = Vec::with_capacity(CONFIRM_WORDS);
        while picked.len() < CONFIRM_WORDS {
            let p = fastrand::usize(..n);
            if !picked.contains(&p) {
                picked.push(p);
            }
        }
        Self::new(words, [picked[0], picked[1], picked[2]])
    }

    /// The 1-based word numbers to ask for ("word #4").
    #[must_use]
    pub fn word_numbers(&self) -> [usize; CONFIRM_WORDS] {
        self.positions.map(|p| p + 1)
    }

    /// Sets the answer for the `slot`-th asked word.
    pub fn set_input(&mut self, slot: usize, text: &str) {
        if let Some(i) = self.inputs.get_mut(slot) {
            i.zeroize();
            i.push_str(text);
        }
        self.error = None;
    }

    /// Checks the answers (case-insensitive, trimmed). Returns whether all
    /// three are correct; otherwise sets [`Self::error`].
    pub fn submit(&mut self) -> bool {
        let ok = self.positions.iter().zip(&self.inputs).all(|(p, input)| {
            self.words
                .get(*p)
                .is_some_and(|w| w.eq_ignore_ascii_case(input.trim()))
        });
        self.confirmed = ok;
        self.error = (!ok).then(|| {
            "These words do not match your recovery phrase. Check your copy and try again."
                .to_owned()
        });
        ok
    }

    /// Whether the words were confirmed.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// The last mismatch message.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Where the registration wizard is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterStep {
    /// Server URL (required; no default, §1.1).
    Server,
    /// Account email.
    Email,
    /// The **current** master password.
    Password,
    /// Probing the server and generating keys.
    Preparing,
    /// The 24 words, shown once, with [`RECOVERY_WARNING`].
    ShowRecovery,
    /// Re-type three words.
    ConfirmRecovery,
    /// Uploading.
    Registering,
    /// The server needs an invite or setup token.
    Token,
    /// Registered; sync starts.
    Done,
}

/// Something the caller must do for the wizard.
#[derive(Clone, PartialEq, Eq)]
pub enum WizardEffect {
    /// Run [`super::prepare_registration`] and answer with
    /// [`WizardInput::Prepared`].
    Prepare {
        /// Server URL.
        server: String,
        /// Email.
        email: String,
        /// The current master password.
        password: Zeroizing<String>,
    },
    /// Run [`super::finish_registration`] and answer with
    /// [`WizardInput::Finished`].
    Finish {
        /// Invite or setup token, when the server asked for one.
        token: Option<String>,
    },
}

impl fmt::Debug for WizardEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare { server, email, .. } => f
                .debug_struct("Prepare")
                .field("server", server)
                .field("email", email)
                .finish_non_exhaustive(),
            Self::Finish { token } => f
                .debug_struct("Finish")
                .field("token", &token.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

/// Input to [`RegisterWizard::handle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardInput {
    /// The text of the current field (server, email, password, token).
    Text(String),
    /// The answer for one of the three confirmation words.
    ConfirmWord {
        /// 0..3.
        slot: usize,
        /// What the user typed.
        text: String,
    },
    /// The "I have written down my recovery phrase" checkbox.
    Acknowledge(bool),
    /// Enter / "Next".
    Next,
    /// Esc / "Back".
    Back,
    /// The result of [`WizardEffect::Prepare`]: the 24 words, or an error.
    Prepared(Result<Vec<String>, String>),
    /// The result of [`WizardEffect::Finish`].
    Finished(Result<(), FinishError>),
}

/// Why [`WizardEffect::Finish`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishError {
    /// Ask for an invite or setup token.
    NeedsToken(String),
    /// Anything else (shown; the user can retry).
    Other(String),
}

/// Settings → Sync → "Create an account on a server" (§2.1).
pub struct RegisterWizard {
    step: RegisterStep,
    server: String,
    email: String,
    password: Zeroizing<String>,
    token: Zeroizing<String>,
    words: Vec<Zeroizing<String>>,
    acknowledged: bool,
    confirm: Option<RecoveryConfirm>,
    error: Option<String>,
}

impl fmt::Debug for RegisterWizard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterWizard")
            .field("step", &self.step)
            .field("server", &self.server)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl Default for RegisterWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterWizard {
    /// A wizard at the server URL step.
    #[must_use]
    pub fn new() -> Self {
        Self {
            step: RegisterStep::Server,
            server: String::new(),
            email: String::new(),
            password: Zeroizing::default(),
            token: Zeroizing::default(),
            words: Vec::new(),
            acknowledged: false,
            confirm: None,
            error: None,
        }
    }

    /// The current step.
    #[must_use]
    pub const fn step(&self) -> RegisterStep {
        self.step
    }

    /// The error to show, if any.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The recovery words ([`RegisterStep::ShowRecovery`] only).
    #[must_use]
    pub fn recovery_words(&self) -> Vec<&str> {
        if self.step == RegisterStep::ShowRecovery {
            self.words.iter().map(|w| w.as_str()).collect()
        } else {
            Vec::new()
        }
    }

    /// The warning shown with the words.
    #[must_use]
    pub const fn recovery_warning(&self) -> &'static str {
        RECOVERY_WARNING
    }

    /// The confirmation step's state.
    #[must_use]
    pub const fn confirm(&self) -> Option<&RecoveryConfirm> {
        self.confirm.as_ref()
    }

    /// Feeds one input; returns the effect to run, if any.
    pub fn handle(&mut self, input: WizardInput) -> Option<WizardEffect> {
        use RegisterStep as S;
        match (self.step, input) {
            (S::Server, WizardInput::Text(t)) => self.server = t,
            (S::Email, WizardInput::Text(t)) => self.email = t,
            (S::Password, WizardInput::Text(t)) => {
                self.password.zeroize();
                self.password.push_str(&t);
            }
            (S::Token, WizardInput::Text(t)) => {
                self.token.zeroize();
                self.token.push_str(&t);
            }
            (S::ShowRecovery, WizardInput::Acknowledge(a)) => self.acknowledged = a,
            (S::ConfirmRecovery, WizardInput::ConfirmWord { slot, text }) => {
                if let Some(c) = &mut self.confirm {
                    c.set_input(slot, &text);
                }
            }
            (S::Server, WizardInput::Next) => {
                let s = self.server.trim();
                if s.starts_with("https://") || s.starts_with("http://") {
                    self.error = None;
                    self.step = S::Email;
                } else {
                    self.error = Some("Enter the server URL (https://…)".into());
                }
            }
            (S::Email, WizardInput::Next) => {
                if self.email.contains('@') {
                    self.error = None;
                    self.step = S::Password;
                } else {
                    self.error = Some("Enter a valid email address".into());
                }
            }
            (S::Password, WizardInput::Next) if !self.password.is_empty() => {
                self.error = None;
                self.step = S::Preparing;
                return Some(WizardEffect::Prepare {
                    server: self.server.trim().to_owned(),
                    email: self.email.trim().to_owned(),
                    password: self.password.clone(),
                });
            }
            (S::Preparing, WizardInput::Prepared(Ok(words))) => {
                self.words = words.into_iter().map(Zeroizing::new).collect();
                self.acknowledged = false;
                self.step = S::ShowRecovery;
            }
            (S::Preparing, WizardInput::Prepared(Err(e))) => {
                self.error = Some(e);
                self.step = S::Password;
            }
            (S::ShowRecovery, WizardInput::Next) => {
                if self.acknowledged {
                    let words: Vec<&str> = self.words.iter().map(|w| w.as_str()).collect();
                    self.confirm = Some(RecoveryConfirm::with_random_positions(&words));
                    self.error = None;
                    self.step = S::ConfirmRecovery;
                } else {
                    self.error = Some("Confirm that you wrote the recovery phrase down".into());
                }
            }
            (S::ConfirmRecovery, WizardInput::Next) => {
                let ok = self.confirm.as_mut().is_some_and(RecoveryConfirm::submit);
                if ok {
                    self.error = None;
                    self.step = S::Registering;
                    return Some(WizardEffect::Finish { token: None });
                }
                self.error = self
                    .confirm
                    .as_ref()
                    .and_then(|c| c.error().map(ToOwned::to_owned));
            }
            (S::ConfirmRecovery, WizardInput::Back) => {
                // Show the words again (they are still only on screen).
                self.step = S::ShowRecovery;
            }
            (S::Registering, WizardInput::Finished(Ok(()))) => {
                self.words.clear();
                self.confirm = None;
                self.password.zeroize();
                self.step = S::Done;
            }
            (S::Registering, WizardInput::Finished(Err(FinishError::NeedsToken(m)))) => {
                self.error = Some(m);
                self.step = S::Token;
            }
            (S::Registering, WizardInput::Finished(Err(FinishError::Other(m)))) => {
                self.error = Some(m);
                self.step = S::ConfirmRecovery;
            }
            (S::Token, WizardInput::Next) if !self.token.trim().is_empty() => {
                self.error = None;
                self.step = S::Registering;
                return Some(WizardEffect::Finish {
                    token: Some(self.token.trim().to_owned()),
                });
            }
            (S::Email, WizardInput::Back) => self.step = S::Server,
            (S::Password, WizardInput::Back) => self.step = S::Email,
            _ => {}
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const WORDS: [&str; 24] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "actress", "actual",
    ];

    // T-03: the confirmation blocks until the three words are correct.
    #[test]
    fn t03_recovery_confirmation_blocks_until_correct() {
        let mut c = RecoveryConfirm::new(&WORDS, [10, 3, 20]);
        assert_eq!(c.word_numbers(), [4, 11, 21]);
        assert!(!c.submit(), "empty answers are rejected");
        c.set_input(0, "about");
        c.set_input(1, "access");
        c.set_input(2, "wrong");
        assert!(!c.submit());
        assert!(c.error().is_some());
        c.set_input(2, " Action ");
        assert!(c.submit());
        assert!(c.is_confirmed());

        let mut w = RegisterWizard::new();
        w.handle(WizardInput::Text("https://sync.example.test".into()));
        w.handle(WizardInput::Next);
        w.handle(WizardInput::Text("me@example.test".into()));
        w.handle(WizardInput::Next);
        w.handle(WizardInput::Text("pw".into()));
        let eff = w.handle(WizardInput::Next);
        assert!(matches!(eff, Some(WizardEffect::Prepare { .. })));
        let words: Vec<String> = WORDS.iter().map(|s| (*s).to_owned()).collect();
        w.handle(WizardInput::Prepared(Ok(words)));
        assert_eq!(w.step(), RegisterStep::ShowRecovery);
        assert_eq!(w.recovery_words().len(), 24);
        // Not acknowledged: blocked.
        assert_eq!(w.handle(WizardInput::Next), None);
        assert_eq!(w.step(), RegisterStep::ShowRecovery);
        w.handle(WizardInput::Acknowledge(true));
        w.handle(WizardInput::Next);
        assert_eq!(w.step(), RegisterStep::ConfirmRecovery);
        assert!(w.recovery_words().is_empty(), "words are no longer exposed");
        let asked = w.confirm().unwrap().positions;
        // Wrong words: no Finish effect, still confirming.
        for slot in 0..3 {
            w.handle(WizardInput::ConfirmWord {
                slot,
                text: "zoo".into(),
            });
        }
        assert_eq!(w.handle(WizardInput::Next), None);
        assert_eq!(w.step(), RegisterStep::ConfirmRecovery);
        assert!(w.error().is_some());
        for (slot, p) in asked.iter().enumerate() {
            w.handle(WizardInput::ConfirmWord {
                slot,
                text: WORDS[*p].to_owned(),
            });
        }
        assert_eq!(
            w.handle(WizardInput::Next),
            Some(WizardEffect::Finish { token: None })
        );
        assert_eq!(w.step(), RegisterStep::Registering);
        w.handle(WizardInput::Finished(Err(FinishError::NeedsToken(
            "invite".into(),
        ))));
        assert_eq!(w.step(), RegisterStep::Token);
        w.handle(WizardInput::Text("tok".into()));
        assert_eq!(
            w.handle(WizardInput::Next),
            Some(WizardEffect::Finish {
                token: Some("tok".into())
            })
        );
        w.handle(WizardInput::Finished(Ok(())));
        assert_eq!(w.step(), RegisterStep::Done);
    }

    #[test]
    fn random_positions_are_distinct() {
        for _ in 0..100 {
            let c = RecoveryConfirm::with_random_positions(&WORDS);
            let p = c.positions;
            assert!(p[0] < p[1] && p[1] < p[2] && p[2] < 24);
        }
    }
}
