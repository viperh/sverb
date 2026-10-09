//! M1-04: the vault in the reducer (SPEC §5.3, task M1-04 §2.2–§2.6).
//!
//! The reducer only knows [`LockState`] and the prompt forms; the keys live in the
//! vault service (`services::vault`). Effects go out as [`Effect::Vault`], results
//! come back as `UiEvent::Vault`.
//!
//! - **Startup:** the runtime marks the app [`App::with_vault`] (locked) and the
//!   service sends [`VaultEvent::Status`]: first-run screen, keyring unlock, or the
//!   password prompt. The launch intent waits until the vault is unlocked.
//! - **While locked** every key goes to the prompt; only `leader q` also works
//!   (`tasks/03-KEYBINDINGS.md` §4.4). Nothing is forwarded to a session; panes are
//!   covered by the lock overlay.
//! - **Lock** (`leader ctrl-l`, idle timer, `sverb lock`, suspend): keys zeroized by
//!   the service, dialogs (and unsaved forms) discarded, sessions kept behind the
//!   overlay or closed with `general.lock_disconnects_sessions`.
//! - **Auto-lock** is a reset-on-input timer: every input while unlocked re-arms
//!   `TimerKind::AutoLockCheck`; when it fires, the vault locks.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{KeyEvent, KeyEventKind};
use ratatui::Frame;
use sverb_core::search::IndexSnapshot;
use sverb_core::vault::{LockState, auto_lock_timeout};
use zeroize::Zeroizing;

use super::{App, Effect, InputEvent, LaunchIntent, TimerKind, ToastLevel};
use crate::keymap::{Lookup, Table, action::ActionName, chord::KeyChord, leader::KeyState};
use crate::views::{
    DialogKind,
    first_run::FirstRunForm,
    lock_overlay,
    unlock::{ChangePasswordForm, FormAction, MaskedField, UnlockForm},
};
use crate::widgets::topbar::{self, TopBarInfo};

/// The toast after unlocking when a lock discarded unsaved forms.
pub const DISCARDED_FORMS: &str = "Unsaved changes were discarded when the vault locked";

/// A password on its way to the vault service. `Debug` is redacted; the buffer is
/// zeroized when the last clone drops.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultPassword(Arc<Zeroizing<String>>);

impl VaultPassword {
    /// Wrap a typed password.
    pub fn new(text: Zeroizing<String>) -> Self {
        Self(Arc::new(text))
    }

    /// The password (keep borrows short).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for VaultPassword {
    fn from(s: &str) -> Self {
        Self::new(Zeroizing::new(s.to_owned()))
    }
}

impl fmt::Debug for VaultPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultPassword([REDACTED])")
    }
}

/// How to unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockRequest {
    /// With the master password.
    Password(VaultPassword),
    /// With the OS keyring.
    Keyring,
}

/// Vault side effects (carried by [`Effect::Vault`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultEffect {
    /// First run: create the LMK, the Personal vault and the password wrap.
    Initialize {
        /// The new master password (already checked for strength by the form).
        password: VaultPassword,
        /// Also enable keyring unlock.
        keyring: bool,
    },
    /// Unlock.
    Unlock(UnlockRequest),
    /// Zeroize the keys now.
    Lock,
    /// Re-wrap the LMK under a new password. `current: None` is the keyring recovery
    /// flow (only after a keyring unlock).
    ChangePassword {
        /// The current password.
        current: Option<VaultPassword>,
        /// The new password.
        new: VaultPassword,
    },
    // M1-07
    /// Item writes and reads (`services::vault::items`).
    Items(super::hosts::ItemEffect),
}

/// The locked database's state, sent once at startup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultStatusInfo {
    /// A master password exists.
    pub initialized: bool,
    /// Keyring unlock is enabled.
    pub keyring_enabled: bool,
    /// A keyring works on this machine (only probed before first run).
    pub keyring_available: bool,
    /// Consecutive failed attempts.
    pub failures: u32,
    /// The next attempt must wait this long.
    pub retry_after: Option<Duration>,
}

/// Why an unlock (or first run) failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnlockFailure {
    /// Wrong password (counted).
    WrongPassword {
        /// Consecutive failures.
        failures: u32,
        /// Delay before the next attempt.
        retry_after: Option<Duration>,
    },
    /// Refused: the backoff delay has not elapsed.
    Backoff {
        /// Remaining delay.
        retry_after: Duration,
    },
    /// The keyring could not unlock (falls back to the password prompt).
    Keyring(String),
    /// Anything else (weak password on first run, storage error).
    Other(String),
}

/// Results and requests from the vault service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultEvent {
    /// The locked database's state (startup).
    Status(VaultStatusInfo),
    /// Unlocked (or created on first run).
    Unlocked {
        /// Via the keyring.
        via_keyring: bool,
        /// A non-fatal note (e.g. keyring enrolment failed on first run).
        note: Option<String>,
    },
    /// An unlock or first run failed.
    UnlockFailed(UnlockFailure),
    /// The master password was changed.
    PasswordChanged,
    /// Changing the password failed.
    PasswordChangeFailed(String),
    /// Lock now (`sverb lock`, system suspend).
    LockRequested,
    // M1-07
    /// A fire-and-forget item write (delete, duplicate, pin) failed.
    ItemFailed(sverb_core::error_report::ErrorReport),
    // M2-03
    /// A keychain result (`ItemEffect::Keychain`).
    Keychain(crate::app::keychain::keys::KeychainEvent),
    // M5-02
    /// A move / copy / override result (`app/hosts/shared_vaults.rs`).
    Shared(crate::app::hosts::SharedVaultEvent),
}

/// What the vault prompt shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VaultScreen {
    /// Nothing (unlocked).
    #[default]
    None,
    /// Locked, waiting for the service's status.
    Starting,
    /// First run.
    FirstRun(FirstRunForm),
    /// The password prompt.
    Unlock(UnlockForm),
    /// Change (or, after a keyring recovery, set) the master password.
    ChangePassword(ChangePasswordForm),
}

/// Vault state in [`App`]. No key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultUi {
    /// A vault service exists (the runtime opened the store). Without one (reducer
    /// tests, `App::new`) the app behaves as unlocked and never locks.
    pub active: bool,
    /// Locked / unlocking / unlocked.
    pub lock: LockState,
    /// The prompt.
    pub screen: VaultScreen,
    /// Keyring unlock is enabled for this database.
    pub keyring_enabled: bool,
    /// The launch intent, delivered after unlock.
    deferred_launch: Option<LaunchIntent>,
    /// A lock discarded unsaved forms; toast after unlock.
    discarded_forms: bool,
    /// The leader was pressed while locked (`leader q` quits).
    leader_armed: bool,
    /// The keyring recovery flow is running (§2.6).
    recovering: bool,
    /// The idle timer is scheduled.
    auto_lock_armed: bool,
    // M1-05
    /// The latest search index snapshot from the vault service (`None` while
    /// locked: dropped on lock so the decrypted entries can be zeroized).
    index: Option<Arc<IndexSnapshot>>,
}

impl Default for VaultUi {
    fn default() -> Self {
        Self {
            active: false,
            lock: LockState::Unlocked,
            screen: VaultScreen::None,
            keyring_enabled: false,
            deferred_launch: None,
            discarded_forms: false,
            leader_armed: false,
            recovering: false,
            auto_lock_armed: false,
            // M1-05
            index: None,
        }
    }
}

/// The spinner glyph shown while Argon2 runs (static: no tick-driven redraws).
const SPINNER: char = '⠋';

impl App {
    /// Start locked, with a vault service attached (the runtime calls this when it
    /// opened the store).
    #[must_use]
    pub fn with_vault(mut self) -> Self {
        self.vault = VaultUi {
            active: true,
            lock: LockState::Locked,
            screen: VaultScreen::Starting,
            ..VaultUi::default()
        };
        self.needs_redraw = true;
        self
    }

    /// The lock state.
    pub fn lock_state(&self) -> LockState {
        self.vault.lock
    }

    // M1-05
    /// The current search index snapshot; `None` while locked (queries are
    /// unavailable, `LockState::Locked`) or before the first snapshot arrives.
    pub fn index(&self) -> Option<&Arc<IndexSnapshot>> {
        self.vault.index.as_ref()
    }

    // M1-05
    /// `UiEvent::IndexUpdated`: keep the newest snapshot. A snapshot that arrives
    /// after a lock (sent before the service saw it) is dropped.
    pub(crate) fn on_index_updated(&mut self, snapshot: Arc<IndexSnapshot>) {
        if self.vault.lock == LockState::Locked {
            return;
        }
        if self
            .vault
            .index
            .as_ref()
            .is_some_and(|cur| cur.version() > snapshot.version())
        {
            return;
        }
        self.vault.index = Some(snapshot);
        self.needs_redraw = true;
    }

    /// The vault prompt.
    pub fn vault_screen(&self) -> &VaultScreen {
        &self.vault.screen
    }

    /// Open the change-password form (Settings → Security → Change password; the
    /// settings view calls this). Only while unlocked.
    pub fn open_change_password(&mut self) {
        if self.vault.active && self.vault.lock == LockState::Unlocked {
            self.vault.screen = VaultScreen::ChangePassword(ChangePasswordForm::new());
            self.needs_redraw = true;
        }
    }

    /// Input hook, run before normal routing. Returns `true` when the vault consumed
    /// the input (locked, or a vault form is open).
    pub(crate) fn vault_on_input(&mut self, input: &InputEvent, effects: &mut Vec<Effect>) -> bool {
        if !self.vault.active {
            return false;
        }
        let user_input = match input {
            InputEvent::Key(key) => key.kind != KeyEventKind::Release,
            InputEvent::Mouse(_) | InputEvent::Paste(_) => true,
            _ => false,
        };
        if !user_input {
            return false;
        }
        if self.vault.lock.is_locked() {
            match input {
                InputEvent::Key(key) => self.vault_locked_key(*key, effects),
                InputEvent::Paste(text) => self.vault_paste(text),
                // Mouse: swallowed.
                _ => {}
            }
            return true;
        }
        // Unlocked: any input resets the idle timer.
        self.arm_auto_lock(effects);
        // A vault form over the shell (change password) takes keys, but not the
        // leader or a pending sequence.
        if matches!(self.vault.screen, VaultScreen::ChangePassword(_)) {
            match input {
                InputEvent::Key(key) => {
                    let chord = KeyChord::from_key_event(key);
                    if matches!(self.input.keys, KeyState::Pending(_))
                        || chord == self.keymap.leader()
                    {
                        return false;
                    }
                    self.vault_form_key(key, effects);
                }
                InputEvent::Paste(text) => self.vault_paste(text),
                _ => {}
            }
            return true;
        }
        false
    }

    fn vault_paste(&mut self, text: &str) {
        let field: Option<&mut MaskedField> = match &mut self.vault.screen {
            VaultScreen::Unlock(f) if !f.input_disabled() => Some(&mut f.password),
            _ => None,
        };
        if let Some(field) = field {
            field.push_str(text);
            self.needs_redraw = true;
        }
    }

    fn vault_locked_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) {
        let chord = KeyChord::from_key_event(&key);
        if std::mem::take(&mut self.vault.leader_armed) {
            // `leader q` (whatever `quit` is bound to after the leader) quits at once:
            // a confirmation dialog could not be answered behind the lock.
            if self.keymap.lookup_seq(Table::Leader, &[chord]) == Lookup::Action(ActionName::Quit) {
                effects.push(Effect::Quit { code: 0 });
            }
            self.needs_redraw = true;
            return;
        }
        if chord == self.keymap.leader() {
            self.vault.leader_armed = true;
            return;
        }
        self.vault_form_key(&key, effects);
    }

    fn vault_form_key(&mut self, key: &KeyEvent, effects: &mut Vec<Effect>) {
        let action = match &mut self.vault.screen {
            VaultScreen::FirstRun(f) => f.handle_key(key),
            VaultScreen::Unlock(f) => f.handle_key(key),
            VaultScreen::ChangePassword(f) => f.handle_key(key),
            VaultScreen::None | VaultScreen::Starting => FormAction::None,
        };
        match action {
            FormAction::None => {}
            FormAction::Changed => self.needs_redraw = true,
            FormAction::Submit => self.vault_submit(effects),
            FormAction::Cancel => {
                if self.vault.lock == LockState::Unlocked {
                    self.vault.screen = VaultScreen::None;
                    self.vault.recovering = false;
                    self.needs_redraw = true;
                }
            }
            FormAction::Forgot => {
                if let VaultScreen::Unlock(f) = &mut self.vault.screen {
                    f.busy = Some("Unlocking with the keyring…".into());
                    f.error = None;
                }
                self.vault.recovering = true;
                self.vault.lock = LockState::Unlocking;
                effects.push(Effect::Vault(VaultEffect::Unlock(UnlockRequest::Keyring)));
                self.needs_redraw = true;
            }
        }
    }

    fn vault_submit(&mut self, effects: &mut Vec<Effect>) {
        let effect = match &mut self.vault.screen {
            VaultScreen::FirstRun(f) => {
                f.busy = true;
                f.error = None;
                let password = VaultPassword::new(f.new.password.take());
                f.new.confirm.clear();
                self.vault.lock = LockState::Unlocking;
                VaultEffect::Initialize {
                    password,
                    keyring: f.keyring_available && f.use_keyring,
                }
            }
            VaultScreen::Unlock(f) => {
                f.busy = Some("Unlocking…".into());
                f.error = None;
                self.vault.lock = LockState::Unlocking;
                VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::new(
                    f.password.take(),
                )))
            }
            VaultScreen::ChangePassword(f) => {
                f.busy = true;
                f.error = None;
                let current = f.current.as_mut().map(|c| VaultPassword::new(c.take()));
                let new = VaultPassword::new(f.new.password.take());
                f.new.confirm.clear();
                VaultEffect::ChangePassword { current, new }
            }
            VaultScreen::None | VaultScreen::Starting => return,
        };
        effects.push(Effect::Vault(effect));
        self.needs_redraw = true;
    }

    /// `leader ctrl-l`, the idle timer, `sverb lock`, suspend.
    pub(crate) fn lock_vault(&mut self, effects: &mut Vec<Effect>) {
        if !self.vault.active || self.vault.lock != LockState::Unlocked {
            return;
        }
        self.vault.lock = LockState::Locked;
        // M1-05: drop the reducer's index snapshot with the keys.
        self.vault.index = None;
        self.vault.leader_armed = false;
        self.vault.recovering = false;
        self.vault.auto_lock_armed = false;
        effects.push(Effect::CancelTimer(TimerKind::AutoLockCheck));
        // Zeroize first, then everything else.
        effects.push(Effect::Vault(VaultEffect::Lock));
        // A pending leader sequence is dropped.
        if matches!(std::mem::take(&mut self.input.keys), KeyState::Pending(_)) {
            effects.push(Effect::CancelTimer(TimerKind::LeaderTimeout));
            effects.push(Effect::CancelTimer(TimerKind::WhichKey));
        }
        // Forms with unsaved edits are discarded (toast after unlock); other dialogs
        // close too, nothing stays readable behind the lock.
        if self
            .dialogs
            .iter()
            .any(|d| matches!(&d.kind, DialogKind::HostForm(f) if f.form.is_dirty()))
        {
            self.vault.discarded_forms = true;
        }
        self.dialogs.clear();
        // M1-07: decrypted host data goes with the keys.
        self.hosts_on_lock();
        let disconnect = self.config.general.lock_disconnects_sessions;
        if disconnect {
            for id in self.tabs.sessions.clone() {
                effects.push(Effect::CloseSession(id));
            }
        }
        self.vault.screen = VaultScreen::Unlock(UnlockForm {
            keyring_enabled: self.vault.keyring_enabled,
            sessions_open: !disconnect && self.tabs.has_sessions(),
            ..UnlockForm::default()
        });
        self.needs_redraw = true;
    }

    /// (Re-)arm the idle auto-lock timer, or cancel it when `auto_lock_minutes = 0`.
    fn arm_auto_lock(&mut self, effects: &mut Vec<Effect>) {
        match auto_lock_timeout(self.config.general.auto_lock_minutes) {
            Some(after) => {
                self.vault.auto_lock_armed = true;
                effects.push(Effect::ScheduleTimer {
                    kind: TimerKind::AutoLockCheck,
                    after,
                });
            }
            None if self.vault.auto_lock_armed => {
                self.vault.auto_lock_armed = false;
                effects.push(Effect::CancelTimer(TimerKind::AutoLockCheck));
            }
            None => {}
        }
    }

    /// `TimerKind::AutoLockCheck` and `TimerKind::UnlockCountdown`.
    pub(crate) fn vault_on_timer(&mut self, kind: TimerKind, effects: &mut Vec<Effect>) {
        match kind {
            TimerKind::AutoLockCheck => {
                self.vault.auto_lock_armed = false;
                // `auto_lock_minutes` may have been set to 0 since the timer was armed.
                if auto_lock_timeout(self.config.general.auto_lock_minutes).is_some() {
                    self.lock_vault(effects);
                }
            }
            TimerKind::UnlockCountdown => {
                if let VaultScreen::Unlock(f) = &mut self.vault.screen
                    && let Some(secs) = f.countdown
                {
                    f.countdown = secs.checked_sub(1).filter(|s| *s > 0);
                    if f.countdown.is_some() {
                        effects.push(Effect::ScheduleTimer {
                            kind: TimerKind::UnlockCountdown,
                            after: Duration::from_secs(1),
                        });
                    }
                    self.needs_redraw = true;
                }
            }
            _ => {}
        }
    }

    fn start_countdown(form: &mut UnlockForm, retry_after: Duration, effects: &mut Vec<Effect>) {
        let secs = retry_after.as_millis().div_ceil(1000);
        let secs = u64::try_from(secs).unwrap_or(u64::MAX).max(1);
        form.countdown = Some(secs);
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::UnlockCountdown,
            after: Duration::from_secs(1),
        });
    }

    /// Holds the launch intent back while locked; returns it when it may run now.
    pub(crate) fn vault_defer_launch(&mut self, intent: LaunchIntent) -> Option<LaunchIntent> {
        if self.vault.active && self.vault.lock.is_locked() {
            self.vault.deferred_launch = Some(intent);
            None
        } else {
            Some(intent)
        }
    }

    /// `UiEvent::Vault`.
    pub(crate) fn on_vault(&mut self, ev: VaultEvent, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        match ev {
            VaultEvent::Status(status) => self.on_vault_status(status, effects),
            VaultEvent::Unlocked {
                via_keyring: _,
                note,
            } => {
                self.vault.lock = LockState::Unlocked;
                self.vault.leader_armed = false;
                self.vault.screen = if std::mem::take(&mut self.vault.recovering) {
                    VaultScreen::ChangePassword(ChangePasswordForm::recovery())
                } else {
                    VaultScreen::None
                };
                effects.push(Effect::CancelTimer(TimerKind::UnlockCountdown));
                self.arm_auto_lock(effects);
                if let Some(note) = note {
                    self.push_toast(ToastLevel::Warning, note, effects);
                }
                if std::mem::take(&mut self.vault.discarded_forms) {
                    self.push_toast(ToastLevel::Info, DISCARDED_FORMS.to_owned(), effects);
                }
                if let Some(intent) = self.vault.deferred_launch.take() {
                    self.on_launch(intent, effects);
                }
            }
            VaultEvent::UnlockFailed(failure) => self.on_unlock_failed(failure, effects),
            VaultEvent::PasswordChanged => {
                if matches!(self.vault.screen, VaultScreen::ChangePassword(_)) {
                    self.vault.screen = VaultScreen::None;
                }
                self.push_toast(
                    ToastLevel::Success,
                    "Master password changed".to_owned(),
                    effects,
                );
            }
            VaultEvent::PasswordChangeFailed(msg) => {
                if let VaultScreen::ChangePassword(f) = &mut self.vault.screen {
                    f.busy = false;
                    f.error = Some(msg);
                    f.focus = 0;
                } else {
                    self.push_toast(ToastLevel::Error, msg, effects);
                }
            }
            VaultEvent::LockRequested => self.lock_vault(effects),
            // M1-07
            VaultEvent::ItemFailed(report) => self.push_error(&report, effects),
            // M2-03
            VaultEvent::Keychain(ev) => self.on_keychain_event(ev, effects),
            // M5-02
            VaultEvent::Shared(ev) => self.on_shared_vault_event(ev, effects),
        }
    }

    fn on_vault_status(&mut self, status: VaultStatusInfo, effects: &mut Vec<Effect>) {
        if !self.vault.active {
            return;
        }
        self.vault.keyring_enabled = status.keyring_enabled;
        if !status.initialized {
            self.vault.lock = LockState::Locked;
            self.vault.screen = VaultScreen::FirstRun(FirstRunForm::new(status.keyring_available));
            return;
        }
        let mut form = UnlockForm {
            keyring_enabled: status.keyring_enabled,
            ..UnlockForm::default()
        };
        if status.keyring_enabled {
            // Keyring first; the prompt appears if it fails.
            form.busy = Some("Unlocking with the keyring…".into());
            self.vault.lock = LockState::Unlocking;
            effects.push(Effect::Vault(VaultEffect::Unlock(UnlockRequest::Keyring)));
        } else {
            self.vault.lock = LockState::Locked;
            if let Some(retry_after) = status.retry_after {
                Self::start_countdown(&mut form, retry_after, effects);
            }
        }
        self.vault.screen = VaultScreen::Unlock(form);
    }

    fn on_unlock_failed(&mut self, failure: UnlockFailure, effects: &mut Vec<Effect>) {
        if self.vault.lock == LockState::Unlocked {
            return;
        }
        self.vault.lock = LockState::Locked;
        match &mut self.vault.screen {
            VaultScreen::FirstRun(f) => {
                f.busy = false;
                f.error = Some(match failure {
                    UnlockFailure::Other(msg) | UnlockFailure::Keyring(msg) => msg,
                    other => format!("{other:?}"),
                });
            }
            VaultScreen::Unlock(f) => {
                f.busy = None;
                f.password.clear();
                match failure {
                    UnlockFailure::WrongPassword {
                        failures,
                        retry_after,
                    } => {
                        f.error = Some(format!(
                            "Wrong password ({failures} failed attempt{})",
                            if failures == 1 { "" } else { "s" }
                        ));
                        if let Some(d) = retry_after {
                            Self::start_countdown(f, d, effects);
                        }
                    }
                    UnlockFailure::Backoff { retry_after } => {
                        Self::start_countdown(f, retry_after, effects);
                    }
                    UnlockFailure::Keyring(msg) => {
                        self.vault.recovering = false;
                        let text =
                            format!("Keyring unlock failed ({msg}); enter your master password");
                        self.push_toast(ToastLevel::Info, text, effects);
                    }
                    UnlockFailure::Other(msg) => f.error = Some(msg),
                }
            }
            _ => {}
        }
    }

    /// Whether the vault covers the screen (locked, or a vault form is open): no pane
    /// cursor is shown.
    pub(crate) fn vault_hides_panes(&self) -> bool {
        self.vault.active
            && (self.vault.lock.is_locked() || !matches!(self.vault.screen, VaultScreen::None))
    }

    /// Draw the lock overlay and the vault prompt over the shell.
    pub(crate) fn render_vault(&self, frame: &mut Frame<'_>) {
        if !self.vault.active {
            return;
        }
        let area = frame.area();
        let locked = self.vault.lock.is_locked();
        if locked {
            let rects = self.shell_rects();
            if rects.too_small {
                return;
            }
            let info = TopBarInfo {
                locked: true,
                ..TopBarInfo::default()
            };
            topbar::render(frame, rects.top_bar, &info, &self.theme);
            let hint = self.keymap.leader().hint();
            lock_overlay::render(frame, rects.main, &self.theme, false, &hint);
            if let Some(detail) = rects.detail {
                lock_overlay::render(frame, detail, &self.theme, false, &hint);
            }
        }
        match &self.vault.screen {
            VaultScreen::FirstRun(f) => f.render(frame, area, &self.theme, SPINNER),
            VaultScreen::Unlock(f) => f.render(frame, area, &self.theme, SPINNER),
            VaultScreen::ChangePassword(f) => f.render(frame, area, &self.theme),
            VaultScreen::None | VaultScreen::Starting => {}
        }
    }
}

#[cfg(test)]
mod tests;
