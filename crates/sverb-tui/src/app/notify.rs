//! Toasts and the notification history (M0-11, SPEC §8.7).
//!
//! - At most [`MAX_VISIBLE_TOASTS`] toasts are visible, newest last; when a fourth
//!   arrives the oldest leaves the screen (it stays in the history).
//! - Info, success and warning toasts fade after [`TOAST_TTL`] (`ScheduleTimer`);
//!   errors are sticky until dismissed: `leader !` (opens the history and clears them)
//!   or `Esc` while the toast stack is the top layer (no dialog, Normal mode).
//! - A toast with the same level and message as a visible one, within
//!   [`COALESCE_WINDOW`], bumps its counter (`(×3)`) instead of stacking.
//! - The history keeps the last [`HISTORY_LEN`] notifications with their detail chain
//!   (`ErrorReport::chain`) and a timestamp. The reducer never reads the clock: the
//!   runtime stamps new entries right after `App::handle` ([`App::stamp_notifications`]).

use std::{collections::VecDeque, time::Duration};

use chrono::{DateTime, Local};
use sverb_core::error_report::ErrorReport;

use super::{App, Effect, TimerKind, Toast, ToastId, ToastLevel};
use crate::views::{DialogKind, dialogs::NotificationList};

/// How long non-error toasts stay visible.
pub const TOAST_TTL: Duration = Duration::from_secs(4);
/// Visible toasts at most.
pub const MAX_VISIBLE_TOASTS: usize = 3;
/// Identical toasts within this window coalesce.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(2);
/// Notifications kept in the history.
pub const HISTORY_LEN: usize = 100;

/// One entry of the notification history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// The toast it was shown as.
    pub toast: ToastId,
    /// Severity.
    pub level: ToastLevel,
    /// Short message.
    pub message: String,
    /// Detail chain (outermost cause first), from `ErrorReport::chain`.
    pub detail: Vec<String>,
    /// Coalesced repeats.
    pub count: u32,
    /// When it happened (stamped by the runtime; `None` until then and in tests).
    pub at: Option<DateTime<Local>>,
}

/// The last [`HISTORY_LEN`] notifications, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notifications {
    entries: VecDeque<Notification>,
}

impl Notifications {
    /// Entries, oldest first.
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &Notification> + ExactSizeIterator {
        self.entries.iter()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn push(&mut self, n: Notification) {
        if self.entries.len() >= HISTORY_LEN {
            self.entries.pop_front();
        }
        self.entries.push_back(n);
    }

    fn bump(&mut self, toast: ToastId, count: u32) {
        if let Some(n) = self.entries.iter_mut().rev().find(|n| n.toast == toast) {
            n.count = count;
        }
    }
}

impl App {
    /// Show a toast (and record it in the history).
    pub(crate) fn push_toast(
        &mut self,
        level: ToastLevel,
        message: String,
        effects: &mut Vec<Effect>,
    ) -> ToastId {
        self.push_notification(level, message, Vec::new(), effects)
    }

    /// An error toast with its detail chain.
    pub(crate) fn push_error(&mut self, report: &ErrorReport, effects: &mut Vec<Effect>) {
        self.push_notification(
            ToastLevel::Error,
            report.short.clone(),
            report.chain.clone(),
            effects,
        );
    }

    fn push_notification(
        &mut self,
        level: ToastLevel,
        message: String,
        detail: Vec<String>,
        effects: &mut Vec<Effect>,
    ) -> ToastId {
        self.needs_redraw = true;
        if let Some(t) = self
            .toasts
            .iter_mut()
            .find(|t| t.coalescing && t.level == level && t.message == message)
        {
            t.count = t.count.saturating_add(1);
            let (id, count) = (t.id, t.count);
            self.notifications.bump(id, count);
            // Restart both windows: the repeat is new information.
            effects.push(Effect::ScheduleTimer {
                kind: TimerKind::ToastCoalesce(id),
                after: COALESCE_WINDOW,
            });
            if !level.is_sticky() {
                effects.push(Effect::ScheduleTimer {
                    kind: TimerKind::ToastExpiry(id),
                    after: TOAST_TTL,
                });
            }
            return id;
        }
        while self.toasts.len() >= MAX_VISIBLE_TOASTS {
            let old = self.toasts.remove(0);
            effects.push(Effect::CancelTimer(TimerKind::ToastExpiry(old.id)));
            effects.push(Effect::CancelTimer(TimerKind::ToastCoalesce(old.id)));
        }
        let id = self.ids.toast();
        self.toasts.push(Toast {
            id,
            level,
            message: message.clone(),
            count: 1,
            coalescing: true,
        });
        self.notifications.push(Notification {
            toast: id,
            level,
            message,
            detail,
            count: 1,
            at: None,
        });
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::ToastCoalesce(id),
            after: COALESCE_WINDOW,
        });
        if !level.is_sticky() {
            effects.push(Effect::ScheduleTimer {
                kind: TimerKind::ToastExpiry(id),
                after: TOAST_TTL,
            });
        }
        id
    }

    /// `TimerKind::ToastExpiry` / `TimerKind::ToastCoalesce`.
    pub(crate) fn on_toast_timer(&mut self, kind: TimerKind) {
        match kind {
            TimerKind::ToastExpiry(id) => {
                let before = self.toasts.len();
                self.toasts.retain(|t| t.id != id);
                self.needs_redraw |= self.toasts.len() != before;
            }
            TimerKind::ToastCoalesce(id) => {
                if let Some(t) = self.toasts.iter_mut().find(|t| t.id == id) {
                    t.coalescing = false;
                }
            }
            _ => {}
        }
    }

    /// Remove the sticky (error) toasts. Returns whether any were visible.
    pub(crate) fn dismiss_sticky_toasts(&mut self, effects: &mut Vec<Effect>) -> bool {
        let before = self.toasts.len();
        self.toasts.retain(|t| {
            if t.level.is_sticky() {
                effects.push(Effect::CancelTimer(TimerKind::ToastCoalesce(t.id)));
                false
            } else {
                true
            }
        });
        let any = self.toasts.len() != before;
        self.needs_redraw |= any;
        any
    }

    /// `leader !`: the history overlay; opening it dismisses sticky toasts.
    pub(crate) fn open_notification_history(&mut self, effects: &mut Vec<Effect>) {
        self.dismiss_sticky_toasts(effects);
        let entries = self.notifications.entries().rev().cloned().collect();
        self.push_dialog(DialogKind::Notifications(NotificationList::new(entries)));
    }

    /// The notification history.
    pub fn notifications(&self) -> &Notifications {
        &self.notifications
    }

    /// Whether a notification is waiting for its timestamp.
    pub fn has_unstamped_notifications(&self) -> bool {
        self.notifications
            .entries
            .back()
            .is_some_and(|n| n.at.is_none())
    }

    /// Stamp notifications created since the last call with `now`. Called by the
    /// runtime after each `handle` (the reducer itself never reads the clock).
    pub fn stamp_notifications(&mut self, now: DateTime<Local>) {
        for n in self.notifications.entries.iter_mut().rev() {
            if n.at.is_some() {
                break;
            }
            n.at = Some(now);
        }
    }
}
