//! M6-03: terminal sharing in the reducer (SPEC §14).
//!
//! **Host.** `leader S` (`share_pane`) on a live pane opens the start dialog
//! (`views::share::start_dialog`); its answer is `ShareEffect::Start`. The service
//! creates the share, attaches the session's output tap and answers
//! `ShareEvent::Started` with the link: it is copied to the clipboard and shown in
//! the viewers panel (`leader S` again while sharing). Each viewer that passed the
//! link-key check opens an approval modal (stacked when several wait); its answer is
//! `ShareEffect::Approve` / `Deny`. The panel grants and revokes control, kicks,
//! copies the link and stops sharing. A shared pane shows `⚠ shared · view` or
//! `⚠ shared · control` on its top border.
//!
//! **Viewer.** `sverb join <link>` (`LaunchIntent::Join`) and a link pasted into the
//! palette open a **viewer pane** in a new tab and send `ShareEffect::Join`. The
//! service runs it as a session over the share (its emulator sized to the host's
//! screen); this module keeps its status for the title
//! (`viewing shared session (read-only)`), the letterboxed drawing, and drops the
//! pane-size resizes the layout would send it. Viewer panes can't be duplicated
//! into splits or saved in workspaces (their pane kind is not a host or a shell).
//!
//! Everything here is plain data: no I/O, no clock (the expiry arrives formatted).

use std::collections::BTreeMap;
use std::time::Duration;

use ratatui::{Frame, layout::Rect, text::Span, widgets::Clear};
use sverb_proto::share::ShareMode;

use super::{App, Effect, SessionId, ToastLevel};
use crate::keymap::action::ActionName;
use crate::views::DialogKind;
use crate::views::share::{
    ApproveDialog, ShareAnswer, ShareDialog, StartDialog, ViewersPanel, letterbox,
};
use crate::widgets::terminal_pane::{PaneCursor, PaneDecor, PaneSource, TerminalPane};

/// The expiries of the start dialog.
pub const EXPIRY_LABELS: [&str; 4] = ["15 min", "1 h", "4 h", "24 h"];
const EXPIRY_SECS: [u64; 4] = [15 * 60, 3600, 4 * 3600, 24 * 3600];

/// What the start dialog chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareStartOptions {
    /// View (default) or control.
    pub mode: ShareMode,
    /// Index into [`EXPIRY_LABELS`] (default 1 h).
    pub expiry: usize,
    /// Viewers must sign in.
    pub require_account: bool,
    /// Admit viewers without asking.
    pub skip_approval: bool,
}

impl Default for ShareStartOptions {
    fn default() -> Self {
        Self {
            mode: ShareMode::View,
            expiry: 1,
            require_account: false,
            skip_approval: false,
        }
    }
}

impl ShareStartOptions {
    /// The chosen lifetime.
    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(EXPIRY_SECS[self.expiry.min(EXPIRY_SECS.len() - 1)])
    }
}

/// A viewer as the host sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerInfo {
    /// Relay-assigned id.
    pub id: u32,
    /// The display name the viewer gave.
    pub name: Option<String>,
    /// The viewer's account email, when signed in.
    pub account: Option<String>,
    /// Coarse IP hint from the server.
    pub ip_hint: Option<String>,
    /// The host granted input.
    pub control: bool,
}

impl ViewerInfo {
    /// The name, else the account, else "anonymous".
    pub fn display_name(&self) -> String {
        self.name
            .as_deref()
            .filter(|n| !n.trim().is_empty())
            .or(self.account.as_deref())
            .unwrap_or("anonymous")
            .to_owned()
    }
}

/// A request for the share service (`services::share`).
#[derive(Clone, PartialEq, Eq)]
pub enum ShareEffect {
    /// Share `session` (answered with `Started` or `StartFailed`).
    Start {
        /// The pane.
        session: SessionId,
        /// The start dialog's choices.
        options: ShareStartOptions,
    },
    /// Admit a viewer.
    Approve {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
    },
    /// Refuse a viewer.
    Deny {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
    },
    /// Grant / revoke control.
    SetControl {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
        /// Grant.
        granted: bool,
    },
    /// Disconnect a viewer.
    Kick {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
    },
    /// Stop sharing.
    Stop {
        /// The shared pane.
        session: SessionId,
    },
    /// Open viewer pane `id` on the share behind `link`.
    Join {
        /// The viewer pane's session id (allocated by the reducer).
        id: SessionId,
        /// The link (carries the key: never logged).
        link: String,
    },
    /// Input typed in viewer pane `id` while the host granted control (encoded by
    /// the service with the viewer emulator's modes).
    Input {
        /// The viewer pane.
        id: SessionId,
        /// What was typed (never logged).
        input: super::SessionInput,
    },
}

impl std::fmt::Debug for ShareEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start { session, options } => f
                .debug_struct("Start")
                .field("session", session)
                .field("options", options)
                .finish(),
            Self::Approve { session, viewer } => write!(f, "Approve({session:?}, {viewer})"),
            Self::Deny { session, viewer } => write!(f, "Deny({session:?}, {viewer})"),
            Self::SetControl {
                session,
                viewer,
                granted,
            } => write!(f, "SetControl({session:?}, {viewer}, {granted})"),
            Self::Kick { session, viewer } => write!(f, "Kick({session:?}, {viewer})"),
            Self::Stop { session } => write!(f, "Stop({session:?})"),
            Self::Join { id, .. } => write!(f, "Join({id:?}, link: [REDACTED])"),
            Self::Input { id, .. } => write!(f, "Input({id:?}, [REDACTED])"),
        }
    }
}

/// A viewer pane's progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerStatus {
    /// The relay admitted the viewer.
    Joined {
        /// The share's mode.
        mode: ShareMode,
    },
    /// "Waiting for host approval…".
    Waiting,
    /// The snapshot arrived: the host's screen is `cols`×`rows`.
    Live {
        /// Host columns.
        cols: u16,
        /// Host rows.
        rows: u16,
    },
    /// The host resized.
    Resized {
        /// Host columns.
        cols: u16,
        /// Host rows.
        rows: u16,
    },
    /// Control granted / revoked.
    Control(bool),
    /// The share is over for this pane.
    Ended {
        /// Why.
        reason: String,
    },
}

/// From the share service.
#[derive(Clone, PartialEq, Eq)]
pub enum ShareEvent {
    /// Sharing `session` started.
    Started {
        /// The pane.
        session: SessionId,
        /// `sverb://join/…#key`.
        link: String,
        /// The `https://` form.
        web_link: String,
        /// The expiry, formatted for display.
        expires: String,
        /// The mode.
        mode: ShareMode,
    },
    /// Sharing `session` could not start.
    StartFailed {
        /// The pane.
        session: SessionId,
        /// Why.
        error: String,
    },
    /// A viewer waits for approval.
    ApprovalNeeded {
        /// The shared pane.
        session: SessionId,
        /// Who.
        viewer: ViewerInfo,
    },
    /// A viewer was admitted.
    ViewerJoined {
        /// The shared pane.
        session: SessionId,
        /// Who.
        viewer: ViewerInfo,
    },
    /// A join request failed the link-key check (the viewer was kicked).
    ViewerRejected {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
    },
    /// A viewer is gone.
    ViewerLeft {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
        /// Why.
        reason: String,
    },
    /// Control changed.
    ControlChanged {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
        /// Granted.
        granted: bool,
    },
    /// Sharing `session` ended.
    Ended {
        /// The pane.
        session: SessionId,
        /// Why.
        reason: String,
    },
    /// A viewer pane's progress.
    Viewer {
        /// The viewer pane.
        id: SessionId,
        /// What happened.
        status: ViewerStatus,
    },
    /// Sharing isn't available (build, sign-in): `id` is a viewer pane to close.
    Unavailable {
        /// The viewer pane that can't open, if any.
        id: Option<SessionId>,
        /// Why.
        message: String,
    },
}

impl std::fmt::Debug for ShareEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The links carry the key.
            Self::Started {
                session,
                expires,
                mode,
                ..
            } => f
                .debug_struct("Started")
                .field("session", session)
                .field("expires", expires)
                .field("mode", mode)
                .finish_non_exhaustive(),
            Self::StartFailed { session, error } => f
                .debug_struct("StartFailed")
                .field("session", session)
                .field("error", error)
                .finish(),
            Self::ApprovalNeeded { session, viewer } => f
                .debug_struct("ApprovalNeeded")
                .field("session", session)
                .field("viewer", viewer)
                .finish(),
            Self::ViewerJoined { session, viewer } => f
                .debug_struct("ViewerJoined")
                .field("session", session)
                .field("viewer", viewer)
                .finish(),
            Self::ViewerRejected { session, viewer } => {
                write!(f, "ViewerRejected({session:?}, {viewer})")
            }
            Self::ViewerLeft {
                session,
                viewer,
                reason,
            } => write!(f, "ViewerLeft({session:?}, {viewer}, {reason:?})"),
            Self::ControlChanged {
                session,
                viewer,
                granted,
            } => write!(f, "ControlChanged({session:?}, {viewer}, {granted})"),
            Self::Ended { session, reason } => write!(f, "Ended({session:?}, {reason:?})"),
            Self::Viewer { id, status } => write!(f, "Viewer({id:?}, {status:?})"),
            Self::Unavailable { id, message } => write!(f, "Unavailable({id:?}, {message:?})"),
        }
    }
}

/// A pane this device shares.
#[derive(Clone, PartialEq, Eq)]
pub struct HostShare {
    /// View or control.
    pub mode: ShareMode,
    /// The link (`None` while the share is being created).
    pub link: Option<String>,
    /// The expiry, formatted.
    pub expires: Option<String>,
    /// Admitted viewers.
    pub viewers: Vec<ViewerInfo>,
}

impl std::fmt::Debug for HostShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostShare")
            .field("mode", &self.mode)
            .field("started", &self.link.is_some())
            .field("viewers", &self.viewers)
            .finish_non_exhaustive()
    }
}

/// A viewer pane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewerPane {
    /// The share's mode, once joined.
    pub mode: Option<ShareMode>,
    /// The host's screen size, once live.
    pub size: Option<(u16, u16)>,
    /// The host granted control.
    pub control: bool,
    /// Waiting for the host's approval.
    pub waiting: bool,
    /// Why it ended, once over.
    pub ended: Option<String>,
}

impl ViewerPane {
    /// The pane title.
    pub fn title(&self) -> String {
        if let Some(reason) = &self.ended {
            return format!("share ended ({reason})");
        }
        if self.waiting {
            return "shared session · waiting for host approval…".to_owned();
        }
        match (self.size, self.control) {
            (None, _) => "joining shared session…".to_owned(),
            (Some(_), false) => "viewing shared session (read-only)".to_owned(),
            (Some(_), true) => "viewing shared session (control)".to_owned(),
        }
    }
}

/// Sharing state of the UI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareUi {
    /// Panes this device shares.
    pub hosts: BTreeMap<SessionId, HostShare>,
    /// Viewer panes.
    pub viewers: BTreeMap<SessionId, ViewerPane>,
}

impl App {
    /// The sharing state.
    pub fn share_ui(&self) -> &ShareUi {
        &self.share
    }

    /// `share_pane` (`leader S`). Returns whether `action` was it.
    pub(crate) fn apply_share_action(
        &mut self,
        action: ActionName,
        effects: &mut Vec<Effect>,
    ) -> bool {
        if action != ActionName::SharePane {
            return false;
        }
        let Some(id) = self.focused_session() else {
            self.push_toast(
                ToastLevel::Info,
                "Focus a terminal pane to share it".to_owned(),
                effects,
            );
            return true;
        };
        if self.share.viewers.contains_key(&id) {
            self.push_toast(
                ToastLevel::Info,
                "A shared terminal you are viewing can't be shared again".to_owned(),
                effects,
            );
        } else if self.share.hosts.contains_key(&id) {
            self.open_viewers_panel(id);
        } else if !self.sync.connected() {
            self.push_toast(
                ToastLevel::Info,
                "Sharing needs a sverb server: connect one in Settings → Sync".to_owned(),
                effects,
            );
        } else if self.is_exited(id) {
            self.push_toast(
                ToastLevel::Info,
                "This pane's session has ended".to_owned(),
                effects,
            );
        } else {
            let label = self.pane(id).label;
            self.push_dialog(DialogKind::Share(Box::new(ShareDialog::Start(
                StartDialog::new(id, label),
            ))));
        }
        true
    }

    fn open_viewers_panel(&mut self, id: SessionId) {
        let Some(host) = self.share.hosts.get(&id) else {
            return;
        };
        let mut panel = ViewersPanel::new(id, host.mode);
        panel.link.clone_from(&host.link);
        panel.expires.clone_from(&host.expires);
        panel.set_viewers(host.viewers.clone());
        self.push_dialog(DialogKind::Share(Box::new(ShareDialog::Viewers(panel))));
    }

    /// Refresh an open viewers panel of `id`.
    fn refresh_viewers_panel(&mut self, id: SessionId) {
        let Some(host) = self.share.hosts.get(&id).cloned() else {
            return;
        };
        for d in &mut self.dialogs {
            if let DialogKind::Share(sd) = &mut d.kind
                && let ShareDialog::Viewers(p) = &mut **sd
                && p.session == id
            {
                p.link.clone_from(&host.link);
                p.expires.clone_from(&host.expires);
                p.set_viewers(host.viewers.clone());
            }
        }
        self.needs_redraw = true;
    }

    /// Drop the share dialogs that match `f` (a viewer left, the share ended).
    fn close_share_dialogs(&mut self, f: impl Fn(&ShareDialog) -> bool) {
        let before = self.dialogs.len();
        self.dialogs
            .retain(|d| !matches!(&d.kind, DialogKind::Share(sd) if f(sd)));
        self.needs_redraw |= self.dialogs.len() != before;
    }

    /// The top share dialog's answer, right after its key.
    pub(crate) fn take_share_answer(&mut self, effects: &mut Vec<Effect>) {
        let Some(top) = self.dialogs.last_mut() else {
            return;
        };
        let DialogKind::Share(sd) = &mut top.kind else {
            return;
        };
        let Some(answer) = sd.take_answer() else {
            return;
        };
        let closes = !matches!(
            answer,
            ShareAnswer::SetControl { .. }
                | ShareAnswer::Kick { .. }
                | ShareAnswer::CopyLink { .. }
        );
        if closes {
            self.dialogs.pop();
        }
        self.needs_redraw = true;
        let effect = match answer {
            ShareAnswer::Start { session, options } => {
                self.share.hosts.insert(
                    session,
                    HostShare {
                        mode: options.mode,
                        link: None,
                        expires: None,
                        viewers: Vec::new(),
                    },
                );
                ShareEffect::Start { session, options }
            }
            ShareAnswer::Approve { session, viewer } => ShareEffect::Approve { session, viewer },
            ShareAnswer::Deny { session, viewer } => ShareEffect::Deny { session, viewer },
            ShareAnswer::SetControl {
                session,
                viewer,
                granted,
            } => ShareEffect::SetControl {
                session,
                viewer,
                granted,
            },
            ShareAnswer::Kick { session, viewer } => ShareEffect::Kick { session, viewer },
            ShareAnswer::CopyLink { session } => {
                if let Some(link) = self.share.hosts.get(&session).and_then(|h| h.link.clone()) {
                    effects.push(Effect::CopyToClipboard(link));
                    self.push_toast(ToastLevel::Info, "Share link copied".to_owned(), effects);
                }
                return;
            }
            ShareAnswer::Stop { session } => ShareEffect::Stop { session },
        };
        effects.push(Effect::Share(effect));
    }

    /// `sverb join <link>` and a link picked in the palette: open a viewer pane.
    pub(crate) fn share_join(&mut self, link: String, effects: &mut Vec<Effect>) {
        if let Err(e) = sverb_crypto::share::ShareLink::parse(&link) {
            self.push_toast(
                ToastLevel::Warning,
                format!("Not a usable share link: {e}"),
                effects,
            );
            return;
        }
        let id = loop {
            let id = self.ids.session();
            if !self.tabs.sessions.contains(&id) {
                break id;
            }
        };
        self.share.viewers.insert(id, ViewerPane::default());
        self.focus_session(id);
        self.set_pane_label(id, ViewerPane::default().title());
        effects.push(Effect::Share(ShareEffect::Join { id, link }));
    }

    /// `UiEvent::Share`.
    pub(crate) fn on_share(&mut self, ev: ShareEvent, effects: &mut Vec<Effect>) {
        match ev {
            ShareEvent::Started {
                session,
                link,
                expires,
                mode,
                ..
            } => {
                let Some(host) = self.share.hosts.get_mut(&session) else {
                    return;
                };
                host.link = Some(link.clone());
                host.expires = Some(expires);
                host.mode = mode;
                effects.push(Effect::CopyToClipboard(link));
                self.push_toast(
                    ToastLevel::Info,
                    "Sharing this pane · link copied to the clipboard".to_owned(),
                    effects,
                );
                self.open_viewers_panel(session);
            }
            ShareEvent::StartFailed { session, error } => {
                self.share.hosts.remove(&session);
                self.push_toast(
                    ToastLevel::Error,
                    format!("Sharing failed: {error}"),
                    effects,
                );
            }
            ShareEvent::ApprovalNeeded { session, viewer } => {
                let Some(host) = self.share.hosts.get(&session) else {
                    return;
                };
                let label = self.pane(session).label;
                let dialog = ApproveDialog::new(session, label, host.mode, viewer);
                self.push_dialog(DialogKind::Share(Box::new(ShareDialog::Approve(dialog))));
            }
            ShareEvent::ViewerJoined { session, viewer } => {
                if let Some(host) = self.share.hosts.get_mut(&session) {
                    host.viewers.retain(|v| v.id != viewer.id);
                    let name = viewer.display_name();
                    host.viewers.push(viewer);
                    self.refresh_viewers_panel(session);
                    self.push_toast(
                        ToastLevel::Info,
                        format!("{name} is viewing your pane"),
                        effects,
                    );
                }
            }
            ShareEvent::ViewerRejected { session, viewer } => {
                self.close_share_dialogs(|d| {
                    matches!(d, ShareDialog::Approve(a) if a.session == session && a.viewer.id == viewer)
                });
                self.push_toast(
                    ToastLevel::Warning,
                    "A join request with a wrong link key was refused".to_owned(),
                    effects,
                );
            }
            ShareEvent::ViewerLeft {
                session, viewer, ..
            } => {
                self.close_share_dialogs(|d| {
                    matches!(d, ShareDialog::Approve(a) if a.session == session && a.viewer.id == viewer)
                });
                if let Some(host) = self.share.hosts.get_mut(&session) {
                    host.viewers.retain(|v| v.id != viewer);
                    self.refresh_viewers_panel(session);
                }
            }
            ShareEvent::ControlChanged {
                session,
                viewer,
                granted,
            } => {
                if let Some(host) = self.share.hosts.get_mut(&session) {
                    for v in &mut host.viewers {
                        if v.id == viewer {
                            v.control = granted;
                        }
                    }
                    self.refresh_viewers_panel(session);
                }
            }
            ShareEvent::Ended { session, reason } => {
                if self.share.hosts.remove(&session).is_some() {
                    self.close_share_dialogs(|d| match d {
                        ShareDialog::Approve(a) => a.session == session,
                        ShareDialog::Viewers(p) => p.session == session,
                        ShareDialog::Start(_) => false,
                    });
                    self.push_toast(
                        ToastLevel::Info,
                        format!("Sharing ended ({reason})"),
                        effects,
                    );
                    self.needs_redraw = true;
                }
            }
            ShareEvent::Viewer { id, status } => self.on_viewer_status(id, status, effects),
            ShareEvent::Unavailable { id, message } => {
                if let Some(id) = id
                    && self.share.viewers.remove(&id).is_some()
                {
                    effects.push(Effect::CloseSession(id));
                }
                self.push_toast(ToastLevel::Warning, message, effects);
            }
        }
    }

    fn on_viewer_status(&mut self, id: SessionId, status: ViewerStatus, effects: &mut Vec<Effect>) {
        let Some(pane) = self.share.viewers.get_mut(&id) else {
            return;
        };
        let mut toast = None;
        match status {
            ViewerStatus::Joined { mode } => pane.mode = Some(mode),
            ViewerStatus::Waiting => pane.waiting = true,
            ViewerStatus::Live { cols, rows } => {
                pane.waiting = false;
                pane.size = Some((cols, rows));
            }
            ViewerStatus::Resized { cols, rows } => pane.size = Some((cols, rows)),
            ViewerStatus::Control(granted) => {
                pane.control = granted;
                toast = Some(if granted {
                    "The host gave you control: your keys reach the shared terminal"
                } else {
                    "The host took control back"
                });
            }
            ViewerStatus::Ended { reason } => {
                pane.waiting = false;
                pane.control = false;
                pane.ended = Some(reason);
            }
        }
        let title = pane.title();
        self.set_pane_label(id, title);
        if let Some(msg) = toast {
            self.push_toast(ToastLevel::Info, msg.to_owned(), effects);
        }
        self.needs_redraw = true;
    }

    /// After every event: viewer panes keep the host's size (their pane-size resizes
    /// are dropped), their input goes to the share (only while the host granted
    /// control; in view mode nothing typed leaves the pane), and closed panes are
    /// forgotten.
    pub(crate) fn share_after_handle(&mut self, effects: &mut Vec<Effect>) {
        if self.share.viewers.is_empty() && self.share.hosts.is_empty() {
            return;
        }
        let viewers = &self.share.viewers;
        effects.retain(|e| match e {
            Effect::ResizeSession { id, .. } => !viewers.contains_key(id),
            Effect::SendToSession { id, .. } => viewers.get(id).is_none_or(|v| v.control),
            _ => true,
        });
        for e in effects.iter_mut() {
            if let Effect::SendToSession { id, input } = e
                && viewers.contains_key(id)
            {
                *e = Effect::Share(ShareEffect::Input {
                    id: *id,
                    input: input.clone(),
                });
            }
        }
        let open = &self.tabs.sessions;
        self.share.viewers.retain(|id, _| open.contains(id));
        self.share.hosts.retain(|id, _| open.contains(id));
    }

    /// The `⚠ shared · …` badge of a pane this device shares.
    pub(crate) fn share_badge(&self, id: SessionId) -> Option<String> {
        let host = self.share.hosts.get(&id)?;
        host.link.as_ref()?;
        Some(match host.mode {
            ShareMode::View => "⚠ shared · view".to_owned(),
            ShareMode::Control => "⚠ shared · control".to_owned(),
        })
    }

    /// Draw a viewer pane: the border and title as usual, the host-sized screen
    /// letterboxed inside. `None` when `id` is not a viewer pane.
    pub(crate) fn render_share_viewer(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        id: SessionId,
        panes: &dyn PaneSource,
    ) -> Option<Option<PaneCursor>> {
        self.share.viewers.get(&id)?;
        let info = self.pane(id);
        let focused = self.dialogs.is_empty() && self.focused_session() == Some(id);
        let pane = TerminalPane {
            info: &info,
            theme: &self.theme,
            focused,
            scheme: self.pane_scheme(id),
            depth: self.pane_depth(),
            use_osc_title: false,
            leader: self.keymap.leader().hint(),
        };
        // The border and title (no emulator: the content is drawn below).
        pane.render_with(area, frame.buffer_mut(), None, &|_, _| PaneDecor::default());
        let inner = Rect {
            x: area.x.saturating_add(1),
            y: area.y.saturating_add(1),
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(2),
        };
        frame.render_widget(Clear, inner);
        let Some(emu) = panes.emulator(id) else {
            return Some(None);
        };
        let term = emu.lock();
        let (cols, rows) = term.size();
        let rect = letterbox(inner, cols, rows);
        let view = pane.view();
        term.render(rect, frame.buffer_mut(), &view);
        let cursor = term.cursor();
        drop(term);
        let cursor = focused
            .then(|| sverb_term::render::cursor_position(&cursor, rect, &view))
            .flatten()
            .map(|position| PaneCursor {
                position,
                shape: cursor.shape,
                blinking: cursor.blinking,
            });
        if let Some(c) = cursor {
            frame.set_cursor_position(c.position);
        }
        Some(cursor)
    }

    /// The badge of a shared pane, on the right of its top border.
    pub(crate) fn render_share_badge(&self, frame: &mut Frame<'_>, area: Rect, id: SessionId) {
        let Some(badge) = self.share_badge(id) else {
            return;
        };
        // Copy mode shows its own badge there.
        if self.input.copy_mode && self.focused_session() == Some(id) {
            return;
        }
        let text = format!(" {badge} ");
        let w = u16::try_from(text.chars().count()).unwrap_or(u16::MAX);
        if area.width < w.saturating_add(4) || area.height == 0 {
            return;
        }
        let x = area.x + area.width - w - 2;
        frame
            .buffer_mut()
            .set_span(x, area.y, &Span::styled(text, self.theme.warn), w);
    }
}
