//! M2-08: the Forwards section (SPEC §8.5, §9.6).
//!
//! ```text
//! ┌ Forwards ─────────────────────────────────────────────────────────────────────────┐
//! │ › db tunnel     L  127.0.0.1:5432 → db:5432        listening        2   1.2 MB  34 kB  prod │
//! │   socks         D  127.0.0.1:1080 → SOCKS          stopped          0      0 B    0 B  bastion │
//! │   webhook       R  *:40121 → localhost:3000        listening  256/256  9.1 MB  1 MB  prod │
//! └───────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Saved rules with their live status (state, active connections, bytes in and out),
//! refreshed at most twice a second by the reducer. The shared list (M1-06): `/`
//! filters, `Space` marks, `s` sorts. Actions: `Enter` start / stop, `t` start without
//! terminal (a standalone tunnel), `x` stop, `a` add, `e` edit, `d` delete (asks).
//!
//! Like the other sections, actions that need the app are left in
//! [`ForwardsView::request`] and taken by the reducer right after the key
//! (`app/forwards.rs`). The add / edit form is [`ForwardDialog`]; its result is taken
//! the same way ([`ForwardDialog::take_result`]).
//!
//! [`status_segment`] is the status bar's `⇄ L:5432→db:5432` / `⇄ 3 forwards`.

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_conn::forward as fwd;
use sverb_core::model::{DEFAULT_BIND_ADDR, ForwardKind, ItemId, PortForward, ValidationError};

use self::fwd::{ForwardState, ForwardStatus, MAX_CHANNELS};
use crate::{
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent},
    widgets::{
        form::{Field, FieldValue, FieldValues, Form, FormRequest, FormValidator, SelectOption},
        list::{DetailRenderer, EmptyState, ListRow, ListView, RowCx, RowRenderer, SortKey},
        truncate,
    },
};

// ---------------------------------------------------------------- rows

/// One rule with its live status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRow {
    /// Rule, state and counters.
    pub status: ForwardStatus,
    /// The carrying host's label.
    pub host: String,
}

impl ForwardRow {
    /// The rule's item id.
    pub fn id(&self) -> ItemId {
        self.status.rule.id
    }
}

impl ListRow for ForwardRow {
    type Key = ItemId;

    fn key(&self) -> ItemId {
        self.status.rule.id
    }

    fn label(&self) -> &str {
        &self.status.rule.label
    }

    fn filter_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.status.rule.label,
            self.host,
            self.status.route(),
            self.status.state
        )
    }

    fn secondary(&self) -> String {
        self.status.state.to_string()
    }
}

/// `1.2 MB`, `34 kB`, `0 B` (SI units, one decimal from kB up).
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut v = n as f64 / 1000.0;
    let mut unit = 0;
    while v >= 1000.0 && unit + 1 < UNITS.len() {
        v /= 1000.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

/// The connections column: `n`, or `256/256` at the cap (§9.6 saturation indicator).
pub fn connections_text(status: &ForwardStatus) -> String {
    if status.saturated() {
        format!("{}/{MAX_CHANNELS}", status.active)
    } else {
        status.active.to_string()
    }
}

/// The status bar segment (§8.1): `⇄ L:5432→db:5432` for one listening forward,
/// `⇄ 3 forwards` for several, nothing when none listens.
pub fn status_segment(statuses: &[ForwardStatus]) -> Option<String> {
    let mut active = statuses
        .iter()
        .filter(|s| s.state == ForwardState::Listening);
    let first = active.next()?;
    let more = active.count();
    Some(if more == 0 {
        let mut rule = first.rule.clone();
        if let Some(port) = first.port {
            rule.bind_port = port;
        }
        format!("⇄ {}", rule.summary())
    } else {
        format!("⇄ {} forwards", more + 1)
    })
}

// ---------------------------------------------------------------- the view

/// What the user asked the reducer to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardsRequest {
    /// `Enter` on a stopped rule: start it on the host's live connection.
    Start(ItemId),
    /// `t`: start on a standalone (tunnel-only) connection.
    StartStandalone(ItemId),
    /// `x` (or `Enter` on a running rule): stop.
    Stop(ItemId),
    /// `a`: a new rule.
    Add,
    /// `e`: edit.
    Edit(ItemId),
    /// `d`: delete these rules (asks first).
    Delete(Vec<ItemId>),
}

/// The Forwards section's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardsView {
    /// The list.
    pub list: ListView<ForwardRow>,
    /// Host labels by id (row labels, the form's host picker).
    pub hosts: BTreeMap<ItemId, String>,
    /// The service delivered the rules (after unlock).
    pub loaded: bool,
    /// A load is in flight.
    pub loading: bool,
    /// The data changed while loading: load again.
    pub reload: bool,
    /// A request for the reducer, taken right after the key.
    pub request: Option<ForwardsRequest>,
    /// The ≤ 2 Hz status refresh timer is scheduled (`app/forwards.rs`).
    pub ticking: bool,
}

impl Default for ForwardsView {
    fn default() -> Self {
        let by_label = SortKey::new("label", |a: &ForwardRow, b: &ForwardRow| {
            a.status
                .rule
                .label
                .to_lowercase()
                .cmp(&b.status.rule.label.to_lowercase())
        });
        let by_state = SortKey::new("state", |a: &ForwardRow, b: &ForwardRow| {
            b.status
                .state
                .is_active()
                .cmp(&a.status.state.is_active())
                .then(b.status.active.cmp(&a.status.active))
        });
        Self {
            list: ListView::new("Forwards")
                .with_sort_keys(vec![by_label, by_state])
                .with_empty(EmptyState::new(
                    "No port forwards yet.",
                    &[("a", "add a forward")],
                )),
            hosts: BTreeMap::new(),
            loaded: false,
            loading: false,
            reload: false,
            request: None,
            ticking: false,
        }
    }
}

impl ForwardsView {
    /// Replace the host labels.
    pub fn set_hosts(&mut self, hosts: impl IntoIterator<Item = (ItemId, String)>) {
        self.hosts = hosts.into_iter().collect();
    }

    /// Replace the rows with fresh statuses. Returns whether anything changed (so
    /// the 2 Hz refresh redraws only when needed).
    pub fn set_statuses(&mut self, statuses: Vec<ForwardStatus>) -> bool {
        let rows: Vec<ForwardRow> = statuses
            .into_iter()
            .map(|status| ForwardRow {
                host: self
                    .hosts
                    .get(&status.rule.host_id)
                    .cloned()
                    .unwrap_or_else(|| "(missing host)".to_owned()),
                status,
            })
            .collect();
        self.loaded = true;
        if rows.as_slice() == self.list.rows() {
            return false;
        }
        self.list.set_rows(rows);
        true
    }

    /// The statuses shown.
    pub fn statuses(&self) -> Vec<ForwardStatus> {
        self.list.rows().iter().map(|r| r.status.clone()).collect()
    }

    /// Forget everything decrypted (on lock).
    pub fn clear(&mut self) {
        self.list.set_rows(Vec::new());
        self.hosts.clear();
        self.loaded = false;
        self.loading = false;
        self.reload = false;
        self.request = None;
        self.ticking = false;
    }

    /// The row with `id`.
    pub fn get(&self, id: ItemId) -> Option<&ForwardRow> {
        self.list.rows().iter().find(|r| r.id() == id)
    }

    /// The list is editing its filter (Insert mode).
    pub fn insert_mode(&self) -> bool {
        self.list.insert_mode()
    }

    fn on_action_key(&self, code: KeyCode, mods: KeyModifiers) -> Option<ForwardsRequest> {
        if mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            return None;
        }
        let selected = || self.list.selected();
        Some(match code {
            KeyCode::Enter => {
                let row = selected()?;
                if row.status.state.is_active() {
                    ForwardsRequest::Stop(row.id())
                } else {
                    ForwardsRequest::Start(row.id())
                }
            }
            KeyCode::Char('t') => ForwardsRequest::StartStandalone(selected()?.id()),
            KeyCode::Char('x') => ForwardsRequest::Stop(selected()?.id()),
            KeyCode::Char('a') => ForwardsRequest::Add,
            KeyCode::Char('e') => ForwardsRequest::Edit(selected()?.id()),
            KeyCode::Char('d') | KeyCode::Delete => {
                let targets = self.list.targets();
                if targets.is_empty() {
                    return None;
                }
                ForwardsRequest::Delete(targets)
            }
            _ => return None,
        })
    }

    /// Draw the selected rule's details (the shell's detail pane).
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let block = Block::bordered()
            .title(Span::styled(" Details ", theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        let width = usize::from(area.width.saturating_sub(2));
        let lines = match self.list.selected() {
            Some(row) => ForwardDetail.lines(row, theme, width),
            None => vec![Line::styled("Nothing selected.", theme.dim)],
        };
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block)
                .style(theme.base),
            area,
        );
    }
}

/// Draws a row: label, kind, `bind → dest`, state, connections, bytes in / out, host.
#[derive(Debug, Clone, Copy, Default)]
pub struct ForwardRowRenderer;

impl RowRenderer<ForwardRow> for ForwardRowRenderer {
    fn spans(&self, row: &ForwardRow, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        let dim = cx.base.patch(cx.theme.dim);
        let w = cx.width;
        const KIND_W: usize = 1;
        const ROUTE_W: usize = 34;
        const STATE_W: usize = 24;
        const CONN_W: usize = 7;
        const BYTES_W: usize = 8;
        const HOST_W: usize = 16;
        let s = &row.status;
        let label_w = w
            .saturating_sub(KIND_W + ROUTE_W + STATE_W + CONN_W + 2 * BYTES_W + HOST_W + 7)
            .clamp(8, 32);
        let mut spans = vec![Span::styled(
            format!("{:<label_w$} ", truncate(&s.rule.label, label_w)),
            cx.base,
        )];
        let mut used = label_w + 1;
        let mut push = |text: String, width: usize, style, right: bool| {
            if used + width <= w {
                let cell = truncate(&text, width);
                spans.push(Span::styled(
                    if right {
                        format!("{cell:>width$} ")
                    } else {
                        format!("{cell:<width$} ")
                    },
                    style,
                ));
                used += width + 1;
            }
        };
        push(
            fwd::kind_letter(s.rule.kind).to_string(),
            KIND_W,
            dim,
            false,
        );
        push(s.route(), ROUTE_W, cx.base, false);
        let state_style = match &s.state {
            ForwardState::Listening => cx.base.patch(cx.theme.ok),
            ForwardState::Error(_) | ForwardState::NeedsApproval => cx.base.patch(cx.theme.error),
            ForwardState::ConnectionLost => cx.base.patch(cx.theme.warn),
            _ => dim,
        };
        push(s.state.to_string(), STATE_W, state_style, false);
        let conn_style = if s.saturated() {
            cx.base.patch(cx.theme.warn)
        } else {
            cx.base
        };
        push(connections_text(s), CONN_W, conn_style, true);
        push(human_bytes(s.bytes_in), BYTES_W, dim, true);
        push(human_bytes(s.bytes_out), BYTES_W, dim, true);
        push(row.host.clone(), HOST_W, dim, false);
        spans
    }
}

/// The detail pane.
#[derive(Debug, Clone, Copy, Default)]
pub struct ForwardDetail;

impl DetailRenderer<ForwardRow> for ForwardDetail {
    fn lines(&self, row: &ForwardRow, theme: &Theme, _width: usize) -> Vec<Line<'static>> {
        let label = |k: &str| Span::styled(format!("{k:<12} "), theme.dim);
        let s = &row.status;
        let kind = match s.rule.kind {
            ForwardKind::Local => "Local (-L)",
            ForwardKind::Remote => "Remote (-R)",
            ForwardKind::Dynamic => "Dynamic (-D, SOCKS)",
        };
        let mut lines = vec![
            Line::from(vec![label("Kind:"), Span::raw(kind)]),
            Line::from(vec![label("Host:"), Span::raw(row.host.clone())]),
            Line::from(vec![label("Route:"), Span::raw(s.route())]),
            Line::from(vec![label("State:"), Span::raw(s.state.to_string())]),
            Line::from(vec![
                label("Connections:"),
                Span::raw(format!(
                    "{} active, {} total, {} refused",
                    connections_text(s),
                    s.total,
                    s.refused
                )),
            ]),
            Line::from(vec![
                label("Bytes:"),
                Span::raw(format!(
                    "{} in, {} out",
                    human_bytes(s.bytes_in),
                    human_bytes(s.bytes_out)
                )),
            ]),
            Line::from(vec![
                label("Auto-start:"),
                Span::raw(if s.rule.auto_start { "yes" } else { "no" }),
            ]),
        ];
        if s.standalone {
            lines.push(Line::styled(
                "Standalone tunnel (no terminal).",
                theme.accent,
            ));
        }
        if s.rule.kind == ForwardKind::Remote && s.rule.bind_port == 0 {
            lines.push(Line::styled(
                "The server allocates the port when the forward starts.",
                theme.dim,
            ));
        }
        lines
    }
}

impl View for ForwardsView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        if self.list.handle(ev, cx) == Outcome::Consumed {
            return Outcome::Consumed;
        }
        let ViewEvent::Key(key) = ev else {
            return Outcome::Ignored;
        };
        match self.on_action_key(key.code, key.modifiers) {
            Some(req) => {
                self.request = Some(req);
                cx.request_redraw();
                Outcome::Consumed
            }
            None => Outcome::Ignored,
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let detail: Option<&dyn DetailRenderer<ForwardRow>> =
            self.list.detail_full().then_some(&ForwardDetail as _);
        self.list
            .render_with(frame, area, cx, &ForwardRowRenderer, detail);
    }

    fn insert_mode(&self) -> bool {
        ForwardsView::insert_mode(self)
    }
}

// ---------------------------------------------------------------- the form

const KIND_LOCAL: &str = "local";
const KIND_REMOTE: &str = "remote";
const KIND_DYNAMIC: &str = "dynamic";

fn text(values: &FieldValues, key: &str) -> String {
    values
        .get(key)
        .and_then(FieldValue::as_text)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn number(values: &FieldValues, key: &str) -> Option<u16> {
    match values.get(key) {
        Some(FieldValue::Number(Some(n))) => u16::try_from(*n).ok(),
        _ => None,
    }
}

fn kind_of(values: &FieldValues) -> ForwardKind {
    match values.get("kind") {
        Some(FieldValue::Choice(Some(k))) if k == KIND_REMOTE => ForwardKind::Remote,
        Some(FieldValue::Choice(Some(k))) if k == KIND_DYNAMIC => ForwardKind::Dynamic,
        _ => ForwardKind::Local,
    }
}

/// The form's whole-rule check (§4.8 validation).
fn check_rule(values: &FieldValues) -> Vec<ValidationError> {
    let kind = kind_of(values);
    let bind = text(values, "bind_addr");
    let bind = if bind.is_empty() {
        DEFAULT_BIND_ADDR.to_owned()
    } else {
        bind
    };
    let dest = text(values, "dest_host");
    let dest = (!dest.is_empty()).then_some(dest);
    let err = |field: &str, e: fwd::RuleError| ValidationError {
        field: field.to_owned(),
        message: e.to_string(),
    };
    let mut errors = Vec::new();
    if text(values, "label").is_empty() {
        errors.push(ValidationError {
            field: "label".to_owned(),
            message: "A label is required".to_owned(),
        });
    }
    if !matches!(values.get("host_id"), Some(FieldValue::Choice(Some(_)))) {
        errors.push(ValidationError {
            field: "host_id".to_owned(),
            message: "Pick the host that carries the tunnel".to_owned(),
        });
    }
    let bind_port = number(values, "bind_port").unwrap_or(0);
    if let Err(e) = fwd::validate_fields(
        kind,
        &bind,
        bind_port,
        dest.as_deref(),
        number(values, "dest_port"),
    ) {
        let field = match e {
            fwd::RuleError::BindAddr => "bind_addr",
            fwd::RuleError::Port("bind port") => "bind_port",
            fwd::RuleError::Port(_) => "dest_port",
            fwd::RuleError::MissingDest | fwd::RuleError::DestHost => "dest_host",
        };
        errors.push(err(field, e));
    }
    errors
}

/// The add / edit form for a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardDialog {
    /// The item (`None`: a new rule).
    pub id: Option<ItemId>,
    /// The form.
    pub form: Box<Form>,
    result: Option<(Option<ItemId>, PortForward)>,
}

impl ForwardDialog {
    /// The form for `rule` (`None`: a new Local rule), with `hosts` to pick from.
    pub fn new(
        id: Option<ItemId>,
        rule: Option<&PortForward>,
        hosts: &BTreeMap<ItemId, String>,
    ) -> Self {
        let kind = match rule.map(|r| r.kind) {
            Some(ForwardKind::Remote) => KIND_REMOTE,
            Some(ForwardKind::Dynamic) => KIND_DYNAMIC,
            _ => KIND_LOCAL,
        };
        let kinds = vec![
            SelectOption::new(
                KIND_LOCAL,
                "Local (-L): a local port to a remote destination",
            ),
            SelectOption::new(
                KIND_REMOTE,
                "Remote (-R): a server port to a local destination",
            ),
            SelectOption::new(KIND_DYNAMIC, "Dynamic (-D): a local SOCKS proxy"),
        ];
        let mut host_options: Vec<SelectOption> = hosts
            .iter()
            .map(|(id, label)| SelectOption::new(id.to_string(), label.clone()))
            .collect();
        host_options.sort_by_key(|o| o.label.to_lowercase());
        let host = rule.map(|r| r.host_id.to_string());
        let title = if id.is_some() {
            "Edit forward"
        } else {
            "New forward"
        };
        let form = Form::new(title)
            .section(
                "Rule",
                vec![
                    Field::text("label", "Label", rule.map_or("", |r| r.label.as_str())).required(),
                    Field::select("kind", "Kind", kinds, Some(kind)),
                    Field::select("host_id", "Host", host_options, host.as_deref()).required(),
                    Field::toggle(
                        "auto_start",
                        "Start when the host connects",
                        rule.is_some_and(|r| r.auto_start),
                    ),
                ],
            )
            .section(
                "Listen",
                vec![
                    Field::text(
                        "bind_addr",
                        "Bind address",
                        rule.map_or(DEFAULT_BIND_ADDR, |r| r.bind_addr.as_str()),
                    )
                    .help("127.0.0.1 (default), localhost, an IP, or * for all interfaces"),
                    Field::number(
                        "bind_port",
                        "Bind port",
                        rule.map(|r| u64::from(r.bind_port)),
                        0,
                        65535,
                    )
                    .help("Remote forwards may use 0: the server picks the port"),
                ],
            )
            .section(
                "Destination",
                vec![
                    Field::text(
                        "dest_host",
                        "Destination host",
                        rule.and_then(|r| r.dest_host.as_deref())
                            .unwrap_or_default(),
                    )
                    .help("Not used by Dynamic (SOCKS) forwards"),
                    Field::number(
                        "dest_port",
                        "Destination port",
                        rule.and_then(|r| r.dest_port).map(u64::from),
                        1,
                        65535,
                    ),
                ],
            )
            .validator(FormValidator::new("forward_rule", check_rule));
        Self {
            id,
            form: Box::new(form),
            result: None,
        }
    }

    /// The rule the form describes.
    fn rule(values: &FieldValues) -> Option<PortForward> {
        let host_id = match values.get("host_id") {
            Some(FieldValue::Choice(Some(id))) => id.parse().ok()?,
            _ => return None,
        };
        let kind = kind_of(values);
        let bind = text(values, "bind_addr");
        let dest = text(values, "dest_host");
        let dynamic = kind == ForwardKind::Dynamic;
        Some(PortForward {
            label: text(values, "label"),
            kind,
            host_id,
            bind_addr: if bind.is_empty() {
                DEFAULT_BIND_ADDR.to_owned()
            } else {
                bind
            },
            bind_port: number(values, "bind_port").unwrap_or(0),
            dest_host: (!dynamic && !dest.is_empty()).then_some(dest),
            dest_port: if dynamic {
                None
            } else {
                number(values, "dest_port")
            },
            auto_start: matches!(values.get("auto_start"), Some(FieldValue::Bool(true))),
            read_only: false,
        })
    }

    /// The saved rule, once (`(item, rule)`), for the reducer.
    pub fn take_result(&mut self) -> Option<(Option<ItemId>, PortForward)> {
        self.result.take()
    }

    /// The dialog edits text.
    pub fn wants_text(&self) -> bool {
        self.form.insert_mode()
    }

    /// Handle input. A save leaves the rule in [`ForwardDialog::take_result`] and
    /// closes; a cancel closes.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        self.form.handle(ev, cx);
        match self.form.take_request() {
            Some(FormRequest::Save(_)) => match Self::rule(&self.form.values()) {
                Some(rule) => {
                    self.result = Some((self.id, rule));
                    cx.close();
                }
                None => self
                    .form
                    .save_failed("Pick the host that carries the tunnel"),
            },
            Some(FormRequest::Cancel) => cx.close(),
            None => {}
        }
    }

    /// Draw.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        frame.render_widget(Clear, area);
        self.form.render(frame, area, cx);
    }
}

/// The confirmation body for values that act locally (§9.6, §17.1).
pub fn approval_body(values: &[fwd::RiskyValue]) -> String {
    let mut lines: Vec<String> = values.iter().map(fwd::RiskyValue::question).collect();
    if values.iter().any(|v| v.synced) {
        lines.push("This rule came from another device (sync).".to_owned());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn status(kind: ForwardKind, state: ForwardState, bind_port: u16) -> ForwardStatus {
        ForwardStatus {
            rule: fwd::ForwardRule {
                id: ItemId::new(),
                label: "db".into(),
                kind,
                host_id: ItemId::new(),
                bind_addr: "127.0.0.1".into(),
                bind_port,
                dest_host: (kind != ForwardKind::Dynamic).then(|| "db".to_owned()),
                dest_port: (kind != ForwardKind::Dynamic).then_some(5432),
                auto_start: false,
                typed_here: true,
            },
            state,
            port: (bind_port != 0).then_some(bind_port),
            active: 0,
            bytes_in: 0,
            bytes_out: 0,
            refused: 0,
            total: 0,
            standalone: false,
        }
    }

    #[test]
    fn status_bar_segment() {
        assert_eq!(status_segment(&[]), None);
        let stopped = status(ForwardKind::Local, ForwardState::Stopped, 5432);
        assert_eq!(status_segment(std::slice::from_ref(&stopped)), None);
        let one = status(ForwardKind::Local, ForwardState::Listening, 5432);
        assert_eq!(
            status_segment(&[one.clone(), stopped]).as_deref(),
            Some("⇄ L:5432→db:5432")
        );
        // A server-allocated port shows the allocated one.
        let mut remote = status(ForwardKind::Remote, ForwardState::Listening, 0);
        remote.port = Some(40121);
        assert_eq!(
            status_segment(std::slice::from_ref(&remote)).as_deref(),
            Some("⇄ R:40121→db:5432")
        );
        let socks = status(ForwardKind::Dynamic, ForwardState::Listening, 1080);
        assert_eq!(
            status_segment(&[one, remote, socks]).as_deref(),
            Some("⇄ 3 forwards")
        );
    }

    #[test]
    fn bytes_and_saturation() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(34_000), "34.0 kB");
        assert_eq!(human_bytes(1_200_000), "1.2 MB");
        let mut s = status(ForwardKind::Local, ForwardState::Listening, 1);
        s.active = 12;
        assert_eq!(connections_text(&s), "12");
        s.active = MAX_CHANNELS;
        assert_eq!(connections_text(&s), "256/256");
    }

    #[test]
    fn keys_make_requests() {
        use crossterm::event::KeyEvent;

        let mut view = ForwardsView::default();
        let running = status(ForwardKind::Local, ForwardState::Listening, 1);
        let id = running.rule.id;
        assert!(view.set_statuses(vec![running.clone()]));
        assert!(!view.set_statuses(vec![running]), "unchanged: no redraw");
        let config = crate::app::Config::default();
        let (mut effects, mut pending, mut ids) = (Vec::new(), BTreeMap::new(), Default::default());
        let mut press = |view: &mut ForwardsView, code| {
            let mut cx = ViewCx::new(&config, &mut effects, &mut pending, &mut ids);
            view.handle(
                &ViewEvent::Key(KeyEvent::new(code, KeyModifiers::NONE)),
                &mut cx,
            );
            view.request.take()
        };
        assert_eq!(
            press(&mut view, KeyCode::Enter),
            Some(ForwardsRequest::Stop(id))
        );
        assert_eq!(
            press(&mut view, KeyCode::Char('t')),
            Some(ForwardsRequest::StartStandalone(id))
        );
        assert_eq!(
            press(&mut view, KeyCode::Char('a')),
            Some(ForwardsRequest::Add)
        );
        assert_eq!(
            press(&mut view, KeyCode::Char('e')),
            Some(ForwardsRequest::Edit(id))
        );
        assert_eq!(
            press(&mut view, KeyCode::Char('d')),
            Some(ForwardsRequest::Delete(vec![id]))
        );
        let stopped = status(ForwardKind::Local, ForwardState::Stopped, 1);
        let sid = stopped.rule.id;
        view.set_statuses(vec![stopped]);
        assert_eq!(
            press(&mut view, KeyCode::Enter),
            Some(ForwardsRequest::Start(sid))
        );
    }

    #[test]
    fn form_builds_and_validates_rules() {
        let host = ItemId::new();
        let hosts = BTreeMap::from([(host, "prod".to_owned())]);
        let rule = PortForward {
            label: "db".into(),
            kind: ForwardKind::Remote,
            host_id: host,
            bind_addr: "*".into(),
            bind_port: 0,
            dest_host: Some("localhost".into()),
            dest_port: Some(3000),
            auto_start: true,
            read_only: false,
        };
        let dialog = ForwardDialog::new(Some(ItemId::new()), Some(&rule), &hosts);
        let values = dialog.form.values();
        assert!(check_rule(&values).is_empty(), "{:?}", check_rule(&values));
        assert_eq!(ForwardDialog::rule(&values), Some(rule));

        let empty = ForwardDialog::new(None, None, &hosts);
        let errors = check_rule(&empty.form.values());
        let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
        assert!(
            fields.contains(&"label") && fields.contains(&"host_id"),
            "{fields:?}"
        );
        assert!(fields.contains(&"bind_port"), "{fields:?}");
    }

    #[test]
    fn approval_text() {
        let v = fwd::RiskyValue {
            rule: ItemId::new(),
            field: "bind_addr",
            value: "0.0.0.0:8080".into(),
            synced: false,
        };
        assert_eq!(
            approval_body(std::slice::from_ref(&v)),
            "This forward listens on 0.0.0.0:8080 (reachable from other machines). Allow?"
        );
    }
}
