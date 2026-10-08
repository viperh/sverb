//! M2-12: the command palette in the reducer (SPEC §8.3, §8.2, §14.1).
//!
//! - **Opening:** the `palette` action (`leader p` everywhere, `ctrl-k` in Normal mode).
//!   The first open of a run asks the palette service for the recent picks
//!   (`PaletteEffect::LoadRecents`, device-local `meta`).
//! - **Sources:** every *available* registry action ([`App::action_enabled`]) with its
//!   key hint from the effective keymap; hosts and snippets from the search index
//!   (`Scope::Palette`); open tabs and panes; the section views and settings. A pasted
//!   share link becomes "Join shared terminal" (M6-03 stub) and a `user@host[:port]`
//!   target "Connect to …" (M1-07), both on top.
//! - **Prefixes:** `>` actions, `@` hosts, `!` snippets; `#tag` filters hosts and
//!   snippets (and hides the other sources).
//! - **Ranking:** no query → Recent, then Actions. With a query: the fuzzy score (the
//!   index's `nucleo` matcher) plus a recency boost from the last
//!   [`RECENTS_LEN`] picks; results are grouped by source, groups ordered by their best
//!   result.
//! - **Running:** an action goes through [`App::run_action`], the same path as its key
//!   binding. Hosts connect in a new tab (`ctrl-enter`: a split); `tab` opens the
//!   host's menu (edit, copy the `ssh` command, run a snippet on it). Snippets run in the
//!   current pane through the Snippets view's request (the variable form if needed).

use nucleo_matcher::{
    Config as MatchConfig, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};
use sverb_core::{
    model::{ItemId, ItemKind, RunMode},
    quick_connect::{self, QuickTarget},
    search::{Query, Scope},
    ssh_command,
    vault::LockState,
};

use super::{App, Effect, PendingKind, SessionId, ToastLevel, VaultEffect, hosts::ItemEffect};
use crate::{
    keymap::{
        Table,
        action::{ActionName, REGISTRY},
        chord::KeyChord,
    },
    views::{
        DialogKind, Section,
        palette::{
            HostAction, PaletteAnswer, PaletteEffect, PaletteEntry, PaletteEvent, PaletteGroup,
            PaletteState, PaletteTarget, RECENTS_LEN, share_link,
        },
        snippets::{RunWhere, SnippetDialog, SnippetDialogKind, SnippetsRequest, VarForm},
    },
};

/// Hosts or snippets listed at most per source.
const MAX_ITEMS: usize = 50;

/// Palette state of the reducer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaletteUi {
    /// Recent picks ([`PaletteTarget::recent_key`]), most recent first.
    pub recents: Vec<String>,
    /// The stored recents arrived (or there is no store).
    pub loaded: bool,
    /// `LoadRecents` is in flight.
    pub loading: bool,
}

/// Which sources a query looks at (its prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Only {
    All,
    Actions,
    Hosts,
    Snippets,
}

/// The recency boost of `key`: every occurrence among the recent picks counts, the
/// newer the more.
pub fn recency_boost(recents: &[String], key: &str) -> u32 {
    recents
        .iter()
        .take(RECENTS_LEN)
        .enumerate()
        .filter(|(_, k)| k.as_str() == key)
        .map(|(i, _)| 4 + u32::try_from(RECENTS_LEN - i).unwrap_or(0) / 2)
        .sum()
}

/// A typed `user@host[:port]` (or `host:port`, `ssh://…`) target.
fn quick_target(raw: &str) -> Option<QuickTarget> {
    let first = raw.chars().next()?;
    if raw.contains(char::is_whitespace)
        || matches!(first, '>' | '@' | '!' | '#')
        || !(raw.contains('@') || raw.contains(':'))
    {
        return None;
    }
    quick_connect::parse(raw).ok()
}

fn tab_number(action: ActionName) -> Option<usize> {
    use ActionName as A;
    Some(match action {
        A::GoToTab1 => 1,
        A::GoToTab2 => 2,
        A::GoToTab3 => 3,
        A::GoToTab4 => 4,
        A::GoToTab5 => 5,
        A::GoToTab6 => 6,
        A::GoToTab7 => 7,
        A::GoToTab8 => 8,
        A::GoToTab9 => 9,
        _ => return None,
    })
}

impl App {
    // ------------------------------------------------------------ availability

    /// Whether `action` makes sense now (the palette lists only these): pane actions
    /// need panes, session actions a focused session, `toggle_log_pane` `--debug`, …
    pub fn action_enabled(&self, action: ActionName) -> bool {
        use ActionName as A;
        let session = self.focused_session().is_some();
        let tabs = self.tabs.list.len();
        let panes = self.active_tab().map_or(0, |t| t.panes.len());
        if let Some(n) = tab_number(action) {
            return tabs >= n;
        }
        match action {
            // The palette is open already.
            A::Palette => false,
            A::SendLeader
            | A::CopyMode
            | A::SessionInfo
            | A::ToggleRecording
            | A::Autocomplete
            | A::AcceptGhostText
            | A::MarkBroadcastPane => session,
            A::NextTab | A::PrevTab | A::MoveTabLeft | A::MoveTabRight => tabs > 1,
            A::RenameTab
            | A::CloseTab
            | A::ClosePane
            | A::SplitHorizontal
            | A::SplitVertical
            | A::ToggleBroadcast => tabs > 0,
            A::FocusLeft
            | A::FocusDown
            | A::FocusUp
            | A::FocusRight
            | A::ResizeLeft
            | A::ResizeDown
            | A::ResizeUp
            | A::ResizeRight
            | A::ResizeMode
            | A::ZoomPane
            | A::EqualizePanes => panes > 1,
            A::ToggleLogPane => self.action_available(action),
            // M4-09: sharing and team / sync actions need a connected server (§1.1).
            A::SharePane => session && self.sync.connected(),
            A::SyncStatus | A::SyncNow | A::Devices | A::TeamKeys => self.sync.connected(),
            A::LockVault => self.vault.active,
            A::Suspend => cfg!(unix),
            _ => true,
        }
    }

    /// The key that runs `action`, from the effective keymap: `^\ -` after the leader,
    /// else the Normal-mode key.
    pub fn key_hint(&self, action: ActionName) -> Option<String> {
        let chords =
            |seq: &[KeyChord]| seq.iter().map(KeyChord::hint).collect::<Vec<_>>().join(" ");
        let leader = self.keymap.leader().hint();
        if action == ActionName::SendLeader {
            return Some(format!("{leader} {leader}"));
        }
        if let Some(seq) = self.keymap.after_leader_keys(action).first() {
            return Some(format!("{leader} {}", chords(seq)));
        }
        self.keymap
            .bindings(Table::Normal)
            .into_iter()
            .find(|(_, a)| *a == action)
            .map(|(seq, _)| chords(&seq))
    }

    // ------------------------------------------------------------ results

    fn action_entry(&self, action: ActionName, group: PaletteGroup, score: u32) -> PaletteEntry {
        PaletteEntry {
            target: PaletteTarget::Action(action),
            group,
            title: action.description().to_owned(),
            detail: action.to_string(),
            hint: self.key_hint(action),
            score,
        }
    }

    /// A recent pick as a result, if it still exists and is available.
    fn recent_entry(&self, key: &str) -> Option<PaletteEntry> {
        let target = PaletteTarget::from_recent_key(key)?;
        let mut entry = match &target {
            PaletteTarget::Action(a) if self.action_enabled(*a) => {
                self.action_entry(*a, PaletteGroup::Recent, 0)
            }
            PaletteTarget::Host(id) | PaletteTarget::Snippet(id) => {
                let e = self.index()?.get(*id)?;
                let (kind, group) = match target {
                    PaletteTarget::Host(_) => (ItemKind::Host, PaletteGroup::Hosts),
                    _ => (ItemKind::Snippet, PaletteGroup::Snippets),
                };
                if e.kind != kind {
                    return None;
                }
                self.item_entry(e, group, 0)?
            }
            PaletteTarget::Section(s) => section_entry(*s, 0),
            _ => return None,
        };
        entry.group = PaletteGroup::Recent;
        Some(entry)
    }

    fn item_entry(
        &self,
        e: &sverb_core::search::IndexEntry,
        group: PaletteGroup,
        score: u32,
    ) -> Option<PaletteEntry> {
        let (target, detail) = match e.kind {
            ItemKind::Host => {
                let address: &str = &e.address;
                let user: &str = &e.user;
                let detail = if user.is_empty() {
                    address.to_owned()
                } else {
                    format!("{user}@{address}")
                };
                (PaletteTarget::Host(e.item_id), detail)
            }
            ItemKind::Snippet => (PaletteTarget::Snippet(e.item_id), "snippet".to_owned()),
            _ => return None,
        };
        Some(PaletteEntry {
            target,
            group,
            title: e.display_label().to_owned(),
            detail,
            hint: None,
            score,
        })
    }

    /// The results for `input` (`on_host`: only snippets, to run on a host).
    pub fn palette_entries(&self, input: &str, on_host: bool) -> Vec<PaletteEntry> {
        let raw = input.trim();
        let mut out = Vec::new();
        if !on_host {
            if let Some(link) = share_link(raw) {
                out.push(PaletteEntry {
                    target: PaletteTarget::Join(link.to_owned()),
                    group: PaletteGroup::Special,
                    title: "Join shared terminal".to_owned(),
                    detail: link.to_owned(),
                    hint: None,
                    score: u32::MAX,
                });
            } else if let Some(t) = quick_target(raw) {
                out.push(PaletteEntry {
                    target: PaletteTarget::QuickConnect(raw.to_owned()),
                    group: PaletteGroup::Special,
                    title: format!("Connect to {}", t.display()),
                    detail: "quick connect".to_owned(),
                    hint: self.key_hint(ActionName::QuickConnect),
                    score: u32::MAX,
                });
            }
        }
        let (only, text) = if on_host {
            (Only::Snippets, raw)
        } else {
            match raw.chars().next() {
                Some('>') => (Only::Actions, raw[1..].trim_start()),
                Some('@') => (Only::Hosts, raw[1..].trim_start()),
                Some('!') => (Only::Snippets, raw[1..].trim_start()),
                _ => (Only::All, raw),
            }
        };
        if only == Only::All && text.is_empty() {
            // No query: Recent, then Actions.
            let mut seen = Vec::new();
            for key in &self.palette.recents {
                if seen.contains(key) {
                    continue;
                }
                seen.push(key.clone());
                if let Some(e) = self.recent_entry(key) {
                    out.push(e);
                }
            }
            for info in REGISTRY {
                let a = info.name;
                let recent = PaletteTarget::Action(a)
                    .recent_key()
                    .is_some_and(|k| seen.contains(&k));
                if self.action_enabled(a) && !recent {
                    out.push(self.action_entry(a, PaletteGroup::Actions, 0));
                }
            }
            return out;
        }
        let query = Query::parse(text);
        let tagged = !query.tags.is_empty();
        let wants = |o: Only| only == Only::All || only == o;
        let pattern = Pattern::parse(text, CaseMatching::Smart, Normalization::Smart);
        let mut matcher = Matcher::new(MatchConfig::DEFAULT);
        let mut buf = Vec::new();
        let mut score = |hay: &str| -> Option<u32> {
            if text.is_empty() {
                Some(0)
            } else {
                pattern.score(Utf32Str::new(hay, &mut buf), &mut matcher)
            }
        };
        let boost = |t: &PaletteTarget| {
            t.recent_key()
                .map_or(0, |k| recency_boost(&self.palette.recents, &k))
        };
        let mut groups: Vec<Vec<PaletteEntry>> = Vec::new();
        if wants(Only::Actions) && !tagged {
            let mut g = Vec::new();
            for info in REGISTRY {
                let a = info.name;
                if !self.action_enabled(a) {
                    continue;
                }
                let hay = format!("{} {a}", info.description);
                if let Some(s) = score(&hay) {
                    let s = s.saturating_add(boost(&PaletteTarget::Action(a)));
                    g.push(self.action_entry(a, PaletteGroup::Actions, s));
                }
            }
            groups.push(g);
        }
        if (wants(Only::Hosts) || wants(Only::Snippets))
            && let Some(index) = self.index()
        {
            let (mut hosts, mut snippets) = (Vec::new(), Vec::new());
            for hit in index.query(&query, Scope::Palette) {
                let Some(e) = index.get(hit.item_id) else {
                    continue;
                };
                let (list, group) = match e.kind {
                    ItemKind::Host if wants(Only::Hosts) => (&mut hosts, PaletteGroup::Hosts),
                    ItemKind::Snippet if wants(Only::Snippets) => {
                        (&mut snippets, PaletteGroup::Snippets)
                    }
                    _ => continue,
                };
                if list.len() >= MAX_ITEMS {
                    continue;
                }
                if let Some(mut entry) = self.item_entry(e, group, hit.score) {
                    entry.score = entry.score.saturating_add(boost(&entry.target));
                    list.push(entry);
                }
            }
            groups.push(hosts);
            groups.push(snippets);
        }
        if only == Only::All && !tagged {
            let items = self.tab_items();
            let mut g = Vec::new();
            for (i, tab) in self.tabs.list.iter().enumerate() {
                let single = tab.panes.len() == 1;
                for pane in tab.panes.values() {
                    let title = if single {
                        let label = items
                            .get(i)
                            .map_or_else(|| self.pane(pane.session).label, |t| t.label.clone());
                        format!("Tab {}: {label}", i + 1)
                    } else {
                        format!("Tab {} · {}", i + 1, self.pane(pane.session).label)
                    };
                    if let Some(s) = score(&title) {
                        let current = i == self.tabs.active && tab.focused == pane.id;
                        g.push(PaletteEntry {
                            target: PaletteTarget::Pane(pane.session),
                            group: PaletteGroup::Tabs,
                            title,
                            detail: if current {
                                "current".to_owned()
                            } else {
                                String::new()
                            },
                            hint: None,
                            score: s,
                        });
                    }
                }
            }
            groups.push(g);
            let mut g = Vec::new();
            for section in Section::ALL {
                let entry = section_entry(section, 0);
                if let Some(s) = score(&entry.title) {
                    let s = s.saturating_add(boost(&entry.target));
                    g.push(PaletteEntry { score: s, ..entry });
                }
            }
            groups.push(g);
        }
        for g in &mut groups {
            // Stable: equal scores keep registry / index / tab order.
            g.sort_by_key(|e| std::cmp::Reverse(e.score));
        }
        groups.retain(|g| !g.is_empty());
        groups.sort_by(|a, b| {
            b[0].score
                .cmp(&a[0].score)
                .then_with(|| a[0].group.cmp(&b[0].group))
        });
        out.extend(groups.into_iter().flatten());
        out
    }

    // ------------------------------------------------------------ opening

    /// The `palette` action.
    pub(crate) fn open_palette(&mut self, effects: &mut Vec<Effect>) {
        if matches!(
            self.dialogs.last().map(|d| &d.kind),
            Some(DialogKind::Palette(_))
        ) {
            return;
        }
        if !self.palette.loaded && !self.palette.loading {
            self.palette.loading = true;
            effects.push(Effect::Palette(PaletteEffect::LoadRecents));
        }
        // Snippets run from the view's list: load it if nothing did yet.
        if !self.views.snippets.loaded && self.index().is_some() {
            self.snippets_on_index(effects);
        }
        self.push_palette(None);
    }

    fn push_palette(&mut self, on_host: Option<(ItemId, String)>) {
        let mut state = PaletteState::new();
        let entries = self.palette_entries("", on_host.is_some());
        state.on_host = on_host;
        state.set_entries(entries);
        self.push_dialog(DialogKind::Palette(Box::new(state)));
    }

    /// Recompute the open palette's results (after its input or the recents changed).
    fn refresh_palette(&mut self, force: bool) {
        let (input, on_host) = match self.dialogs.last().map(|d| &d.kind) {
            Some(DialogKind::Palette(p)) if p.stale || force => {
                (p.input.clone(), p.on_host.is_some())
            }
            _ => return,
        };
        let entries = self.palette_entries(&input, on_host);
        if let Some(DialogKind::Palette(p)) = self.dialogs.last_mut().map(|d| &mut d.kind) {
            p.set_entries(entries);
        }
        self.needs_redraw = true;
    }

    // ------------------------------------------------------------ events

    /// From the palette service: the stored recent picks.
    pub(crate) fn on_palette(&mut self, ev: PaletteEvent, effects: &mut Vec<Effect>) {
        match ev {
            PaletteEvent::Recents(stored) => {
                let picked_before = !self.palette.recents.is_empty();
                let mut merged = std::mem::take(&mut self.palette.recents);
                merged.extend(stored);
                merged.truncate(RECENTS_LEN);
                self.palette.recents = merged;
                self.palette.loaded = true;
                self.palette.loading = false;
                if picked_before {
                    effects.push(Effect::Palette(PaletteEffect::SaveRecents(
                        self.palette.recents.clone(),
                    )));
                }
                self.refresh_palette(true);
            }
        }
    }

    /// Locking closes the palette (its results show host and snippet names).
    pub(crate) fn palette_lock_transition(&mut self, was: LockState) {
        let now = self.lock_state();
        if now != was && now != LockState::Unlocked {
            let before = self.dialogs.len();
            self.dialogs
                .retain(|d| !matches!(d.kind, DialogKind::Palette(_)));
            self.needs_redraw |= before != self.dialogs.len();
        }
    }

    /// After a key: re-rank on input changes, carry out an answer.
    pub(crate) fn take_palette_answer(&mut self, effects: &mut Vec<Effect>) {
        self.refresh_palette(false);
        let (answer, on_host) = match self.dialogs.last_mut().map(|d| &mut d.kind) {
            Some(DialogKind::Palette(p)) => match p.take_answer() {
                Some(a) => (a, p.on_host.clone()),
                None => return,
            },
            _ => return,
        };
        self.dialogs.pop();
        self.needs_redraw = true;
        match answer {
            PaletteAnswer::Run { target, split } => {
                self.palette_remember(&target, effects);
                self.palette_run(target, split, on_host, effects);
            }
            PaletteAnswer::Host {
                host,
                label,
                action,
            } => {
                self.palette_remember(&PaletteTarget::Host(host), effects);
                match action {
                    HostAction::Connect => self.connect_host(host, effects),
                    HostAction::ConnectSplit => self.connect_split(vec![host], effects),
                    HostAction::Edit => {
                        let id = self.ids.effect();
                        self.pending.insert(id, PendingKind::EditHost);
                        effects.push(Effect::Vault(VaultEffect::Items(ItemEffect::LoadHost {
                            id,
                            item: host,
                        })));
                    }
                    HostAction::CopyCommand => self.palette_copy_command(host, effects),
                    HostAction::RunSnippet => self.push_palette(Some((host, label))),
                }
            }
        }
    }

    /// Remember a pick (device-local `meta`, never an item).
    fn palette_remember(&mut self, target: &PaletteTarget, effects: &mut Vec<Effect>) {
        let Some(key) = target.recent_key() else {
            return;
        };
        self.palette.recents.insert(0, key);
        self.palette.recents.truncate(RECENTS_LEN);
        effects.push(Effect::Palette(PaletteEffect::SaveRecents(
            self.palette.recents.clone(),
        )));
    }

    fn palette_run(
        &mut self,
        target: PaletteTarget,
        split: bool,
        on_host: Option<(ItemId, String)>,
        effects: &mut Vec<Effect>,
    ) {
        match target {
            // Exactly the key binding's path.
            PaletteTarget::Action(action) => self.run_action(action, effects),
            PaletteTarget::Host(id) if split => self.connect_split(vec![id], effects),
            PaletteTarget::Host(id) => self.connect_host(id, effects),
            PaletteTarget::Snippet(id) => {
                let Some(snippet) = self.views.snippets.get(id).cloned() else {
                    self.push_toast(
                        ToastLevel::Info,
                        "Snippets are still loading; try again".to_owned(),
                        effects,
                    );
                    self.snippets_on_index(effects);
                    return;
                };
                match on_host {
                    Some((host, label)) => {
                        let target = RunWhere::Hosts(vec![(host, label)]);
                        match VarForm::new(id, &snippet, RunMode::Exec, target) {
                            Ok(form) => {
                                self.push_dialog(DialogKind::Snippet(Box::new(
                                    SnippetDialog::new(SnippetDialogKind::Vars(Box::new(form))),
                                )));
                            }
                            Err(e) => {
                                self.push_toast(
                                    ToastLevel::Error,
                                    format!("\"{}\" cannot run: {e}", snippet.name),
                                    effects,
                                );
                            }
                        }
                    }
                    // The Snippets view's `Enter`: the current pane, the variable form.
                    None => {
                        self.views.snippets.request = Some(SnippetsRequest::RunHere(id));
                        self.take_snippets_request(effects);
                    }
                }
            }
            PaletteTarget::Pane(session) => self.palette_focus_pane(session),
            PaletteTarget::Section(section) => self.open_section(section),
            PaletteTarget::QuickConnect(text) => self.connect_target(&text, effects),
            PaletteTarget::Join(_) => {
                self.push_toast(
                    ToastLevel::Info,
                    "Joining shared terminals is not available yet (M6-03)".to_owned(),
                    effects,
                );
            }
        }
    }

    fn palette_focus_pane(&mut self, session: SessionId) {
        let Some(i) = self.tabs.list.iter().position(|t| t.has_session(session)) else {
            return;
        };
        let tab = &mut self.tabs.list[i];
        if let Some(pane) = tab
            .panes
            .values()
            .find(|p| p.session == session)
            .map(|p| p.id)
        {
            tab.focus(pane);
        }
        self.activate_tab(i);
    }

    fn palette_copy_command(&mut self, id: ItemId, effects: &mut Vec<Effect>) {
        let line = self.views.hosts.catalog().and_then(|c| {
            c.hosts
                .get(&id)
                .map(|h| ssh_command::render(&c.ssh_target(h)))
        });
        match line {
            Some(line) => {
                effects.push(Effect::CopyToClipboard(line.clone()));
                self.push_toast(ToastLevel::Success, format!("Copied: {line}"), effects);
            }
            None => {
                self.push_toast(
                    ToastLevel::Info,
                    "The host is still loading; try again".to_owned(),
                    effects,
                );
            }
        }
    }
}

fn section_entry(section: Section, score: u32) -> PaletteEntry {
    let title = match section {
        Section::Settings => "Settings".to_owned(),
        s => format!("Go to {}", s.title()),
    };
    PaletteEntry {
        target: PaletteTarget::Section(section),
        group: PaletteGroup::Settings,
        title,
        detail: String::new(),
        hint: None,
        score,
    }
}
