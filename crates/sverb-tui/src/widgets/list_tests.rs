#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyModifiers, MouseEvent, MouseEventKind};
use pretty_assertions::assert_eq;
use ratatui::{style::Modifier, text::Line};
use sverb_core::{
    model::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, VaultId},
    search::{ItemIndex, Scope},
};

use super::{
    list::{DefaultRenderer, DetailRenderer, EmptyState, FilterSource, ListRow, ListView, SortKey},
    test_util::{draw, draw_with, key, keys, send, text, type_text},
};
use crate::{theme::Theme, views::ViewEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    id: u32,
    name: String,
    addr: String,
    parent: Option<u32>,
    group: bool,
    item: Option<ItemId>,
}

fn row(id: u32, name: &str, addr: &str) -> Row {
    Row {
        id,
        name: name.to_owned(),
        addr: addr.to_owned(),
        parent: None,
        group: false,
        item: None,
    }
}

impl ListRow for Row {
    type Key = u32;

    fn key(&self) -> u32 {
        self.id
    }

    fn label(&self) -> &str {
        &self.name
    }

    fn filter_text(&self) -> String {
        format!("{} {}", self.name, self.addr)
    }

    fn item_id(&self) -> Option<ItemId> {
        self.item
    }

    fn parent(&self) -> Option<u32> {
        self.parent
    }

    fn is_group(&self) -> bool {
        self.group
    }

    fn secondary(&self) -> String {
        self.addr.clone()
    }
}

struct Detail;

impl DetailRenderer<Row> for Detail {
    fn lines(&self, row: &Row, _theme: &Theme, _width: usize) -> Vec<Line<'static>> {
        vec![
            Line::raw(format!("address: {}", row.addr)),
            Line::raw(format!("id: {}", row.id)),
        ]
    }
}

fn hundred() -> ListView<Row> {
    let mut list = ListView::new("Hosts");
    list.set_rows(
        (0..100)
            .map(|i| row(i, &format!("host-{i:02}"), &format!("10.0.0.{i}")))
            .collect(),
    );
    list
}

fn names(list: &ListView<Row>) -> Vec<String> {
    list.visible_rows().map(|r| r.name.clone()).collect()
}

/// The screen row of the cursor marker `›` and the screen rows shown.
fn cursor_line(screen: &str) -> usize {
    screen
        .lines()
        .position(|l| l.contains('›'))
        .expect("cursor visible")
}

#[test]
fn t01_navigation_keeps_the_selection_in_view_with_scrolloff() {
    let mut list = hundred();
    draw(&list, 80, 24, false);
    keys(&mut list, "j j j");
    assert_eq!(list.cursor(), 3);
    keys(&mut list, "k");
    assert_eq!(list.cursor(), 2);
    keys(&mut list, "G");
    assert_eq!(list.cursor(), 99);
    keys(&mut list, "g");
    assert_eq!(list.cursor(), 0);
    keys(&mut list, "k");
    assert_eq!(list.cursor(), 0, "k at the top stays");

    // 22 rows fit (24 minus the border). Moving down 25: the cursor sits 2 rows
    // above the bottom edge.
    for _ in 0..25 {
        keys(&mut list, "j");
    }
    let screen = text(&draw(&list, 80, 24, false));
    let at = cursor_line(&screen);
    assert_eq!(at, 22 - 2, "scrolloff 2 at the bottom edge");
    assert!(screen.contains("host-25"));
    assert!(
        screen.contains("host-27"),
        "two rows below the cursor are visible"
    );
    insta::assert_snapshot!("t01_scrolled_80x24", screen);

    // Going back up: the view scrolls once the cursor is 2 rows from the top.
    for _ in 0..18 {
        keys(&mut list, "k");
    }
    let screen = text(&draw(&list, 80, 24, false));
    assert_eq!(list.cursor(), 7);
    assert_eq!(cursor_line(&screen), 1 + 2, "scrolloff 2 at the top edge");

    // Half pages and pages.
    keys(&mut list, "ctrl-d");
    assert_eq!(list.cursor(), 7 + 11);
    keys(&mut list, "ctrl-u ctrl-u");
    assert_eq!(list.cursor(), 0);
    key(&mut list, KeyCode::PageDown, KeyModifiers::NONE);
    assert_eq!(list.cursor(), 22);
    key(&mut list, KeyCode::End, KeyModifiers::NONE);
    let screen = text(&draw(&list, 80, 24, false));
    assert!(screen.contains("host-99"));

    // Mouse wheel and click.
    let mouse = |kind, column, row| {
        ViewEvent::Mouse(MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        })
    };
    send(&mut list, &mouse(MouseEventKind::ScrollUp, 5, 5));
    assert_eq!(list.cursor(), 96);
    draw(&list, 80, 24, false);
    send(
        &mut list,
        &mouse(
            MouseEventKind::Down(crossterm::event::MouseButton::Left),
            5,
            1,
        ),
    );
    assert_eq!(
        list.selected().unwrap().name,
        "host-78",
        "click on the first row"
    );
}

#[test]
fn t02_filter_highlights_and_esc_restores_the_selection() {
    let mut list = ListView::new("Hosts");
    list.set_rows(vec![
        row(1, "db-1", "10.0.0.1"),
        row(2, "web-1", "10.0.0.2"),
        row(3, "cache", "10.0.0.3"),
        row(4, "web-2", "10.0.0.4"),
        row(5, "mail", "10.0.0.5"),
    ]);
    keys(&mut list, "/");
    assert!(list.insert_mode(), "the filter line is Insert mode");
    type_text(&mut list, "web");
    assert_eq!(names(&list), ["web-1", "web-2"]);
    assert_eq!(list.highlights(0), &[0, 1, 2]);

    // Highlights render bold + underlined (visible without color).
    let buf = draw(&list, 60, 10, true);
    let screen = text(&buf);
    assert!(screen.contains("/web"), "{screen}");
    let (y, line) = screen
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("web-2"))
        .unwrap();
    let x = line.chars().position(|c| c == 'w').unwrap();
    let cell = &buf[(u16::try_from(x).unwrap(), u16::try_from(y).unwrap())];
    assert!(
        cell.modifier
            .contains(Modifier::UNDERLINED | Modifier::BOLD)
    );

    // Down while filtering, then Enter keeps the filter and returns to the list.
    key(&mut list, KeyCode::Down, KeyModifiers::NONE);
    key(&mut list, KeyCode::Enter, KeyModifiers::NONE);
    assert!(!list.insert_mode());
    assert_eq!(list.filter_text(), "web");
    assert_eq!(list.selected().unwrap().name, "web-2");

    // Esc clears it; the selection stays on web-2.
    keys(&mut list, "/");
    key(&mut list, KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(names(&list).len(), 5);
    assert_eq!(list.filter_text(), "");
    assert_eq!(list.selected().unwrap().name, "web-2");

    // No match: a message, and the address is matched too.
    keys(&mut list, "/");
    type_text(&mut list, "zzz");
    assert!(text(&draw(&list, 60, 10, false)).contains("No matches"));
    key(&mut list, KeyCode::Esc, KeyModifiers::NONE);
    keys(&mut list, "/");
    type_text(&mut list, "0.0.3");
    assert_eq!(names(&list), ["cache"]);
}

#[test]
fn t02_filter_through_the_search_index() {
    let mut clock = HlcClock::default();
    let device = DeviceId::new();
    let vault = VaultId::new();
    let mut bodies = Vec::new();
    let mut rows = Vec::new();
    for (n, label) in ["prod-web", "prod-db", "staging"].into_iter().enumerate() {
        let id = ItemId::new();
        let mut body = ItemBody::new(ItemKind::Host, 1);
        body.set("label", label, &mut clock, device);
        body.set("address", "10.0.0.1", &mut clock, device);
        bodies.push((id, vault, body));
        let mut r = row(u32::try_from(n).unwrap(), label, "10.0.0.1");
        r.item = Some(id);
        rows.push(r);
    }
    let mut index = ItemIndex::build(bodies.iter().map(|(i, v, b)| (*i, *v, b)));
    let snapshot = index.snapshot();
    let mut list = ListView::new("Hosts");
    list.set_rows(rows);
    list.set_source(FilterSource::Index {
        snapshot: Arc::clone(&snapshot),
        scope: Scope::Hosts,
    });
    keys(&mut list, "/");
    type_text(&mut list, "prod");
    assert_eq!(names(&list), ["prod-web", "prod-db"]);
    assert_eq!(list.highlights(0), &[0, 1, 2, 3]);
}

#[test]
fn t03_marks_and_bulk_targets() {
    let mut list = hundred();
    assert_eq!(list.targets(), [0], "no marks: the cursor row");
    keys(&mut list, "space j space space");
    assert_eq!(list.marks().len(), 3);
    let screen = text(&draw(&list, 80, 24, false));
    assert!(screen.contains("Hosts · 3 selected"), "{screen}");
    assert_eq!(list.targets(), [0, 2, 3]);
    // Toggling again unmarks; Esc clears all.
    keys(&mut list, "k space");
    assert_eq!(list.targets(), [0, 2]);
    key(&mut list, KeyCode::Esc, KeyModifiers::NONE);
    assert!(list.marks().is_empty());
    keys(&mut list, "V");
    assert_eq!(list.marks().len(), 100);
    key(&mut list, KeyCode::Esc, KeyModifiers::NONE);
    // ctrl-a marks only the visible (filtered) rows.
    keys(&mut list, "/");
    type_text(&mut list, "^host-1");
    key(&mut list, KeyCode::Enter, KeyModifiers::NONE);
    keys(&mut list, "ctrl-a");
    assert_eq!(list.marks().len(), 10, "host-10..19");
}

#[test]
fn t04_sort_keys_cycle_and_reverse() {
    let by_name = SortKey::new("name", |a: &Row, b: &Row| a.name.cmp(&b.name));
    let by_addr = SortKey::new("address", |a: &Row, b: &Row| a.addr.cmp(&b.addr));
    let mut list = ListView::new("Hosts").with_sort_keys(vec![by_name, by_addr]);
    list.set_rows(vec![
        row(1, "b", "10.0.0.3"),
        row(2, "c", "10.0.0.1"),
        row(3, "a", "10.0.0.2"),
    ]);
    assert_eq!(names(&list), ["a", "b", "c"]);
    assert_eq!(list.sort(), Some(("name", false)));
    keys(&mut list, "S");
    assert_eq!(names(&list), ["c", "b", "a"]);
    keys(&mut list, "s");
    assert_eq!(list.sort(), Some(("address", false)));
    assert_eq!(names(&list), ["c", "a", "b"]);
    keys(&mut list, "S");
    assert_eq!(names(&list), ["b", "a", "c"]);
    assert!(text(&draw(&list, 60, 8, false)).contains("address ↑"));
    keys(&mut list, "s");
    assert_eq!(names(&list), ["a", "b", "c"], "cycles back to name");
}

fn tree() -> ListView<Row> {
    let group = |id, name: &str| Row {
        group: true,
        ..row(id, name, "")
    };
    let child = |id, name: &str, parent| Row {
        parent: Some(parent),
        ..row(id, name, "10.0.0.1")
    };
    let mut list = ListView::new("Hosts").with_tree(true);
    list.set_rows(vec![
        group(1, "prod"),
        child(2, "prod-web", 1),
        child(3, "prod-db", 1),
        group(4, "dev"),
        child(5, "dev-box", 4),
        row(6, "lonely", "10.0.0.9"),
    ]);
    list
}

#[test]
fn t05_tree_collapse_and_expand() {
    let mut list = tree();
    assert_eq!(
        names(&list),
        ["prod", "prod-web", "prod-db", "dev", "dev-box", "lonely"]
    );
    keys(&mut list, "h");
    assert_eq!(names(&list), ["prod", "dev", "dev-box", "lonely"]);
    assert_eq!(list.collapsed(), &BTreeSet::from([1]));
    let screen = text(&draw(&list, 60, 10, false));
    assert!(
        screen.contains("▸ prod") && screen.contains("▾ dev"),
        "{screen}"
    );
    keys(&mut list, "l");
    assert_eq!(names(&list).len(), 6);
    // `h` on a child jumps to its parent; Left/Right work like h/l.
    keys(&mut list, "j j h");
    assert_eq!(list.selected().unwrap().name, "prod");
    key(&mut list, KeyCode::Left, KeyModifiers::NONE);
    assert_eq!(names(&list).len(), 4);
    key(&mut list, KeyCode::Right, KeyModifiers::NONE);
    assert_eq!(names(&list).len(), 6);
    // Groups are not markable.
    keys(&mut list, "g space");
    assert!(list.marks().is_empty());
    // The collapsed set survives a refresh of the rows.
    keys(&mut list, "g h");
    let rows = list.rows().to_vec();
    list.set_rows(rows);
    assert_eq!(names(&list).len(), 4);
}

#[test]
fn t06_detail_pane_at_wide_widths_only() {
    let mut list = hundred();
    keys(&mut list, "j");
    let wide = text(&draw_with(160, 48, false, |f, cx| {
        list.render_with(f, f.area(), cx, &DefaultRenderer, Some(&Detail));
    }));
    assert!(wide.contains("address: 10.0.0.1"), "{wide}");
    insta::assert_snapshot!("t06_detail_160x48", wide);
    let narrow = text(&draw_with(80, 24, false, |f, cx| {
        list.render_with(f, f.area(), cx, &DefaultRenderer, Some(&Detail));
    }));
    assert!(!narrow.contains("address: 10.0.0.1"));
    insta::assert_snapshot!("t06_no_detail_80x24", narrow);
    // `i` opens a full-screen detail; Esc closes it.
    keys(&mut list, "i");
    let full = text(&draw_with(80, 24, false, |f, cx| {
        list.render_with(f, f.area(), cx, &DefaultRenderer, Some(&Detail));
    }));
    assert!(full.contains("address: 10.0.0.1"));
    key(&mut list, KeyCode::Esc, KeyModifiers::NONE);
    assert!(!list.detail_full());
}

#[test]
fn t07_render_10k_rows_under_2ms() {
    let mut list = ListView::new("Hosts");
    list.set_rows(
        (0..10_000)
            .map(|i| {
                row(
                    i,
                    &format!("host-{i:05}"),
                    &format!("10.{}.{}.1", i / 256, i % 256),
                )
            })
            .collect(),
    );
    keys(&mut list, "G");
    let mut best = Duration::MAX;
    for _ in 0..20 {
        draw_with(160, 48, false, |f, cx| {
            let start = Instant::now();
            list.render_with(f, f.area(), cx, &DefaultRenderer, Some(&Detail));
            best = best.min(start.elapsed());
        });
    }
    // The 2 ms target (SPEC §19) applies to optimized builds. Debug builds under a
    // parallel test run are far noisier, so they get a 20 ms bound, which still catches a
    // non-virtualized list (rendering all 10k rows takes orders of magnitude longer).
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(20)
    } else {
        Duration::from_millis(2)
    };
    assert!(best < limit, "render took {best:?} (limit {limit:?})");
}

#[test]
fn empty_state_shows_message_and_hints() {
    let list: ListView<Row> = ListView::new("Hosts").with_empty(EmptyState::new(
        "No hosts yet",
        &[("a", "add a host"), ("^\\ o", "quick connect")],
    ));
    let screen = text(&draw(&list, 50, 8, false));
    assert!(screen.contains("No hosts yet"));
    assert!(screen.contains("a  add a host"));
}
