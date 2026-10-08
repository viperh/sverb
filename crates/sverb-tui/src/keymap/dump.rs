//! `sverb keys --dump` and `docs/keybindings.md`, both generated from the registry
//! and [`Keymap::effective`] so they never drift from the code.

use std::fmt::Write as _;

use strum::IntoEnumIterator;
use sverb_core::config::Config;

use super::{
    action::Group,
    keymap::{BindingRow, Keymap, Table},
};

/// The static part of `docs/keybindings.md` (rules from `tasks/03-KEYBINDINGS.md` §1,
/// the leader rationale from §3.2 and nesting from §5.4).
const DOCS_INTRO: &str = include_str!("docs_intro.md");

/// The effective keymap as an aligned table:
/// `MODE  KEYS  ACTION  DESCRIPTION  SOURCE`.
pub fn render_text(rows: &[BindingRow]) -> String {
    let header = ["MODE", "KEYS", "ACTION", "DESCRIPTION", "SOURCE"];
    let cells: Vec<[String; 5]> = rows
        .iter()
        .map(|r| {
            [
                r.table.label().to_owned(),
                r.keys.clone(),
                r.action.to_string(),
                r.description.to_owned(),
                r.source.label().to_owned(),
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for row in &cells {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cols: [&str; 5]| {
        let mut s = String::new();
        for (i, (cell, w)) in cols.iter().zip(widths).enumerate() {
            if i == 4 {
                s.push_str(cell);
            } else {
                let pad = w.saturating_sub(cell.chars().count());
                s.push_str(cell);
                s.push_str(&" ".repeat(pad + 2));
            }
        }
        out.push_str(s.trim_end());
        out.push('\n');
    };
    line(header);
    for row in &cells {
        line([&row[0], &row[1], &row[2], &row[3], &row[4]]);
    }
    out
}

/// The effective keymap as a JSON array of
/// `{mode, keys, action, description, group, source}` objects.
pub fn render_json(rows: &[BindingRow]) -> String {
    match serde_json::to_string_pretty(rows) {
        Ok(mut s) => {
            s.push('\n');
            s
        }
        // Serializing plain strings and enums can't fail.
        Err(e) => format!("{{\"error\": \"{e}\"}}\n"),
    }
}

/// `sverb keys --dump [--json]` output for `config`.
pub fn dump(config: &Config, json: bool) -> String {
    let rows = Keymap::effective(config);
    if json {
        render_json(&rows)
    } else {
        render_text(&rows)
    }
}

fn md_key(keys: &str) -> String {
    // `|` would end the table cell.
    format!("`{}`", keys.replace('|', "\\|"))
}

/// `docs/keybindings.md`, generated from the built-in keymap (`Config::default()`).
pub fn markdown() -> String {
    let config = Config::default();
    let rows = Keymap::effective(&config);
    let leader = Keymap::from_config(&config).leader().to_string();
    let mut out = String::new();
    out.push_str(
        "<!-- Generated from crates/sverb-tui/src/keymap (registry + built-in tables). Do not edit:\n     \
         run `SVERB_BLESS=1 cargo test -p sverb-tui --test keybindings_doc` to regenerate. -->\n\n",
    );
    out.push_str(DOCS_INTRO);
    let _ = writeln!(out, "\n## After the leader (`{leader}`), in every mode\n");
    out.push_str(
        "Press the leader, then one of these keys. The table is `[keys.terminal]` in \
         `config.toml` (the name is historical: it applies in every mode). After the leader, \
         an unbound key shows a toast and is discarded; `esc` cancels; the leader times out \
         after 1.5 s; the which-key popup appears after `ui.which_key_delay_ms` (400 ms).\n",
    );
    for group in Group::iter() {
        let in_group: Vec<&BindingRow> = rows
            .iter()
            .filter(|r| r.table == Table::Leader && r.group == group)
            .collect();
        if in_group.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n### {}\n", group.title());
        out.push_str("| Keys | Action | Description |\n|---|---|---|\n");
        for r in in_group {
            let _ = writeln!(
                out,
                "| {} | `{}` | {} |",
                md_key(&r.keys),
                r.action,
                r.description
            );
        }
    }
    out.push_str("\n## Normal mode (sverb views have focus)\n\n");
    out.push_str(
        "No session receives keys in Normal mode. These are the global bindings \
         (`[keys.normal]`); list and view keys (`/` filter, `j k`/arrows, `g`/`G`, \
         `ctrl-d`/`ctrl-u`, `space` mark, `s`/`S` sort, `h`/`l` collapse/expand, `enter` \
         open, `ctrl-enter`/`v` connect in split, `a e d y` add/edit/delete/duplicate, `p` \
         pin, `m` move, `t` tag, `c` copy `ssh` command, `i` detail, `tab` cycle focus) are \
         handled by the focused view after this table.\n\n",
    );
    out.push_str("| Keys | Action | Description |\n|---|---|---|\n");
    for r in rows.iter().filter(|r| r.table == Table::Normal) {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} |",
            md_key(&r.keys),
            r.action,
            r.description
        );
    }
    // M3-04
    copy_mode_markdown(&mut out);
    out.push_str(
        "\n## Configuration\n\n\
         ```toml\n\
         [general]\n\
         leader = \"ctrl-\\\\\"      # TOML needs the backslash escaped; \"ctrl-g\" for non-US layouts\n\n\
         [keys.terminal]          # after-leader table (applies in every mode, despite the name)\n\
         \"v\" = \"split_vertical\"   # override: merged over the built-ins\n\
         \"-\" = \"none\"             # unbind\n\n\
         [keys.normal]\n\
         \"ctrl-k\" = \"palette\"\n\
         ```\n\n\
         - Overrides merge key by key over the built-ins; `\"none\"` unbinds a key.\n\
         - Binding the leader itself in `[keys.terminal]` is an error (press it twice to send it).\n\
         - Two spellings of one key in a table (`\"L\"` and `\"shift-l\"`) are an error.\n\
         - The leader must include `ctrl` or `alt`. `ctrl-c`, `ctrl-d`, `ctrl-z`, `ctrl-m`/`enter`, \
         `ctrl-i`/`tab` and `ctrl-[`/`esc` are rejected; `ctrl-a b e k r u w l` are accepted \
         with a warning.\n\
         - There is deliberately no table for Terminal-mode keys without the leader.\n\
         - `sverb keys --dump` (`--json`) prints the effective keymap including your overrides.\n\n\
         ### Chord syntax\n\n\
         `[ctrl-][alt-][shift-][super-]<key>`: modifiers are case-insensitive, `<key>` is one \
         character (`-`, `|`, `\\`, `[`, `,`, `<`, `>`, `?`, `!`, `/` included) or `space enter esc \
         tab backspace delete insert home end pageup pagedown up down left right f1…f24`. A lone \
         `-` is the minus key and `ctrl--` is ctrl + minus. An uppercase letter means shift \
         (`L`); after `ctrl-` letter case is ignored, so write `ctrl-shift-l` for the shifted \
         chord. Separate chords with spaces for a multi-key sequence (`\"g g\"`).\n",
    );
    out
}

// M3-04
/// The copy-mode table (`[keys.copy]`): one row per action, its default keys.
fn copy_mode_markdown(out: &mut String) {
    use crate::views::sessions::copy_mode::{COPY_DEFAULTS, CopyAction};
    use strum::IntoEnumIterator;
    out.push_str("\n## Copy mode (`leader [`)\n\n");
    out.push_str(
        "Vim-style motions over the screen and the scrollback; output keeps flowing but the \
         view stays frozen (the pane border counts the new lines). A count before a motion \
         repeats it (`5j`, `3w`). `/` and `?` take a Rust regex (an invalid one is searched \
         literally). `o` on a link asks before opening it. Bind keys with `[keys.copy]`.\n\n",
    );
    out.push_str("| Keys | Action |\n|---|---|\n");
    for action in CopyAction::iter() {
        let keys: Vec<String> = COPY_DEFAULTS
            .iter()
            .filter(|(_, a)| *a == action)
            .map(|(k, _)| md_key(k))
            .collect();
        let name: &str = action.into();
        let _ = writeln!(out, "| {} | `{name}` |", keys.join(" "));
    }
}
