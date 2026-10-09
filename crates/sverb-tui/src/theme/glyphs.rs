//! The ASCII glyph fallback (`ui.ascii`, a spec addition) and the spinner
//! (`ui.reduce_motion`, a spec addition).
//!
//! Views draw Unicode (box drawing, `✓`, `●`, `▸`, `⚠`, `🔒`, braille spinners). When
//! ASCII is wanted ([`ascii_wanted`]: `ui.ascii = "on"`, or `"auto"` with a non-UTF-8
//! locale or `TERM=linux`), [`asciify`] rewrites the finished frame cell by cell, so no
//! view needs its own fallback and none can forget one. Session content is rewritten
//! too: a terminal that can't show UTF-8 can't show the remote side's either.
//!
//! The mapping keeps meaning, not shape: borders become `+ - |`, checks `+`, crosses
//! `x`, bullets `*`, pointers `>`/`<`, warnings `!`, blocks `#`. Anything unknown
//! becomes `?`. A double-width glyph becomes one character and a space.

use ratatui::buffer::Buffer;
use sverb_core::config::AsciiMode;

/// Spinner frames (braille). [`spinner`] picks one.
pub const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Whether ASCII glyphs are drawn: `ui.ascii`, with `env_wants_ascii` deciding `auto`
/// (see `runtime::capabilities::TermEnv::wants_ascii`).
pub fn ascii_wanted(mode: AsciiMode, env_wants_ascii: bool) -> bool {
    match mode {
        AsciiMode::On => true,
        AsciiMode::Off => false,
        AsciiMode::Auto => env_wants_ascii,
    }
}

/// The spinner glyph for animation frame `frame`. With `reduce_motion` it never
/// changes (always the first frame).
pub fn spinner(frame: usize, reduce_motion: bool) -> char {
    if reduce_motion {
        SPINNER[0]
    } else {
        SPINNER[frame % SPINNER.len()]
    }
}

/// The ASCII stand-in for one non-ASCII character.
pub fn ascii_char(c: char) -> char {
    match c {
        // Box drawing: horizontal, vertical, everything else is a junction.
        '─' | '━' | '═' | '╌' | '╍' | '┄' | '┅' | '┈' | '┉' | '╴' | '╶' | '╸' | '╺' | '▔' | '▁'
        | '—' | '–' | '−' | '‐' | '‒' => '-',
        '│' | '┃' | '║' | '╎' | '╏' | '┆' | '┇' | '┊' | '┋' | '╵' | '╷' | '╹' | '╻' | '▏' | '▕'
        | '▎' | '▍' | '▌' | '▐' => '|',
        '\u{2500}'..='\u{257F}' => '+',
        // Blocks and shades.
        '█' | '▓' | '▒' | '░' | '▀' | '▄' | '■' => '#',
        // Status marks.
        '✓' | '✔' | '☑' => '+',
        '✗' | '✕' | '✖' | '×' | '☒' => 'x',
        '●' | '•' | '◆' | '◉' | '★' | '☆' | '∙' | '⏺' => '*',
        '○' | '◯' | '◇' => 'o',
        '⚠' | '❗' | '‼' | '🔔' => '!',
        '🔒' | '🔐' => 'L',
        '🔑' => 'K',
        '⟳' | '↻' | '↺' | '⇄' | '↔' | '≋' | '∿' | '≈' => '~',
        '⏸' => '=',
        '⏎' | '↵' => '<',
        // Pointers and arrows.
        '▸' | '▶' | '►' | '›' | '»' | '→' | '⇥' | '↳' | '⟩' => '>',
        '◂' | '◀' | '◄' | '‹' | '«' | '←' | '⇤' | '⟨' => '<',
        '▾' | '▼' | '↓' => 'v',
        '▴' | '▲' | '↑' => '^',
        // Punctuation.
        '…' | '·' | '⋯' => '.',
        '“' | '”' | '„' => '"',
        '‘' | '’' | '‚' => '\'',
        '≤' => '<',
        '≥' => '>',
        '≠' => '#',
        '±' => '+',
        '§' => 'S',
        // Braille (spinners).
        '\u{2800}'..='\u{28FF}' => '*',
        c if c.is_ascii() => c,
        _ => '?',
    }
}

/// Rewrite every non-ASCII cell of `buf` with [`ascii_char`]. Styles are kept.
pub fn asciify(buf: &mut Buffer) {
    let area = buf.area;
    for y in area.top()..area.bottom() {
        let mut x = area.left();
        while x < area.right() {
            let mut skip = 0;
            if let Some(cell) = buf.cell_mut((x, y)) {
                let symbol = cell.symbol();
                if !symbol.is_ascii() {
                    let first = symbol.chars().next().unwrap_or(' ');
                    let wide = ratatui::text::Span::raw(symbol).width() > 1;
                    cell.set_char(ascii_char(first));
                    if wide {
                        skip = 1;
                    }
                }
            }
            // The cell a wide glyph covered becomes a plain space.
            if skip == 1
                && let Some(next) = buf.cell_mut((x + 1, y))
            {
                next.set_char(' ');
                x += 1;
            }
            x += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ratatui::{
        layout::Rect,
        style::{Modifier, Style},
    };

    use super::*;

    #[test]
    fn modes() {
        assert!(ascii_wanted(AsciiMode::On, false));
        assert!(!ascii_wanted(AsciiMode::Off, true));
        assert!(ascii_wanted(AsciiMode::Auto, true));
        assert!(!ascii_wanted(AsciiMode::Auto, false));
    }

    #[test]
    fn spinner_is_static_with_reduced_motion() {
        assert_eq!(spinner(3, false), SPINNER[3]);
        assert_eq!(spinner(13, false), SPINNER[3]);
        for frame in 0..20 {
            assert_eq!(spinner(frame, true), SPINNER[0]);
        }
    }

    #[test]
    fn known_glyphs_keep_their_meaning() {
        for (from, to) in [
            ('┌', '+'),
            ('─', '-'),
            ('│', '|'),
            ('✓', '+'),
            ('✕', 'x'),
            ('●', '*'),
            ('▸', '>'),
            ('⚠', '!'),
            ('⠋', '*'),
            ('…', '.'),
            ('中', '?'),
            ('a', 'a'),
        ] {
            assert_eq!(ascii_char(from), to, "{from}");
        }
    }

    #[test]
    fn asciify_rewrites_every_cell_and_keeps_styles() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 12, 2));
        let bold = Style::new().add_modifier(Modifier::BOLD);
        buf.set_string(0, 0, "┌─✓ ok…🔒x", bold);
        buf.set_string(0, 1, "中文 ⠋ end", Style::new());
        asciify(&mut buf);
        let row = |y: u16| {
            (0..12)
                .map(|x| buf.cell((x, y)).unwrap().symbol().to_owned())
                .collect::<String>()
        };
        assert_eq!(row(0), "+-+ ok.L x  ");
        assert_eq!(row(1), "? ?  * end  ");
        assert!(buf.content.iter().all(|c| c.symbol().is_ascii()));
        assert_eq!(
            buf.cell((0, 0)).unwrap().style().add_modifier,
            Modifier::BOLD
        );
    }
}
