//! Alacritty theme import (SPEC §7.4): `.toml` (Alacritty ≥ 0.13) and the legacy
//! `.yml` `colors:` section.
//!
//! Read keys: `colors.primary.{foreground,background}`, `colors.cursor.cursor`,
//! `colors.selection.background`, `colors.normal.*`, `colors.bright.*` and
//! `colors.indexed_colors` (`[{ index, color }]`, TOML only). Cell-relative values such as
//! `CellForeground` are ignored (the cursor then defaults to the foreground).

use super::{ColorScheme, Draft, Rgb, SchemeError};

const NAMES: [&str; 8] = [
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
];

fn field(i: usize) -> String {
    let group = if i < 8 { "normal" } else { "bright" };
    format!("colors.{group}.{}", NAMES[i % 8])
}

/// Set one draft color from `(section, key, value)`; unknown keys are ignored.
fn apply(draft: &mut Draft, section: &str, key: &str, value: &str) -> Result<(), SchemeError> {
    let color = || {
        Rgb::parse(value)
            .ok_or_else(|| SchemeError::InvalidField(format!("colors.{section}.{key}")))
    };
    match (section, key) {
        ("primary", "foreground") => draft.foreground = Some(color()?),
        ("primary", "background") => draft.background = Some(color()?),
        ("cursor", "cursor") => draft.cursor = Rgb::parse(value),
        ("selection", "background") => draft.selection_bg = Rgb::parse(value),
        ("normal" | "bright", name) => {
            if let Some(i) = NAMES.iter().position(|n| *n == name) {
                let i = if section == "bright" { i + 8 } else { i };
                draft.ansi[i] = Some(color()?);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Import an Alacritty TOML theme.
pub fn import_alacritty(src: &str, name: &str) -> Result<ColorScheme, SchemeError> {
    let table: toml::Table =
        toml::from_str(src).map_err(|e| SchemeError::Syntax(e.message().to_owned()))?;
    let Some(toml::Value::Table(colors)) = table.get("colors") else {
        return Err(SchemeError::MissingField("colors".to_owned()));
    };
    let mut draft = Draft::new();
    for (section, value) in colors {
        match value {
            toml::Value::Table(t) => {
                for (key, v) in t {
                    if let toml::Value::String(s) = v {
                        apply(&mut draft, section, key, s)?;
                    }
                }
            }
            toml::Value::Array(items) if section == "indexed_colors" => {
                for item in items {
                    let index = item
                        .get("index")
                        .and_then(toml::Value::as_integer)
                        .and_then(|i| u8::try_from(i).ok());
                    let color = item
                        .get("color")
                        .and_then(toml::Value::as_str)
                        .and_then(Rgb::parse);
                    if let (Some(i @ 16..), Some(c)) = (index, color) {
                        draft.extended.insert(i, c);
                    }
                }
            }
            _ => {}
        }
    }
    draft.finish(name, field)
}

/// Import the `colors:` section of a legacy Alacritty YAML config or theme.
///
/// A small indentation-based reader for nested maps of scalars, which is all the colors
/// section uses; anything else (lists, anchors, flow maps) is skipped.
pub fn import_alacritty_yaml(src: &str, name: &str) -> Result<ColorScheme, SchemeError> {
    let mut draft = Draft::new();
    // Path of keys for the current indentation levels: (indent, key).
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut seen_colors = false;
    for raw in src.lines() {
        let line = strip_comment(raw);
        if line.trim().is_empty() || line.trim_start().starts_with('-') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let key = unquote(key.trim());
        let value = unquote(value.trim());
        while stack.last().is_some_and(|(i, _)| *i >= indent) {
            stack.pop();
        }
        if value.is_empty() {
            stack.push((indent, key.to_owned()));
            continue;
        }
        let path: Vec<&str> = stack.iter().map(|(_, k)| k.as_str()).collect();
        if let ["colors", section] = path.as_slice() {
            seen_colors = true;
            apply(&mut draft, section, key, value)?;
        }
    }
    if !seen_colors {
        return Err(SchemeError::MissingField("colors".to_owned()));
    }
    draft.finish(name, field)
}

fn strip_comment(line: &str) -> &str {
    // `#` starts a comment only at the line start or after whitespace (not inside '#rrggbb').
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match (quote, b) {
            (Some(q), _) if b == q => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(b),
            (None, b'#') if i == 0 || bytes[i - 1].is_ascii_whitespace() => {
                // A bare `#rrggbb` value right after `key: ` would be a YAML comment too, so
                // Alacritty themes always quote colors; honor YAML here.
                return &line[..i];
            }
            _ => {}
        }
    }
    line
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    for q in ['\'', '"'] {
        if let Some(inner) = s.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_with_0x_and_cell_relative_cursor() {
        let src = r##"
[colors.primary]
foreground = "0xd8dee9"
background = "#2e3440"
[colors.cursor]
text = "CellBackground"
cursor = "CellForeground"
[colors.normal]
black = "#000000"
red = "#110000"
green = "#001100"
yellow = "#111100"
blue = "#000011"
magenta = "#110011"
cyan = "#001111"
white = "#111111"
[colors.bright]
black = "#222222"
red = "#220000"
green = "#002200"
yellow = "#222200"
blue = "#000022"
magenta = "#220022"
cyan = "#002222"
white = "#ffffff"
[[colors.indexed_colors]]
index = 16
color = "#123456"
"##;
        let s = import_alacritty(src, "t").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.foreground, Rgb::new(0xd8, 0xde, 0xe9));
        assert_eq!(s.cursor, s.foreground);
        assert_eq!(s.ansi[9], Rgb::new(0x22, 0, 0));
        assert_eq!(s.indexed(16), Rgb::new(0x12, 0x34, 0x56));
    }

    #[test]
    fn missing_bright_color_is_named() {
        let src = "[colors.primary]\nforeground = \"#fff\"\nbackground = \"#000\"\n";
        assert_eq!(
            import_alacritty(src, "t"),
            Err(SchemeError::MissingField("colors.normal.black".to_owned()))
        );
    }
}
