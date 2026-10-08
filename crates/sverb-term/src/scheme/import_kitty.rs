//! Kitty theme import (M1-10, SPEC §7.4): `.conf` files with `color0` … `color255`,
//! `foreground`, `background`, `cursor` and `selection_background`. Other keys are ignored.

use super::{ColorScheme, Draft, Rgb, SchemeError};

/// Import a Kitty theme (`key value` lines, `#` comments).
pub fn import_kitty(src: &str, name: &str) -> Result<ColorScheme, SchemeError> {
    let mut draft = Draft::new();
    for line in src.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim();
        let color = || Rgb::parse(value).ok_or_else(|| SchemeError::InvalidField(key.to_owned()));
        match key {
            "foreground" => draft.foreground = Some(color()?),
            "background" => draft.background = Some(color()?),
            // `cursor none` (reverse video) keeps the default.
            "cursor" => draft.cursor = Rgb::parse(value),
            "selection_background" => draft.selection_bg = Rgb::parse(value),
            k => {
                if let Some(i) = k.strip_prefix("color").and_then(|n| n.parse::<u8>().ok()) {
                    let c = color()?;
                    if i < 16 {
                        draft.ansi[usize::from(i)] = Some(c);
                    } else {
                        draft.extended.insert(i, c);
                    }
                }
            }
        }
    }
    draft.finish(name, |i| format!("color{i}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_color_is_named() {
        let src = "foreground #ffffff\nbackground #000000\ncolor0 #000000\n";
        assert_eq!(
            import_kitty(src, "k"),
            Err(SchemeError::MissingField("color1".to_owned()))
        );
    }

    #[test]
    fn invalid_color_is_named() {
        assert_eq!(
            import_kitty("foreground nope", "k"),
            Err(SchemeError::InvalidField("foreground".to_owned()))
        );
    }
}
