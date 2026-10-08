//! M2-01: tag palette and rules (SPEC §4.11).
//!
//! - Names are unique per vault, compared case-insensitively, and contain no
//!   whitespace (they are typed as `#name` in the search filter, §8.5).
//! - Colors come from a fixed palette of 12 named colors ([`TAG_COLORS`]). The UI
//!   renders them through its theme, so monochrome terminals show only `[name]`.
//!   Older items may hold a `#rrggbb` color; it stays valid.

use super::ids::ItemId;
use super::validate::ValidationError;

/// The tag color palette (names `ratatui::style::Color` parses).
pub const TAG_COLORS: [&str; 12] = [
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "lightred",
    "lightgreen",
    "lightyellow",
    "lightblue",
    "lightmagenta",
    "gray",
];

/// Whether `color` is a palette name or `#rrggbb`.
pub fn is_valid_color(color: &str) -> bool {
    TAG_COLORS.contains(&color)
        || (color.len() == 7
            && color.starts_with('#')
            && color[1..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Normalized name for uniqueness checks (trimmed, lowercase).
pub fn tag_key(name: &str) -> String {
    name.trim().to_lowercase()
}

/// Validate a tag about to be saved as `id` (`None`: new) named `name`, against the
/// other tags of the same vault (`(id, name)`).
///
/// # Errors
/// An empty name, whitespace in the name, a name another tag of the vault already
/// has (case-insensitive), or a color outside the palette.
pub fn validate_tag<'a>(
    id: Option<ItemId>,
    name: &str,
    color: Option<&str>,
    others: impl IntoIterator<Item = (ItemId, &'a str)>,
) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    let key = tag_key(name);
    if key.is_empty() {
        errors.push(ValidationError::new("name", "a tag needs a name"));
    } else if key.chars().any(char::is_whitespace) || key.starts_with('#') {
        errors.push(ValidationError::new(
            "name",
            "tag names can't contain spaces or start with #",
        ));
    } else if others
        .into_iter()
        .any(|(other, n)| Some(other) != id && tag_key(n) == key)
    {
        errors.push(ValidationError::new(
            "name",
            format!("a tag named {:?} already exists", name.trim()),
        ));
    }
    if let Some(c) = color
        && !is_valid_color(c)
    {
        errors.push(ValidationError::new(
            "color",
            "pick a color from the palette",
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> ItemId {
        ItemId::from_bytes([b; 16])
    }

    // M2-01 T-09
    #[test]
    fn tag_names_are_unique_case_insensitively() {
        let others = [(id(1), "prod"), (id(2), "Web")];
        assert!(validate_tag(None, "PROD", None, others).is_err());
        assert!(validate_tag(None, " web ", None, others).is_err());
        assert!(validate_tag(None, "db", Some("red"), others).is_ok());
        // Renaming a tag to its own name (other case) is fine.
        assert!(validate_tag(Some(id(1)), "Prod", None, others).is_ok());
        assert!(validate_tag(None, "", None, others).is_err());
        assert!(validate_tag(None, "two words", None, others).is_err());
        assert!(validate_tag(None, "x", Some("chartreuse"), others).is_err());
        assert!(validate_tag(None, "x", Some("#00ff00"), others).is_ok());
    }

    #[test]
    fn palette_has_twelve_parseable_names() {
        assert_eq!(TAG_COLORS.len(), 12);
        assert!(TAG_COLORS.iter().all(|c| is_valid_color(c)));
    }
}
