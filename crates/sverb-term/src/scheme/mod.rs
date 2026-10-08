//! Terminal color schemes (M1-10, SPEC §7.4).
//!
//! A [`ColorScheme`] colors **pane content** only: the 16 ANSI colors, the default
//! foreground/background, the cursor, an optional selection background and optionally the
//! 240 extended palette entries (16–255; computed per xterm when absent). The sverb chrome
//! uses the separate UI theme (`sverb-tui::theme`, M0-11).
//!
//! - **Built-ins** are TOML files under `scheme/builtin/`, embedded with `include_str!`
//!   ([`BUILTIN_NAMES`], [`builtin`]).
//! - **`terminal`** (the default, [`TERMINAL`]) is a marker without a palette: named and
//!   indexed colors are passed through to the outer terminal unchanged. It is represented
//!   as "no scheme" (`ViewState::scheme == None`).
//! - **User schemes** are `config_dir/themes/*.toml` in the same format
//!   ([`load_dir`], documented in `docs/themes.md`).
//! - **Imports**: Alacritty (`.toml`, legacy `.yml`) and Kitty (`.conf`) theme files
//!   ([`import_file`], [`import_alacritty`], [`import_kitty`]).
//!
//! # File format
//! ```toml
//! name = "my-scheme"          # optional; defaults to the file stem
//! [colors]
//! foreground = "#c0caf5"
//! background = "#1a1b26"
//! cursor = "#c0caf5"          # optional, defaults to the foreground
//! selection_bg = "#283457"    # optional
//! color0 = "#15161e"          # color0 … color15 are required
//! # color16 … color255 are optional; missing ones use the xterm defaults
//! ```

pub mod import_alacritty;
pub mod import_kitty;

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

/// The name of the pass-through scheme (the default `terminal.color_scheme`).
pub const TERMINAL: &str = "terminal";

/// RGB color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Parse `#rrggbb`, `rrggbb`, `0xrrggbb` or `#rgb`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let hex = s
            .strip_prefix('#')
            .or_else(|| s.strip_prefix("0x"))
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let byte = |i: usize| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok();
        match hex.len() {
            6 => Some(Self::new(byte(0)?, byte(2)?, byte(4)?)),
            3 => {
                let nib = |i: usize| {
                    let v = u8::from_str_radix(hex.get(i..=i)?, 16).ok()?;
                    Some(v * 17)
                };
                Some(Self::new(nib(0)?, nib(1)?, nib(2)?))
            }
            _ => None,
        }
    }
}

impl fmt::Display for Rgb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }
}

/// A terminal color scheme (SPEC §7.4). M1-09 introduced it in `emulator.rs`; M1-10 owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorScheme {
    pub name: String,
    pub foreground: Rgb,
    pub background: Rgb,
    pub cursor: Rgb,
    pub selection_bg: Option<Rgb>,
    pub ansi: [Rgb; 16],
    /// Indices 16..=255. `None` → computed per xterm.
    pub extended: Option<Box<[Rgb; 240]>>,
}

impl Default for ColorScheme {
    /// xterm's default palette with a light-on-black foreground. Used to answer queries for the
    /// `terminal` scheme until the UI provides the outer terminal's real colors.
    fn default() -> Self {
        const ANSI: [Rgb; 16] = [
            Rgb::new(0x00, 0x00, 0x00),
            Rgb::new(0xcd, 0x00, 0x00),
            Rgb::new(0x00, 0xcd, 0x00),
            Rgb::new(0xcd, 0xcd, 0x00),
            Rgb::new(0x00, 0x00, 0xee),
            Rgb::new(0xcd, 0x00, 0xcd),
            Rgb::new(0x00, 0xcd, 0xcd),
            Rgb::new(0xe5, 0xe5, 0xe5),
            Rgb::new(0x7f, 0x7f, 0x7f),
            Rgb::new(0xff, 0x00, 0x00),
            Rgb::new(0x00, 0xff, 0x00),
            Rgb::new(0xff, 0xff, 0x00),
            Rgb::new(0x5c, 0x5c, 0xff),
            Rgb::new(0xff, 0x00, 0xff),
            Rgb::new(0x00, 0xff, 0xff),
            Rgb::new(0xff, 0xff, 0xff),
        ];
        Self {
            name: TERMINAL.to_owned(),
            foreground: ANSI[7],
            background: ANSI[0],
            cursor: ANSI[7],
            selection_bg: None,
            ansi: ANSI,
            extended: None,
        }
    }
}

impl ColorScheme {
    /// Palette entry `index` (0..=255): the 16 ANSI colors, then `extended` or the xterm 6×6×6
    /// cube and grayscale ramp.
    #[must_use]
    pub fn indexed(&self, index: u8) -> Rgb {
        let i = usize::from(index);
        if i < 16 {
            return self.ansi[i];
        }
        if let Some(ext) = &self.extended {
            return ext[i - 16];
        }
        xterm_256(index)
    }

    /// Parse a scheme in the sverb format. `fallback_name` (usually the file stem) is used
    /// when the file has no `name`. The `terminal` marker file is rejected with
    /// [`SchemeError::Passthrough`]: it has no palette.
    pub fn from_toml(src: &str, fallback_name: &str) -> Result<Self, SchemeError> {
        let table: toml::Table =
            toml::from_str(src).map_err(|e| SchemeError::Syntax(e.message().to_owned()))?;
        if table.get("passthrough").and_then(toml::Value::as_bool) == Some(true) {
            return Err(SchemeError::Passthrough);
        }
        let name = match table.get("name") {
            None => fallback_name.to_owned(),
            Some(toml::Value::String(s)) if !s.trim().is_empty() => s.trim().to_owned(),
            Some(_) => return Err(SchemeError::InvalidField("name".to_owned())),
        };
        let Some(toml::Value::Table(colors)) = table.get("colors") else {
            return Err(SchemeError::MissingField("colors".to_owned()));
        };
        // Unknown keys are rejected so typos (`colour4`) don't silently fall back.
        for key in colors.keys() {
            let known = matches!(
                key.as_str(),
                "foreground" | "background" | "cursor" | "selection_bg"
            ) || key
                .strip_prefix("color")
                .and_then(|n| n.parse::<u16>().ok())
                .is_some_and(|n| n <= 255);
            if !known {
                return Err(SchemeError::UnknownField(format!("colors.{key}")));
            }
        }
        let get = |key: &str| -> Result<Option<Rgb>, SchemeError> {
            match colors.get(key) {
                None => Ok(None),
                Some(toml::Value::String(s)) => Rgb::parse(s)
                    .map(Some)
                    .ok_or_else(|| SchemeError::InvalidField(format!("colors.{key}"))),
                Some(_) => Err(SchemeError::InvalidField(format!("colors.{key}"))),
            }
        };
        let required = |key: &str| -> Result<Rgb, SchemeError> {
            get(key)?.ok_or_else(|| SchemeError::MissingField(format!("colors.{key}")))
        };
        let foreground = required("foreground")?;
        let background = required("background")?;
        let cursor = get("cursor")?.unwrap_or(foreground);
        let selection_bg = get("selection_bg")?;
        let mut ansi = [Rgb::default(); 16];
        for (i, slot) in ansi.iter_mut().enumerate() {
            *slot = required(&format!("color{i}"))?;
        }
        let mut extended: Option<Box<[Rgb; 240]>> = None;
        for i in 16..=255u8 {
            if let Some(rgb) = get(&format!("color{i}"))? {
                let ext = extended.get_or_insert_with(|| Box::new(std::array::from_fn(xterm_ext)));
                ext[usize::from(i) - 16] = rgb;
            }
        }
        Ok(Self {
            name,
            foreground,
            background,
            cursor,
            selection_bg,
            ansi,
            extended,
        })
    }

    /// The scheme in the sverb TOML format (what imports write to `themes/`).
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        let name = toml::Value::from(self.name.as_str());
        let _ = writeln!(out, "name = {name}\n\n[colors]");
        let _ = writeln!(out, "foreground = \"{}\"", self.foreground);
        let _ = writeln!(out, "background = \"{}\"", self.background);
        let _ = writeln!(out, "cursor = \"{}\"", self.cursor);
        if let Some(sel) = self.selection_bg {
            let _ = writeln!(out, "selection_bg = \"{sel}\"");
        }
        for (i, c) in self.ansi.iter().enumerate() {
            let _ = writeln!(out, "color{i} = \"{c}\"");
        }
        if let Some(ext) = &self.extended {
            for (i, c) in ext.iter().enumerate() {
                let _ = writeln!(out, "color{} = \"{c}\"", i + 16);
            }
        }
        out
    }
}

fn xterm_ext(i: usize) -> Rgb {
    xterm_256(u8::try_from(i + 16).unwrap_or(u8::MAX))
}

/// The xterm default color for palette indices 16..=255.
#[must_use]
pub fn xterm_256(index: u8) -> Rgb {
    let i = index;
    if i >= 232 {
        let v = 8 + (i - 232) * 10;
        return Rgb::new(v, v, v);
    }
    let i = i.saturating_sub(16);
    let level = |n: u8| if n == 0 { 0 } else { 55 + n * 40 };
    Rgb::new(level(i / 36), level((i / 6) % 6), level(i % 6))
}

/// Why a scheme file was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemeError {
    #[error("invalid TOML: {0}")]
    Syntax(String),
    #[error("missing `{0}`")]
    MissingField(String),
    #[error("`{0}` is not a valid color")]
    InvalidField(String),
    #[error("unknown key `{0}`")]
    UnknownField(String),
    #[error("the `terminal` marker has no palette")]
    Passthrough,
    #[error("unsupported theme file `{0}` (expected Alacritty .toml/.yml or Kitty .conf)")]
    UnsupportedFormat(String),
    #[error("{0}")]
    Io(String),
}

// ---- built-ins ----------------------------------------------------------------------------

/// The built-in scheme files, `(name, source)`, in display order. `terminal` comes first.
const BUILTIN_FILES: [(&str, &str); 15] = [
    (TERMINAL, include_str!("builtin/terminal.toml")),
    ("sverb-dark", include_str!("builtin/sverb-dark.toml")),
    ("sverb-light", include_str!("builtin/sverb-light.toml")),
    ("dracula", include_str!("builtin/dracula.toml")),
    (
        "solarized-dark",
        include_str!("builtin/solarized-dark.toml"),
    ),
    (
        "solarized-light",
        include_str!("builtin/solarized-light.toml"),
    ),
    ("gruvbox", include_str!("builtin/gruvbox.toml")),
    ("nord", include_str!("builtin/nord.toml")),
    (
        "catppuccin-latte",
        include_str!("builtin/catppuccin-latte.toml"),
    ),
    (
        "catppuccin-frappe",
        include_str!("builtin/catppuccin-frappe.toml"),
    ),
    (
        "catppuccin-macchiato",
        include_str!("builtin/catppuccin-macchiato.toml"),
    ),
    (
        "catppuccin-mocha",
        include_str!("builtin/catppuccin-mocha.toml"),
    ),
    ("tokyo-night", include_str!("builtin/tokyo-night.toml")),
    ("one-dark", include_str!("builtin/one-dark.toml")),
    ("monokai", include_str!("builtin/monokai.toml")),
];

/// Names of the built-in schemes (SPEC §7.4), `terminal` first.
pub const BUILTIN_NAMES: [&str; 15] = {
    let mut names = [""; 15];
    let mut i = 0;
    while i < 15 {
        names[i] = BUILTIN_FILES[i].0;
        i += 1;
    }
    names
};

/// The embedded TOML source of a built-in scheme.
#[must_use]
pub fn builtin_source(name: &str) -> Option<&'static str> {
    BUILTIN_FILES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, src)| *src)
}

fn builtins() -> &'static BTreeMap<&'static str, Arc<ColorScheme>> {
    static BUILTINS: OnceLock<BTreeMap<&'static str, Arc<ColorScheme>>> = OnceLock::new();
    BUILTINS.get_or_init(|| {
        BUILTIN_FILES
            .iter()
            .filter(|(name, _)| *name != TERMINAL)
            .filter_map(|(name, src)| {
                // Covered by the T-10 test; a broken built-in is skipped, never a panic.
                ColorScheme::from_toml(src, name)
                    .ok()
                    .map(|s| (*name, Arc::new(s)))
            })
            .collect()
    })
}

/// A built-in scheme. `terminal` (the pass-through marker) returns `None`.
#[must_use]
pub fn builtin(name: &str) -> Option<Arc<ColorScheme>> {
    builtins().get(name).cloned()
}

/// Whether `name` is a built-in scheme (including `terminal`).
#[must_use]
pub fn is_builtin(name: &str) -> bool {
    BUILTIN_NAMES.contains(&name)
}

// ---- user schemes -------------------------------------------------------------------------

/// A user scheme file that failed to load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeLoadError {
    pub path: PathBuf,
    pub error: SchemeError,
}

impl fmt::Display for SchemeLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.error)
    }
}

/// Load every `*.toml` in `dir` (sorted by file name). Broken files are reported and
/// skipped; the others still load. A missing directory is empty, not an error. User
/// schemes may not shadow built-ins (those are reported too).
#[must_use]
pub fn load_dir(dir: &Path) -> (Vec<ColorScheme>, Vec<SchemeLoadError>) {
    let mut schemes = Vec::new();
    let mut errors = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (schemes, errors);
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml") && p.is_file())
        .collect();
    paths.sort();
    for path in paths {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        let result = std::fs::read_to_string(&path)
            .map_err(|e| SchemeError::Io(e.to_string()))
            .and_then(|src| ColorScheme::from_toml(&src, &stem));
        match result {
            Ok(s) if is_builtin(&s.name) => errors.push(SchemeLoadError {
                path,
                error: SchemeError::InvalidField(format!("name ({} is built in)", s.name)),
            }),
            Ok(s) => schemes.push(s),
            Err(error) => errors.push(SchemeLoadError { path, error }),
        }
    }
    (schemes, errors)
}

/// Built-in plus user schemes, by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemeCatalog {
    user: BTreeMap<String, Arc<ColorScheme>>,
}

impl SchemeCatalog {
    /// Only the built-ins.
    #[must_use]
    pub fn builtin_only() -> Self {
        Self::default()
    }

    /// Built-ins plus `schemes` (later duplicates win).
    #[must_use]
    pub fn with_user(schemes: impl IntoIterator<Item = ColorScheme>) -> Self {
        Self {
            user: schemes
                .into_iter()
                .map(|s| (s.name.clone(), Arc::new(s)))
                .collect(),
        }
    }

    /// Built-ins plus `dir/*.toml`; also publishes the user names for config validation
    /// ([`user_scheme_known`]).
    #[must_use]
    pub fn load(dir: &Path) -> (Self, Vec<SchemeLoadError>) {
        let (schemes, errors) = load_dir(dir);
        let catalog = Self::with_user(schemes);
        catalog.publish();
        (catalog, errors)
    }

    /// Whether `name` exists (`terminal` included).
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        is_builtin(name) || self.user.contains_key(name)
    }

    /// The palette for `name`: `None` for `terminal` and for unknown names (which fall
    /// back to pass-through; config validation rejects them earlier).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<ColorScheme>> {
        builtin(name).or_else(|| self.user.get(name).cloned())
    }

    /// Every scheme name: built-ins in display order, then user schemes sorted.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        BUILTIN_NAMES
            .iter()
            .map(|s| (*s).to_owned())
            .chain(self.user.keys().cloned())
            .collect()
    }

    /// Make this catalog's user scheme names visible to [`user_scheme_known`].
    pub fn publish(&self) {
        let names = self.user.keys().cloned().collect();
        if let Ok(mut known) = user_names().write() {
            *known = names;
        }
    }
}

fn user_names() -> &'static RwLock<std::collections::BTreeSet<String>> {
    static NAMES: OnceLock<RwLock<std::collections::BTreeSet<String>>> = OnceLock::new();
    NAMES.get_or_init(Default::default)
}

/// Whether the last published catalog ([`SchemeCatalog::publish`]) has a user scheme of
/// this name. Used by the config `ThemeCatalog`, which has no handle on the catalog.
#[must_use]
pub fn user_scheme_known(name: &str) -> bool {
    user_names().read().is_ok_and(|n| n.contains(name))
}

/// Whether a scheme of this name exists (built-in or published user scheme).
#[must_use]
pub fn scheme_known(name: &str) -> bool {
    is_builtin(name) || user_scheme_known(name)
}

// ---- imports ------------------------------------------------------------------------------

pub use import_alacritty::{import_alacritty, import_alacritty_yaml};
pub use import_kitty::import_kitty;

/// Import an Alacritty (`.toml`, `.yml`/`.yaml`) or Kitty (`.conf`) theme file. The
/// scheme is named after the file stem (lower-cased, spaces → `-`).
pub fn import_file(path: &Path) -> Result<ColorScheme, SchemeError> {
    let src = std::fs::read_to_string(path).map_err(|e| SchemeError::Io(e.to_string()))?;
    let name = scheme_name_from_path(path);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "toml" => import_alacritty(&src, &name),
        "yml" | "yaml" => import_alacritty_yaml(&src, &name),
        "conf" => import_kitty(&src, &name),
        _ => Err(SchemeError::UnsupportedFormat(path.display().to_string())),
    }
}

/// Import `path` and write it to `themes_dir/<name>.toml` (creating the directory).
/// Returns the scheme and the written path.
pub fn import_into(path: &Path, themes_dir: &Path) -> Result<(ColorScheme, PathBuf), SchemeError> {
    let mut scheme = import_file(path)?;
    if is_builtin(&scheme.name) {
        scheme.name = format!("{}-imported", scheme.name);
    }
    std::fs::create_dir_all(themes_dir).map_err(|e| SchemeError::Io(e.to_string()))?;
    let out = themes_dir.join(format!("{}.toml", scheme.name));
    let body = format!(
        "# Imported by sverb from {}\n{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        scheme.to_toml()
    );
    std::fs::write(&out, body).map_err(|e| SchemeError::Io(e.to_string()))?;
    Ok((scheme, out))
}

fn scheme_name_from_path(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("imported");
    let name: String = stem
        .trim()
        .chars()
        .map(|c| {
            if c.is_whitespace() || c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    if name.is_empty() {
        "imported".to_owned()
    } else {
        name
    }
}

/// Fill a scheme from optional parts (shared by the importers). `field` names the
/// missing color in the source format.
pub(crate) struct Draft {
    pub foreground: Option<Rgb>,
    pub background: Option<Rgb>,
    pub cursor: Option<Rgb>,
    pub selection_bg: Option<Rgb>,
    pub ansi: [Option<Rgb>; 16],
    pub extended: BTreeMap<u8, Rgb>,
}

impl Draft {
    pub(crate) fn new() -> Self {
        Self {
            foreground: None,
            background: None,
            cursor: None,
            selection_bg: None,
            ansi: [None; 16],
            extended: BTreeMap::new(),
        }
    }

    pub(crate) fn finish(
        self,
        name: &str,
        ansi_field: impl Fn(usize) -> String,
    ) -> Result<ColorScheme, SchemeError> {
        let foreground = self
            .foreground
            .ok_or_else(|| SchemeError::MissingField("foreground".to_owned()))?;
        let background = self
            .background
            .ok_or_else(|| SchemeError::MissingField("background".to_owned()))?;
        let mut ansi = [Rgb::default(); 16];
        for (i, slot) in ansi.iter_mut().enumerate() {
            *slot = self.ansi[i].ok_or_else(|| SchemeError::MissingField(ansi_field(i)))?;
        }
        let extended = (!self.extended.is_empty()).then(|| {
            let mut ext = Box::new(std::array::from_fn(xterm_ext));
            for (i, rgb) in &self.extended {
                ext[usize::from(*i) - 16] = *rgb;
            }
            ext
        });
        Ok(ColorScheme {
            name: name.to_owned(),
            foreground,
            background,
            cursor: self.cursor.unwrap_or(foreground),
            selection_bg: self.selection_bg,
            ansi,
            extended,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xterm_palette() {
        assert_eq!(xterm_256(16), Rgb::new(0, 0, 0));
        assert_eq!(xterm_256(196), Rgb::new(255, 0, 0));
        assert_eq!(xterm_256(231), Rgb::new(255, 255, 255));
        assert_eq!(xterm_256(232), Rgb::new(8, 8, 8));
        assert_eq!(xterm_256(255), Rgb::new(238, 238, 238));
    }

    #[test]
    fn rgb_parse_forms() {
        assert_eq!(Rgb::parse("#ff8000"), Some(Rgb::new(255, 128, 0)));
        assert_eq!(Rgb::parse("0xFF8000"), Some(Rgb::new(255, 128, 0)));
        assert_eq!(Rgb::parse("ff8000"), Some(Rgb::new(255, 128, 0)));
        assert_eq!(Rgb::parse("#f80"), Some(Rgb::new(255, 136, 0)));
        assert_eq!(Rgb::parse("#ff80"), None);
        assert_eq!(Rgb::parse("#gg0000"), None);
        assert_eq!(Rgb::new(1, 2, 255).to_string(), "#0102ff");
    }

    // T-10: every built-in parses and defines 16 ANSI colors + fg + bg.
    #[test]
    fn builtins_all_parse() {
        for name in BUILTIN_NAMES {
            let src = builtin_source(name).unwrap_or_default();
            if name == TERMINAL {
                assert_eq!(
                    ColorScheme::from_toml(src, name),
                    Err(SchemeError::Passthrough)
                );
                assert!(builtin(name).is_none());
                continue;
            }
            let s = ColorScheme::from_toml(src, "x").unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(s.name, name);
            assert_ne!(s.foreground, s.background, "{name}");
            assert!(src.contains("# Source:"), "{name} cites its source");
            assert!(builtin(name).is_some());
        }
        assert_eq!(builtins().len(), BUILTIN_NAMES.len() - 1);
        for n in [
            "sverb-dark",
            "sverb-light",
            "dracula",
            "solarized-dark",
            "solarized-light",
            "gruvbox",
            "nord",
            "catppuccin-latte",
            "catppuccin-frappe",
            "catppuccin-macchiato",
            "catppuccin-mocha",
            "tokyo-night",
            "one-dark",
            "monokai",
            "terminal",
        ] {
            assert!(is_builtin(n), "{n}");
        }
    }

    #[test]
    fn round_trip_through_toml() {
        let mut s = (*builtin("dracula").unwrap_or_default()).clone();
        s.name = "mine".to_owned();
        let mut ext = Box::new(std::array::from_fn(xterm_ext));
        ext[0] = Rgb::new(1, 2, 3);
        s.extended = Some(ext);
        let back = ColorScheme::from_toml(&s.to_toml(), "other").unwrap_or_default();
        assert_eq!(back, s);
        assert_eq!(back.indexed(16), Rgb::new(1, 2, 3));
        assert_eq!(back.indexed(17), xterm_256(17));
    }

    #[test]
    fn errors_name_the_field() {
        let src = builtin_source("nord")
            .unwrap_or_default()
            .replace("color4 ", "# ");
        assert_eq!(
            ColorScheme::from_toml(&src, "n"),
            Err(SchemeError::MissingField("colors.color4".to_owned()))
        );
        let src = "[colors]\nforeground = \"#000\"\nbackground = \"nope\"";
        assert_eq!(
            ColorScheme::from_toml(src, "n"),
            Err(SchemeError::InvalidField("colors.background".to_owned()))
        );
        assert!(matches!(
            ColorScheme::from_toml("name = [", "n"),
            Err(SchemeError::Syntax(_))
        ));
        let src = builtin_source("nord")
            .unwrap_or_default()
            .replace("color4 ", "colour4 ");
        assert_eq!(
            ColorScheme::from_toml(&src, "n"),
            Err(SchemeError::UnknownField("colors.colour4".to_owned()))
        );
    }

    #[test]
    fn catalog_lookup() {
        let mut user = (*builtin("nord").unwrap_or_default()).clone();
        user.name = "mine".to_owned();
        let cat = SchemeCatalog::with_user([user]);
        assert!(cat.contains("terminal"));
        assert!(cat.get("terminal").is_none());
        assert!(cat.contains("mine"));
        assert_eq!(
            cat.get("mine").map(|s| s.name.clone()).as_deref(),
            Some("mine")
        );
        assert!(cat.get("dracula").is_some());
        assert!(!cat.contains("nope"));
        assert_eq!(cat.names().first().map(String::as_str), Some("terminal"));
        assert_eq!(cat.names().last().map(String::as_str), Some("mine"));
    }

    #[test]
    fn names_from_paths() {
        assert_eq!(
            scheme_name_from_path(Path::new("/x/Tokyo Night.conf")),
            "tokyo-night"
        );
        assert_eq!(
            scheme_name_from_path(Path::new("dracula_pro.toml")),
            "dracula-pro"
        );
    }
}
