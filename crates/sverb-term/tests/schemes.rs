//! M1-10: color scheme import and user scheme loading (T-11, T-12, T-13).
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::PathBuf;

use sverb_term::scheme::{
    self, ColorScheme, Rgb, SchemeCatalog, SchemeError, import_alacritty, import_alacritty_yaml,
    import_file, import_kitty, load_dir,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/themes/{name}"))
}

fn rgb(s: &str) -> Rgb {
    Rgb::parse(s).unwrap()
}

fn expected_dracula(name: &str) -> ColorScheme {
    ColorScheme {
        name: name.to_owned(),
        foreground: rgb("#f8f8f2"),
        background: rgb("#282a36"),
        cursor: rgb("#f8f8f2"),
        selection_bg: Some(rgb("#44475a")),
        ansi: [
            "#21222c", "#ff5555", "#50fa7b", "#f1fa8c", "#bd93f9", "#ff79c6", "#8be9fd", "#f8f8f2",
            "#6272a4", "#ff6e6e", "#69ff94", "#ffffa5", "#d6acff", "#ff92df", "#a4ffff", "#ffffff",
        ]
        .map(rgb),
        extended: None,
    }
}

// T-11: Alacritty TOML and legacy YAML.
#[test]
fn alacritty_import() {
    let toml = std::fs::read_to_string(fixture("alacritty_dracula.toml")).unwrap();
    assert_eq!(
        import_alacritty(&toml, "dracula-alacritty").unwrap(),
        expected_dracula("dracula-alacritty")
    );
    let yml = std::fs::read_to_string(fixture("alacritty_dracula.yml")).unwrap();
    assert_eq!(
        import_alacritty_yaml(&yml, "dracula-yml").unwrap(),
        expected_dracula("dracula-yml")
    );
    // By extension, named after the file.
    assert_eq!(
        import_file(&fixture("alacritty_dracula.toml")).unwrap(),
        expected_dracula("alacritty-dracula")
    );
    assert_eq!(
        import_file(&fixture("alacritty_dracula.yml")).unwrap(),
        expected_dracula("alacritty-dracula")
    );
    // The imported palette equals the built-in Dracula.
    let builtin = scheme::builtin("dracula").unwrap();
    assert_eq!(builtin.ansi, expected_dracula("x").ansi);
}

// T-12: Kitty.
#[test]
fn kitty_import() {
    let conf = std::fs::read_to_string(fixture("kitty_nord.conf")).unwrap();
    let s = import_kitty(&conf, "nord-kitty").unwrap();
    let expected = ColorScheme {
        name: "nord-kitty".to_owned(),
        foreground: rgb("#d8dee9"),
        background: rgb("#2e3440"),
        cursor: rgb("#81a1c1"),
        selection_bg: Some(rgb("#fffacd")),
        ansi: [
            "#3b4252", "#bf616a", "#a3be8c", "#ebcb8b", "#81a1c1", "#b48ead", "#88c0d0", "#e5e9f0",
            "#4c566a", "#bf616a", "#a3be8c", "#ebcb8b", "#81a1c1", "#b48ead", "#8fbcbb", "#eceff4",
        ]
        .map(rgb),
        extended: None,
    };
    assert_eq!(s, expected);
    assert_eq!(
        import_file(&fixture("kitty_nord.conf")).unwrap().name,
        "kitty-nord"
    );
}

#[test]
fn unsupported_extension() {
    assert!(matches!(
        import_file(&fixture("../../streams/gen.sh")),
        Err(SchemeError::UnsupportedFormat(_))
    ));
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sverb-m1-10-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// T-13: a broken user scheme names the missing field; the others still load.
#[test]
fn invalid_user_scheme() {
    let dir = scratch("themes");
    let good = scheme::builtin_source("nord")
        .unwrap()
        .replace("name = \"nord\"", "");
    std::fs::write(dir.join("my-nord.toml"), &good).unwrap();
    let bad = good.replace("color4 ", "# color4 ");
    std::fs::write(dir.join("broken.toml"), bad).unwrap();
    std::fs::write(dir.join("notes.txt"), "ignored").unwrap();

    let (schemes, errors) = load_dir(&dir);
    assert_eq!(schemes.len(), 1);
    assert_eq!(schemes[0].name, "my-nord");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].path.ends_with("broken.toml"));
    assert_eq!(
        errors[0].error,
        SchemeError::MissingField("colors.color4".to_owned())
    );
    assert!(errors[0].to_string().contains("colors.color4"));

    let (catalog, errors) = SchemeCatalog::load(&dir);
    assert_eq!(errors.len(), 1);
    assert!(catalog.contains("my-nord"));
    assert!(!catalog.contains("broken"));
    assert!(scheme::scheme_known("my-nord"));
    assert!(scheme::scheme_known("dracula"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_dir_is_empty() {
    let (schemes, errors) = load_dir(&std::env::temp_dir().join("sverb-m1-10-does-not-exist"));
    assert!(schemes.is_empty() && errors.is_empty());
}

#[test]
fn import_into_writes_a_loadable_scheme() {
    let dir = scratch("import");
    let (s, path) = scheme::import_into(&fixture("kitty_nord.conf"), &dir).unwrap();
    assert_eq!(path, dir.join("kitty-nord.toml"));
    let (loaded, errors) = load_dir(&dir);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(loaded, [s]);
    let _ = std::fs::remove_dir_all(&dir);
}
