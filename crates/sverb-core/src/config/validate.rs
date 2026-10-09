//! Parsing with spans, structural checks (unknown keys, types) and semantic validation.
//!
//! The pipeline collects **all** errors it can:
//! 1. TOML syntax (one error; nothing else can be checked).
//! 2. Structure: every table and key is known, every value has the right type. Each
//!    key is type-checked on its own, so one bad value doesn't hide the next.
//! 3. Semantics on the typed [`Config`]: ranges, formats, names, chords.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use serde::Deserialize;
use toml::Spanned;
use toml::de::{DeTable, DeValue, ValueDeserializer};

use super::model::{
    ClipboardConfig, Config, GeneralConfig, HistoryConfig, LogsConfig, RecordingConfig, SshConfig,
    SyncConfig, TABLES, TerminalConfig, UiConfig, table_keys,
};
use super::{ConfigError, LeaderCheck, Validators};

/// Output of [`parse`].
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    /// Set when there were no structural errors (semantic errors may still exist).
    pub(crate) config: Option<Config>,
    pub(crate) errors: Vec<ConfigError>,
    pub(crate) warnings: Vec<ConfigError>,
}

const SECRET_HINT: &str =
    "server URL and tokens are set with `sverb login` and stored encrypted in the database";

/// Key names that look like credentials or server settings. They are never config keys.
const SECRET_KEYS: &[&str] = &[
    "server",
    "server_url",
    "url",
    "token",
    "tokens",
    "access_token",
    "refresh_token",
    "device_id",
    "password",
    "secret",
    "api_key",
];

/// Byte offset → 1-based (line, column in chars).
struct LineIndex<'a> {
    src: &'a str,
}

impl LineIndex<'_> {
    fn pos(&self, offset: usize) -> (usize, usize) {
        let offset = offset.min(self.src.len());
        let before = self.src.get(..offset).unwrap_or(self.src);
        let line = before.matches('\n').count() + 1;
        let line_start = before.rfind('\n').map_or(0, |i| i + 1);
        let col = before.get(line_start..).map_or(0, |s| s.chars().count()) + 1;
        (line, col)
    }

    fn span(&self, span: &Range<usize>) -> (usize, usize) {
        self.pos(span.start)
    }
}

/// Nearest candidate within Levenshtein distance 2.
fn suggest<'a>(word: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    candidates
        .into_iter()
        .map(|c| (strsim::levenshtein(word, c), c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| format!("did you mean `{c}`?"))
}

fn secret_hint(key: &str) -> Option<String> {
    SECRET_KEYS.contains(&key).then(|| SECRET_HINT.to_owned())
}

/// Type-check one `key = value` of `table` by deserializing a one-entry table into the
/// section struct.
fn check_field(
    table: &str,
    key: &Spanned<std::borrow::Cow<'_, str>>,
    value: &Spanned<DeValue<'_>>,
) -> Result<(), String> {
    let mut one = DeTable::new();
    one.insert(key.clone(), value.clone());
    let de = ValueDeserializer::from(Spanned::new(value.span(), DeValue::Table(one)));
    let res = match table {
        "general" => GeneralConfig::deserialize(de).map(drop),
        "ui" => UiConfig::deserialize(de).map(drop),
        "terminal" => TerminalConfig::deserialize(de).map(drop),
        "clipboard" => ClipboardConfig::deserialize(de).map(drop),
        "ssh" => SshConfig::deserialize(de).map(drop),
        "recording" => RecordingConfig::deserialize(de).map(drop),
        "history" => HistoryConfig::deserialize(de).map(drop),
        "sync" => SyncConfig::deserialize(de).map(drop),
        "logs" => LogsConfig::deserialize(de).map(drop),
        _ => Ok(()),
    };
    res.map_err(|e| e.message().trim().to_owned())
}

/// Parse and validate `src`.
pub(crate) fn parse(src: &str, validators: &Validators) -> Parsed {
    let idx = LineIndex { src };
    let mut out = Parsed::default();

    let root = match DeTable::parse(src) {
        Ok(root) => root,
        Err(e) => {
            let pos = e.span().map_or((0, 0), |s| idx.span(&s));
            out.errors
                .push(ConfigError::new("", e.message().trim().to_owned()).at(pos));
            return out;
        }
    };

    // Position of every value, by dotted path, for semantic errors.
    let mut positions: HashMap<String, (usize, usize)> = HashMap::new();
    let modes = validators.keymap.modes();

    for (tkey, tval) in root.get_ref() {
        let table: &str = tkey.get_ref();
        if !TABLES.contains(&table) {
            let hint = secret_hint(table).or_else(|| suggest(table, TABLES.iter().copied()));
            out.errors.push(
                ConfigError::new(table, format!("unknown table or key `{table}`"))
                    .at(idx.span(&tkey.span()))
                    .hint(hint),
            );
            continue;
        }
        let Some(entries) = tval.get_ref().as_table() else {
            out.errors.push(
                ConfigError::new(
                    table,
                    format!("expected a table, found {}", tval.get_ref().type_str()),
                )
                .at(idx.span(&tval.span())),
            );
            continue;
        };
        positions.insert(table.to_owned(), idx.span(&tkey.span()));

        if table == "keys" {
            check_keys(entries, &modes, validators, &idx, &mut positions, &mut out);
            continue;
        }

        for (k, v) in entries {
            let key: &str = k.get_ref();
            let path = format!("{table}.{key}");
            if !table_keys(table).any(|known| known == key) {
                let hint = secret_hint(key).or_else(|| suggest(key, table_keys(table)));
                out.errors.push(
                    ConfigError::new(&path, format!("unknown key `{key}` in [{table}]"))
                        .at(idx.span(&k.span()))
                        .hint(hint),
                );
                continue;
            }
            positions.insert(path.clone(), idx.span(&v.span()));
            if let Err(msg) = check_field(table, k, v) {
                out.errors
                    .push(ConfigError::new(&path, msg).at(idx.span(&v.span())));
            }
        }
    }

    if !out.errors.is_empty() {
        return out;
    }

    let root_span = root.span();
    let de = ValueDeserializer::from(Spanned::new(root_span, DeValue::Table(root.into_inner())));
    let config = match Config::deserialize(de) {
        Ok(config) => config,
        Err(e) => {
            // Not expected after the structural pass; reported rather than unwrapped.
            let pos = e.span().map_or((0, 0), |s| idx.span(&s));
            out.errors
                .push(ConfigError::new("", e.message().trim().to_owned()).at(pos));
            return out;
        }
    };

    validate_semantics(&config, validators, &positions, &mut out);
    out.config = Some(config);
    out
}

fn check_keys(
    entries: &DeTable<'_>,
    modes: &[String],
    validators: &Validators,
    idx: &LineIndex<'_>,
    positions: &mut HashMap<String, (usize, usize)>,
    out: &mut Parsed,
) {
    for (mkey, mval) in entries {
        let mode: &str = mkey.get_ref();
        let path = format!("keys.{mode}");
        if !modes.iter().any(|m| m == mode) {
            out.errors.push(
                ConfigError::new(&path, format!("unknown key mode `{mode}`"))
                    .at(idx.span(&mkey.span()))
                    .hint(suggest(mode, modes.iter().map(String::as_str))),
            );
            continue;
        }
        let Some(bindings) = mval.get_ref().as_table() else {
            out.errors.push(
                ConfigError::new(
                    &path,
                    format!(
                        "expected a table of `\"chord\" = \"action\"`, found {}",
                        mval.get_ref().type_str()
                    ),
                )
                .at(idx.span(&mval.span())),
            );
            continue;
        };
        for (ck, cv) in bindings {
            let chord: &str = ck.get_ref();
            let bpath = format!("keys.{mode}.{chord}");
            positions.insert(bpath.clone(), idx.span(&ck.span()));
            let Some(action) = cv.get_ref().as_str() else {
                out.errors.push(
                    ConfigError::new(
                        &bpath,
                        format!(
                            "invalid type: {}, expected an action name string",
                            cv.get_ref().type_str()
                        ),
                    )
                    .at(idx.span(&cv.span())),
                );
                continue;
            };
            if let Err(e) = validators.keymap.parse_chord(chord) {
                out.errors
                    .push(ConfigError::new(&bpath, e).at(idx.span(&ck.span())));
            }
            if !validators.keymap.action_exists(mode, action) {
                out.errors.push(
                    ConfigError::new(&bpath, format!("unknown action `{action}`"))
                        .at(idx.span(&cv.span()))
                        .hint(Some(
                            "`sverb` lists actions in the help screen (`leader ?`)".to_owned(),
                        )),
                );
            }
        }
    }
}

/// Range/format/name checks on a structurally valid config. Collects every problem.
fn validate_semantics(
    config: &Config,
    validators: &Validators,
    positions: &HashMap<String, (usize, usize)>,
    out: &mut Parsed,
) {
    let pos = |path: &str| positions.get(path).copied().unwrap_or((0, 0));
    let mut err = |path: &str, msg: String, hint: Option<String>| {
        out.errors
            .push(ConfigError::new(path, msg).at(pos(path)).hint(hint));
    };

    // general.leader
    let leader = config.general.leader.as_str();
    let mut leader_warning = None;
    match validators.keymap.check_leader(leader) {
        LeaderCheck::Ok => {}
        LeaderCheck::Warn(msg) => leader_warning = Some(msg),
        LeaderCheck::Reject(msg) => err(
            "general.leader",
            format!("invalid leader `{leader}`: {msg}"),
            Some("try \"ctrl-\\\\\" (the default) or \"ctrl-g\"".to_owned()),
        ),
    }

    // ui
    if !validators.themes.has_ui_theme(&config.ui.theme) {
        err(
            "ui.theme",
            format!("unknown UI theme `{}`", config.ui.theme),
            Some("built-in themes: default-dark, default-light, high-contrast".to_owned()),
        );
    }
    if config.ui.which_key_delay_ms > 10_000 {
        err(
            "ui.which_key_delay_ms",
            format!(
                "{} is out of range (0..=10000)",
                config.ui.which_key_delay_ms
            ),
            None,
        );
    }
    if let Err(msg) = check_date_format(&config.ui.date_format) {
        err(
            "ui.date_format",
            msg,
            Some("e.g. \"%Y-%m-%d %H:%M\"".to_owned()),
        );
    }

    // terminal
    let term = &config.terminal.term;
    if term.is_empty()
        || term.len() > 64
        || !term.is_ascii()
        || term
            .chars()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
    {
        err(
            "terminal.term",
            format!(
                "invalid TERM `{term}`: must be 1 to 64 printable ASCII characters without spaces"
            ),
            None,
        );
    }
    if config.terminal.scrollback > 1_000_000 {
        err(
            "terminal.scrollback",
            format!(
                "{} is out of range (at most 1000000)",
                config.terminal.scrollback
            ),
            None,
        );
    }

    // ssh
    if config.ssh.exec_timeout_secs < 1 {
        err(
            "ssh.exec_timeout_secs",
            "must be at least 1".to_owned(),
            None,
        );
    }
    if !(1..=20).contains(&config.ssh.max_auth_attempts) {
        err(
            "ssh.max_auth_attempts",
            format!("{} is out of range (1..=20)", config.ssh.max_auth_attempts),
            None,
        );
    }
    if config.ssh.connect_timeout_secs < 1 {
        err(
            "ssh.connect_timeout_secs",
            "must be at least 1".to_owned(),
            None,
        );
    }

    // sync
    if config.sync.push_debounce_ms < 100 {
        err(
            "sync.push_debounce_ms",
            format!(
                "{} is too small (at least 100)",
                config.sync.push_debounce_ms
            ),
            None,
        );
    }
    if config.sync.poll_fallback_secs < 30 {
        err(
            "sync.poll_fallback_secs",
            format!(
                "{} is too small (at least 30)",
                config.sync.poll_fallback_secs
            ),
            None,
        );
    }

    // keys: the leader can't be rebound after itself, and no chord twice per mode.
    let leader_norm = validators.keymap.parse_chord(leader).ok();
    for (mode, bindings) in &config.keys.0 {
        let mut seen: BTreeMap<String, &str> = BTreeMap::new();
        for chord in bindings.keys() {
            let path = format!("keys.{mode}.{}", chord.as_str());
            let Ok(norm) = validators.keymap.parse_chord(chord.as_str()) else {
                continue; // reported in the structural pass
            };
            if mode == "terminal" && leader_norm.as_deref() == Some(norm.as_str()) {
                err(
                    &path,
                    format!(
                        "`{}` is the leader and can't be bound after the leader",
                        chord.as_str()
                    ),
                    Some("pressing the leader twice sends it to the session".to_owned()),
                );
            }
            if let Some(first) = seen.insert(norm, chord.as_str()) {
                err(
                    &path,
                    format!(
                        "`{}` is the same key as `{first}` in [keys.{mode}]",
                        chord.as_str()
                    ),
                    None,
                );
            }
        }
    }

    // Warnings last, so they never count as errors.
    if let Some(msg) = leader_warning {
        out.warnings.push(
            ConfigError::new("general.leader", msg)
                .at(pos("general.leader"))
                .warning(),
        );
    }
    // M7-07: keys the model accepts but this version doesn't act on yet (SPEC
    // decisions log, 2026-10-09). A warning, so a file written for a later version
    // still loads.
    if config.ssh.read_ssh_config {
        out.warnings.push(
            ConfigError::new(
                "ssh.read_ssh_config",
                "live ~/.ssh/config hosts are not implemented in this version; \
                 use `sverb import ssh-config`",
            )
            .at(pos("ssh.read_ssh_config"))
            .warning(),
        );
    }
    if config.terminal.bell != super::BellMode::Visual {
        out.warnings.push(
            ConfigError::new(
                "terminal.bell",
                "only \"visual\" (the tab's bell marker) is implemented in this version",
            )
            .at(pos("terminal.bell"))
            .warning(),
        );
    }
    if !validators
        .themes
        .has_color_scheme(&config.terminal.color_scheme)
    {
        out.warnings.push(
            ConfigError::new(
                "terminal.color_scheme",
                format!(
                    "unknown color scheme `{}`; panes use `terminal` instead",
                    config.terminal.color_scheme
                ),
            )
            .at(pos("terminal.color_scheme"))
            .warning(),
        );
    }
}

/// Checks a strftime-style format (the specifiers chrono and `time`'s strftime parser share).
pub(crate) fn check_date_format(fmt: &str) -> Result<(), String> {
    const SPECIFIERS: &str = "aAbBcCdDeFfgGhHIjklLmMnpPqrRsStTuUvVwWxXyYzZ%+";
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        // Optional padding flag, width, `.`/`:` modifiers (`%-d`, `%3f`, `%.3f`, `%:z`).
        if matches!(chars.peek(), Some('-' | '_' | '0' | '^' | '#')) {
            chars.next();
        }
        while matches!(chars.peek(), Some(c) if c.is_ascii_digit() || *c == '.' || *c == ':') {
            chars.next();
        }
        match chars.next() {
            Some(spec) if SPECIFIERS.contains(spec) => {}
            Some(spec) => return Err(format!("unknown date format specifier `%{spec}`")),
            None => return Err("date format ends with a lone `%`".to_owned()),
        }
    }
    Ok(())
}
