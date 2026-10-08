//! The typed `config.toml` model (SPEC §15).
//!
//! One struct per table, every field defaulted. The defaults here must match
//! `default_config.toml` byte for byte in meaning (a test checks it) and the
//! [`APPLY_SCOPES`] table must list every key (another test checks that).
//!
//! # Hotspot
//! Later tasks add keys here (see `tasks/01-DEPENDENCIES.md` §3). Add a field to the
//! struct, its default, a row in [`APPLY_SCOPES`], the line in `default_config.toml`
//! and regenerate `docs/config.schema.json` (`SVERB_BLESS_SCHEMA=1 cargo test -p sverb-core schema`).

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// The whole configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(title = "sverb config.toml")]
pub struct Config {
    /// General behaviour: leader key, quitting and the vault lock.
    pub general: GeneralConfig,
    /// The look of the sverb UI.
    pub ui: UiConfig,
    /// Defaults for terminal panes.
    pub terminal: TerminalConfig,
    /// Clipboard integration.
    pub clipboard: ClipboardConfig,
    /// SSH connection defaults.
    pub ssh: SshConfig,
    /// Session recording defaults.
    pub recording: RecordingConfig,
    /// Command history.
    pub history: HistoryConfig,
    /// Sync tuning knobs. The server URL and tokens are set with `sverb login`, never here.
    pub sync: SyncConfig,
    /// Connection log retention.
    pub logs: LogsConfig,
    /// Key binding overrides, one table per mode (`[keys.terminal]` is the after-leader table).
    pub keys: KeysConfig,
}

/// A key chord as written in the config, e.g. `"ctrl-\\"` or `"p"`.
///
/// Kept as a string in `sverb-core` (no crossterm here). The TUI parses and
/// normalizes it; [`super::KeymapValidator`] checks it at load time.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct KeyChordSpec(pub String);

impl KeyChordSpec {
    /// The chord text as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyChordSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for KeyChordSpec {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// `[general]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    /// The leader (command) key. `"ctrl-\\"` by default; `"ctrl-g"` is recommended where `\` needs AltGr.
    pub leader: KeyChordSpec,
    /// Ask before quitting while sessions are open.
    pub confirm_quit: bool,
    /// Lock the vault after this many idle minutes. 0 disables auto-lock.
    pub auto_lock_minutes: u32,
    /// Disconnect all sessions when the vault locks.
    pub lock_disconnects_sessions: bool,
    /// Vault selected at unlock.
    pub default_vault: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            leader: KeyChordSpec("ctrl-\\".to_owned()),
            confirm_quit: true,
            auto_lock_minutes: 15,
            lock_disconnects_sessions: false,
            default_vault: "personal".to_owned(),
        }
    }
}

/// When the sidebar is shown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SidebarMode {
    /// Shown when the terminal is wide enough.
    #[default]
    Auto,
    /// Always shown.
    Always,
    /// Never shown.
    Never,
}

/// Whether 24-bit color is used.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TruecolorMode {
    /// Detected from `COLORTERM` and the terminal's answers.
    #[default]
    Auto,
    /// Always use 24-bit color.
    On,
    /// Never use 24-bit color.
    Off,
}

/// `[ui]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// UI chrome theme (built-in or a file in `themes/`).
    pub theme: String,
    /// When the sidebar is shown: auto, always or never.
    pub sidebar: SidebarMode,
    /// Capture the mouse.
    pub mouse: bool,
    /// 24-bit color: auto, on or off.
    pub truecolor: TruecolorMode,
    /// Show the which-key popup after the leader.
    pub show_which_key: bool,
    /// Delay before the which-key popup appears, in milliseconds (0..=10000).
    pub which_key_delay_ms: u32,
    /// strftime-style format for dates shown in the UI.
    pub date_format: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "default-dark".to_owned(),
            sidebar: SidebarMode::Auto,
            mouse: true,
            truecolor: TruecolorMode::Auto,
            show_which_key: true,
            which_key_delay_ms: 400,
            date_format: "%Y-%m-%d %H:%M".to_owned(),
        }
    }
}

/// What the terminal bell does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BellMode {
    /// Ignore the bell.
    None,
    /// Flash the pane.
    #[default]
    Visual,
    /// Ring the outer terminal's bell.
    Audible,
}

/// `[terminal]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TerminalConfig {
    /// `TERM` sent to the remote side. ASCII, no whitespace, at most 64 characters.
    pub term: String,
    /// Scrollback lines per pane (at most 1000000).
    pub scrollback: u32,
    /// Color scheme for hosts without one.
    pub color_scheme: String,
    /// What the bell does: none, visual or audible.
    pub bell: BellMode,
    /// Ask before pasting text that contains newlines.
    pub paste_confirm_multiline: bool,
    /// Let the remote side set the tab title with OSC 0/2.
    pub use_osc_title: bool,
    /// Characters that end a word for double-click selection.
    pub word_separators: String,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            term: "xterm-256color".to_owned(),
            scrollback: 10_000,
            color_scheme: "terminal".to_owned(),
            bell: BellMode::Visual,
            paste_confirm_multiline: true,
            use_osc_title: false,
            word_separators: " ,│`|:\"'()[]{}<>".to_owned(),
        }
    }
}

/// Whether remote programs may write the local clipboard (OSC 52).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteWritePolicy {
    /// Never.
    Never,
    /// Ask each time.
    #[default]
    Ask,
    /// Always allow.
    Always,
}

/// `[clipboard]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClipboardConfig {
    /// Copy through the outer terminal with OSC 52.
    pub osc52: bool,
    /// Remote clipboard writes: never, ask or always.
    pub allow_remote_write: RemoteWritePolicy,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            osc52: true,
            allow_remote_write: RemoteWritePolicy::Ask,
        }
    }
}

/// What to do with an unknown host key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyPolicy {
    /// Refuse unknown host keys.
    Strict,
    /// Ask the user.
    #[default]
    Ask,
    /// Accept and store new keys; refuse changed ones.
    AcceptNew,
}

/// `[ssh]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SshConfig {
    /// Reuse one connection for several sessions to the same host.
    pub multiplex: bool,
    /// Keepalive interval in seconds. 0 disables keepalives.
    pub keepalive_secs: u32,
    /// Unknown host keys: strict, ask or accept-new.
    pub host_key_policy: HostKeyPolicy,
    /// Also offer keys from the system ssh-agent.
    pub use_system_agent: bool,
    /// Also resolve hosts from `~/.ssh/config` (read-only).
    pub read_ssh_config: bool,
    /// Store new known_hosts entries hashed.
    pub hash_known_hosts: bool,
    /// Timeout for remote commands run by sverb, in seconds (at least 1).
    pub exec_timeout_secs: u32,
    /// Authentication attempts per connection (1..=20).
    pub max_auth_attempts: u32,
    /// TCP and handshake timeout in seconds (at least 1).
    pub connect_timeout_secs: u32,
    // M1-16 (spec addition): §6.1.2 "optional auto-reconnect" names no key.
    /// Reconnect dropped sessions automatically (exponential backoff 1 s → 30 s, at most
    /// 10 tries). A host's `auto_reconnect` overrides it.
    pub auto_reconnect: bool,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            multiplex: true,
            keepalive_secs: 30,
            host_key_policy: HostKeyPolicy::Ask,
            use_system_agent: true,
            read_ssh_config: false,
            hash_known_hosts: false,
            exec_timeout_secs: 60,
            max_auth_attempts: 5,
            connect_timeout_secs: 15,
            // M1-16
            auto_reconnect: false,
        }
    }
}

/// `[recording]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RecordingConfig {
    /// Record new sessions.
    pub enabled: bool,
    /// Also record keyboard input.
    pub include_input: bool,
    // M3-06 (spec addition)
    /// Delete recordings this many days old. 0 keeps them until deleted.
    pub retention_days: u32,
}

/// `[history]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    /// Keep a per-host command history.
    pub enabled: bool,
    /// Sync the history between devices.
    pub sync: bool,
    /// History entries kept per host.
    pub max_entries_per_host: u32,
    // M7-01 (spec addition)
    /// Show an inline ghost-text suggestion after the cursor (needs shell integration,
    /// OSC 133). Accepted with `leader Tab` only.
    pub ghost_text: bool,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync: false,
            max_entries_per_host: 5000,
            // M7-01
            ghost_text: false,
        }
    }
}

/// `[sync]` (tuning only; no server URL or tokens).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SyncConfig {
    /// Wait this long after a change before pushing, in milliseconds (at least 100).
    pub push_debounce_ms: u32,
    /// Poll interval when push notifications are unavailable, in seconds (at least 30).
    pub poll_fallback_secs: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            push_debounce_ms: 2000,
            poll_fallback_secs: 300,
        }
    }
}

/// `[logs]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LogsConfig {
    /// Keep connection logs this many days. 0 keeps them forever.
    pub retention_days: u32,
    /// Sync connection logs between devices.
    pub sync: bool,
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            sync: false,
        }
    }
}

/// Bindings of one mode: chord → action name.
pub type ModeBindings = BTreeMap<KeyChordSpec, String>;

/// `[keys.<mode>]` tables: mode name → (chord → action name).
///
/// User tables are merged key by key over the defaults (`p`, `-`, `|` after the
/// leader, `ctrl-k` in Normal mode, `y`, `/` and `o` in copy mode), so a user file only
/// lists its changes. `[keys.copy]` binds copy-mode actions (M3-04).
/// The full built-in keymap lives in `sverb-tui` (M0-10) and is merged under this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct KeysConfig(pub BTreeMap<String, ModeBindings>);

impl KeysConfig {
    /// Bindings for `mode`, if any.
    pub fn mode(&self, mode: &str) -> Option<&ModeBindings> {
        self.0.get(mode)
    }
}

impl Default for KeysConfig {
    fn default() -> Self {
        let terminal: ModeBindings = [
            ("p", "palette"),
            ("-", "split_horizontal"),
            ("|", "split_vertical"),
        ]
        .into_iter()
        .map(|(k, v)| (KeyChordSpec::from(k), v.to_owned()))
        .collect();
        let normal: ModeBindings = [(KeyChordSpec::from("ctrl-k"), "palette".to_owned())]
            .into_iter()
            .collect();
        // M3-04: copy mode (`leader [`); the full built-in table lives in sverb-tui.
        let copy: ModeBindings = [("y", "yank"), ("/", "search_forward"), ("o", "open_link")]
            .into_iter()
            .map(|(k, v)| (KeyChordSpec::from(k), v.to_owned()))
            .collect();
        Self(BTreeMap::from([
            ("terminal".to_owned(), terminal),
            ("normal".to_owned(), normal),
            // M3-04
            ("copy".to_owned(), copy),
        ]))
    }
}

impl<'de> Deserialize<'de> for KeysConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let user = BTreeMap::<String, ModeBindings>::deserialize(deserializer)?;
        let mut merged = Self::default();
        for (mode, bindings) in user {
            merged.0.entry(mode).or_default().extend(bindings);
        }
        Ok(merged)
    }
}

/// When a changed key takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplyScope {
    /// Immediately, on reload.
    Live,
    /// At the next vault unlock.
    NextUnlock,
    /// For sessions opened after the change.
    NewSessions,
    /// For connections opened after the change.
    NewConnections,
    /// For remote commands started after the change.
    NewRuns,
}

impl ApplyScope {
    /// Short human text, used in comments and toasts.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::NextUnlock => "next unlock",
            Self::NewSessions => "new sessions",
            Self::NewConnections => "new connections",
            Self::NewRuns => "new runs",
        }
    }
}

/// Every key (`table.key`) and when a change to it applies (SPEC §15 "Applies").
///
/// `keys` covers every `[keys.<mode>]` table. Also the list of known keys used for
/// unknown-key errors and suggestions.
pub const APPLY_SCOPES: &[(&str, ApplyScope)] = &[
    ("general.leader", ApplyScope::Live),
    ("general.confirm_quit", ApplyScope::Live),
    ("general.auto_lock_minutes", ApplyScope::Live),
    ("general.lock_disconnects_sessions", ApplyScope::Live),
    ("general.default_vault", ApplyScope::NextUnlock),
    ("ui.theme", ApplyScope::Live),
    ("ui.sidebar", ApplyScope::Live),
    ("ui.mouse", ApplyScope::Live),
    ("ui.truecolor", ApplyScope::Live),
    ("ui.show_which_key", ApplyScope::Live),
    ("ui.which_key_delay_ms", ApplyScope::Live),
    ("ui.date_format", ApplyScope::Live),
    ("terminal.term", ApplyScope::NewSessions),
    ("terminal.scrollback", ApplyScope::NewSessions),
    ("terminal.color_scheme", ApplyScope::Live),
    ("terminal.bell", ApplyScope::Live),
    ("terminal.paste_confirm_multiline", ApplyScope::Live),
    ("terminal.use_osc_title", ApplyScope::Live),
    ("terminal.word_separators", ApplyScope::Live),
    ("clipboard.osc52", ApplyScope::Live),
    ("clipboard.allow_remote_write", ApplyScope::Live),
    ("ssh.multiplex", ApplyScope::NewConnections),
    ("ssh.keepalive_secs", ApplyScope::NewConnections),
    ("ssh.host_key_policy", ApplyScope::NewConnections),
    ("ssh.use_system_agent", ApplyScope::NewConnections),
    ("ssh.read_ssh_config", ApplyScope::Live),
    ("ssh.hash_known_hosts", ApplyScope::Live),
    ("ssh.exec_timeout_secs", ApplyScope::NewRuns),
    ("ssh.max_auth_attempts", ApplyScope::NewConnections),
    ("ssh.connect_timeout_secs", ApplyScope::NewConnections),
    // M1-16 (spec addition)
    ("ssh.auto_reconnect", ApplyScope::NewConnections),
    ("recording.enabled", ApplyScope::NewSessions),
    ("recording.include_input", ApplyScope::NewSessions),
    // M3-06 (spec addition): applied by the next maintenance run.
    ("recording.retention_days", ApplyScope::Live),
    ("history.enabled", ApplyScope::Live),
    ("history.sync", ApplyScope::Live),
    ("history.max_entries_per_host", ApplyScope::Live),
    // M7-01 (spec addition)
    ("history.ghost_text", ApplyScope::Live),
    ("sync.push_debounce_ms", ApplyScope::Live),
    ("sync.poll_fallback_secs", ApplyScope::Live),
    ("logs.retention_days", ApplyScope::Live),
    ("logs.sync", ApplyScope::Live),
    ("keys", ApplyScope::Live),
];

/// The scope of a `table.key` path (`keys.*` paths map to `keys`). `None` if unknown.
pub fn apply_scope(path: &str) -> Option<ApplyScope> {
    let lookup = if path == "keys" || path.starts_with("keys.") {
        "keys"
    } else {
        path
    };
    APPLY_SCOPES
        .iter()
        .find(|(key, _)| *key == lookup)
        .map(|(_, scope)| *scope)
}

/// The top-level table names, in file order.
pub const TABLES: &[&str] = &[
    "general",
    "ui",
    "terminal",
    "clipboard",
    "ssh",
    "recording",
    "history",
    "sync",
    "logs",
    "keys",
];

/// Known keys of `table` (empty for `keys` and unknown tables).
pub fn table_keys(table: &str) -> impl Iterator<Item = &'static str> + '_ {
    APPLY_SCOPES.iter().filter_map(move |(path, _)| {
        path.split_once('.')
            .filter(|(t, _)| *t == table)
            .map(|(_, key)| key)
    })
}
