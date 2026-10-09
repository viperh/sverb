//! What changed between two configs, and the reload state machine the TUI reducer

use std::sync::Arc;

use super::model::{ApplyScope, Config, apply_scope};
use super::{ConfigError, ConfigEvent};

/// Shown once when a reload changes keys that only affect new sessions/connections.
pub const NEW_SESSIONS_NOTICE: &str = "Some changes apply to new sessions";

/// The keys that differ between two configs (`table.key`, or `keys.<mode>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    /// Changed paths, sorted.
    pub changed: Vec<String>,
}

fn flatten(config: &Config) -> Vec<(String, toml::Value)> {
    let mut out = Vec::new();
    // Serializing plain structs, enums, strings and integers into a TOML value can't fail;
    // if it ever did, the diff would be empty rather than the app crashing.
    let Ok(toml::Value::Table(root)) = toml::Value::try_from(config) else {
        return out;
    };
    for (table, value) in root {
        match value {
            toml::Value::Table(entries) => {
                for (key, v) in entries {
                    out.push((format!("{table}.{key}"), v));
                }
            }
            other => out.push((table, other)),
        }
    }
    out
}

impl ConfigDiff {
    /// Keys whose values differ between `old` and `new`.
    pub fn between(old: &Config, new: &Config) -> Self {
        let old = flatten(old);
        let new = flatten(new);
        let mut changed: Vec<String> = new
            .iter()
            .filter(|(path, v)| old.iter().find(|(p, _)| p == path).map(|(_, o)| o) != Some(v))
            .map(|(path, _)| path.clone())
            .chain(
                old.iter()
                    .filter(|(path, _)| !new.iter().any(|(p, _)| p == path))
                    .map(|(path, _)| path.clone()),
            )
            .collect();
        changed.sort();
        changed.dedup();
        Self { changed }
    }

    /// Nothing changed.
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty()
    }

    /// Changed keys that take effect immediately.
    pub fn live(&self) -> impl Iterator<Item = &str> {
        self.scoped(|s| s == ApplyScope::Live)
    }

    /// Changed keys that only affect new sessions, connections, runs or the next unlock.
    pub fn deferred(&self) -> impl Iterator<Item = &str> {
        self.scoped(|s| s != ApplyScope::Live)
    }

    fn scoped(&self, keep: impl Fn(ApplyScope) -> bool) -> impl Iterator<Item = &str> {
        self.changed
            .iter()
            .filter(move |p| apply_scope(p).is_some_and(&keep))
            .map(String::as_str)
    }

    /// Whether `path` changed.
    pub fn contains(&self, path: &str) -> bool {
        self.changed.iter().any(|p| p == path)
    }

    /// The info toast to show, if some changes only apply to new sessions/connections.
    pub fn notice(&self) -> Option<&'static str> {
        self.deferred().next().map(|_| NEW_SESSIONS_NOTICE)
    }
}

/// What the reducer should do after a [`ConfigEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigUpdate {
    /// A new config is in effect. Apply the live keys in `diff`; show `notice` once if set.
    Applied {
        /// The new config.
        config: Arc<Config>,
        /// What changed.
        diff: ConfigDiff,
        /// Info toast for deferred keys.
        notice: Option<&'static str>,
        /// Non-fatal problems to show as a warning toast.
        warnings: Vec<ConfigError>,
    },
    /// The file was rejected; the last good config stays. Show the errors as a toast.
    Rejected(Vec<ConfigError>),
}

/// The config currently in effect, updated by [`ConfigEvent`]s. Never partially applied.
#[derive(Debug, Clone, Default)]
pub struct LiveConfig {
    current: Arc<Config>,
}

impl LiveConfig {
    /// Start with `config` in effect.
    pub fn new(config: Arc<Config>) -> Self {
        Self { current: config }
    }

    /// The config in effect.
    pub fn current(&self) -> &Arc<Config> {
        &self.current
    }

    /// Apply a watcher event.
    pub fn apply(&mut self, event: ConfigEvent) -> ConfigUpdate {
        let (next, warnings) = match event {
            ConfigEvent::Reloaded { config, warnings } => (config, warnings),
            ConfigEvent::Removed => (Arc::new(Config::default()), Vec::new()),
            ConfigEvent::Invalid(errors) => return ConfigUpdate::Rejected(errors),
        };
        let diff = ConfigDiff::between(&self.current, &next);
        let notice = diff.notice();
        self.current = Arc::clone(&next);
        ConfigUpdate::Applied {
            config: next,
            diff,
            notice,
            warnings,
        }
    }
}
