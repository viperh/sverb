//! Hot reload of `config.toml` (SPEC §15).
//!
//! Watches the **parent directory** (editors save by writing a temp file and renaming
//! it over the original), keeps only events for the config file name, and debounces
//! them: a reload happens once the file has been quiet for [`DEBOUNCE`].

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use super::{Config, ConfigError, Validators};

/// Quiet time before a burst of file events triggers one reload.
pub const DEBOUNCE: Duration = Duration::from_millis(200);

/// A reload result, sent to the TUI event stream (`UiEvent::Config`, M0-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigEvent {
    /// The file changed and is valid.
    Reloaded {
        /// The new config.
        config: Arc<Config>,
        /// Non-fatal problems (e.g. a leader that shadows a shell key).
        warnings: Vec<ConfigError>,
    },
    /// The file changed but has errors; the last good config stays in effect.
    Invalid(Vec<ConfigError>),
    /// The file was deleted; the defaults are in effect.
    Removed,
}

/// The watcher could not start; the app runs without hot reload (warning toast).
#[derive(Debug)]
pub enum WatchError {
    /// The config file path has no parent directory or file name.
    BadPath(PathBuf),
    /// The OS watcher failed (e.g. inotify watch limit reached).
    Notify(notify::Error),
    /// The debounce thread could not be spawned.
    Thread(std::io::Error),
}

impl fmt::Display for WatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPath(p) => write!(f, "can't watch {}: not a file path", p.display()),
            Self::Notify(e) => write!(f, "config hot reload unavailable: {e}"),
            Self::Thread(e) => write!(f, "config hot reload unavailable: {e}"),
        }
    }
}

impl std::error::Error for WatchError {}

/// Watches `config.toml` until dropped.
pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
}

impl fmt::Debug for ConfigWatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigWatcher").finish_non_exhaustive()
    }
}

fn is_target(event: &notify::Event, name: &OsString) -> bool {
    event
        .paths
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n == name.as_os_str()))
}

impl ConfigWatcher {
    /// Start watching `config_file`. `last_good` is the config in effect now (kept on
    /// invalid reloads); `sink` receives one [`ConfigEvent`] per debounced change, on a
    /// background thread. The parent directory must exist.
    pub fn spawn(
        config_file: &Path,
        validators: Validators,
        last_good: Arc<Config>,
        sink: impl Fn(ConfigEvent) + Send + 'static,
    ) -> Result<Self, WatchError> {
        let bad = || WatchError::BadPath(config_file.to_owned());
        let dir = config_file
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .ok_or_else(bad)?
            .to_owned();
        let name = config_file.file_name().ok_or_else(bad)?.to_owned();
        let file = config_file.to_owned();

        let (tx, rx) = mpsc::channel::<()>();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
                Ok(event) if is_target(&event, &name) && !event.kind.is_access() => {
                    // The receiver is gone only while shutting down.
                    let _ = tx.send(());
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "config watcher error"),
            }
        })
        .map_err(WatchError::Notify)?;
        watcher
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(WatchError::Notify)?;

        thread::Builder::new()
            .name("sverb-config-watch".to_owned())
            .spawn(move || debounce_loop(&rx, &file, &validators, last_good, &sink))
            .map_err(WatchError::Thread)?;

        Ok(Self { _watcher: watcher })
    }
}

/// Runs until the watcher (and with it the sender) is dropped.
fn debounce_loop(
    rx: &mpsc::Receiver<()>,
    file: &Path,
    validators: &Validators,
    mut last_good: Arc<Config>,
    sink: &dyn Fn(ConfigEvent),
) {
    while rx.recv().is_ok() {
        loop {
            match rx.recv_timeout(DEBOUNCE) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        let event = if file.exists() {
            let outcome = Config::reload(file, validators, &last_good);
            if outcome.is_ok() {
                last_good = Arc::new(outcome.config);
                ConfigEvent::Reloaded {
                    config: Arc::clone(&last_good),
                    warnings: outcome.warnings,
                }
            } else {
                ConfigEvent::Invalid(outcome.errors)
            }
        } else {
            last_good = Arc::new(Config::default());
            ConfigEvent::Removed
        };
        tracing::debug!(?event, "config reloaded");
        sink(event);
    }
}

#[cfg(test)]
mod tests {
    //! T-15..T-19: real file system events under a temporary `SVERB_HOME`.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::mpsc::Receiver;

    use super::*;
    use crate::config::{ConfigUpdate, LiveConfig};
    use crate::paths::{DirKind, MapEnv, Paths};

    struct Home {
        root: PathBuf,
        paths: Paths,
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn home(tag: &str) -> Home {
        let root =
            std::env::temp_dir().join(format!("sverb-config-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let env = MapEnv::new()
            .var("SVERB_HOME", root.as_os_str())
            .home(&root);
        let paths = Paths::resolve(&env).unwrap();
        paths.ensure(DirKind::Config).unwrap();
        Home { root, paths }
    }

    fn start(h: &Home) -> (ConfigWatcher, Receiver<ConfigEvent>) {
        let (tx, rx) = mpsc::channel();
        let w = ConfigWatcher::spawn(
            &h.paths.config_file(),
            Validators::default(),
            Arc::new(Config::default()),
            move |e| {
                let _ = tx.send(e);
            },
        )
        .unwrap();
        // Let the OS watch settle before the first write.
        thread::sleep(Duration::from_millis(50));
        (w, rx)
    }

    fn next(rx: &Receiver<ConfigEvent>) -> ConfigEvent {
        rx.recv_timeout(Duration::from_secs(1))
            .expect("no config event within 1 s")
    }

    fn reloaded_theme(e: &ConfigEvent) -> String {
        match e {
            ConfigEvent::Reloaded { config, .. } => config.ui.theme.clone(),
            other => panic!("expected Reloaded, got {other:?}"),
        }
    }

    #[test]
    fn t15_t16_valid_then_invalid_keeps_last_good() {
        let h = home("t15");
        let (_w, rx) = start(&h);
        let mut live = LiveConfig::default();

        std::fs::write(h.paths.config_file(), "[ui]\ntheme = \"default-light\"\n").unwrap();
        let e = next(&rx);
        assert_eq!(reloaded_theme(&e), "default-light");
        assert!(matches!(live.apply(e), ConfigUpdate::Applied { .. }));

        std::fs::write(h.paths.config_file(), "[[[").unwrap();
        let e = next(&rx);
        assert!(
            matches!(&e, ConfigEvent::Invalid(errs) if !errs.is_empty()),
            "{e:?}"
        );
        assert!(matches!(live.apply(e), ConfigUpdate::Rejected(_)));
        assert_eq!(live.current().ui.theme, "default-light");
    }

    #[test]
    fn t17_rename_save_is_detected() {
        let h = home("t17");
        let (_w, rx) = start(&h);
        let swp = h.paths.config_dir().join("config.toml.swp");
        std::fs::write(&swp, "[ui]\ntheme = \"default-light\"\n").unwrap();
        std::fs::rename(&swp, h.paths.config_file()).unwrap();
        assert_eq!(reloaded_theme(&next(&rx)), "default-light");
    }

    #[test]
    fn t18_burst_of_writes_is_one_event() {
        let h = home("t18");
        let (_w, rx) = start(&h);
        for i in 0..5 {
            std::fs::write(
                h.paths.config_file(),
                format!("[ssh]\nkeepalive_secs = {}\n", 10 + i),
            )
            .unwrap();
            thread::sleep(Duration::from_millis(20));
        }
        match next(&rx) {
            ConfigEvent::Reloaded { config, .. } => assert_eq!(config.ssh.keepalive_secs, 14),
            other => panic!("expected Reloaded, got {other:?}"),
        }
        assert!(
            rx.recv_timeout(DEBOUNCE * 3).is_err(),
            "more than one event for one burst"
        );
    }

    #[test]
    fn t19_removal_reverts_to_defaults() {
        let h = home("t19");
        std::fs::write(h.paths.config_file(), "[ui]\ntheme = \"default-light\"\n").unwrap();
        let (_w, rx) = start(&h);
        let mut live = LiveConfig::default();
        std::fs::write(
            h.paths.config_file(),
            "[ui]\ntheme = \"default-light\"\nmouse = false\n",
        )
        .unwrap();
        live.apply(next(&rx));
        assert_eq!(live.current().ui.theme, "default-light");

        std::fs::remove_file(h.paths.config_file()).unwrap();
        let e = next(&rx);
        assert_eq!(e, ConfigEvent::Removed);
        live.apply(e);
        assert_eq!(**live.current(), Config::default());
    }

    #[test]
    fn missing_dir_is_an_error_not_a_panic() {
        let r = ConfigWatcher::spawn(
            Path::new("/nonexistent-sverb-dir/config.toml"),
            Validators::default(),
            Arc::new(Config::default()),
            |_| {},
        );
        assert!(r.is_err());
    }
}
