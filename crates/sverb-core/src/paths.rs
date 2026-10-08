//! Where sverb keeps its files on disk (SPEC §5.1).
//!
//! [`Paths`] is a value object: it is resolved **once** at startup with
//! [`Paths::resolve`] and then passed explicitly to whatever needs it (logging,
//! config, the store, the agent). There are deliberately no global statics, so
//! tests can resolve as many independent homes as they like in one process.
//!
//! The environment is injected through [`EnvSource`]. Production code uses
//! [`SystemEnv`]; tests use [`MapEnv`]. The per-platform rules are selected by
//! [`Platform`], so the Linux/XDG, macOS and Windows layouts can all be
//! exercised on any host with [`Paths::resolve_for`].
//!
//! | Root | Linux / other Unix | macOS | Windows |
//! |---|---|---|---|
//! | config | `$XDG_CONFIG_HOME/sverb` or `~/.config/sverb` | `~/Library/Application Support/sverb` | `%APPDATA%\sverb` |
//! | data | `$XDG_DATA_HOME/sverb` or `~/.local/share/sverb` | `~/Library/Application Support/sverb` | `%LOCALAPPDATA%\sverb` |
//! | state | `$XDG_STATE_HOME/sverb` or `~/.local/state/sverb` | `~/Library/Logs/sverb` | `%LOCALAPPDATA%\sverb\state` |
//! | runtime | `$XDG_RUNTIME_DIR/sverb` | `$TMPDIR/sverb` | none (named pipe) |
//!
//! `SVERB_HOME=P` overrides all of them with `P/config`, `P/data`, `P/state`
//! and `P/run`.

use std::{
    collections::HashMap,
    ffi::OsString,
    fmt, io,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Name of the directory appended to every platform base directory.
const APP_DIR: &str = "sverb";

/// Environment variable that relocates every sverb directory.
pub const SVERB_HOME_ENV: &str = "SVERB_HOME";

/// Base name of the Windows named pipe the built-in agent listens on.
const PIPE_BASE: &str = r"\\.\pipe\sverb-agent";

/// Errors from [`Paths::resolve`].
#[derive(Debug, Error)]
pub enum PathsError {
    /// Neither a home directory nor `SVERB_HOME` is available.
    #[error(
        "could not determine your home directory; set SVERB_HOME to the directory \
         where sverb should keep its config, data and logs"
    )]
    NoHome,
    /// `SVERB_HOME` is relative and could not be made absolute.
    #[error("SVERB_HOME ({}) could not be made absolute: {source}", path.display())]
    InvalidHome {
        /// The value of `SVERB_HOME`.
        path: PathBuf,
        /// Why it could not be resolved.
        #[source]
        source: io::Error,
    },
}

/// Non-fatal findings from [`Paths::resolve`].
///
/// Paths are resolved before logging is initialized, so they are returned as
/// values (see [`Paths::warnings`]) for the caller to log once it can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathsWarning {
    /// `XDG_RUNTIME_DIR` is not set; the runtime directory falls back to a
    /// per-user directory under the system temp dir.
    NoXdgRuntimeDir {
        /// The directory used instead.
        fallback: PathBuf,
    },
}

impl fmt::Display for PathsWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoXdgRuntimeDir { fallback } => write!(
                f,
                "XDG_RUNTIME_DIR is not set; using {} for the runtime directory",
                fallback.display()
            ),
        }
    }
}

/// Source of environment information for [`Paths::resolve`].
///
/// [`SystemEnv`] reads the real process environment; [`MapEnv`] is an
/// in-memory map for tests.
pub trait EnvSource {
    /// Value of an environment variable, or `None` when unset.
    fn var(&self, key: &str) -> Option<OsString>;

    /// The user's home directory, or `None` when it cannot be determined.
    fn home_dir(&self) -> Option<PathBuf>;

    /// The effective user id (Unix). `None` where it is unknown or meaningless.
    fn uid(&self) -> Option<u32>;

    /// Windows roaming application data (`%APPDATA%`).
    fn roaming_app_data(&self) -> Option<PathBuf> {
        absolute_var(self, "APPDATA")
    }

    /// Windows local application data (`%LOCALAPPDATA%`).
    fn local_app_data(&self) -> Option<PathBuf> {
        absolute_var(self, "LOCALAPPDATA")
    }
}

/// The real process environment, backed by [`directories::BaseDirs`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl EnvSource for SystemEnv {
    fn var(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }

    fn home_dir(&self) -> Option<PathBuf> {
        directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
    }

    fn uid(&self) -> Option<u32> {
        current_uid()
    }

    fn roaming_app_data(&self) -> Option<PathBuf> {
        directories::BaseDirs::new().map(|b| b.config_dir().to_path_buf())
    }

    fn local_app_data(&self) -> Option<PathBuf> {
        directories::BaseDirs::new().map(|b| b.data_local_dir().to_path_buf())
    }
}

/// An in-memory environment for tests.
///
/// `home_dir` is taken from the `HOME` variable unless set explicitly with
/// [`MapEnv::home`].
#[derive(Debug, Clone, Default)]
pub struct MapEnv {
    vars: HashMap<String, OsString>,
    home: Option<PathBuf>,
    uid: Option<u32>,
}

impl MapEnv {
    /// An empty environment: no variables, no home, no uid.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a variable.
    #[must_use]
    pub fn var(mut self, key: impl Into<String>, value: impl Into<OsString>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }

    /// Set the home directory explicitly (otherwise `HOME` is used).
    #[must_use]
    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Set the user id.
    #[must_use]
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }
}

impl EnvSource for MapEnv {
    fn var(&self, key: &str) -> Option<OsString> {
        self.vars.get(key).cloned()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home.clone().or_else(|| absolute_var(self, "HOME"))
    }

    fn uid(&self) -> Option<u32> {
        self.uid
    }
}

/// Which platform's directory conventions to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux and other Unix systems: XDG base directories.
    Xdg,
    /// macOS: `~/Library/...`.
    MacOs,
    /// Windows: known folders and a named pipe for the agent.
    Windows,
}

impl Platform {
    /// The platform this binary was compiled for.
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Xdg
        }
    }
}

/// One of the four directory roots, for [`Paths::ensure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirKind {
    /// [`Paths::config_dir`].
    Config,
    /// [`Paths::data_dir`].
    Data,
    /// [`Paths::state_dir`].
    State,
    /// [`Paths::runtime_dir`]. Must be private: it holds the agent socket.
    Run,
}

/// Where the built-in SSH agent listens (SPEC §6.1.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEndpoint {
    /// A Unix domain socket path.
    UnixSocket(PathBuf),
    /// A Windows named pipe name, e.g. `\\.\pipe\sverb-agent`.
    NamedPipe(String),
}

impl fmt::Display for AgentEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnixSocket(p) => write!(f, "{}", p.display()),
            Self::NamedPipe(name) => f.write_str(name),
        }
    }
}

/// The resolved sverb directories. See the [module docs](self) for the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    config_dir: PathBuf,
    data_dir: PathBuf,
    state_dir: PathBuf,
    runtime_dir: Option<PathBuf>,
    agent_endpoint: AgentEndpoint,
    sverb_home: Option<PathBuf>,
    uid: Option<u32>,
    warnings: Vec<PathsWarning>,
}

impl Paths {
    /// Resolve the directories for the current platform from `env`.
    pub fn resolve(env: &dyn EnvSource) -> Result<Self, PathsError> {
        Self::resolve_for(env, Platform::current())
    }

    /// Resolve the directories using `platform`'s conventions.
    ///
    /// Mostly useful for tests: it lets every platform's rules run on any host.
    pub fn resolve_for(env: &dyn EnvSource, platform: Platform) -> Result<Self, PathsError> {
        let uid = env.uid();
        if let Some(home) = non_empty_var(env, SVERB_HOME_ENV) {
            return Self::from_sverb_home(PathBuf::from(home), platform, uid);
        }
        match platform {
            Platform::Xdg => Self::resolve_xdg(env, uid),
            Platform::MacOs => Self::resolve_macos(env, uid),
            Platform::Windows => Self::resolve_windows(env, uid),
        }
    }

    fn from_sverb_home(
        home: PathBuf,
        platform: Platform,
        uid: Option<u32>,
    ) -> Result<Self, PathsError> {
        let home = if home.is_absolute() {
            home
        } else {
            std::path::absolute(&home).map_err(|source| PathsError::InvalidHome {
                path: home.clone(),
                source,
            })?
        };
        let (runtime_dir, agent_endpoint) = match platform {
            Platform::Windows => (None, AgentEndpoint::NamedPipe(pipe_name_for(&home))),
            Platform::Xdg | Platform::MacOs => {
                let run = home.join("run");
                let sock = AgentEndpoint::UnixSocket(run.join("agent.sock"));
                (Some(run), sock)
            }
        };
        Ok(Self {
            config_dir: home.join("config"),
            data_dir: home.join("data"),
            state_dir: home.join("state"),
            runtime_dir,
            agent_endpoint,
            sverb_home: Some(home),
            uid,
            warnings: Vec::new(),
        })
    }

    fn resolve_xdg(env: &dyn EnvSource, uid: Option<u32>) -> Result<Self, PathsError> {
        let home = env.home_dir().ok_or(PathsError::NoHome)?;
        let base = |var: &str, default: &[&str]| -> PathBuf {
            absolute_var(env, var)
                .unwrap_or_else(|| default.iter().fold(home.clone(), |p, s| p.join(s)))
        };
        let config_dir = base("XDG_CONFIG_HOME", &[".config"]).join(APP_DIR);
        let data_dir = base("XDG_DATA_HOME", &[".local", "share"]).join(APP_DIR);
        let state_dir = base("XDG_STATE_HOME", &[".local", "state"]).join(APP_DIR);

        let mut warnings = Vec::new();
        let runtime_dir = match absolute_var(env, "XDG_RUNTIME_DIR") {
            Some(dir) => dir.join(APP_DIR),
            None => {
                let tmp = absolute_var(env, "TMPDIR").unwrap_or_else(|| PathBuf::from("/tmp"));
                let name = match uid {
                    Some(uid) => format!("{APP_DIR}-{uid}"),
                    None => APP_DIR.to_owned(),
                };
                let fallback = tmp.join(name);
                warnings.push(PathsWarning::NoXdgRuntimeDir {
                    fallback: fallback.clone(),
                });
                fallback
            }
        };
        Ok(Self::unix(
            config_dir,
            data_dir,
            state_dir,
            runtime_dir,
            uid,
            warnings,
        ))
    }

    fn resolve_macos(env: &dyn EnvSource, uid: Option<u32>) -> Result<Self, PathsError> {
        let home = env.home_dir().ok_or(PathsError::NoHome)?;
        let library = home.join("Library");
        let app_support = library.join("Application Support").join(APP_DIR);
        let state_dir = library.join("Logs").join(APP_DIR);
        let tmp = absolute_var(env, "TMPDIR").unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(Self::unix(
            app_support.clone(),
            app_support,
            state_dir,
            tmp.join(APP_DIR),
            uid,
            Vec::new(),
        ))
    }

    fn resolve_windows(env: &dyn EnvSource, uid: Option<u32>) -> Result<Self, PathsError> {
        let roaming = env.roaming_app_data().ok_or(PathsError::NoHome)?;
        let local = env.local_app_data().ok_or(PathsError::NoHome)?;
        let data_dir = local.join(APP_DIR);
        Ok(Self {
            config_dir: roaming.join(APP_DIR),
            state_dir: data_dir.join("state"),
            data_dir,
            runtime_dir: None,
            agent_endpoint: AgentEndpoint::NamedPipe(PIPE_BASE.to_owned()),
            sverb_home: None,
            uid,
            warnings: Vec::new(),
        })
    }

    fn unix(
        config_dir: PathBuf,
        data_dir: PathBuf,
        state_dir: PathBuf,
        runtime_dir: PathBuf,
        uid: Option<u32>,
        warnings: Vec<PathsWarning>,
    ) -> Self {
        Self {
            config_dir,
            data_dir,
            state_dir,
            agent_endpoint: AgentEndpoint::UnixSocket(runtime_dir.join("agent.sock")),
            runtime_dir: Some(runtime_dir),
            sverb_home: None,
            uid,
            warnings,
        }
    }

    /// Directory holding `config.toml` and `themes/`.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// `config_dir/config.toml`.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// `config_dir/themes`.
    pub fn themes_dir(&self) -> PathBuf {
        self.config_dir.join("themes")
    }

    /// Directory holding the database.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// `data_dir/sverb.db`.
    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join("sverb.db")
    }

    /// Directory for logs, recordings and crash reports.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Directory for log files (the state dir itself).
    pub fn log_dir(&self) -> &Path {
        &self.state_dir
    }

    /// `state_dir/recordings`.
    pub fn recordings_dir(&self) -> PathBuf {
        self.state_dir.join("recordings")
    }

    /// `state_dir/crash`.
    pub fn crash_dir(&self) -> PathBuf {
        self.state_dir.join("crash")
    }

    /// Private directory for the agent socket. `None` on Windows.
    pub fn runtime_dir(&self) -> Option<&Path> {
        self.runtime_dir.as_deref()
    }

    /// Where the built-in agent listens.
    pub fn agent_endpoint(&self) -> &AgentEndpoint {
        &self.agent_endpoint
    }

    /// The `SVERB_HOME` in effect, if any.
    pub fn sverb_home(&self) -> Option<&Path> {
        self.sverb_home.as_deref()
    }

    /// Non-fatal findings from resolution, to be logged once logging is up.
    pub fn warnings(&self) -> &[PathsWarning] {
        &self.warnings
    }

    /// The directory for `which`, or `None` (the runtime dir on Windows).
    pub fn dir(&self, which: DirKind) -> Option<&Path> {
        match which {
            DirKind::Config => Some(&self.config_dir),
            DirKind::Data => Some(&self.data_dir),
            DirKind::State => Some(&self.state_dir),
            DirKind::Run => self.runtime_dir.as_deref(),
        }
    }

    /// A human-readable summary of the four roots, for `--version`.
    pub fn describe(&self) -> String {
        let runtime = match &self.runtime_dir {
            Some(dir) => dir.display().to_string(),
            None => format!("(none; agent pipe {})", self.agent_endpoint),
        };
        let home = match &self.sverb_home {
            Some(home) => format!("in effect ({})", home.display()),
            None => "not set".to_owned(),
        };
        format!(
            "Config directory:  {}\n\
             Data directory:    {}\n\
             State directory:   {}\n\
             Runtime directory: {runtime}\n\
             SVERB_HOME:        {home}",
            self.config_dir.display(),
            self.data_dir.display(),
            self.state_dir.display(),
        )
    }

    /// Create the directory for `which` if it does not exist yet.
    ///
    /// On Unix new directories get mode `0700`. An existing runtime directory
    /// that is accessible by group/others, not owned by the current user, or not
    /// a real directory is refused with [`io::ErrorKind::PermissionDenied`],
    /// because it will hold the agent socket (SPEC §6.1.6). For the other
    /// directories such problems are only logged as warnings. Permissions of
    /// existing directories (including a user-provided `SVERB_HOME` root) are
    /// never changed.
    ///
    /// On Windows the directory inherits the profile ACLs, and `Run` is a no-op.
    pub fn ensure(&self, which: DirKind) -> io::Result<()> {
        let Some(dir) = self.dir(which) else {
            return Ok(());
        };
        ensure_dir(dir, which, self.uid)
    }
}

#[cfg(unix)]
fn ensure_dir(dir: &Path, which: DirKind, uid: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    // The runtime dir must be a real directory, so symlinks are not followed
    // there; elsewhere a symlinked directory (e.g. dotfiles) is fine.
    let meta = if which == DirKind::Run {
        std::fs::symlink_metadata(dir)?
    } else {
        std::fs::metadata(dir)?
    };
    if !meta.file_type().is_dir() {
        let kind = if which == DirKind::Run {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::NotADirectory
        };
        return Err(io::Error::new(
            kind,
            format!("{} is not a directory", dir.display()),
        ));
    }
    let mut problems = Vec::new();
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        problems.push(format!("has mode {mode:04o}, expected 0700"));
    }
    if let Some(uid) = uid
        && meta.uid() != uid
    {
        problems.push(format!("is owned by uid {}, not {uid}", meta.uid()));
    }
    if problems.is_empty() {
        return Ok(());
    }
    let msg = format!("{} {}", dir.display(), problems.join(" and "));
    if which == DirKind::Run {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to use insecure runtime directory: {msg}"),
        ));
    }
    tracing::warn!("sverb directory {msg}");
    Ok(())
}

#[cfg(not(unix))]
fn ensure_dir(dir: &Path, _which: DirKind, _uid: Option<u32>) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// The effective uid of this process, without `unsafe`.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    // Linux and most BSDs with procfs: /proc/self is owned by the process' euid.
    if let Ok(meta) = std::fs::metadata("/proc/self") {
        return Some(meta.uid());
    }
    // Elsewhere, create a probe file and read its owner.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let probe =
        std::env::temp_dir().join(format!(".sverb-uid-probe-{}-{nanos}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .ok()?;
    let uid = file.metadata().ok().map(|m| m.uid());
    drop(file);
    let _ = std::fs::remove_file(&probe);
    uid
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// `\\.\pipe\sverb-agent-<first 8 hex digits of sha256(home)>`.
fn pipe_name_for(home: &Path) -> String {
    let digest = Sha256::digest(home.as_os_str().as_encoded_bytes());
    let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{PIPE_BASE}-{hex}")
}

fn non_empty_var(env: &(impl EnvSource + ?Sized), key: &str) -> Option<OsString> {
    env.var(key).filter(|v| !v.is_empty())
}

/// A variable holding an absolute path. Relative values are ignored, as the
/// XDG base directory specification requires.
fn absolute_var(env: &(impl EnvSource + ?Sized), key: &str) -> Option<PathBuf> {
    non_empty_var(env, key)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn assert_all_absolute(paths: &Paths) {
        for dir in [paths.config_dir(), paths.data_dir(), paths.state_dir()] {
            assert!(dir.is_absolute(), "{} is relative", dir.display());
        }
        if let Some(run) = paths.runtime_dir() {
            assert!(run.is_absolute(), "{} is relative", run.display());
        }
    }

    // T-01
    #[test]
    fn sverb_home_overrides_everything() -> TestResult {
        let env = MapEnv::new()
            .var("SVERB_HOME", "/h")
            .var("HOME", "/home/u")
            .var("XDG_CONFIG_HOME", "/c")
            .var("XDG_RUNTIME_DIR", "/r");
        for platform in [Platform::Xdg, Platform::MacOs] {
            let paths = Paths::resolve_for(&env, platform)?;
            assert_eq!(paths.config_dir(), p("/h/config"));
            assert_eq!(paths.data_dir(), p("/h/data"));
            assert_eq!(paths.state_dir(), p("/h/state"));
            assert_eq!(paths.runtime_dir(), Some(p("/h/run").as_path()));
            assert_eq!(paths.db_file(), p("/h/data/sverb.db"));
            assert_eq!(paths.config_file(), p("/h/config/config.toml"));
            assert_eq!(
                paths.agent_endpoint(),
                &AgentEndpoint::UnixSocket(p("/h/run/agent.sock"))
            );
            assert_eq!(paths.sverb_home(), Some(p("/h").as_path()));
            assert!(paths.warnings().is_empty());
        }
        Ok(())
    }

    // T-02
    #[test]
    fn linux_defaults() -> TestResult {
        let env = MapEnv::new()
            .var("HOME", "/home/u")
            .var("XDG_RUNTIME_DIR", "/run/user/1000");
        let paths = Paths::resolve_for(&env, Platform::Xdg)?;
        assert_eq!(paths.config_dir(), p("/home/u/.config/sverb"));
        assert_eq!(paths.data_dir(), p("/home/u/.local/share/sverb"));
        assert_eq!(paths.state_dir(), p("/home/u/.local/state/sverb"));
        assert_eq!(paths.log_dir(), p("/home/u/.local/state/sverb"));
        assert_eq!(
            paths.recordings_dir(),
            p("/home/u/.local/state/sverb/recordings")
        );
        assert_eq!(paths.crash_dir(), p("/home/u/.local/state/sverb/crash"));
        assert_eq!(paths.themes_dir(), p("/home/u/.config/sverb/themes"));
        assert_eq!(paths.sverb_home(), None);
        Ok(())
    }

    // T-03
    #[test]
    fn xdg_overrides() -> TestResult {
        let env = MapEnv::new()
            .var("HOME", "/home/u")
            .var("XDG_CONFIG_HOME", "/c")
            .var("XDG_DATA_HOME", "/d")
            .var("XDG_STATE_HOME", "/s")
            .var("XDG_RUNTIME_DIR", "/r");
        let paths = Paths::resolve_for(&env, Platform::Xdg)?;
        assert_eq!(paths.config_dir(), p("/c/sverb"));
        assert_eq!(paths.data_dir(), p("/d/sverb"));
        assert_eq!(paths.state_dir(), p("/s/sverb"));
        assert_eq!(paths.runtime_dir(), Some(p("/r/sverb").as_path()));
        assert_eq!(
            paths.agent_endpoint(),
            &AgentEndpoint::UnixSocket(p("/r/sverb/agent.sock"))
        );
        assert!(paths.warnings().is_empty());
        Ok(())
    }

    #[test]
    fn relative_xdg_values_are_ignored() -> TestResult {
        let env = MapEnv::new()
            .var("HOME", "/home/u")
            .var("XDG_CONFIG_HOME", "relative")
            .var("XDG_DATA_HOME", "")
            .var("XDG_RUNTIME_DIR", "/r");
        let paths = Paths::resolve_for(&env, Platform::Xdg)?;
        assert_eq!(paths.config_dir(), p("/home/u/.config/sverb"));
        assert_eq!(paths.data_dir(), p("/home/u/.local/share/sverb"));
        Ok(())
    }

    // T-04
    #[test]
    fn missing_runtime_dir_falls_back_with_warning() -> TestResult {
        let env = MapEnv::new().var("HOME", "/home/u").uid(1000);
        let paths = Paths::resolve_for(&env, Platform::Xdg)?;
        assert_eq!(paths.runtime_dir(), Some(p("/tmp/sverb-1000").as_path()));
        assert_eq!(
            paths.warnings(),
            &[PathsWarning::NoXdgRuntimeDir {
                fallback: p("/tmp/sverb-1000")
            }]
        );

        let env = env.var("TMPDIR", "/var/tmp");
        let paths = Paths::resolve_for(&env, Platform::Xdg)?;
        assert_eq!(
            paths.runtime_dir(),
            Some(p("/var/tmp/sverb-1000").as_path())
        );
        Ok(())
    }

    // T-05
    #[test]
    fn no_home_is_an_error_mentioning_sverb_home() {
        let env = MapEnv::new().var("XDG_CONFIG_HOME", "/c").uid(1000);
        for platform in [Platform::Xdg, Platform::MacOs, Platform::Windows] {
            match Paths::resolve_for(&env, platform) {
                Ok(paths) => panic!("expected an error, got {paths:?}"),
                Err(e) => assert!(e.to_string().contains("SVERB_HOME"), "{e}"),
            }
        }
    }

    #[test]
    fn resolved_paths_are_never_relative() -> TestResult {
        let envs = [
            MapEnv::new().var("HOME", "/home/u").uid(1),
            MapEnv::new().var("SVERB_HOME", "relative/home"),
            MapEnv::new()
                .var("HOME", "/home/u")
                .var("XDG_STATE_HOME", "s")
                .var("TMPDIR", "t"),
        ];
        for env in &envs {
            assert_all_absolute(&Paths::resolve_for(env, Platform::Xdg)?);
            assert_all_absolute(&Paths::resolve_for(env, Platform::MacOs)?);
        }
        Ok(())
    }

    #[test]
    fn macos_layout() -> TestResult {
        let env = MapEnv::new()
            .var("HOME", "/Users/u")
            .var("TMPDIR", "/var/folders/x/T");
        let paths = Paths::resolve_for(&env, Platform::MacOs)?;
        let support = p("/Users/u/Library/Application Support/sverb");
        assert_eq!(paths.config_dir(), support);
        assert_eq!(paths.data_dir(), support);
        assert_eq!(paths.state_dir(), p("/Users/u/Library/Logs/sverb"));
        assert_eq!(
            paths.runtime_dir(),
            Some(p("/var/folders/x/T/sverb").as_path())
        );
        Ok(())
    }

    #[test]
    fn windows_layout() -> TestResult {
        let env = MapEnv::new()
            .var("APPDATA", "/Users/u/AppData/Roaming")
            .var("LOCALAPPDATA", "/Users/u/AppData/Local");
        let paths = Paths::resolve_for(&env, Platform::Windows)?;
        assert_eq!(paths.config_dir(), p("/Users/u/AppData/Roaming/sverb"));
        assert_eq!(paths.data_dir(), p("/Users/u/AppData/Local/sverb"));
        assert_eq!(paths.state_dir(), p("/Users/u/AppData/Local/sverb/state"));
        assert_eq!(paths.runtime_dir(), None);
        assert_eq!(
            paths.agent_endpoint(),
            &AgentEndpoint::NamedPipe(r"\\.\pipe\sverb-agent".to_owned())
        );
        Ok(())
    }

    #[test]
    fn windows_sverb_home_pipe_names_differ() -> TestResult {
        let a = Paths::resolve_for(&MapEnv::new().var("SVERB_HOME", "/a"), Platform::Windows)?;
        let b = Paths::resolve_for(&MapEnv::new().var("SVERB_HOME", "/b"), Platform::Windows)?;
        let (AgentEndpoint::NamedPipe(pa), AgentEndpoint::NamedPipe(pb)) =
            (a.agent_endpoint(), b.agent_endpoint())
        else {
            panic!("expected named pipes");
        };
        assert_ne!(pa, pb);
        for name in [pa, pb] {
            let suffix = name
                .strip_prefix(r"\\.\pipe\sverb-agent-")
                .ok_or("missing pipe prefix")?;
            assert_eq!(suffix.len(), 8);
            assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        }
        assert_eq!(a.runtime_dir(), None);
        Ok(())
    }

    #[test]
    fn describe_lists_all_roots() -> TestResult {
        let paths = Paths::resolve_for(&MapEnv::new().var("SVERB_HOME", "/h"), Platform::Xdg)?;
        let text = paths.describe();
        for needle in [
            "/h/config",
            "/h/data",
            "/h/state",
            "/h/run",
            "SVERB_HOME",
            "in effect",
        ] {
            assert!(text.contains(needle), "{needle} missing from {text}");
        }
        let paths = Paths::resolve_for(
            &MapEnv::new()
                .var("HOME", "/home/u")
                .var("XDG_RUNTIME_DIR", "/r"),
            Platform::Xdg,
        )?;
        assert!(paths.describe().contains("not set"));
        Ok(())
    }

    // T-06
    #[cfg(target_os = "macos")]
    #[test]
    fn real_macos_resolution() -> TestResult {
        let paths = Paths::resolve(&WithoutSverbHome)?;
        assert!(
            paths
                .config_dir()
                .ends_with("Library/Application Support/sverb")
        );
        assert!(
            paths
                .data_dir()
                .ends_with("Library/Application Support/sverb")
        );
        assert!(paths.state_dir().ends_with("Library/Logs/sverb"));
        Ok(())
    }

    // T-07
    #[cfg(windows)]
    #[test]
    fn real_windows_resolution() -> TestResult {
        let paths = Paths::resolve(&WithoutSverbHome)?;
        let appdata = PathBuf::from(std::env::var_os("APPDATA").ok_or("APPDATA unset")?);
        let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA unset")?);
        assert_eq!(paths.config_dir(), appdata.join("sverb"));
        assert_eq!(paths.data_dir(), local.join("sverb"));
        let AgentEndpoint::NamedPipe(name) = paths.agent_endpoint() else {
            panic!("expected a named pipe");
        };
        assert!(name.starts_with(r"\\.\pipe\sverb-agent"));
        Ok(())
    }

    // T-08
    #[cfg(windows)]
    #[test]
    fn real_windows_sverb_homes_get_distinct_pipes() -> TestResult {
        let a = Paths::resolve(&MapEnv::new().var("SVERB_HOME", r"C:\sverb-a"))?;
        let b = Paths::resolve(&MapEnv::new().var("SVERB_HOME", r"C:\sverb-b"))?;
        assert_ne!(a.agent_endpoint(), b.agent_endpoint());
        Ok(())
    }

    /// The real environment with `SVERB_HOME` hidden.
    #[cfg(any(target_os = "macos", windows))]
    struct WithoutSverbHome;

    #[cfg(any(target_os = "macos", windows))]
    impl EnvSource for WithoutSverbHome {
        fn var(&self, key: &str) -> Option<OsString> {
            (key != SVERB_HOME_ENV)
                .then(|| SystemEnv.var(key))
                .flatten()
        }
        fn home_dir(&self) -> Option<PathBuf> {
            SystemEnv.home_dir()
        }
        fn uid(&self) -> Option<u32> {
            SystemEnv.uid()
        }
        fn roaming_app_data(&self) -> Option<PathBuf> {
            SystemEnv.roaming_app_data()
        }
        fn local_app_data(&self) -> Option<PathBuf> {
            SystemEnv.local_app_data()
        }
    }

    // T-11
    #[cfg(unix)]
    #[test]
    fn non_utf8_sverb_home_resolves() -> TestResult {
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(b"/tmp/sverb-\xff\xfe-home".to_vec());
        let env = MapEnv::new().var("SVERB_HOME", raw.clone());
        let paths = Paths::resolve_for(&env, Platform::Xdg)?;
        assert_eq!(paths.data_dir(), PathBuf::from(&raw).join("data"));
        assert!(paths.data_dir().to_str().is_none());
        let _ = paths.describe();
        let windows = Paths::resolve_for(&env, Platform::Windows)?;
        assert!(matches!(
            windows.agent_endpoint(),
            AgentEndpoint::NamedPipe(_)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn system_env_reports_a_uid() {
        assert!(SystemEnv.uid().is_some());
    }
}
