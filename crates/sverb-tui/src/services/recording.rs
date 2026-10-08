//! M3-05: the recording service (`Effect::StartRecording` / `StopRecording`, SPEC §7.5).
//!
//! Starting a recording:
//! 1. derive the recording key from the unlocked vault's LMK ([`recording_key`],
//!    `HKDF(LMK, "sverb/recording/v1")`); a locked vault fails the start,
//! 2. create `state_dir/recordings/<conn_id>.cast.sv` (0600, directory 0700); M3-06: the
//!    `conn_id` is the session's ConnLog id (`ConnLogService::recording_id`), and the
//!    file is recorded in `device_local.recording_dir` under that id,
//! 3. start the writer task (`sverb_term::recording::spawn_recorder`) and send its tap to
//!    the session (`SessionCmd::AttachRecorder`),
//! 4. report `SessionEvent::Recording(Started)`, and when the writer finishes
//!    `Stopped` (or `Failed`), through the session event channel.
//!
//! The writer holds its own copy of the key until the recording closes (zeroized on
//! drop), so locking the vault does not stop a running recording: sessions stay
//! connected while locked (SPEC §5.3), and so do their recordings.
//!
//! Replays and exports read recordings with [`open_recording`] (blocking; call it from
//! `spawn_blocking`).

use std::path::{Path, PathBuf};

use sverb_conn::{SendOutcome, SessionCmd, SessionEvent, session::event::RecordingStatus};
use sverb_core::{error_report::ErrorReport, model::ItemId};
use sverb_crypto::Key32;
use sverb_term::recording::{
    RecorderMeta, RecorderOptions, Recording, RecordingError, create_recording_file, export_plain,
    read_recording, recording_file_name, spawn_recorder,
};
use tracing::{debug, warn};

use super::{sessions::SessionService, vault::UnlockedVault};
use crate::app::SessionId;

/// The recording key of an unlocked vault: `HKDF(LMK, info = "sverb/recording/v1")`.
/// The only way the UI derives anything from the LMK for recordings.
pub fn recording_key(vault: &UnlockedVault) -> Key32 {
    sverb_crypto::recording::recording_key(vault.lmk())
}

/// What `Effect::StartRecording` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRequest {
    /// The session.
    pub id: SessionId,
    /// The reducer's token.
    pub token: u64,
    /// Header title (host label).
    pub title: String,
    /// Record input too.
    pub include_input: bool,
}

/// Starts recordings into a directory.
#[derive(Debug, Clone)]
pub struct RecordingService {
    dir: PathBuf,
}

impl RecordingService {
    /// Recordings go to `dir` (`Paths::recordings_dir`).
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The recordings directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `Effect::StartRecording`. `key` is `None` while the vault is locked.
    /// M3-06: `conn_id` names the file (the session's ConnLog id; a fresh UUIDv7 without
    /// a ConnLog service), and `on_created` learns the file's path.
    pub fn start(
        &self,
        req: StartRequest,
        key: Option<Key32>,
        conn_id: Option<ItemId>,
        on_created: impl FnOnce(ItemId, PathBuf),
        sessions: &mut SessionService,
    ) {
        let StartRequest {
            id,
            token,
            title,
            include_input,
        } = req;
        let fail = |sessions: &SessionService, msg: String| {
            warn!(session = id.0, "{msg}");
            sessions.notify(
                id,
                SessionEvent::Recording(RecordingStatus::Failed {
                    token,
                    error: ErrorReport::msg(msg),
                }),
            );
        };
        let Some(key) = key else {
            fail(sessions, "cannot record: the vault is locked".to_owned());
            return;
        };
        // M3-06
        let conn_item = conn_id.unwrap_or_else(ItemId::new);
        let conn_id = *conn_item.as_bytes();
        let (path, file) = match create_recording_file(&self.dir, &conn_id) {
            Ok(created) => created,
            Err(err) => {
                fail(sessions, format!("cannot create the recording file: {err}"));
                return;
            }
        };
        let mut opts = RecorderOptions::new(conn_id, key);
        opts.meta = RecorderMeta {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_secs()).ok()),
            term: Some("xterm-256color".to_owned()),
            title: Some(title),
            include_input,
        };
        let (tap, handle) = match spawn_recorder(file, opts) {
            Ok(started) => started,
            Err(err) => {
                fail(sessions, format!("cannot start the recording: {err}"));
                return;
            }
        };
        match sessions.command(id, SessionCmd::AttachRecorder(tap)) {
            SendOutcome::Sent => {}
            other => {
                // The tap was dropped with the command: the writer closes the file.
                fail(
                    sessions,
                    format!("cannot record: the session is gone ({other:?})"),
                );
                return;
            }
        }
        debug!(session = id.0, file = %path.display(), "recording started");
        // M3-06: `device_local.recording_dir` for the Logs view.
        on_created(conn_item, path.clone());
        sessions.notify(
            id,
            SessionEvent::Recording(RecordingStatus::Started {
                token,
                path: path.clone(),
            }),
        );
        let notices = sessions.clone_notifier();
        tokio::spawn(async move {
            let status = match handle.join.await {
                Ok(Ok(summary)) => {
                    debug!(
                        session = id.0,
                        chunks = summary.chunks,
                        dropped = summary.dropped_bytes,
                        "recording closed"
                    );
                    RecordingStatus::Stopped { token }
                }
                Ok(Err(err)) => RecordingStatus::Failed {
                    token,
                    error: ErrorReport::msg(format!("recording failed: {err}")),
                },
                Err(err) => RecordingStatus::Failed {
                    token,
                    error: ErrorReport::msg(format!("recording task failed: {err}")),
                },
            };
            notices(id, SessionEvent::Recording(status));
        });
    }

    /// `Effect::StopRecording`.
    pub fn stop(&self, id: SessionId, sessions: &mut SessionService) {
        let _ = sessions.command(id, SessionCmd::StopRecording);
    }
}

/// Resolve a recording argument: a path to an existing file, a file name in `dir`
/// (with or without `.cast.sv`), or a conn id (UUID, hyphenated or not).
pub fn resolve_recording(dir: &Path, arg: &str) -> Option<PathBuf> {
    let direct = Path::new(arg);
    if direct.is_file() {
        return Some(direct.to_path_buf());
    }
    let mut candidates = vec![dir.join(arg), dir.join(format!("{arg}.cast.sv"))];
    if let Ok(id) = arg.parse::<ItemId>() {
        candidates.push(dir.join(recording_file_name(id.as_bytes())));
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Decrypt a whole recording file (blocking).
///
/// # Errors
/// I/O, authentication and format errors.
pub fn open_recording(path: &Path, key: Key32) -> Result<Recording, RecordingError> {
    let file = std::fs::File::open(path)?;
    read_recording(std::io::BufReader::new(file), key)
}

/// Decrypt `src` into a plain asciicast v2 file `dst` (created 0600 on unix,
/// truncated if it exists; removed again if the export fails). Returns whether the
/// recording was incomplete. Blocking.
///
/// # Errors
/// I/O, authentication and format errors.
pub fn export_recording(src: &Path, dst: &Path, key: Key32) -> Result<bool, RecordingError> {
    let input = std::fs::File::open(src)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let output = opts.open(dst)?;
    let result = export_plain(
        std::io::BufReader::new(input),
        key,
        std::io::BufWriter::new(output),
    );
    if result.is_err() {
        let _ = std::fs::remove_file(dst);
    }
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn resolves_ids_names_and_paths() {
        let dir = std::env::temp_dir().join(format!("sverb-m305-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = ItemId::new();
        let name = recording_file_name(id.as_bytes());
        std::fs::write(dir.join(&name), b"x").unwrap();
        let want = Some(dir.join(&name));
        assert_eq!(resolve_recording(&dir, &id.to_string()), want);
        assert_eq!(
            resolve_recording(&dir, &id.uuid().simple().to_string()),
            want
        );
        assert_eq!(resolve_recording(&dir, &name), want);
        assert_eq!(
            resolve_recording(&dir, dir.join(&name).to_str().unwrap()),
            Some(dir.join(&name))
        );
        assert_eq!(resolve_recording(&dir, "nope"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
