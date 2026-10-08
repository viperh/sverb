//! M0-07: machine-readable output (`--json`), see `docs/cli-json.md`.
//!
//! Every `--json` document is one line: `{"version":1,"data":…}`. `version` changes
//! only on incompatible changes to a command's `data`.

use std::io::Write;

use serde::Serialize;

use super::CliError;

/// The current JSON envelope version.
pub(crate) const JSON_VERSION: u32 = 1;

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    version: u32,
    data: &'a T,
}

/// The JSON text for `data`, wrapped in the envelope (no trailing newline).
#[allow(dead_code)] // see `write_json`
pub(crate) fn to_json<T: Serialize>(data: &T) -> Result<String, CliError> {
    serde_json::to_string(&Envelope {
        version: JSON_VERSION,
        data,
    })
    .map_err(|e| CliError::failure(&e))
}

/// Print `data` as one JSON line.
#[allow(dead_code)] // M0-10 (`keys --dump --json`), M1-07 (`hosts list --json`).
pub(crate) fn write_json<T: Serialize>(out: &mut dyn Write, data: &T) -> Result<(), CliError> {
    let mut text = to_json(data)?;
    text.push('\n');
    super::write_out(out, &text)
}
