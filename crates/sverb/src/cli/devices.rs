//! M0-07: `sverb devices list | revoke <id>` (sync builds only). Bodies land in M4-09.
#![cfg(feature = "sync")]

use std::io::Write;

use clap::Subcommand;

use super::{CliError, Ctx, not_implemented};

/// `sverb devices …`
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum DevicesCmd {
    /// List this account's devices
    List,
    /// Revoke a device
    Revoke {
        /// Device id
        id: String,
    },
}

pub(crate) fn run(cmd: DevicesCmd, _ctx: &Ctx, _out: &mut dyn Write) -> Result<u8, CliError> {
    match cmd {
        DevicesCmd::List => not_implemented("devices list", "M4-09"),
        DevicesCmd::Revoke { .. } => not_implemented("devices revoke", "M4-09"),
    }
}
