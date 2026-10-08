//! M0-07: `sverb doctor [--algos]`. Body lands in M7-04 (`--algos` with M1-13).

use std::io::Write;

use clap::Args;

use super::{CliError, Ctx, not_implemented};

/// `sverb doctor …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct DoctorArgs {
    /// List the supported SSH algorithms
    #[arg(long)]
    pub algos: bool,
}

pub(crate) fn run(_args: DoctorArgs, _ctx: &Ctx, _out: &mut dyn Write) -> Result<u8, CliError> {
    not_implemented("doctor", "M7-04")
}
