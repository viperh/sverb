//! M7-01: the static completion set of common commands (SPEC §9.10): coreutils, git,
//! docker, kubectl and systemctl subcommands, shipped as `static_commands.txt`.

use std::sync::OnceLock;

const RAW: &str = include_str!("static_commands.txt");

/// The common commands, in file order, without duplicates.
pub fn static_commands() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        let mut seen = std::collections::HashSet::new();
        RAW.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| seen.insert(*l))
            .collect()
    })
}
