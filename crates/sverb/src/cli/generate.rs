//! M7-07: `sverb generate man | completions <shell>` (hidden; SPEC §20 packaging).
//!
//! The release archives and packages ship a man page (`sverb.1`) and shell completions
//! for bash, zsh, fish and PowerShell. `clap_mangen` / `clap_complete` aren't in the
//! pinned dependency set, so both are generated here from the same clap tree that parses
//! the command line ([`super::Cli`]): a command or flag added there shows up in the man
//! page and the completions without further work.
//!
//! The output is deterministic (no dates, no git describe), so release builds are
//! reproducible and the man page is a snapshot test (T-05).

use std::fmt::Write as _;
use std::path::PathBuf;

use clap::{Arg, ArgAction, Args, CommandFactory, Subcommand, ValueEnum};

use super::{Cli, CliError, Ctx, exit, write_out};

/// `sverb generate`.
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct GenerateArgs {
    #[command(subcommand)]
    pub what: GenerateCmd,
}

/// What to generate.
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum GenerateCmd {
    /// The man page (roff), to stdout or `<dir>/sverb.1`
    Man {
        /// Write `sverb.1` into this directory instead of stdout
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
    },
    /// A shell completion script, to stdout
    Completions {
        /// The shell
        shell: Shell,
    },
}

/// Shells with completion scripts.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shell {
    /// bash (bash-completion)
    Bash,
    /// zsh (`_sverb` in `$fpath`)
    Zsh,
    /// fish (`sverb.fish` in `completions/`)
    Fish,
    /// PowerShell (`. _sverb.ps1` from the profile)
    Powershell,
}

pub(crate) fn run(
    args: GenerateArgs,
    _ctx: &Ctx,
    out: &mut dyn std::io::Write,
) -> Result<u8, CliError> {
    match args.what {
        GenerateCmd::Man { out_dir: None } => write_out(out, &man_page())?,
        GenerateCmd::Man { out_dir: Some(dir) } => {
            std::fs::create_dir_all(&dir)
                .and_then(|()| std::fs::write(dir.join("sverb.1"), man_page()))
                .map_err(|e| CliError::failure(&e))?;
        }
        GenerateCmd::Completions { shell } => write_out(out, &completions(shell))?,
    }
    Ok(exit::OK)
}

// ------------------------------------------------------------------ the tree

/// A flag or option.
#[derive(Debug, Clone)]
struct Flag {
    long: Option<String>,
    short: Option<char>,
    help: String,
    /// The value name, for options that take a value.
    value: Option<String>,
    /// Possible values (value enums).
    choices: Vec<String>,
}

/// A positional argument.
#[derive(Debug, Clone)]
struct Positional {
    name: String,
    help: String,
    required: bool,
    many: bool,
    choices: Vec<String>,
}

/// One (sub)command.
#[derive(Debug, Clone)]
struct Node {
    /// `["sverb", "hosts", "list"]`.
    path: Vec<String>,
    about: String,
    flags: Vec<Flag>,
    positionals: Vec<Positional>,
    subs: Vec<Node>,
    /// A subcommand must be given (`sverb` alone opens the TUI, `sverb hosts` needs one).
    sub_required: bool,
}

fn plain(s: Option<&clap::builder::StyledStr>) -> String {
    s.map(ToString::to_string)
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn choices(arg: &Arg) -> Vec<String> {
    arg.get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| v.get_name().to_owned())
        .collect()
}

fn takes_value(arg: &Arg) -> bool {
    matches!(arg.get_action(), ArgAction::Set | ArgAction::Append)
}

fn node(cmd: &clap::Command, parent: &[String]) -> Node {
    let mut path = parent.to_vec();
    path.push(cmd.get_name().to_owned());
    let mut flags = Vec::new();
    let mut positionals = Vec::new();
    for arg in cmd.get_arguments().filter(|a| !a.is_hide_set()) {
        if arg.is_positional() {
            positionals.push(Positional {
                name: arg
                    .get_value_names()
                    .and_then(|v| v.first())
                    .map_or_else(|| arg.get_id().to_string(), ToString::to_string),
                help: plain(arg.get_help()),
                required: arg.is_required_set(),
                many: matches!(arg.get_action(), ArgAction::Append)
                    || arg.get_num_args().is_some_and(|n| n.max_values() > 1),
                choices: choices(arg),
            });
        } else {
            flags.push(Flag {
                long: arg.get_long().map(str::to_owned),
                short: arg.get_short(),
                help: plain(arg.get_help()),
                value: takes_value(arg).then(|| {
                    arg.get_value_names().and_then(|v| v.first()).map_or_else(
                        || arg.get_id().to_string().to_uppercase(),
                        ToString::to_string,
                    )
                }),
                choices: choices(arg),
            });
        }
    }
    let subs = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .map(|s| node(s, &path))
        .collect();
    Node {
        path,
        about: plain(cmd.get_about()),
        flags,
        positionals,
        subs,
        sub_required: cmd.is_subcommand_required_set(),
    }
}

/// The documented command tree (hidden commands and arguments left out).
fn tree() -> Node {
    let mut cmd = Cli::command().version(env!("CARGO_PKG_VERSION"));
    cmd.build();
    node(&cmd, &[])
}

fn walk<'a>(n: &'a Node, out: &mut Vec<&'a Node>) {
    out.push(n);
    for s in &n.subs {
        walk(s, out);
    }
}

fn all_nodes(root: &Node) -> Vec<&Node> {
    let mut v = Vec::new();
    walk(root, &mut v);
    v
}

// ------------------------------------------------------------------ man page

/// Escape text for roff.
fn roff(s: &str) -> String {
    let s = s.replace('\\', "\\e").replace('-', "\\-");
    // Non-ASCII as `\[uXXXX]` (groff and mandoc both read it).
    let s: String = s
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                format!("\\[u{:04X}]", u32::from(c))
            }
        })
        .collect();
    if s.starts_with('.') || s.starts_with('\'') {
        format!("\\&{s}")
    } else {
        s
    }
}

fn synopsis(n: &Node) -> String {
    let mut s = format!("\\fB{}\\fR", roff(&n.path.join(" ")));
    if !n.flags.is_empty() {
        s.push_str(" [\\fIOPTIONS\\fR]");
    }
    for p in &n.positionals {
        let name = roff(&p.name);
        let dots = if p.many { "..." } else { "" };
        if p.required {
            let _ = write!(s, " \\fI{name}\\fR{dots}");
        } else {
            let _ = write!(s, " [\\fI{name}\\fR]{dots}");
        }
    }
    if !n.subs.is_empty() {
        s.push_str(if n.sub_required {
            " \\fICOMMAND\\fR"
        } else {
            " [\\fICOMMAND\\fR]"
        });
    }
    s
}

fn flag_lines(out: &mut String, flags: &[Flag]) {
    for f in flags {
        let mut names = Vec::new();
        if let Some(c) = f.short {
            names.push(format!("\\fB\\-{}\\fR", roff(&c.to_string())));
        }
        if let Some(l) = &f.long {
            names.push(format!("\\fB\\-\\-{}\\fR", roff(l)));
        }
        let mut head = names.join(", ");
        if let Some(v) = &f.value {
            let _ = write!(head, " \\fI{}\\fR", roff(v));
        }
        let _ = writeln!(out, ".TP\n{head}");
        let mut help = f.help.clone();
        if !f.choices.is_empty() {
            let _ = write!(help, " [possible values: {}]", f.choices.join(", "));
        }
        let _ = writeln!(out, "{}", roff(&help));
    }
}

const MAN_NAME: &str = "SSH client and server manager for the terminal";

const MAN_DESCRIPTION: &str = "sverb is a terminal-native SSH client and server manager. \
Running it without a command opens the TUI: hosts, groups, identities, keys, port \
forwards, snippets, workspaces, tabs and split panes, all kept in an encrypted local \
vault. Sync between devices, team vaults and terminal sharing need a self-hosted \
sverb-server and are optional; everything else works offline. The headless commands \
below manage the same vault from scripts; those that need it unlocked prompt for the \
master password on the terminal or use the OS keyring.";

const MAN_ENVIRONMENT: &[(&str, &str)] = &[
    (
        "SVERB_HOME",
        "Keep config, data, state and runtime files under this directory (config/, data/, state/, run/) instead of the platform directories.",
    ),
    (
        "SVERB_LOG",
        "Log filter for the log file (default info; for example debug or sverb_conn=trace). RUST_LOG is ignored.",
    ),
    (
        "SVERB_KEYRING",
        "Set to off to never use the OS keyring (the master password is always asked).",
    ),
    (
        "SVERB_EXPORT_PASSWORD",
        "The backup password for export backup and import backup in scripts (instead of a prompt).",
    ),
    (
        "NO_COLOR",
        "Any non-empty value turns colors off; focus and selection use reverse video and bold.",
    ),
    (
        "TERM, LANG, LC_ALL, LC_CTYPE",
        "With ui.ascii = \"auto\", a non-UTF-8 locale or TERM=linux selects ASCII glyphs.",
    ),
];

const MAN_FILES: &[(&str, &str)] = &[
    (
        "~/.config/sverb/config.toml",
        "The configuration (sverb config \\-\\-path prints the real location; see docs/config.md).",
    ),
    ("~/.local/share/sverb/", "The encrypted vault database."),
    (
        "~/.local/state/sverb/",
        "Logs (rotated daily, 7 kept), crash reports and encrypted session recordings.",
    ),
];

/// The man page, `sverb.1`.
pub(crate) fn man_page() -> String {
    let root = tree();
    let mut out = String::new();
    let _ = writeln!(
        out,
        ".TH SVERB 1 \"\" \"sverb {}\" \"User Commands\"",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(out, ".SH NAME\nsverb \\- {}", roff(MAN_NAME));
    let _ = writeln!(out, ".SH SYNOPSIS\n{}", synopsis(&root));
    let _ = writeln!(out, ".SH DESCRIPTION\n{}", roff(MAN_DESCRIPTION));
    out.push_str(".SH OPTIONS\n");
    flag_lines(&mut out, &root.flags);
    out.push_str(".SH COMMANDS\n");
    for n in all_nodes(&root).into_iter().skip(1) {
        let _ = writeln!(out, ".SS \"{}\"", roff(&n.path.join(" ")));
        let _ = writeln!(out, "{}\n.PP\n{}", synopsis(n), roff(&n.about));
        for p in &n.positionals {
            let mut help = p.help.clone();
            if !p.choices.is_empty() {
                let _ = write!(help, " [possible values: {}]", p.choices.join(", "));
            }
            let _ = writeln!(out, ".TP\n\\fI{}\\fR\n{}", roff(&p.name), roff(&help));
        }
        // `--help` is on every command; the root section already lists it.
        let flags: Vec<Flag> = n
            .flags
            .iter()
            .filter(|f| !matches!(f.long.as_deref(), Some("help" | "debug")))
            .cloned()
            .collect();
        flag_lines(&mut out, &flags);
    }
    out.push_str(".SH \"EXIT STATUS\"\n.nf\n");
    for line in exit::HELP.lines().skip(1) {
        let _ = writeln!(out, "{}", roff(line.trim()));
    }
    out.push_str(".fi\n.SH ENVIRONMENT\n");
    for (name, what) in MAN_ENVIRONMENT {
        let _ = writeln!(out, ".TP\n\\fB{}\\fR\n{}", roff(name), roff(what));
    }
    out.push_str(".SH FILES\n");
    for (path, what) in MAN_FILES {
        // MAN_FILES entries are written pre-escaped where needed.
        let _ = writeln!(out, ".TP\n\\fI{}\\fR\n{}", roff(path), what);
    }
    out.push_str(
        ".PP\nOn macOS the directories are under ~/Library/Application Support/sverb/, on \
         Windows under %APPDATA%\\esverb\\e and %LOCALAPPDATA%\\esverb\\e.\n",
    );
    out.push_str(
        ".SH \"SEE ALSO\"\n\\fBssh\\fR(1), \\fBssh_config\\fR(5)\n.PP\n\
         The keybindings, configuration reference, threat model and self\\-hosting guide are in \
         the docs/ directory of the source distribution.\n",
    );
    out
}

// ------------------------------------------------------------------ completions

/// The completion script for `shell`.
pub(crate) fn completions(shell: Shell) -> String {
    let root = tree();
    match shell {
        Shell::Bash => bash(&root),
        Shell::Zsh => zsh(&root),
        Shell::Fish => fish(&root),
        Shell::Powershell => powershell(&root),
    }
}

/// Words offered at a node: subcommand names, then flags.
fn words(n: &Node) -> Vec<String> {
    let mut w: Vec<String> = n
        .subs
        .iter()
        .map(|s| s.path[s.path.len() - 1].clone())
        .collect();
    for f in &n.flags {
        if let Some(l) = &f.long {
            w.push(format!("--{l}"));
        }
        if let Some(c) = f.short {
            w.push(format!("-{c}"));
        }
    }
    w
}

/// Single-quote for POSIX shells.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn bash(root: &Node) -> String {
    let mut out = String::from(
        "# bash completion for sverb (generated by `sverb generate completions bash`)\n\
         _sverb() {\n    local cur prev path i w\n    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n    \
         prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n    path=sverb\n    \
         for ((i = 1; i < COMP_CWORD; i++)); do\n        w=\"${COMP_WORDS[i]}\"\n        \
         case \"$path:$w\" in\n",
    );
    for n in all_nodes(root).into_iter() {
        for s in &n.subs {
            let name = &s.path[s.path.len() - 1];
            let _ = writeln!(
                out,
                "            {}) path={} ;;",
                sq(&format!("{}:{name}", n.path.join("__"))),
                sq(&s.path.join("__"))
            );
        }
    }
    out.push_str("        esac\n    done\n    case \"$path:$prev\" in\n");
    for n in all_nodes(root) {
        for f in n.flags.iter().filter(|f| f.value.is_some()) {
            let Some(l) = &f.long else { continue };
            let action = if f.choices.is_empty() {
                "COMPREPLY=($(compgen -f -- \"$cur\")); return ;;".to_owned()
            } else {
                format!(
                    "COMPREPLY=($(compgen -W {} -- \"$cur\")); return ;;",
                    sq(&f.choices.join(" "))
                )
            };
            let _ = writeln!(
                out,
                "        {}) {action}",
                sq(&format!("{}:--{l}", n.path.join("__")))
            );
        }
    }
    out.push_str("    esac\n    case \"$path\" in\n");
    for n in all_nodes(root) {
        let mut w = words(n);
        for p in &n.positionals {
            w.extend(p.choices.iter().cloned());
        }
        let _ = writeln!(
            out,
            "        {}) COMPREPLY=($(compgen -W {} -- \"$cur\")) ;;",
            sq(&n.path.join("__")),
            sq(&w.join(" "))
        );
    }
    out.push_str("    esac\n}\ncomplete -o default -F _sverb sverb\n");
    out
}

fn zsh_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "'\\''")
        .replace(':', "\\:")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn zsh(root: &Node) -> String {
    let mut out = String::from(
        "#compdef sverb\n# zsh completion for sverb (generated by `sverb generate completions zsh`)\n\
         _sverb() {\n    local path=sverb w i\n    local -a subs opts\n    \
         for ((i = 2; i < CURRENT; i++)); do\n        w=${words[i]}\n        \
         case \"$path:$w\" in\n",
    );
    for n in all_nodes(root) {
        for s in &n.subs {
            let name = &s.path[s.path.len() - 1];
            let _ = writeln!(
                out,
                "            {}) path={} ;;",
                sq(&format!("{}:{name}", n.path.join("__"))),
                sq(&s.path.join("__"))
            );
        }
    }
    out.push_str("        esac\n    done\n    case \"$path\" in\n");
    for n in all_nodes(root) {
        let _ = writeln!(out, "        {})", sq(&n.path.join("__")));
        let subs: Vec<String> = n
            .subs
            .iter()
            .map(|s| {
                format!(
                    "'{}:{}'",
                    zsh_escape(&s.path[s.path.len() - 1]),
                    zsh_escape(&s.about)
                )
            })
            .collect();
        let mut opts = Vec::new();
        for f in &n.flags {
            for name in f
                .long
                .iter()
                .map(|l| format!("--{l}"))
                .chain(f.short.map(|c| format!("-{c}")))
            {
                opts.push(format!("'{}:{}'", zsh_escape(&name), zsh_escape(&f.help)));
            }
        }
        let _ = writeln!(out, "            subs=({})", subs.join(" "));
        let _ = writeln!(out, "            opts=({})", opts.join(" "));
        out.push_str("            ;;\n");
    }
    out.push_str(
        "    esac\n    if [[ ${words[CURRENT]} == -* ]]; then\n        \
         _describe -t options 'option' opts\n    elif (( ${#subs} )); then\n        \
         _describe -t commands 'command' subs\n    else\n        _files\n    fi\n}\n\
         if [ \"$funcstack[1]\" = \"_sverb\" ]; then\n    _sverb \"$@\"\nelse\n    \
         compdef _sverb sverb\nfi\n",
    );
    out
}

fn fish_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn fish(root: &Node) -> String {
    let mut out = String::from(
        "# fish completion for sverb (generated by `sverb generate completions fish`)\n\
         function __sverb_path\n    set -l path sverb\n    \
         for w in (commandline -opc)[2..-1]\n        switch \"$path:$w\"\n",
    );
    for n in all_nodes(root) {
        for s in &n.subs {
            let name = &s.path[s.path.len() - 1];
            let _ = writeln!(
                out,
                "            case '{}'\n                set path '{}'",
                fish_escape(&format!("{}:{name}", n.path.join("__"))),
                fish_escape(&s.path.join("__"))
            );
        }
    }
    out.push_str("        end\n    end\n    echo $path\nend\n\n");
    for n in all_nodes(root) {
        let cond = format!(
            "test (__sverb_path) = '{}'",
            fish_escape(&n.path.join("__"))
        );
        for s in &n.subs {
            let _ = writeln!(
                out,
                "complete -c sverb -f -n \"{cond}\" -a '{}' -d '{}'",
                fish_escape(&s.path[s.path.len() - 1]),
                fish_escape(&s.about)
            );
        }
        for f in &n.flags {
            let mut line = format!("complete -c sverb -n \"{cond}\"");
            if let Some(l) = &f.long {
                let _ = write!(line, " -l '{}'", fish_escape(l));
            }
            if let Some(c) = f.short {
                let _ = write!(line, " -s '{}'", fish_escape(&c.to_string()));
            }
            if f.value.is_some() {
                line.push_str(" -r");
                if !f.choices.is_empty() {
                    let _ = write!(line, " -f -a '{}'", fish_escape(&f.choices.join(" ")));
                }
            }
            let _ = writeln!(line, " -d '{}'", fish_escape(&f.help));
            out.push_str(&line);
        }
        for p in n.positionals.iter().filter(|p| !p.choices.is_empty()) {
            let _ = writeln!(
                out,
                "complete -c sverb -f -n \"{cond}\" -a '{}' -d '{}'",
                fish_escape(&p.choices.join(" ")),
                fish_escape(&p.help)
            );
        }
    }
    out
}

fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
}

fn powershell(root: &Node) -> String {
    let mut out = String::from(
        "# PowerShell completion for sverb (generated by `sverb generate completions powershell`)\n\
         using namespace System.Management.Automation\n\n\
         Register-ArgumentCompleter -Native -CommandName 'sverb' -ScriptBlock {\n    \
         param($wordToComplete, $commandAst, $cursorPosition)\n    $path = 'sverb'\n    \
         foreach ($element in $commandAst.CommandElements | Select-Object -Skip 1) {\n        \
         if ($element -isnot [StringConstantExpressionAst] -or \
         $element.StringConstantType -ne [StringConstantType]::BareWord -or \
         $element.Value.StartsWith('-') -or $element.Extent.EndOffset -ge $cursorPosition) { break }\n        \
         $next = $path + ';' + $element.Value\n        \
         if ($script:SverbPaths -notcontains $next) { break }\n        $path = $next\n    }\n    \
         $results = switch ($path) {\n",
    );
    let mut paths = Vec::new();
    for n in all_nodes(root) {
        paths.push(format!("'{}'", ps_escape(&n.path.join(";"))));
        let _ = writeln!(out, "        '{}' {{", ps_escape(&n.path.join(";")));
        for s in &n.subs {
            let name = ps_escape(&s.path[s.path.len() - 1]);
            let about = ps_escape(if s.about.is_empty() { &name } else { &s.about });
            let _ = writeln!(
                out,
                "            [CompletionResult]::new('{name}', '{name}', [CompletionResultType]::ParameterValue, '{about}')"
            );
        }
        for f in &n.flags {
            let help = ps_escape(if f.help.is_empty() { "option" } else { &f.help });
            for name in f
                .long
                .iter()
                .map(|l| format!("--{l}"))
                .chain(f.short.map(|c| format!("-{c}")))
            {
                let name = ps_escape(&name);
                let _ = writeln!(
                    out,
                    "            [CompletionResult]::new('{name}', '{name}', [CompletionResultType]::ParameterName, '{help}')"
                );
            }
        }
        out.push_str("        }\n");
    }
    out.push_str(
        "    }\n    $results | Where-Object { $_.CompletionText -like \"$wordToComplete*\" } |\n        \
         Sort-Object -Property ListItemText\n}\n",
    );
    format!("$script:SverbPaths = @({})\n{out}", paths.join(", "))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// T-05: the man page generates and is stable (snapshot).
    #[test]
    fn t05_man_page_snapshot() {
        let page = man_page();
        assert!(page.starts_with(".TH SVERB 1"));
        for section in [
            ".SH NAME",
            ".SH SYNOPSIS",
            ".SH COMMANDS",
            ".SH \"EXIT STATUS\"",
            ".SH ENVIRONMENT",
        ] {
            assert!(page.contains(section), "{section}");
        }
        // Every visible command has a section; hidden ones don't.
        assert!(page.contains(".SS \"sverb hosts list\""));
        assert!(page.contains(".SS \"sverb doctor\""));
        assert!(!page.contains(".SS \"sverb keymap\""));
        assert!(!page.contains(".SS \"sverb generate"));
        // No raw dashes or backslashes outside roff escapes at line starts.
        assert!(page.lines().all(|l| !l.starts_with('\'')));
        // groff warns about raw non-ASCII input.
        assert!(page.is_ascii());
        insta::assert_snapshot!(
            if cfg!(feature = "sync") {
                "man_sync"
            } else {
                "man_local"
            },
            page
        );
    }

    /// T-05: every shell's script generates and names every visible command.
    #[test]
    fn t05_completions_generate() {
        let root = tree();
        let names: Vec<String> = all_nodes(&root)
            .iter()
            .skip(1)
            .map(|n| n.path[n.path.len() - 1].clone())
            .collect();
        assert!(names.contains(&"hosts".to_owned()));
        assert!(names.contains(&"doctor".to_owned()));
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Powershell] {
            let script = completions(shell);
            assert!(!script.is_empty());
            for name in &names {
                assert!(script.contains(name.as_str()), "{shell:?} lacks {name}");
            }
            let json = if shell == Shell::Fish {
                "-l 'json'"
            } else {
                "--json"
            };
            assert!(script.contains(json), "{shell:?} lacks flags");
            for hidden in [
                "sverb__keymap",
                "sverb;keymap",
                "sverb__generate",
                "sverb;generate",
            ] {
                assert!(!script.contains(hidden), "{shell:?} lists a hidden command");
            }
        }
        assert!(completions(Shell::Bash).ends_with("complete -o default -F _sverb sverb\n"));
        assert!(completions(Shell::Zsh).starts_with("#compdef sverb\n"));
    }

    /// The bash script is valid bash (when bash is installed): `bash -n`.
    #[test]
    fn bash_and_zsh_syntax() {
        for (shell, kind) in [
            ("bash", Shell::Bash),
            ("zsh", Shell::Zsh),
            ("fish", Shell::Fish),
        ] {
            let Ok(mut child) = std::process::Command::new(shell)
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
            else {
                continue; // not installed
            };
            {
                use std::io::Write as _;
                let mut stdin = child.stdin.take().unwrap();
                stdin.write_all(completions(kind).as_bytes()).unwrap();
            }
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{shell} -n: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
