//! M7-01: the "Install sverb shell integration" snippet (SPEC §9.10).
//!
//! The hooks (`assets/shell-integration/{bash,zsh,fish}`) make the shell emit OSC 133
//! prompt marks: `A` prompt start, `B` command start (prompt end), `C` output start and
//! `D;<exit>` command finished. With them sverb records exact commands and exit codes.
//!
//! - **Install** appends the hook, between the [`BEGIN_MARKER`] / [`END_MARKER`] lines,
//!   to `~/.bashrc`, `${ZDOTDIR:-~}/.zshrc` or
//!   `${XDG_CONFIG_HOME:-~/.config}/fish/conf.d/sverb.fish`. It is idempotent: a file
//!   that already has the marker is left alone. The shell is the `shell` variable
//!   (`auto`: the login shell, `$SHELL`).
//! - **Uninstall** removes the marked block from all three files (an emptied fish file
//!   is deleted).
//!
//! Both are POSIX `sh` scripts (`grep`, `awk`, `cat`, `mkdir`, `tail`), run with
//! *Exec on hosts*.

use crate::model::{RunMode, Snippet, VarDef};

/// First line of the installed block.
pub const BEGIN_MARKER: &str = "# >>> sverb shell integration >>>";
/// Last line of the installed block.
pub const END_MARKER: &str = "# <<< sverb shell integration <<<";
/// Name of the install snippet.
pub const INSTALL_NAME: &str = "Install sverb shell integration";
/// Name of the uninstall snippet.
pub const UNINSTALL_NAME: &str = "Uninstall sverb shell integration";

const BASH: &str = include_str!("../../../../../assets/shell-integration/bash");
const ZSH: &str = include_str!("../../../../../assets/shell-integration/zsh");
const FISH: &str = include_str!("../../../../../assets/shell-integration/fish");

/// A supported shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shell {
    /// bash (≥ 4.4 for `PS0`).
    Bash,
    /// zsh.
    Zsh,
    /// fish.
    Fish,
}

impl Shell {
    /// Every supported shell.
    pub const ALL: [Self; 3] = [Self::Bash, Self::Zsh, Self::Fish];

    /// The shell's name (`basename $SHELL`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    /// The hook block (markers included, ends with a newline).
    pub fn hook(self) -> &'static str {
        match self {
            Self::Bash => BASH,
            Self::Zsh => ZSH,
            Self::Fish => FISH,
        }
    }

    /// The file the hook goes into, as a `sh` expression.
    pub fn rc_file(self) -> &'static str {
        match self {
            Self::Bash => "$HOME/.bashrc",
            Self::Zsh => "${ZDOTDIR:-$HOME}/.zshrc",
            Self::Fish => "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/sverb.fish",
        }
    }
}

/// Everything after `shell=…`: pick the file, skip if installed, append the hook.
fn install_body(out: &mut String) {
    out.push_str("case \"$shell\" in\n");
    for shell in Shell::ALL {
        out.push_str(&format!(
            "  {}) rc=\"{}\" ;;\n",
            shell.name(),
            shell.rc_file()
        ));
    }
    out.push_str(
        "  *) echo \"sverb: unsupported shell '$shell' (bash, zsh or fish)\" >&2; exit 2 ;;\n\
         esac\n\
         mkdir -p \"$(dirname \"$rc\")\"\n",
    );
    out.push_str(&format!(
        "if [ -f \"$rc\" ] && grep -qF '{BEGIN_MARKER}' \"$rc\"; then\n  \
         echo \"sverb shell integration is already installed in $rc\"\n  exit 0\nfi\n"
    ));
    // Start on a fresh line when the file does not end with one.
    out.push_str(
        "if [ -s \"$rc\" ] && [ -n \"$(tail -c 1 \"$rc\")\" ]; then printf '\\n' >> \"$rc\"; fi\n",
    );
    out.push_str("case \"$shell\" in\n");
    for shell in Shell::ALL {
        out.push_str(&format!(
            "  {})\n    cat >> \"$rc\" <<'SVERB_HOOK_EOF'\n{}SVERB_HOOK_EOF\n    ;;\n",
            shell.name(),
            shell.hook()
        ));
    }
    out.push_str("esac\necho \"sverb shell integration installed in $rc (open a new shell)\"\n");
}

/// The install script: `shell_expr` is a `sh` word giving the shell (`auto` picks
/// `basename "$SHELL"`).
pub fn install_script(shell_expr: &str) -> String {
    let mut out = String::from("set -e\n");
    out.push_str(&format!("shell={shell_expr}\n"));
    out.push_str("if [ \"$shell\" = auto ]; then shell=$(basename \"${SHELL:-sh}\"); fi\n");
    install_body(&mut out);
    out
}

/// The uninstall script (all three files).
pub fn uninstall_script() -> String {
    let mut out = String::from("set -e\nremoved=0\n");
    let files: Vec<String> = Shell::ALL
        .iter()
        .map(|s| format!("\"{}\"", s.rc_file()))
        .collect();
    out.push_str(&format!("for rc in {}; do\n", files.join(" ")));
    out.push_str(&format!(
        "  [ -f \"$rc\" ] || continue\n  \
         grep -qF '{BEGIN_MARKER}' \"$rc\" || continue\n  \
         tmp=\"$rc.sverb-tmp.$$\"\n  \
         awk -v b='{BEGIN_MARKER}' -v e='{END_MARKER}' \
         '$0 == b {{ skip = 1; next }} $0 == e {{ skip = 0; next }} !skip' \"$rc\" > \"$tmp\"\n  \
         cat \"$tmp\" > \"$rc\"\n  rm -f \"$tmp\"\n  \
         case \"$rc\" in *conf.d/sverb.fish) [ -s \"$rc\" ] || rm -f \"$rc\" ;; esac\n  \
         echo \"sverb shell integration removed from $rc\"\n  \
         removed=1\ndone\n"
    ));
    out.push_str("[ \"$removed\" = 1 ] || echo \"sverb shell integration is not installed\"\n");
    out
}

/// The "Install sverb shell integration" snippet (`{{shell:auto|q}}`, *Exec on hosts*).
pub fn install_snippet() -> Snippet {
    Snippet {
        name: INSTALL_NAME.to_owned(),
        script: install_script("{{shell:auto|q}}"),
        description: Some(
            "Adds an OSC 133 hook to ~/.bashrc, ~/.zshrc or fish conf.d so sverb records \
             exact commands and exit codes. shell: auto, bash, zsh or fish."
                .to_owned(),
        ),
        tags: Vec::new(),
        variables: vec![VarDef {
            name: "shell".to_owned(),
            default: Some("auto".to_owned()),
            secret: false,
        }],
        run_mode: RunMode::Exec,
        read_only: false,
    }
}

/// The "Uninstall sverb shell integration" snippet (*Exec on hosts*).
pub fn uninstall_snippet() -> Snippet {
    Snippet {
        name: UNINSTALL_NAME.to_owned(),
        script: uninstall_script(),
        description: Some("Removes the sverb OSC 133 hook from bash, zsh and fish.".to_owned()),
        tags: Vec::new(),
        variables: Vec::new(),
        run_mode: RunMode::Exec,
        read_only: false,
    }
}
