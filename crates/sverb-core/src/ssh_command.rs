//! "copy as command" (SPEC §9.1): the OpenSSH command line equivalent to a
//! host, e.g. `ssh -J bastion,user@jump2:2222 -p 2222 -i ~/.ssh/id_ed25519 user@host`.
//!
//! [`render`] takes an [`SshTarget`], the subset of a resolved host the command line
//! view builds it from the host's own fields.
//!
//! - `-J` lists the jump chain as `[user@]addr[:port]`, comma-separated; an IPv6 hop
//!   with a port is bracketed (`[fe80::1]:2222`),
//! - `-p` only when the port is not 22,
//! - `-i` only when the key has a known source path; a key that lives only in the
//!   vault adds the comment `# key stored in sverb vault`,
//! - `-o ProxyCommand=…`, `-A` for agent forwarding, one `-o SetEnv=…` per variable,
//! - the destination is `[user@]addr`; IPv6 addresses are not bracketed there (ssh
//!   accepts them bare).
//!
//! Every word that needs it is quoted for a POSIX shell with single quotes
//! (`'` → `'\''`), so the line can be pasted as is.

use crate::model::DEFAULT_SSH_PORT;

/// One jump hop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hop {
    /// Login user, if set.
    pub user: Option<String>,
    /// Hostname or IP literal (no brackets).
    pub address: String,
    /// Port, if not the default.
    pub port: Option<u16>,
}

/// Where the session's key comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// A file on disk (`-i path`).
    File(String),
    /// Stored only in the sverb vault (no `-i`; a comment says so).
    Vault,
}

/// What the command line needs from a resolved host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshTarget {
    /// Login user, if set.
    pub user: Option<String>,
    /// Hostname or IP literal (no brackets).
    pub address: String,
    /// Port (22 when `None`).
    pub port: Option<u16>,
    /// Jump hosts, in order.
    pub jump: Vec<Hop>,
    /// The key, if any.
    pub key: Option<KeySource>,
    /// `ProxyCommand` (`%h %p %r` are expanded by ssh).
    pub proxy_command: Option<String>,
    /// `-A`.
    pub agent_forwarding: bool,
    /// Environment variables (`SetEnv`).
    pub env: Vec<(String, String)>,
}

/// The comment appended when the key is only in the vault.
pub const VAULT_KEY_COMMENT: &str = "# key stored in sverb vault";

/// Quote `word` for a POSIX shell: unchanged when it only contains safe characters,
/// else wrapped in single quotes with `'` written as `'\''`.
pub fn shell_quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '_' | '.' | ',' | '/' | ':' | '@' | '%' | '+' | '=' | '[' | ']'
                )
        })
        && !word.starts_with('~');
    if safe {
        return word.to_owned();
    }
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// Like [`shell_quote`], but a leading `~/` stays unquoted so the shell expands it.
fn quote_path(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) if !rest.is_empty() => {
            let quoted = shell_quote(rest);
            format!("~/{quoted}")
        }
        _ => shell_quote(path),
    }
}

fn hop_spec(hop: &Hop) -> String {
    let mut out = String::new();
    if let Some(user) = &hop.user {
        out.push_str(user);
        out.push('@');
    }
    match hop.port.filter(|p| *p != DEFAULT_SSH_PORT) {
        Some(port) if hop.address.contains(':') => {
            out.push_str(&format!("[{}]:{port}", hop.address))
        }
        Some(port) => out.push_str(&format!("{}:{port}", hop.address)),
        None => out.push_str(&hop.address),
    }
    out
}

/// An env value for `SetEnv`: double-quoted (OpenSSH syntax) when it has spaces or quotes.
fn setenv_value(value: &str) -> String {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        format!("\"{}\"", value.replace('\\', r"\\").replace('"', "\\\""))
    } else {
        value.to_owned()
    }
}

/// The `ssh` command line for `target`. See the [module docs](self).
pub fn render(target: &SshTarget) -> String {
    let mut words: Vec<String> = vec!["ssh".to_owned()];
    if !target.jump.is_empty() {
        let hops: Vec<String> = target.jump.iter().map(hop_spec).collect();
        words.push("-J".to_owned());
        words.push(shell_quote(&hops.join(",")));
    }
    if let Some(port) = target.port.filter(|p| *p != DEFAULT_SSH_PORT) {
        words.push("-p".to_owned());
        words.push(port.to_string());
    }
    if let Some(KeySource::File(path)) = &target.key {
        words.push("-i".to_owned());
        words.push(quote_path(path));
    }
    if let Some(cmd) = &target.proxy_command {
        words.push("-o".to_owned());
        words.push(format!("ProxyCommand={}", shell_quote(cmd)));
    }
    if target.agent_forwarding {
        words.push("-A".to_owned());
    }
    for (name, value) in &target.env {
        words.push("-o".to_owned());
        words.push(shell_quote(&format!(
            "SetEnv={name}={}",
            setenv_value(value)
        )));
    }
    let dest = match &target.user {
        Some(user) => format!("{user}@{}", target.address),
        None => target.address.clone(),
    };
    words.push(shell_quote(&dest));
    let mut line = words.join(" ");
    if target.key == Some(KeySource::Vault) {
        line.push_str("  ");
        line.push_str(VAULT_KEY_COMMENT);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(address: &str) -> SshTarget {
        SshTarget {
            address: address.to_owned(),
            ..SshTarget::default()
        }
    }

    #[test]
    fn t02_render_table() {
        let plain = host("example.com");
        let mut user_port = host("db.internal");
        user_port.user = Some("root".into());
        user_port.port = Some(2222);
        let mut default_port = host("h");
        default_port.port = Some(22);
        let mut jumps = host("10.0.0.5");
        jumps.user = Some("deploy".into());
        jumps.jump = vec![
            Hop {
                user: None,
                address: "bastion".into(),
                port: None,
            },
            Hop {
                user: Some("user".into()),
                address: "jump2".into(),
                port: Some(2222),
            },
        ];
        jumps.port = Some(2222);
        jumps.key = Some(KeySource::File("~/.ssh/id_ed25519".into()));
        let mut proxy = host("h");
        proxy.proxy_command = Some("nc -X 5 -x proxy:1080 %h %p 'it's'".into());
        let mut v6 = host("fe80::1");
        v6.user = Some("u".into());
        v6.port = Some(2200);
        v6.jump = vec![Hop {
            user: None,
            address: "2001:db8::1".into(),
            port: Some(2022),
        }];
        let mut agent = host("h");
        agent.agent_forwarding = true;
        agent.key = Some(KeySource::Vault);
        let mut env = host("h");
        env.env = vec![
            ("LANG".into(), "C.UTF-8".into()),
            ("GREETING".into(), "hi there".into()),
        ];

        let cases: &[(&SshTarget, &str)] = &[
            (&plain, "ssh example.com"),
            (&user_port, "ssh -p 2222 root@db.internal"),
            (&default_port, "ssh h"),
            (
                &jumps,
                "ssh -J bastion,user@jump2:2222 -p 2222 -i ~/.ssh/id_ed25519 deploy@10.0.0.5",
            ),
            (
                &proxy,
                r"ssh -o ProxyCommand='nc -X 5 -x proxy:1080 %h %p '\''it'\''s'\''' h",
            ),
            (&v6, "ssh -J [2001:db8::1]:2022 -p 2200 u@fe80::1"),
            (&agent, "ssh -A h  # key stored in sverb vault"),
            (
                &env,
                r#"ssh -o SetEnv=LANG=C.UTF-8 -o 'SetEnv=GREETING="hi there"' h"#,
            ),
        ];
        for (target, want) in cases {
            assert_eq!(render(target), *want, "{target:?}");
        }
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("plain-word_1.2"), "plain-word_1.2");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(quote_path("~/my keys/id"), "~/'my keys/id'");
    }
}
