//! The `ssh_config(5)` line lexer: `Keyword value…` or `Keyword=value…`.
//!
//! - Keywords are case-insensitive (lowercased here, the original spelling is kept for
//!   messages).
//! - Blank lines and lines starting with `#` are skipped; an unquoted argument starting
//!   with `#` starts a trailing comment.
//! - Arguments are split on whitespace; `"double"` and `'single'` quotes group words
//!   and `\` escapes the next quote or backslash inside quotes (OpenSSH `argv_split`).
//! - An unterminated quote makes the line an error (skipped with a reason).

/// One configuration line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// 1-based line number in its file.
    pub line: usize,
    /// Lowercased keyword.
    pub keyword: String,
    /// The keyword as written.
    pub raw_keyword: String,
    /// Arguments (quotes removed).
    pub args: Vec<String>,
}

/// A line that could not be lexed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    /// 1-based line number.
    pub line: usize,
    /// Why.
    pub reason: String,
}

/// Lexes a whole file. Lines that cannot be read are returned as errors, in order.
pub fn lex(text: &str) -> (Vec<Line>, Vec<LexError>) {
    let mut lines = Vec::new();
    let mut errors = Vec::new();
    // A UTF-8 BOM is ignored.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        match lex_line(raw) {
            Ok(Some((raw_keyword, args))) => lines.push(Line {
                line: n,
                keyword: raw_keyword.to_ascii_lowercase(),
                raw_keyword,
                args,
            }),
            Ok(None) => {}
            Err(reason) => errors.push(LexError { line: n, reason }),
        }
    }
    (lines, errors)
}

/// Lexes one line: `None` for blank and comment lines.
fn lex_line(raw: &str) -> Result<Option<(String, Vec<String>)>, String> {
    let s = raw.trim_matches(|c: char| c.is_whitespace());
    if s.is_empty() || s.starts_with('#') {
        return Ok(None);
    }
    // The keyword ends at whitespace or `=`.
    let end = s
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(s.len());
    let keyword = &s[..end];
    if keyword.is_empty() {
        return Err("missing keyword".to_owned());
    }
    let mut rest = s[end..].trim_start();
    // At most one `=` separates the keyword from its value.
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start();
    }
    let args = split_args(rest)?;
    Ok(Some((keyword.to_owned(), args)))
}

/// Splits arguments, honoring quotes and trailing comments.
pub fn split_args(s: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            break;
        };
        if first == '#' {
            break; // trailing comment
        }
        let mut arg = String::new();
        let mut quote: Option<char> = None;
        while let Some(&c) = chars.peek() {
            match quote {
                Some(q) => {
                    chars.next();
                    if c == '\\' {
                        match chars.peek() {
                            Some(&n) if n == q || n == '\\' => {
                                arg.push(n);
                                chars.next();
                            }
                            _ => arg.push('\\'),
                        }
                    } else if c == q {
                        quote = None;
                    } else {
                        arg.push(c);
                    }
                }
                None => {
                    if c.is_whitespace() {
                        break;
                    }
                    chars.next();
                    if c == '"' || c == '\'' {
                        quote = Some(c);
                    } else {
                        arg.push(c);
                    }
                }
            }
        }
        if quote.is_some() {
            return Err("unterminated quote".to_owned());
        }
        args.push(arg);
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(s: &str) -> Line {
        let (lines, errors) = lex(s);
        assert!(errors.is_empty(), "{errors:?}");
        lines.into_iter().next().unwrap_or_else(|| Line {
            line: 0,
            keyword: String::new(),
            raw_keyword: String::new(),
            args: Vec::new(),
        })
    }

    #[test]
    fn keyword_forms() {
        assert_eq!(one("HostName example.com").args, ["example.com"]);
        assert_eq!(one("HOSTNAME=example.com").keyword, "hostname");
        assert_eq!(one("  User = alice  ").args, ["alice"]);
        assert_eq!(one("\tPort\t2222").args, ["2222"]);
        assert_eq!(one("Port= 2222").args, ["2222"]);
    }

    #[test]
    fn quotes_and_comments() {
        assert_eq!(
            one(r#"IdentityFile "~/my keys/id ed""#).args,
            ["~/my keys/id ed"]
        );
        assert_eq!(
            one(r#"ProxyCommand ssh -W "%h:%p" bastion # via bastion"#).args,
            ["ssh", "-W", "%h:%p", "bastion"]
        );
        assert_eq!(one(r#"SetEnv A="x \"y\"""#).args, [r#"A=x "y""#]);
        assert_eq!(one("Host 'a b' c").args, ["a b", "c"]);
        let (lines, errors) = lex("# comment\n\n   # indented\nUser \"open\n");
        assert!(lines.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].line, 4);
    }
}
