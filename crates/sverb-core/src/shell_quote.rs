//! M2-04: POSIX single-quote escaping (SPEC §9.4, §9.7).
//!
//! [`posix_single_quote`] wraps a string in `'…'` and writes every `'` as `'\''` (close
//! the quote, an escaped quote, reopen). Inside single quotes a POSIX shell treats every
//! byte literally, newlines included, so the result is one word whose value is exactly
//! the input. NUL bytes cannot be passed through a shell word at all and are rejected.
//!
//! Used by "install key on host" (§9.4), the snippet `|q` filter (M2-09) and
//! copy-as-command. (`ssh_command::shell_quote` leaves "safe" words unquoted for
//! readability; this one always quotes.)

/// Why a string cannot be quoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ShellQuoteError {
    /// The string contains a NUL byte (at this byte offset).
    #[error("a NUL byte (at offset {0}) cannot be passed to a shell")]
    Nul(usize),
}

/// `s` as one POSIX shell word: `'…'` with each `'` written as `'\''`.
///
/// ```
/// use sverb_core::shell_quote::posix_single_quote;
/// assert_eq!(posix_single_quote("it's").unwrap(), r"'it'\''s'");
/// ```
///
/// # Errors
/// [`ShellQuoteError::Nul`] when `s` contains a NUL byte.
pub fn posix_single_quote(s: &str) -> Result<String, ShellQuoteError> {
    if let Some(at) = s.find('\0') {
        return Err(ShellQuoteError::Nul(at));
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// T-01: the table.
    #[test]
    fn t01_table() {
        let cases: &[(&str, &str)] = &[
            ("abc", "'abc'"),
            ("it's", r"'it'\''s'"),
            ("", "''"),
            ("a\nb", "'a\nb'"),
            ("''", r"''\'''\'''"),
            ("$HOME `x` \\ \"q\"", "'$HOME `x` \\ \"q\"'"),
        ];
        for (input, want) in cases {
            assert_eq!(posix_single_quote(input).unwrap(), *want, "{input:?}");
        }
        assert_eq!(posix_single_quote("a\0b"), Err(ShellQuoteError::Nul(1)));
    }

    /// T-01 (property, local): `sh -c "printf %s <quoted>"` prints the original, for
    /// 200 random strings without NUL (quotes, newlines, `$`, backslashes, non-ASCII).
    /// The Docker variant runs the same check in the e2e container.
    #[cfg(unix)]
    #[test]
    fn t01_roundtrip_through_sh() {
        const ALPHABET: &[char] = &[
            'a', 'Z', '0', ' ', '\'', '"', '\\', '$', '`', '\n', '\t', '*', '?', '~', '#', ';',
            '&', '|', '(', ')', '<', '>', '!', '{', '}', '%', 'é', '✓', '\u{1}', '\r',
        ];
        // xorshift: deterministic without a dependency.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut script = String::new();
        let mut inputs = Vec::new();
        for _ in 0..200 {
            let len = usize::try_from(next() % 24).unwrap();
            let s: String = (0..len)
                .map(|_| ALPHABET[usize::try_from(next()).unwrap() % ALPHABET.len()])
                .collect();
            script.push_str(&format!(
                "printf %s {}; printf '\\0'\n",
                posix_single_quote(&s).unwrap()
            ));
            inputs.push(s);
        }
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("sh runs");
        assert!(out.status.success(), "{out:?}");
        let got: Vec<String> = out
            .stdout
            .split(|b| *b == 0)
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect();
        // A trailing empty piece after the last NUL.
        assert_eq!(got.len(), inputs.len() + 1);
        for (want, got) in inputs.iter().zip(&got) {
            assert_eq!(got, want);
        }
    }
}
