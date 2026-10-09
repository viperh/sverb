//! Master-password strength (SPEC §11.2: zxcvbn score ≥ 3, in both modes).

use std::fmt;

/// The minimum zxcvbn score for a new master password.
pub const MIN_SCORE: u8 = 3;

/// The warning shown on the first-run and change-password screens.
pub const NO_RECOVERY_WARNING: &str = "There is no way to recover this password. If you forget \
     it, your data is lost unless you enable keyring unlock.";

/// A strength estimate for the meter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordStrength {
    /// zxcvbn score, 0–4.
    pub score: u8,
    /// zxcvbn's warning, if any.
    pub warning: Option<String>,
    /// zxcvbn's suggestions.
    pub suggestions: Vec<String>,
}

impl PasswordStrength {
    /// Strong enough for a master password.
    pub fn acceptable(&self) -> bool {
        self.score >= MIN_SCORE
    }

    /// One line of feedback (warning first, then suggestions).
    pub fn feedback(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(w) = &self.warning {
            parts.push(w);
        }
        parts.extend(self.suggestions.iter().map(String::as_str));
        parts.join(" ")
    }

    /// A short label for the meter.
    pub fn label(&self) -> &'static str {
        match self.score {
            0 => "very weak",
            1 => "weak",
            2 => "fair",
            3 => "strong",
            _ => "very strong",
        }
    }
}

/// The password was rejected as too weak.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct WeakPassword {
    /// The estimate, with zxcvbn's feedback.
    pub strength: PasswordStrength,
}

impl fmt::Display for WeakPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the password is too weak ({}, score {} of 4; at least {MIN_SCORE} is required)",
            self.strength.label(),
            self.strength.score
        )?;
        let feedback = self.strength.feedback();
        if !feedback.is_empty() {
            write!(f, ": {feedback}")?;
        }
        Ok(())
    }
}

/// Estimate `password`'s strength. `user_inputs` are words the password should not
/// be built from (e.g. the user name).
pub fn estimate(password: &str, user_inputs: &[&str]) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength::default();
    }
    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    let (warning, suggestions) = entropy.feedback().map_or((None, Vec::new()), |fb| {
        (
            fb.warning().map(|w| w.to_string()),
            fb.suggestions().iter().map(ToString::to_string).collect(),
        )
    });
    PasswordStrength {
        score: u8::from(entropy.score()),
        warning,
        suggestions,
    }
}

/// Accept `password` as a new master password (score ≥ [`MIN_SCORE`]).
///
/// # Errors
/// [`WeakPassword`] with zxcvbn's feedback.
pub fn check_strength(
    password: &str,
    user_inputs: &[&str],
) -> Result<PasswordStrength, WeakPassword> {
    let strength = estimate(password, user_inputs);
    if strength.acceptable() {
        Ok(strength)
    } else {
        Err(WeakPassword { strength })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_password_is_rejected_with_feedback() {
        let err = check_strength("password123", &[]).err();
        let Some(err) = err else {
            panic!("password123 must be rejected");
        };
        assert!(err.strength.score < MIN_SCORE);
        let msg = err.to_string();
        assert!(msg.contains("too weak"), "{msg}");
        assert!(
            !err.strength.feedback().is_empty(),
            "zxcvbn feedback expected: {msg}"
        );
        assert!(msg.contains(&err.strength.feedback()), "{msg}");
    }

    #[test]
    fn strong_password_is_accepted() {
        let ok = check_strength("correct horse battery staple violin", &[]);
        assert!(ok.is_ok_and(|s| s.score >= MIN_SCORE));
        assert_eq!(estimate("", &[]).score, 0);
    }
}
