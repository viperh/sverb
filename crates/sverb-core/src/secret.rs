//! Secret values that can't be printed, logged, cloned or serialized by accident
//! (SPEC §11.5, §17).
//!
//! [`Secret<T>`] wraps [`secrecy::SecretBox<T>`]:
//! - `Debug` and `Display` always write `[REDACTED]`, so `tracing` fields recorded with
//!   `?secret` or `%secret` are redacted by type.
//! - There is no `Clone`, `PartialEq` or `Serialize` impl. Compare with [`Secret::ct_eq`]
//!   (constant time) and read the value with [`Secret::expose`], which is named so every
//!   access is easy to find in review (`grep -n 'expose('`).
//! - The value is zeroized when the `Secret` is dropped (secrecy does this).
//!
//! ```
//! use sverb_core::secret::SecretString;
//!
//! let password = SecretString::from("hunter2");
//! assert_eq!(format!("{password:?}"), "[REDACTED]");
//! assert_eq!(format!("{password}"), "[REDACTED]");
//! assert_eq!(password.expose(), "hunter2");
//! ```

use std::fmt;

use secrecy::{ExposeSecret, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// What `Debug` and `Display` print for every [`Secret`].
pub const REDACTED: &str = "[REDACTED]";

/// A heap-allocated secret, zeroized on drop and redacted when formatted.
pub struct Secret<T: Zeroize + ?Sized>(SecretBox<T>);

/// A secret UTF-8 string (passwords, passphrases, tokens).
pub type SecretString = Secret<str>;

/// A secret byte string (private keys, raw key material).
pub type SecretBytes = Secret<[u8]>;

impl<T: Zeroize + ?Sized> Secret<T> {
    /// Wraps an already boxed value without copying it.
    pub fn from_box(value: Box<T>) -> Self {
        Self(SecretBox::new(value))
    }

    /// Borrows the secret value.
    ///
    /// Every call site is a place where the plaintext leaves the wrapper, so keep
    /// them few and never pass the result to `tracing`, `format!` or `println!`.
    pub fn expose(&self) -> &T {
        self.0.expose_secret()
    }

    /// Borrows the secret value for the encrypted item serializer.
    ///
    /// This is the same as [`Secret::expose`], under a separate name so the one
    /// legitimate serialization path stays grep-able and reviewable on its own.
    /// Nothing outside the envelope code should call it.
    pub fn expose_for_envelope(&self) -> &T {
        self.0.expose_secret()
    }
}

impl<T: Zeroize> Secret<T> {
    /// Moves `value` onto the heap behind the wrapper.
    ///
    /// The stack copy that `value` occupied is not zeroized; prefer building the
    /// secret directly in a `Box` (or from a `String`/`Vec`) for long-lived keys.
    pub fn new(value: T) -> Self {
        Self::from_box(Box::new(value))
    }
}

impl<T: Zeroize + AsRef<[u8]> + ?Sized> Secret<T> {
    /// Compares two secrets in constant time (for equal lengths; the length itself
    /// is not treated as secret).
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.expose().as_ref().ct_eq(other.expose().as_ref()).into()
    }
}

impl<T: Zeroize + ?Sized> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T: Zeroize + ?Sized> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::from_box(value.into_boxed_str())
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::from_box(Box::from(value))
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::from_box(value.into_boxed_slice())
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(value: &[u8]) -> Self {
        Self::from_box(Box::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting_is_redacted() {
        let s = SecretString::from("CANARY-1b9f");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{s:#?}"), "[REDACTED]");
        assert_eq!(format!("{:>20}", s), "[REDACTED]");

        let b = SecretBytes::from(vec![1_u8, 2, 3]);
        assert_eq!(format!("{b:?}"), "[REDACTED]");
        assert_eq!(format!("{b}"), "[REDACTED]");

        let k = Secret::new([7_u8; 32]);
        assert_eq!(format!("{k:?}"), "[REDACTED]");
    }

    #[test]
    fn expose_returns_the_inner_value() {
        let s = SecretString::from(String::from("hunter2"));
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(s.expose_for_envelope(), "hunter2");
        let b = SecretBytes::from(&b"key"[..]);
        assert_eq!(b.expose(), b"key");
        let k = Secret::new([7_u8; 4]);
        assert_eq!(k.expose(), &[7, 7, 7, 7]);
    }

    #[test]
    fn ct_eq_compares_values() {
        let a = SecretString::from("same");
        let b = SecretString::from("same");
        let c = SecretString::from("diff");
        let d = SecretString::from("longer");
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&d));
        assert!(SecretBytes::from(vec![1, 2]).ct_eq(&SecretBytes::from(vec![1, 2])));
        assert!(!SecretBytes::from(vec![1, 2]).ct_eq(&SecretBytes::from(vec![2, 1])));
        assert!(Secret::new([1_u8; 32]).ct_eq(&Secret::new([1_u8; 32])));
    }

    // T-08 (unit half; the file canary is in tests/logging.rs)
    #[test]
    fn tracing_fields_are_redacted() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if let Ok(mut v) = self.0.lock() {
                    v.extend_from_slice(data);
                }
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let secret = SecretString::from("CANARY-1b9f");
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(pw = ?secret, "x");
            tracing::info!(pw = %secret, "y");
            tracing::debug!("{:?} {}", secret, secret);
        });
        let out = buf
            .0
            .lock()
            .map(|v| String::from_utf8_lossy(&v).into_owned());
        let out = out.unwrap_or_default();
        assert!(out.contains("[REDACTED]"), "{out}");
        assert!(!out.contains("CANARY-1b9f"), "{out}");
    }
}
