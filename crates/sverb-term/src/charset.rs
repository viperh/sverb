//! Host charset conversion (SPEC §7.1).
//!
//! The emulator always consumes UTF-8. For hosts whose `charset` isn't UTF-8, the session read
//! loop passes remote bytes through [`CharsetCodec::decode`] before `Emulator::feed`, and the
//! write path passes encoded key bytes through [`CharsetCodec::encode`]. Both directions are
//! streaming: a multi-byte sequence split across reads is decoded once the rest arrives.

use std::borrow::Cow;

use encoding_rs::{CoderResult, Decoder, Encoder, Encoding, UTF_8};

/// The host's `charset` label isn't known to `encoding_rs`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown charset {0:?}")]
pub struct UnknownCharset(pub String);

/// Streaming decoder/encoder pair for one session.
pub struct CharsetCodec {
    encoding: &'static Encoding,
    decoder: Decoder,
    encoder: Encoder,
}

impl std::fmt::Debug for CharsetCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharsetCodec")
            .field("encoding", &self.encoding.name())
            .finish()
    }
}

impl Default for CharsetCodec {
    fn default() -> Self {
        Self::utf8()
    }
}

impl CharsetCodec {
    /// The UTF-8 pass-through codec.
    #[must_use]
    pub fn utf8() -> Self {
        Self::for_encoding(UTF_8)
    }

    /// Codec for a WHATWG encoding label (`"windows-1252"`, `"shift_jis"`, `"latin1"`, …).
    ///
    /// # Errors
    /// [`UnknownCharset`] if `encoding_rs` doesn't recognize the label. Config validation
    /// rejects such labels on save.
    pub fn for_label(label: &str) -> Result<Self, UnknownCharset> {
        Encoding::for_label(label.trim().as_bytes())
            .map(Self::for_encoding)
            .ok_or_else(|| UnknownCharset(label.to_owned()))
    }

    /// Codec for `label`, falling back to UTF-8 (runtime behaviour, SPEC §7.1). Returns the error
    /// alongside so the caller can log a warning.
    #[must_use]
    pub fn for_label_or_utf8(label: &str) -> (Self, Option<UnknownCharset>) {
        match Self::for_label(label) {
            Ok(codec) => (codec, None),
            Err(err) => (Self::utf8(), Some(err)),
        }
    }

    fn for_encoding(encoding: &'static Encoding) -> Self {
        Self {
            encoding,
            decoder: encoding.new_decoder(),
            encoder: encoding.new_encoder(),
        }
    }

    /// The encoding's canonical name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.encoding.name()
    }

    /// Whether this codec is the UTF-8 pass-through.
    #[must_use]
    pub fn is_utf8(&self) -> bool {
        self.encoding == UTF_8
    }

    /// Convert a chunk of remote output to UTF-8.
    ///
    /// UTF-8 hosts are passed through untouched (the emulator's parser already handles split
    /// UTF-8 sequences). Other encodings keep incomplete trailing sequences in the decoder until
    /// the next call. Invalid input becomes U+FFFD.
    pub fn decode<'a>(&mut self, chunk: &'a [u8]) -> Cow<'a, [u8]> {
        if self.is_utf8() {
            return Cow::Borrowed(chunk);
        }
        let mut out = String::with_capacity(
            self.decoder
                .max_utf8_buffer_length(chunk.len())
                .unwrap_or(chunk.len() * 3 + 16),
        );
        let mut input = chunk;
        loop {
            let (result, read, _had_errors) = self.decoder.decode_to_string(input, &mut out, false);
            input = &input[read..];
            match result {
                CoderResult::InputEmpty => break,
                CoderResult::OutputFull => out.reserve(input.len() * 3 + 16),
            }
        }
        Cow::Owned(out.into_bytes())
    }

    /// Convert UTF-8 input (encoded keys, pastes) to the host charset.
    ///
    /// Characters the host charset can't represent become HTML numeric character references, as
    /// `encoding_rs` does; that matches what browsers send and is visible rather than silent.
    pub fn encode<'a>(&mut self, input: &'a str) -> Cow<'a, [u8]> {
        if self.is_utf8() {
            return Cow::Borrowed(input.as_bytes());
        }
        let mut out = Vec::with_capacity(input.len() + 16);
        let mut rest = input;
        loop {
            let (result, read, _had_errors) =
                self.encoder.encode_from_utf8_to_vec(rest, &mut out, false);
            rest = &rest[read..];
            match result {
                CoderResult::InputEmpty => break,
                CoderResult::OutputFull => out.reserve(rest.len() * 2 + 16),
            }
        }
        Cow::Owned(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn utf8_is_passthrough() {
        let mut c = CharsetCodec::utf8();
        assert!(matches!(c.decode(b"\xc3"), Cow::Borrowed(_)));
        assert_eq!(&*c.encode("é"), "é".as_bytes());
    }

    #[test]
    fn windows_1252_round_trip() {
        let mut c = CharsetCodec::for_label("windows-1252").unwrap();
        assert_eq!(&*c.decode(&[0x80]), "€".as_bytes());
        assert_eq!(&*c.encode("€"), &[0x80]);
    }

    #[test]
    fn shift_jis_split_across_reads() {
        let mut c = CharsetCodec::for_label("Shift_JIS").unwrap();
        // "日本" in Shift_JIS: 93 FA 96 7B. Split inside the first character.
        let mut out = Vec::new();
        out.extend_from_slice(&c.decode(&[0x93]));
        out.extend_from_slice(&c.decode(&[0xFA, 0x96]));
        out.extend_from_slice(&c.decode(&[0x7B]));
        assert_eq!(String::from_utf8(out).unwrap(), "日本");
    }

    #[test]
    fn unknown_label_falls_back() {
        assert!(CharsetCodec::for_label("klingon-8").is_err());
        let (c, err) = CharsetCodec::for_label_or_utf8("klingon-8");
        assert!(c.is_utf8());
        assert_eq!(err, Some(UnknownCharset("klingon-8".into())));
    }
}
