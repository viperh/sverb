//! Terminal-share payloads (§14.2): the encrypted [`ShareFrame`] and the relay
//! payload that carries the handshake messages and sealed frames.
//!
//! The relay (`RelayEnvelope`) routes an opaque `payload`. That payload
//! is a [`SharePayload`]:
//!
//! ```text
//! payload = tag (u8) || body
//!   0x01 Hello    body = version (u8 = 1) || cbor({"viewer_eph_pub": bstr(32), "name": tstr, "mac": bstr(32)})
//!   0x02 Welcome  body = version (u8 = 1) || cbor({"host_eph_pub": bstr(32), "mac": bstr(32)})
//!   0x03 Frame    body = seq (u64 BE) || ct       (sverb_crypto::share::Channel wire)
//! ```
//!
//! `Hello` and `Welcome` travel **unencrypted** (they are MAC'd, see
//! `sverb_crypto::share`). Everything after the handshake, including the
//! approval signalling (`ApprovalPending`, `Approved`, `Denied`), is a
//! [`ShareFrame`] sealed on the viewer's channel:
//!
//! ```text
//! plaintext = version (u8 = 1) || cbor(ShareFrame)
//! ```
//!
//! `ShareFrame` uses serde's externally tagged enum form with snake_case
//! variant names: unit variants are a text string (`"approved"`), the others a
//! one-entry map (`{"output": h'…'}`, `{"resize": {"cols": 80, "rows": 24}}`).
//! Byte fields are CBOR byte strings. Decoding is strict: unknown variants,
//! trailing bytes and any non-canonical form (anything that does not
//! re-encode to the identical bytes) are rejected. The encodings are frozen
//! by the KATs below.

use core::fmt;

use serde::{Deserialize, Serialize};
use sverb_crypto::share::{Channel, ChannelError, Hello, MAC_LEN, MAX_NAME_LEN, PUB_LEN, Welcome};

/// Version byte of a [`ShareFrame`] plaintext and of the handshake bodies.
pub const SHARE_FRAME_VERSION: u8 = 1;

/// Upper bound on any share payload or frame plaintext we decode (4 MiB).
pub const MAX_SHARE_PAYLOAD_LEN: usize = 4 * 1024 * 1024;

/// Relay payload tag of a [`Hello`].
pub const TAG_HELLO: u8 = 0x01;
/// Relay payload tag of a [`Welcome`].
pub const TAG_WELCOME: u8 = 0x02;
/// Relay payload tag of a sealed frame.
pub const TAG_FRAME: u8 = 0x03;

/// A frame inside a viewer's encrypted channel (§14.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ShareFrame {
    /// h2v: the visible screen as a VT byte stream (`emulator.snapshot_vt()`).
    Snapshot {
        /// Host pane columns.
        cols: u16,
        /// Host pane rows.
        rows: u16,
        /// VT bytes that redraw the screen (SGR, cursor, modes).
        #[serde(with = "cbor_bytes")]
        vt: Vec<u8>,
    },
    /// h2v: live output bytes.
    Output(#[serde(with = "cbor_bytes")] Vec<u8>),
    /// h2v: the host pane was resized.
    Resize {
        /// New columns.
        cols: u16,
        /// New rows.
        rows: u16,
    },
    /// v2h: keyboard input; honored only if this viewer has control.
    Input(#[serde(with = "cbor_bytes")] Vec<u8>),
    /// h2v: control granted (`true`) or revoked (`false`).
    ControlGranted(bool),
    /// Either direction: the channel is ending.
    Bye {
        /// Human-readable reason.
        reason: String,
    },
    /// h2v: the host is deciding whether to admit this viewer.
    ApprovalPending,
    /// h2v: the host admitted this viewer (a `Snapshot` follows).
    Approved,
    /// h2v: the host refused this viewer (the channel ends).
    Denied,
}

/// Share payload / frame decoding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareFrameError {
    /// The leading version byte is not [`SHARE_FRAME_VERSION`].
    UnsupportedVersion(u8),
    /// Unknown payload tag.
    UnknownTag(u8),
    /// Structurally invalid (bad CBOR, trailing bytes, wrong field length,
    /// over-long name, non-canonical, too large, empty).
    Malformed,
    /// The channel rejected the frame (auth, sequence, closed).
    Channel(ChannelError),
}

impl fmt::Display for ShareFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported share frame version {v}"),
            Self::UnknownTag(t) => write!(f, "unknown share payload tag {t:#04x}"),
            Self::Malformed => f.write_str("malformed share payload"),
            Self::Channel(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ShareFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Channel(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ChannelError> for ShareFrameError {
    fn from(e: ChannelError) -> Self {
        Self::Channel(e)
    }
}

// ---------------------------------------------------------------------------
// Versioned strict CBOR helpers
// ---------------------------------------------------------------------------

fn encode_versioned<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = vec![SHARE_FRAME_VERSION];
    // Serializing these plain data types into a Vec cannot fail.
    if ciborium::into_writer(value, &mut out).is_err() {
        unreachable!("CBOR serialization into a Vec is infallible for share types");
    }
    out
}

fn decode_versioned<T: Serialize + for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, ShareFrameError> {
    if bytes.len() > MAX_SHARE_PAYLOAD_LEN {
        return Err(ShareFrameError::Malformed);
    }
    let (&version, body) = bytes.split_first().ok_or(ShareFrameError::Malformed)?;
    if version != SHARE_FRAME_VERSION {
        return Err(ShareFrameError::UnsupportedVersion(version));
    }
    let mut reader = body;
    let value: T = ciborium::from_reader(&mut reader).map_err(|_| ShareFrameError::Malformed)?;
    if !reader.is_empty() {
        return Err(ShareFrameError::Malformed);
    }
    // Strict: only the canonical encoding is accepted.
    if encode_versioned(&value) != bytes {
        return Err(ShareFrameError::Malformed);
    }
    Ok(value)
}

impl ShareFrame {
    /// `version (u8) || cbor(self)`: the plaintext sealed on the channel.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_versioned(self)
    }

    /// Strict decoder of [`ShareFrame::encode`].
    ///
    /// # Errors
    /// [`ShareFrameError::UnsupportedVersion`] or [`ShareFrameError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ShareFrameError> {
        decode_versioned(bytes)
    }
}

// ---------------------------------------------------------------------------
// Handshake wire forms
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloWire {
    #[serde(with = "cbor_array32")]
    viewer_eph_pub: [u8; PUB_LEN],
    name: String,
    #[serde(with = "cbor_array32")]
    mac: [u8; MAC_LEN],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WelcomeWire {
    #[serde(with = "cbor_array32")]
    host_eph_pub: [u8; PUB_LEN],
    #[serde(with = "cbor_array32")]
    mac: [u8; MAC_LEN],
}

/// One relay payload of a share (see the module docs for the layout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharePayload {
    /// Viewer → host join request (unencrypted, MAC'd).
    Hello(Hello),
    /// Host → viewer join answer (unencrypted, MAC'd).
    Welcome(Welcome),
    /// A sealed frame: `seq (u64 BE) || ct`, opened with
    /// [`ShareChannelExt::open_frame`].
    Frame(Vec<u8>),
}

impl SharePayload {
    /// Encodes `tag || body`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Hello(h) => {
                let mut out = vec![TAG_HELLO];
                out.extend(encode_versioned(&HelloWire {
                    viewer_eph_pub: h.viewer_eph_pub,
                    name: h.name.clone(),
                    mac: h.mac,
                }));
                out
            }
            Self::Welcome(w) => {
                let mut out = vec![TAG_WELCOME];
                out.extend(encode_versioned(&WelcomeWire {
                    host_eph_pub: w.host_eph_pub,
                    mac: w.mac,
                }));
                out
            }
            Self::Frame(wire) => {
                let mut out = Vec::with_capacity(1 + wire.len());
                out.push(TAG_FRAME);
                out.extend_from_slice(wire);
                out
            }
        }
    }

    /// Strict decoder of [`SharePayload::encode`]. A frame body is only
    /// length-checked here (`≥ 8 + 16` bytes); the channel authenticates it.
    ///
    /// # Errors
    /// [`ShareFrameError::UnknownTag`], [`ShareFrameError::UnsupportedVersion`]
    /// or [`ShareFrameError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ShareFrameError> {
        if bytes.len() > MAX_SHARE_PAYLOAD_LEN {
            return Err(ShareFrameError::Malformed);
        }
        let (&tag, body) = bytes.split_first().ok_or(ShareFrameError::Malformed)?;
        match tag {
            TAG_HELLO => {
                let w: HelloWire = decode_versioned(body)?;
                if w.name.len() > MAX_NAME_LEN {
                    return Err(ShareFrameError::Malformed);
                }
                Ok(Self::Hello(Hello {
                    viewer_eph_pub: w.viewer_eph_pub,
                    name: w.name,
                    mac: w.mac,
                }))
            }
            TAG_WELCOME => {
                let w: WelcomeWire = decode_versioned(body)?;
                Ok(Self::Welcome(Welcome {
                    host_eph_pub: w.host_eph_pub,
                    mac: w.mac,
                }))
            }
            TAG_FRAME => {
                if body.len() < sverb_crypto::share::SEQ_LEN + sverb_crypto::aead::TAG_LEN {
                    return Err(ShareFrameError::Malformed);
                }
                Ok(Self::Frame(body.to_vec()))
            }
            other => Err(ShareFrameError::UnknownTag(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Channel integration
// ---------------------------------------------------------------------------

/// Seals and opens [`ShareFrame`]s on a `sverb_crypto::share::Channel`.
pub trait ShareChannelExt {
    /// Encodes and seals `frame` as the next outgoing frame (`seq || ct`).
    /// Wrap the result in [`SharePayload::Frame`] for the relay.
    ///
    /// # Errors
    /// [`ShareFrameError::Channel`] if the channel is closed or exhausted.
    fn seal_frame(&mut self, frame: &ShareFrame) -> Result<Vec<u8>, ShareFrameError>;

    /// Opens and decodes the next incoming frame. A frame that authenticates
    /// but does not decode also **closes** the channel.
    ///
    /// # Errors
    /// [`ShareFrameError::Channel`] (auth, sequence, closed) or a decode error.
    fn open_frame(&mut self, wire: &[u8]) -> Result<ShareFrame, ShareFrameError>;
}

impl ShareChannelExt for Channel {
    fn seal_frame(&mut self, frame: &ShareFrame) -> Result<Vec<u8>, ShareFrameError> {
        Ok(self.seal(&frame.encode())?)
    }

    fn open_frame(&mut self, wire: &[u8]) -> Result<ShareFrame, ShareFrameError> {
        let pt = self.open(wire)?;
        ShareFrame::decode(&pt).inspect_err(|_| self.close())
    }
}

// ---------------------------------------------------------------------------
// serde helpers
// ---------------------------------------------------------------------------

mod cbor_bytes {
    use core::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    #[allow(clippy::ptr_arg)]
    pub(super) fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub(super) struct BytesVisitor;

    impl Visitor<'_> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_byte_buf(BytesVisitor)
    }
}

mod cbor_array32 {
    use serde::de::Error as _;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = d.deserialize_byte_buf(super::cbor_bytes::BytesVisitor)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected a 32-byte string"))
    }
}

// ---------------------------------------------------------------------------
// Fuzzing
// ---------------------------------------------------------------------------

/// Fuzz entry point: feeds arbitrary bytes to every share decoder and
/// to a channel open. Must never panic.
#[doc(hidden)]
pub fn fuzz_share_frame_decode(data: &[u8]) {
    use sverb_crypto::Key32;
    use sverb_crypto::share::{ChannelKeys, Role};

    let _ = ShareFrame::decode(data);
    if let Ok(SharePayload::Frame(wire)) = SharePayload::decode(data) {
        let keys = ChannelKeys {
            k_h2v: Key32::from_bytes([1; 32]),
            k_v2h: Key32::from_bytes([2; 32]),
        };
        let mut ch = Channel::from_keys(keys, [0; 16], 1, Role::Viewer);
        let _ = ch.open_frame(&wire);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use sverb_crypto::Key32;
    use sverb_crypto::share::{ChannelKeys, HostHandshake, Role, ShareKey, ViewerHandshake};

    use super::*;

    fn hex(b: &[u8]) -> String {
        use core::fmt::Write as _;
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }

    fn all_frames() -> Vec<ShareFrame> {
        vec![
            ShareFrame::Snapshot {
                cols: 80,
                rows: 24,
                vt: b"\x1b[2J".to_vec(),
            },
            ShareFrame::Output(b"hi".to_vec()),
            ShareFrame::Resize {
                cols: 132,
                rows: 50,
            },
            ShareFrame::Input(b"ls\r".to_vec()),
            ShareFrame::ControlGranted(true),
            ShareFrame::Bye {
                reason: "host ended".into(),
            },
            ShareFrame::ApprovalPending,
            ShareFrame::Approved,
            ShareFrame::Denied,
        ]
    }

    /// FROZEN encodings (T-01 / §5 "encodings are frozen with KATs").
    const FRAME_KATS: [&str; 9] = [
        // snapshot
        "01a168736e617073686f74a364636f6c73185064726f77731818627674441b5b324a",
        // output
        "01a1666f7574707574426869",
        // resize
        "01a166726573697a65a264636f6c73188464726f77731832",
        // input
        "01a165696e707574436c730d",
        // control_granted
        "01a16f636f6e74726f6c5f6772616e746564f5",
        // bye
        "01a163627965a166726561736f6e6a686f737420656e646564",
        // approval_pending
        "0170617070726f76616c5f70656e64696e67",
        // approved
        "0168617070726f766564",
        // denied
        "016664656e696564",
    ];
    const HELLO_KAT: &str = "0101a36e7669657765725f6570685f7075625820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa646e616d6565616c696365636d61635820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const WELCOME_KAT: &str = "0201a26c686f73745f6570685f7075625820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc636d61635820dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn frame_encodings_are_frozen() {
        let got: Vec<String> = all_frames().iter().map(|f| hex(&f.encode())).collect();
        if std::env::var_os("SVERB_PRINT_KAT").is_some() {
            for g in &got {
                println!("{g}");
            }
        }
        assert_eq!(got, FRAME_KATS.map(str::to_owned));
        for f in all_frames() {
            assert_eq!(ShareFrame::decode(&f.encode()).unwrap(), f);
        }
    }

    #[test]
    fn handshake_payload_encodings_are_frozen() {
        let hello = Hello {
            viewer_eph_pub: [0xaa; 32],
            name: "alice".into(),
            mac: [0xbb; 32],
        };
        let welcome = Welcome {
            host_eph_pub: [0xcc; 32],
            mac: [0xdd; 32],
        };
        let h = SharePayload::Hello(hello).encode();
        let w = SharePayload::Welcome(welcome).encode();
        if std::env::var_os("SVERB_PRINT_KAT").is_some() {
            println!("{}\n{}", hex(&h), hex(&w));
        }
        assert_eq!(hex(&h), HELLO_KAT);
        assert_eq!(hex(&w), WELCOME_KAT);
        for p in [&h, &w] {
            assert_eq!(SharePayload::decode(p).unwrap().encode(), *p);
        }
        let f = SharePayload::Frame(vec![7; 30]).encode();
        assert_eq!(f[0], TAG_FRAME);
        assert_eq!(
            SharePayload::decode(&f).unwrap(),
            SharePayload::Frame(vec![7; 30])
        );
    }

    #[test]
    fn strict_decoding() {
        let good = ShareFrame::Output(b"hi".to_vec()).encode();
        // Wrong version.
        let mut bad = good.clone();
        bad[0] = 2;
        assert_eq!(
            ShareFrame::decode(&bad).unwrap_err(),
            ShareFrameError::UnsupportedVersion(2)
        );
        // Trailing bytes.
        let mut bad = good.clone();
        bad.push(0);
        assert_eq!(
            ShareFrame::decode(&bad).unwrap_err(),
            ShareFrameError::Malformed
        );
        // Empty, truncated.
        assert!(ShareFrame::decode(&[]).is_err());
        assert!(ShareFrame::decode(&good[..good.len() - 1]).is_err());
        // Unknown variant: {"nope": h''}.
        let mut unk = vec![1, 0xa1, 0x64];
        unk.extend_from_slice(b"nope");
        unk.push(0x40);
        assert!(ShareFrame::decode(&unk).is_err());
        // Output as an array of ints instead of a byte string.
        let mut arr = vec![1, 0xa1, 0x66];
        arr.extend_from_slice(b"output");
        arr.extend_from_slice(&[0x82, 0x01, 0x02]);
        assert!(ShareFrame::decode(&arr).is_err());
        // Non-canonical integer (cols = 80 as a 2-byte uint) is rejected.
        let mut long = vec![1, 0xa1, 0x66];
        long.extend_from_slice(b"resize");
        long.push(0xa2);
        long.push(0x64);
        long.extend_from_slice(b"cols");
        long.extend_from_slice(&[0x19, 0x00, 0x50]);
        long.push(0x64);
        long.extend_from_slice(b"rows");
        long.extend_from_slice(&[0x18, 0x18]);
        assert_eq!(
            ShareFrame::decode(&long).unwrap_err(),
            ShareFrameError::Malformed
        );
        // Unknown payload tag; short frame; bad key length in Hello.
        assert_eq!(
            SharePayload::decode(&[0x09, 1]).unwrap_err(),
            ShareFrameError::UnknownTag(9)
        );
        assert!(SharePayload::decode(&[TAG_FRAME; 10]).is_err());
        assert!(SharePayload::decode(&[]).is_err());
    }

    #[test]
    fn hello_with_long_name_or_short_key_rejected() {
        let mk = |pub_len: usize, name: String| {
            #[derive(Serialize)]
            struct W {
                #[serde(with = "cbor_bytes")]
                viewer_eph_pub: Vec<u8>,
                name: String,
                #[serde(with = "cbor_bytes")]
                mac: Vec<u8>,
            }
            let mut out = vec![TAG_HELLO];
            out.extend(encode_versioned(&W {
                viewer_eph_pub: vec![1; pub_len],
                name,
                mac: vec![2; 32],
            }));
            out
        };
        assert!(SharePayload::decode(&mk(32, "ok".into())).is_ok());
        assert!(SharePayload::decode(&mk(31, "ok".into())).is_err());
        assert!(SharePayload::decode(&mk(32, "x".repeat(MAX_NAME_LEN + 1))).is_err());
    }

    #[test]
    fn frames_over_a_real_channel() {
        let key = ShareKey::from_bytes([3; 32]);
        let id = [4; 16];
        let mut rng = sverb_crypto::random::os_rng();
        let (hello, state) = ViewerHandshake::start(&key, &id, "v", &mut rng).unwrap();
        // Hello / Welcome go through the relay payload encoding.
        let hello = match SharePayload::decode(&SharePayload::Hello(hello).encode()).unwrap() {
            SharePayload::Hello(h) => h,
            other => panic!("{other:?}"),
        };
        let (welcome, mut host) = HostHandshake::respond(&key, &id, 5, &hello, &mut rng).unwrap();
        let welcome = match SharePayload::decode(&SharePayload::Welcome(welcome).encode()).unwrap()
        {
            SharePayload::Welcome(w) => w,
            other => panic!("{other:?}"),
        };
        let mut viewer = state.finish(&welcome, 5).unwrap();

        for f in all_frames() {
            let payload = SharePayload::Frame(host.seal_frame(&f).unwrap()).encode();
            let SharePayload::Frame(wire) = SharePayload::decode(&payload).unwrap() else {
                panic!("not a frame");
            };
            assert_eq!(viewer.open_frame(&wire).unwrap(), f);
        }
        let input = ShareFrame::Input(b"q".to_vec());
        let wire = viewer.seal_frame(&input).unwrap();
        assert_eq!(host.open_frame(&wire).unwrap(), input);
    }

    #[test]
    fn undecodable_authentic_frame_closes_channel() {
        let keys = || ChannelKeys {
            k_h2v: Key32::from_bytes([1; 32]),
            k_v2h: Key32::from_bytes([2; 32]),
        };
        let mut host = Channel::from_keys(keys(), [0; 16], 1, Role::Host);
        let mut viewer = Channel::from_keys(keys(), [0; 16], 1, Role::Viewer);
        let wire = host.seal(b"\x01garbage").unwrap();
        assert_eq!(
            viewer.open_frame(&wire).unwrap_err(),
            ShareFrameError::Malformed
        );
        assert!(viewer.is_closed());
        let next = host.seal_frame(&ShareFrame::Approved).unwrap();
        assert_eq!(
            viewer.open_frame(&next).unwrap_err(),
            ShareFrameError::Channel(ChannelError::Closed)
        );
    }

    /// T-08 companion: the fuzz body never panics on random or mutated input.
    #[test]
    fn fuzz_body_never_panics() {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut seeds: Vec<Vec<u8>> = all_frames().iter().map(ShareFrame::encode).collect();
        seeds.push(HELLO_KAT.as_bytes().to_vec());
        for _ in 0..4000 {
            let r = next();
            let mut data = if r % 3 == 0 {
                let len = (next() % 64) as usize;
                (0..len).map(|_| next() as u8).collect()
            } else {
                seeds[(r as usize / 3) % seeds.len()].clone()
            };
            if !data.is_empty() {
                for _ in 0..(next() % 4) {
                    let i = (next() as usize) % data.len();
                    data[i] = next() as u8;
                }
            }
            fuzz_share_frame_decode(&data);
            let mut tagged = vec![TAG_HELLO];
            tagged.extend_from_slice(&data);
            fuzz_share_frame_decode(&tagged);
            tagged[0] = TAG_FRAME;
            fuzz_share_frame_decode(&tagged);
        }
    }
}
