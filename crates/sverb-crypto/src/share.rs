//! Terminal-share cryptography (§14.2): link key, join handshake, per-viewer
//! channel keys and sequenced frames. No I/O.
//!
//! ```text
//! share_key  = 32 random bytes, only ever in the link fragment (§14.1)
//! k_join     = HKDF(ikm = share_key, salt = none, info = "sverb/share/join/v1")
//! Hello      = { viewer_eph_pub, name,
//!                mac  = HMAC-SHA256(k_join, share_id || viewer_eph_pub || u32 len || name) }
//! Welcome    = { host_eph_pub,
//!                mac' = HMAC-SHA256(k_join, share_id || viewer_eph_pub || u32 len || name
//!                                           || host_eph_pub || "welcome") }
//! k_viewer   = HKDF(ikm = X25519(eph, eph'), salt = share_key,
//!                   info = "sverb/share/chan/v1" || share_id || viewer_eph_pub || host_eph_pub)
//!              64 bytes = k_h2v (first 32) || k_v2h (last 32)
//! frame      = seq (u64 BE) || XChaCha20Poly1305(k_dir,
//!                  nonce = 16 zero bytes || seq (u64 BE),
//!                  aad   = share_id || viewer_id (u32 BE) || dir (u8: 0 = h2v, 1 = v2h) || seq (u64 BE),
//!                  pt)
//! ```
//!
//! - The link key only authenticates the join. Each viewer gets its own
//!   X25519-derived channel key (the host uses a fresh ephemeral per viewer),
//!   so viewers cannot read or forge each other's frames, and channel keys
//!   have forward secrecy.
//! - Per-direction counters start at `seq = 0`. The receiver accepts only
//!   `seq == last + 1`; anything else (replay, gap, reorder) or any
//!   authentication failure **closes the channel** permanently.
//! - Frame plaintexts are opaque here; `sverb-proto::share_frame` defines the
//!   versioned CBOR `ShareFrame` encoding and the relay payload tags.
//! - [`ShareLink`] parses and formats `sverb://join/<server>/<share_id>#<key>`
//!   and `https://<server>/s/<share_id>#<key>`. [`ShareLink::server`] and
//!   [`ShareLink::web_base_url`] never contain the fragment.

use hkdf::hmac::{Hmac, KeyInit, Mac};
use rand_core::CryptoRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::aead;
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::kdf::{hkdf_key32, hkdf_sha256};
use crate::keys::{KEY_LEN, Key32, NONCE_LEN, Nonce24};
use crate::random::random_key32;

/// Length of the link key.
pub const SHARE_KEY_LEN: usize = 32;
/// Length of an X25519 public key.
pub const PUB_LEN: usize = 32;
/// Length of an HMAC-SHA256 tag.
pub const MAC_LEN: usize = 32;
/// Length of the `seq` prefix of a sealed frame.
pub const SEQ_LEN: usize = 8;
/// Maximum viewer name length in bytes (UTF-8). Longer names are rejected.
pub const MAX_NAME_LEN: usize = 256;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Link key
// ---------------------------------------------------------------------------

/// The 256-bit link key (`share_key`). Zeroized on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareKey(Key32);

impl ShareKey {
    /// Generates a fresh random link key.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(random_key32(rng))
    }

    /// Wraps raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHARE_KEY_LEN]) -> Self {
        Self(Key32::from_bytes(bytes))
    }

    /// Exposes the raw key bytes.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; SHARE_KEY_LEN] {
        self.0.expose_secret()
    }

    /// The join HMAC key `HKDF(share_key, info = "sverb/share/join/v1")`.
    fn join_key(&self) -> Key32 {
        hkdf_key32(self.expose_secret(), None, &canon::info_share_join())
    }
}

impl core::fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShareKey([REDACTED])")
    }
}

// ---------------------------------------------------------------------------
// Handshake messages and MACs
// ---------------------------------------------------------------------------

/// Viewer → host join request (sent unencrypted inside the relay payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// The viewer's ephemeral X25519 public key.
    pub viewer_eph_pub: [u8; PUB_LEN],
    /// Display name chosen by the viewer (may be empty for "anonymous").
    pub name: String,
    /// `HMAC-SHA256(k_join, canon::mac_share_hello(..))`.
    pub mac: [u8; MAC_LEN],
}

/// Host → viewer join answer (sent unencrypted inside the relay payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// The host's fresh ephemeral X25519 public key for this viewer.
    pub host_eph_pub: [u8; PUB_LEN],
    /// `HMAC-SHA256(k_join, canon::mac_share_welcome(..))`.
    pub mac: [u8; MAC_LEN],
}

fn hmac_key(key: &Key32) -> HmacSha256 {
    // HMAC accepts keys of any length, so this cannot fail.
    match <HmacSha256 as KeyInit>::new_from_slice(key.expose_secret()) {
        Ok(m) => m,
        Err(_) => unreachable!("HMAC accepts any key length"),
    }
}

fn hmac(key: &Key32, msg: &[u8]) -> [u8; MAC_LEN] {
    let mut m = hmac_key(key);
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Constant-time HMAC verification.
fn hmac_verify(key: &Key32, msg: &[u8], tag: &[u8; MAC_LEN]) -> bool {
    let mut m = hmac_key(key);
    m.update(msg);
    m.verify_slice(tag).is_ok()
}

fn check_name(name: &str) -> Result<()> {
    if name.len() > MAX_NAME_LEN {
        return Err(CryptoError::InvalidParams("share viewer name too long"));
    }
    Ok(())
}

/// The `Hello` MAC (§14.2.1). Exposed for KATs.
#[must_use]
pub fn hello_mac(
    share_key: &ShareKey,
    share_id: &Id16,
    viewer_eph_pub: &[u8; PUB_LEN],
    name: &str,
) -> [u8; MAC_LEN] {
    hmac(
        &share_key.join_key(),
        &canon::mac_share_hello(share_id, viewer_eph_pub, name.as_bytes()),
    )
}

/// The `Welcome` MAC over the full transcript (§14.2.1). Exposed for KATs.
#[must_use]
pub fn welcome_mac(
    share_key: &ShareKey,
    share_id: &Id16,
    viewer_eph_pub: &[u8; PUB_LEN],
    name: &str,
    host_eph_pub: &[u8; PUB_LEN],
) -> [u8; MAC_LEN] {
    hmac(
        &share_key.join_key(),
        &canon::mac_share_welcome(share_id, viewer_eph_pub, name.as_bytes(), host_eph_pub),
    )
}

/// Verifies a `Hello` MAC in constant time (host side), without doing the
/// key exchange. [`HostHandshake::respond`] calls this first.
///
/// # Errors
/// [`CryptoError::Auth`] on a bad MAC (wrong link key, tampered field);
/// [`CryptoError::Malformed`] if the name is longer than [`MAX_NAME_LEN`].
pub fn verify_hello(share_key: &ShareKey, share_id: &Id16, hello: &Hello) -> Result<()> {
    if hello.name.len() > MAX_NAME_LEN {
        return Err(CryptoError::Malformed("share viewer name too long"));
    }
    let msg = canon::mac_share_hello(share_id, &hello.viewer_eph_pub, hello.name.as_bytes());
    if hmac_verify(&share_key.join_key(), &msg, &hello.mac) {
        Ok(())
    } else {
        Err(CryptoError::Auth)
    }
}

// ---------------------------------------------------------------------------
// Channel keys
// ---------------------------------------------------------------------------

/// The two directional keys of one viewer's channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelKeys {
    /// Host → viewer key (first 32 bytes of the HKDF output).
    pub k_h2v: Key32,
    /// Viewer → host key (last 32 bytes of the HKDF output).
    pub k_v2h: Key32,
}

/// Derives the channel keys from the X25519 shared secret (§14.2.2).
/// Exposed for KATs; the handshakes call it.
#[must_use]
pub fn derive_channel_keys(
    shared_secret: &[u8; 32],
    share_key: &ShareKey,
    share_id: &Id16,
    viewer_eph_pub: &[u8; PUB_LEN],
    host_eph_pub: &[u8; PUB_LEN],
) -> ChannelKeys {
    let info = canon::info_share_chan(share_id, viewer_eph_pub, host_eph_pub);
    let okm = match hkdf_sha256(
        shared_secret,
        Some(share_key.expose_secret()),
        &info,
        2 * KEY_LEN,
    ) {
        Ok(okm) => okm,
        Err(_) => unreachable!("64-byte HKDF output is always valid"),
    };
    let (h2v, v2h) = okm.split_at(KEY_LEN);
    let to_key = |s: &[u8]| {
        let mut a = Zeroizing::new([0u8; KEY_LEN]);
        a.copy_from_slice(s);
        Key32::from_bytes(*a)
    };
    ChannelKeys {
        k_h2v: to_key(h2v),
        k_v2h: to_key(v2h),
    }
}

fn dh(secret: EphemeralSecret, their_pub: &[u8; PUB_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(&PublicKey::from(*their_pub));
    // Reject low-order points: they would force a known shared secret.
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidParams(
            "non-contributory x25519 public key",
        ));
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

// ---------------------------------------------------------------------------
// Handshakes
// ---------------------------------------------------------------------------

/// Viewer side of the join handshake: holds the ephemeral secret between
/// sending `Hello` and receiving `Welcome`.
pub struct ViewerHandshake {
    share_key: ShareKey,
    share_id: Id16,
    name: String,
    secret: EphemeralSecret,
    viewer_eph_pub: [u8; PUB_LEN],
}

impl core::fmt::Debug for ViewerHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViewerHandshake")
            .field("share_id", &self.share_id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl ViewerHandshake {
    /// Generates the viewer's ephemeral key pair and the `Hello` to send.
    ///
    /// # Errors
    /// [`CryptoError::InvalidParams`] if `name` exceeds [`MAX_NAME_LEN`] bytes.
    pub fn start<R: CryptoRng + ?Sized>(
        share_key: &ShareKey,
        share_id: &Id16,
        name: &str,
        rng: &mut R,
    ) -> Result<(Hello, Self)> {
        check_name(name)?;
        let secret = EphemeralSecret::random_from_rng(rng);
        let viewer_eph_pub = PublicKey::from(&secret).to_bytes();
        let hello = Hello {
            viewer_eph_pub,
            name: name.to_owned(),
            mac: hello_mac(share_key, share_id, &viewer_eph_pub, name),
        };
        let state = Self {
            share_key: share_key.clone(),
            share_id: *share_id,
            name: name.to_owned(),
            secret,
            viewer_eph_pub,
        };
        Ok((hello, state))
    }

    /// The viewer's ephemeral public key (as sent in `Hello`).
    #[must_use]
    pub const fn viewer_eph_pub(&self) -> &[u8; PUB_LEN] {
        &self.viewer_eph_pub
    }

    /// Verifies the `Welcome` MAC over the full transcript and derives the
    /// channel. `viewer_id` is the id the relay assigned to this viewer (it is
    /// bound into every frame's AAD).
    ///
    /// # Errors
    /// [`CryptoError::Auth`] if the `Welcome` MAC does not verify;
    /// [`CryptoError::InvalidParams`] on a low-order host public key.
    pub fn finish(self, welcome: &Welcome, viewer_id: u32) -> Result<Channel> {
        let msg = canon::mac_share_welcome(
            &self.share_id,
            &self.viewer_eph_pub,
            self.name.as_bytes(),
            &welcome.host_eph_pub,
        );
        if !hmac_verify(&self.share_key.join_key(), &msg, &welcome.mac) {
            return Err(CryptoError::Auth);
        }
        let shared = dh(self.secret, &welcome.host_eph_pub)?;
        let keys = derive_channel_keys(
            &shared,
            &self.share_key,
            &self.share_id,
            &self.viewer_eph_pub,
            &welcome.host_eph_pub,
        );
        Ok(Channel::from_keys(
            keys,
            self.share_id,
            viewer_id,
            Role::Viewer,
        ))
    }
}

/// Host side of the join handshake.
#[derive(Debug, Clone, Copy)]
pub struct HostHandshake;

impl HostHandshake {
    /// Verifies the viewer's `Hello` MAC (constant time), generates a **fresh**
    /// ephemeral for this viewer and returns the `Welcome` plus the channel.
    /// `viewer_id` is the id the relay assigned to this viewer.
    ///
    /// # Errors
    /// [`CryptoError::Auth`] if the `Hello` MAC does not verify;
    /// [`CryptoError::Malformed`] on an over-long name;
    /// [`CryptoError::InvalidParams`] on a low-order viewer public key.
    pub fn respond<R: CryptoRng + ?Sized>(
        share_key: &ShareKey,
        share_id: &Id16,
        viewer_id: u32,
        hello: &Hello,
        rng: &mut R,
    ) -> Result<(Welcome, Channel)> {
        verify_hello(share_key, share_id, hello)?;
        let secret = EphemeralSecret::random_from_rng(rng);
        let host_eph_pub = PublicKey::from(&secret).to_bytes();
        let shared = dh(secret, &hello.viewer_eph_pub)?;
        let keys = derive_channel_keys(
            &shared,
            share_key,
            share_id,
            &hello.viewer_eph_pub,
            &host_eph_pub,
        );
        let welcome = Welcome {
            host_eph_pub,
            mac: welcome_mac(
                share_key,
                share_id,
                &hello.viewer_eph_pub,
                &hello.name,
                &host_eph_pub,
            ),
        };
        Ok((
            welcome,
            Channel::from_keys(keys, *share_id, viewer_id, Role::Host),
        ))
    }
}

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/// Which end of a channel this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The sharing host: sends h2v, receives v2h.
    Host,
    /// A viewer: sends v2h, receives h2v.
    Viewer,
}

/// Frame direction, as encoded in the AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// Host → viewer (`0`).
    HostToViewer = 0,
    /// Viewer → host (`1`).
    ViewerToHost = 1,
}

/// Channel failures. Every one of them closes the channel for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// The frame did not authenticate (wrong key, viewer, direction, tampering
    /// or truncation). Deliberately carries no detail.
    #[error("share frame authentication failed")]
    Auth,
    /// An authentic frame arrived with `seq != last + 1` (replay, gap or
    /// reorder).
    #[error("share frame out of sequence")]
    Sequence,
    /// The channel was already closed by an earlier error or by [`Channel::close`].
    #[error("share channel closed")]
    Closed,
    /// The send counter is exhausted (2^64 frames); the channel is closed.
    #[error("share channel sequence exhausted")]
    Exhausted,
}

/// One viewer's encrypted, strictly sequenced, bidirectional channel.
pub struct Channel {
    share_id: Id16,
    viewer_id: u32,
    role: Role,
    send_key: Key32,
    recv_key: Key32,
    /// Next `seq` to send.
    send_seq: u64,
    /// Next `seq` expected from the peer.
    recv_seq: u64,
    closed: bool,
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("viewer_id", &self.viewer_id)
            .field("role", &self.role)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

fn frame_nonce(seq: u64) -> Nonce24 {
    let mut n = [0u8; NONCE_LEN];
    n[NONCE_LEN - 8..].copy_from_slice(&seq.to_be_bytes());
    Nonce24::from_bytes(n)
}

impl Channel {
    /// Builds a channel from already-derived keys. Both counters start at 0.
    /// Normally obtained from the handshakes; public for KATs and tests.
    #[must_use]
    pub fn from_keys(keys: ChannelKeys, share_id: Id16, viewer_id: u32, role: Role) -> Self {
        let ChannelKeys { k_h2v, k_v2h } = keys;
        let (send_key, recv_key) = match role {
            Role::Host => (k_h2v, k_v2h),
            Role::Viewer => (k_v2h, k_h2v),
        };
        Self {
            share_id,
            viewer_id,
            role,
            send_key,
            recv_key,
            send_seq: 0,
            recv_seq: 0,
            closed: false,
        }
    }

    const fn send_dir(&self) -> Direction {
        match self.role {
            Role::Host => Direction::HostToViewer,
            Role::Viewer => Direction::ViewerToHost,
        }
    }

    const fn recv_dir(&self) -> Direction {
        match self.role {
            Role::Host => Direction::ViewerToHost,
            Role::Viewer => Direction::HostToViewer,
        }
    }

    /// This end's role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The relay-assigned viewer id bound into the AAD.
    #[must_use]
    pub const fn viewer_id(&self) -> u32 {
        self.viewer_id
    }

    /// The share id bound into the AAD.
    #[must_use]
    pub const fn share_id(&self) -> &Id16 {
        &self.share_id
    }

    /// Whether the channel is closed (after any error or [`Channel::close`]).
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// The `seq` the next [`Channel::seal`] will use.
    #[must_use]
    pub const fn next_send_seq(&self) -> u64 {
        self.send_seq
    }

    /// The `seq` the next [`Channel::open`] expects.
    #[must_use]
    pub const fn next_recv_seq(&self) -> u64 {
        self.recv_seq
    }

    /// Closes the channel (e.g. after the decrypted plaintext failed to
    /// decode). Every later `seal`/`open` returns [`ChannelError::Closed`].
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Seals `plaintext` as the next outgoing frame: `seq (u64 BE) || ct`.
    ///
    /// # Errors
    /// [`ChannelError::Closed`] if closed; [`ChannelError::Exhausted`] when
    /// the counter would wrap (the channel is then closed).
    pub fn seal(&mut self, plaintext: &[u8]) -> core::result::Result<Vec<u8>, ChannelError> {
        if self.closed {
            return Err(ChannelError::Closed);
        }
        let seq = self.send_seq;
        let Some(next) = seq.checked_add(1) else {
            self.closed = true;
            return Err(ChannelError::Exhausted);
        };
        let aad =
            canon::aad_share_frame(&self.share_id, self.viewer_id, self.send_dir() as u8, seq);
        let ct = match aead::seal(&self.send_key, &frame_nonce(seq), &aad, plaintext) {
            Ok(ct) => ct,
            Err(_) => {
                self.closed = true;
                return Err(ChannelError::Auth);
            }
        };
        self.send_seq = next;
        let mut out = Vec::with_capacity(SEQ_LEN + ct.len());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Opens the next incoming frame. The frame is authenticated first, then
    /// its `seq` must equal the expected value exactly. Any failure closes
    /// the channel.
    ///
    /// # Errors
    /// [`ChannelError::Auth`], [`ChannelError::Sequence`] or
    /// [`ChannelError::Closed`].
    pub fn open(&mut self, wire: &[u8]) -> core::result::Result<Zeroizing<Vec<u8>>, ChannelError> {
        if self.closed {
            return Err(ChannelError::Closed);
        }
        let result = self.open_inner(wire);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn open_inner(
        &mut self,
        wire: &[u8],
    ) -> core::result::Result<Zeroizing<Vec<u8>>, ChannelError> {
        let (seq_bytes, ct) = wire.split_at_checked(SEQ_LEN).ok_or(ChannelError::Auth)?;
        let mut sb = [0u8; SEQ_LEN];
        sb.copy_from_slice(seq_bytes);
        let seq = u64::from_be_bytes(sb);
        let aad =
            canon::aad_share_frame(&self.share_id, self.viewer_id, self.recv_dir() as u8, seq);
        let pt = aead::open(&self.recv_key, &frame_nonce(seq), &aad, ct)
            .map_err(|_| ChannelError::Auth)?;
        if seq != self.recv_seq {
            return Err(ChannelError::Sequence);
        }
        // An authentic frame with seq == u64::MAX means the peer exhausted its
        // counter; nothing valid can follow.
        self.recv_seq = seq.checked_add(1).ok_or(ChannelError::Sequence)?;
        Ok(pt)
    }
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

/// Link parse failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// Not a `sverb://join/…` or `https://…/s/…` link.
    #[error("not a sverb share link")]
    Scheme,
    /// The `#<key>` fragment is missing or empty.
    #[error("share link has no key fragment")]
    MissingFragment,
    /// The fragment is not base64url (no padding) of exactly 32 bytes.
    #[error("share link key is invalid")]
    Key,
    /// The share id is not a hyphenated UUID.
    #[error("share link id is invalid")]
    ShareId,
    /// The server part is empty or contains forbidden characters.
    #[error("share link server is invalid")]
    Server,
}

/// A parsed share link. `Debug` redacts the key.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareLink {
    server: String,
    share_id: Id16,
    key: ShareKey,
}

impl core::fmt::Debug for ShareLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareLink")
            .field("server", &self.server)
            .field("share_id", &format_uuid(&self.share_id))
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// `host[:port]` (IPv6 in brackets): no `/`, `#`, `?`, `@`, `\`, `%`,
/// whitespace or control characters.
fn valid_server(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().all(|c| {
            !c.is_whitespace()
                && !c.is_control()
                && !matches!(c, '/' | '#' | '?' | '@' | '\\' | '%')
        })
}

impl ShareLink {
    /// Builds a link, validating the server part.
    ///
    /// # Errors
    /// [`LinkError::Server`] if `server` is not a bare `host[:port]`.
    pub fn new(
        server: &str,
        share_id: Id16,
        key: ShareKey,
    ) -> core::result::Result<Self, LinkError> {
        if !valid_server(server) {
            return Err(LinkError::Server);
        }
        Ok(Self {
            server: server.to_owned(),
            share_id,
            key,
        })
    }

    /// Parses `sverb://join/<server>/<share_id>#<key>` or
    /// `https://<server>/s/<share_id>#<key>` (schemes are case-insensitive).
    ///
    /// # Errors
    /// The [`LinkError`] for the first part that fails validation.
    pub fn parse(link: &str) -> core::result::Result<Self, LinkError> {
        let link = link.trim();
        let (rest, web) = if let Some(r) = strip_prefix_ci(link, "sverb://join/") {
            (r, false)
        } else if let Some(r) = strip_prefix_ci(link, "https://") {
            (r, true)
        } else {
            return Err(LinkError::Scheme);
        };
        let (path, fragment) = rest.split_once('#').ok_or(LinkError::MissingFragment)?;
        if fragment.is_empty() {
            return Err(LinkError::MissingFragment);
        }
        let (server, id_part) = path.split_once('/').ok_or(LinkError::ShareId)?;
        let id_str = if web {
            id_part.strip_prefix("s/").ok_or(LinkError::Scheme)?
        } else {
            id_part
        };
        if !valid_server(server) {
            return Err(LinkError::Server);
        }
        let share_id = parse_uuid(id_str).ok_or(LinkError::ShareId)?;
        let key_bytes = Zeroizing::new(b64url_decode(fragment).ok_or(LinkError::Key)?);
        let key: [u8; SHARE_KEY_LEN] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LinkError::Key)?;
        Ok(Self {
            server: server.to_owned(),
            share_id,
            key: ShareKey::from_bytes(key),
        })
    }

    /// The `host[:port]` server part. Never contains the fragment.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// `https://<server>`: the base URL for HTTP/WS use. Never contains the
    /// fragment.
    #[must_use]
    pub fn web_base_url(&self) -> String {
        format!("https://{}", self.server)
    }

    /// The share id (16 raw UUID bytes).
    #[must_use]
    pub const fn share_id(&self) -> &Id16 {
        &self.share_id
    }

    /// The link key.
    #[must_use]
    pub const fn key(&self) -> &ShareKey {
        &self.key
    }

    /// `sverb://join/<server>/<share_id>#<base64url(key)>`.
    #[must_use]
    pub fn to_sverb_link(&self) -> String {
        format!(
            "sverb://join/{}/{}#{}",
            self.server,
            format_uuid(&self.share_id),
            b64url_encode(self.key.expose_secret())
        )
    }

    /// `https://<server>/s/<share_id>#<base64url(key)>`.
    #[must_use]
    pub fn to_web_link(&self) -> String {
        format!(
            "https://{}/s/{}#{}",
            self.server,
            format_uuid(&self.share_id),
            b64url_encode(self.key.expose_secret())
        )
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// Formats 16 bytes as a lowercase hyphenated UUID.
#[must_use]
pub fn format_uuid(id: &Id16) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in id.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parses a hyphenated UUID (8-4-4-4-12 hex, either case).
#[must_use]
pub fn parse_uuid(s: &str) -> Option<Id16> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut n = 0;
    let mut i = 0;
    while i < 36 {
        if matches!(i, 8 | 13 | 18 | 23) {
            if b[i] != b'-' {
                return None;
            }
            i += 1;
            continue;
        }
        let hi = hex_val(b[i])?;
        let lo = hex_val(*b.get(i + 1)?)?;
        out[n] = (hi << 4) | lo;
        n += 1;
        i += 2;
    }
    Some(out)
}

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding (RFC 4648 §5).
#[must_use]
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for k in 0..chars {
            out.push(char::from(B64URL[((n >> (18 - 6 * k)) & 0x3f) as usize]));
        }
    }
    out
}

/// Strict base64url decoder: no padding, no whitespace, canonical trailing
/// bits. Returns `None` on any error.
#[must_use]
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 4 == 1 {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        Some(u32::from(v))
    };
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    for chunk in b.chunks(4) {
        let mut n = 0u32;
        for (k, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * k);
        }
        let bytes = n.to_be_bytes();
        let take = chunk.len() - 1;
        // Non-canonical: leftover bits beyond the decoded bytes must be zero.
        let mask_bits = 24 - 8 * take;
        if mask_bits < 24 && n & ((1u32 << mask_bits) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&bytes[1..=take]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_vectors() {
        // RFC 4648 §10 vectors, unpadded.
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64url_encode(raw.as_bytes()), enc);
            assert_eq!(b64url_decode(enc).as_deref(), Some(raw.as_bytes()));
        }
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("Zh"), None, "non-canonical trailing bits");
        assert_eq!(b64url_decode("Zm9v="), None, "padding rejected");
        assert_eq!(b64url_decode("Z"), None);
        assert_eq!(b64url_decode("Zm+v"), None, "standard alphabet rejected");
    }

    #[test]
    fn uuid_round_trip() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let s = format_uuid(&id);
        assert_eq!(s, "01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(parse_uuid(&s), Some(id));
        assert_eq!(parse_uuid(&s.to_uppercase()), Some(id));
        assert_eq!(parse_uuid("0123456789abcdef0123456789abcdef"), None);
        assert_eq!(parse_uuid("01234567-89ab-cdef-0123-456789abcdeg"), None);
    }
}
