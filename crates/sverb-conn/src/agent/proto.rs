//! M2-07: the SSH agent wire protocol (draft-miller-ssh-agent), the subset sverb's
//! built-in agent speaks.
//!
//! A frame is `uint32 length || payload`; the payload starts with the message type.
//! The built-in agent answers `REQUEST_IDENTITIES` and `SIGN_REQUEST`; every other
//! request (add, remove, lock, extensions, …) gets `SSH_AGENT_FAILURE`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame accepted (OpenSSH uses 256 KiB as well).
pub const MAX_FRAME: usize = 256 * 1024;

/// `SSH_AGENT_FAILURE`.
pub const FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS`.
pub const SUCCESS: u8 = 6;
/// `SSH_AGENTC_REQUEST_IDENTITIES`.
pub const REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER`.
pub const IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENTC_SIGN_REQUEST`.
pub const SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_SIGN_RESPONSE`.
pub const SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENTC_ADD_IDENTITY`.
pub const ADD_IDENTITY: u8 = 17;
/// `SSH_AGENTC_REMOVE_IDENTITY`.
pub const REMOVE_IDENTITY: u8 = 18;
/// `SSH_AGENTC_REMOVE_ALL_IDENTITIES`.
pub const REMOVE_ALL_IDENTITIES: u8 = 19;
/// `SSH_AGENTC_LOCK`.
pub const LOCK: u8 = 22;
/// `SSH_AGENTC_UNLOCK`.
pub const UNLOCK: u8 = 23;
/// `SSH_AGENTC_EXTENSION`.
pub const EXTENSION: u8 = 27;

/// Sign-request flag: `rsa-sha2-256`.
pub const RSA_SHA2_256: u32 = 2;
/// Sign-request flag: `rsa-sha2-512`.
pub const RSA_SHA2_512: u32 = 4;

/// A malformed message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed agent message")]
pub struct Malformed;

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `REQUEST_IDENTITIES`.
    Identities,
    /// `SIGN_REQUEST`.
    Sign {
        /// The key (or certificate) blob.
        key_blob: Vec<u8>,
        /// The data to sign.
        data: Vec<u8>,
        /// `SSH_AGENT_RSA_SHA2_*` flags.
        flags: u32,
    },
    /// Anything else (by message type); answered with `FAILURE`.
    Unsupported(u8),
}

/// Reads SSH wire primitives from a slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Result<u32, Malformed> {
        let (head, rest) = self.0.split_first_chunk::<4>().ok_or(Malformed)?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Result<&'a [u8], Malformed> {
        let len = usize::try_from(self.u32()?).map_err(|_| Malformed)?;
        if len > self.0.len() {
            return Err(Malformed);
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(s)
    }
}

/// Parse one frame's payload.
///
/// # Errors
/// [`Malformed`] for an empty payload or a truncated `SIGN_REQUEST`.
pub fn parse(payload: &[u8]) -> Result<Request, Malformed> {
    let (&kind, body) = payload.split_first().ok_or(Malformed)?;
    match kind {
        REQUEST_IDENTITIES => Ok(Request::Identities),
        SIGN_REQUEST => {
            let mut r = Reader(body);
            let key_blob = r.string()?.to_vec();
            let data = r.string()?.to_vec();
            // Old clients omit the flags.
            let flags = r.u32().unwrap_or(0);
            Ok(Request::Sign {
                key_blob,
                data,
                flags,
            })
        }
        other => Ok(Request::Unsupported(other)),
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
}

/// `IDENTITIES_ANSWER` for `(blob, comment)` pairs.
pub fn identities_answer(ids: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![IDENTITIES_ANSWER];
    let n = u32::try_from(ids.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&n.to_be_bytes());
    for (blob, comment) in ids {
        put_string(&mut out, blob);
        put_string(&mut out, comment.as_bytes());
    }
    out
}

/// Parse an `IDENTITIES_ANSWER` payload (the `both` merge reads the system agent's).
///
/// # Errors
/// [`Malformed`] when it isn't one.
pub fn parse_identities(payload: &[u8]) -> Result<Vec<(Vec<u8>, String)>, Malformed> {
    let (&kind, body) = payload.split_first().ok_or(Malformed)?;
    if kind != IDENTITIES_ANSWER {
        return Err(Malformed);
    }
    let mut r = Reader(body);
    let n = r.u32()?;
    let mut ids = Vec::new();
    for _ in 0..n {
        let blob = r.string()?.to_vec();
        let comment = String::from_utf8_lossy(r.string()?).into_owned();
        ids.push((blob, comment));
    }
    Ok(ids)
}

/// `SIGN_RESPONSE` carrying `signature` (the encoded signature: algorithm + blob).
pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let mut out = vec![SIGN_RESPONSE];
    put_string(&mut out, signature);
    out
}

/// A `SIGN_REQUEST` payload.
pub fn sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut out = vec![SIGN_REQUEST];
    put_string(&mut out, key_blob);
    put_string(&mut out, data);
    out.extend_from_slice(&flags.to_be_bytes());
    out
}

/// The signature inside a `SIGN_RESPONSE` payload.
///
/// # Errors
/// [`Malformed`] when it isn't one.
pub fn parse_sign_response(payload: &[u8]) -> Result<Vec<u8>, Malformed> {
    let (&kind, body) = payload.split_first().ok_or(Malformed)?;
    if kind != SIGN_RESPONSE {
        return Err(Malformed);
    }
    Ok(Reader(body).string()?.to_vec())
}

/// `FAILURE`.
pub fn failure() -> Vec<u8> {
    vec![FAILURE]
}

/// Read one frame. `Ok(None)` on a clean end of stream before a frame starts.
///
/// # Errors
/// I/O errors, a truncated frame, or a frame over [`MAX_FRAME`] (`InvalidData`).
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0_u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent frame too large",
        ));
    }
    let mut buf = vec![0_u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Write one frame.
///
/// # Errors
/// I/O errors.
pub async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "agent frame too large")
    })?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}
