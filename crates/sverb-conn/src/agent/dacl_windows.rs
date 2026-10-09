//! The owner-only DACL of the `sverb agent` named pipe, and the
//! check that a connected client runs as the same user (SPEC §6.1.6).
//!
//! - The pipe is created with a **protected** DACL from the SDDL
//!   `D:P(A;;GA;;;<user SID>)`: only the current user gets access; nothing is inherited,
//!   and Everyone / Administrators / SYSTEM get no ACE (the default DACL gives Everyone
//!   read access).
//! - After a client connects, its process token's user SID is compared with ours
//!   (`GetNamedPipeClientProcessId` → `OpenProcessToken` → `EqualSid`); a mismatch drops
//!   the connection. With the DACL this is defense in depth.
//!
//! One of the two documented `unsafe` exceptions (SPEC §17; `scripts/check-unsafe.py`):
//! the Win32 security calls have no safe wrapper in our dependency set. Only compiled on
//! Windows.
#![allow(unsafe_code)]

use std::{ffi::c_void, io, os::windows::io::AsRawHandle, ptr::null_mut};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            EqualSid, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
            TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::{
            Pipes::GetNamedPipeClientProcessId,
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
    core::PWSTR,
};

/// Closes a kernel handle on drop.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was returned by OpenProcess/OpenProcessToken, is owned
            // by this guard, and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Frees a `LocalAlloc` block (SDDL conversions) on drop.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the block was allocated by a Convert* function, which documents
            // LocalFree as its release; it is owned by this guard and freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A `TOKEN_USER` copied out of a token (8-byte aligned buffer).
struct TokenUserBuf(Vec<u64>);

impl TokenUserBuf {
    fn sid(&self) -> PSID {
        // SAFETY: the buffer was filled by GetTokenInformation(TokenUser) and starts
        // with a TOKEN_USER (Vec<u64> is aligned for its pointer field); the SID it
        // points to lives inside the same buffer, which outlives every use of it.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

/// The user of `process`'s token.
fn token_user(process: HANDLE) -> io::Result<TokenUserBuf> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `token` is a valid out pointer; the process handle is valid for the call.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut len = 0u32;
    // SAFETY: a size query (null buffer, length 0) only writes `len`.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &raw mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` has at least `len` writable bytes and outlives the call.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast(),
            len,
            &raw mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TokenUserBuf(buf))
}

/// The current user's SID as a string (`S-1-5-21-…`).
fn current_user_sid_string() -> io::Result<String> {
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing.
    let user = token_user(unsafe { GetCurrentProcess() })?;
    let mut wide: PWSTR = null_mut();
    // SAFETY: the SID is valid (see `TokenUserBuf::sid`); `wide` is a valid out pointer.
    if unsafe { ConvertSidToStringSidW(user.sid(), &raw mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = Local(wide.cast());
    let mut len = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 string, read up to
    // (not past) its terminator while `guard` keeps it alive.
    let units = unsafe {
        while *wide.add(len) != 0 {
            len += 1;
        }
        std::slice::from_raw_parts(wide, len)
    };
    let sid = String::from_utf16_lossy(units);
    drop(guard);
    Ok(sid)
}

/// Security attributes granting the current user, and nobody else, access.
pub(crate) struct OwnerOnly {
    attrs: SECURITY_ATTRIBUTES,
    _descriptor: Local,
    sddl: String,
}

// SAFETY: the security descriptor is an immutable LocalAlloc block owned exclusively by
// this value (only read by CreateNamedPipeW), so moving it to another thread is sound.
unsafe impl Send for OwnerOnly {}

impl OwnerOnly {
    /// Build the descriptor for the current user.
    ///
    /// # Errors
    /// The token or the SDDL conversion failed.
    pub(crate) fn current_user() -> io::Result<Self> {
        let sid = current_user_sid_string()?;
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `descriptor` is a valid
        // out pointer; the size out pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(24),
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Self {
            attrs,
            _descriptor: Local(descriptor),
            sddl,
        })
    }

    /// The SDDL the descriptor was built from (for logs and the T-14 test).
    pub(crate) fn sddl(&self) -> &str {
        &self.sddl
    }

    /// Create a pipe instance named `name` with this DACL.
    ///
    /// # Errors
    /// See [`ServerOptions::create`].
    pub(crate) fn create(
        &mut self,
        options: &ServerOptions,
        name: &str,
    ) -> io::Result<NamedPipeServer> {
        // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose descriptor lives as long
        // as `self`; CreateNamedPipeW copies the descriptor into the pipe object and
        // keeps no pointer to it.
        unsafe { options.create_with_security_attributes_raw(name, (&raw mut self.attrs).cast()) }
    }
}

/// The pid of the client connected to `pipe`, if it runs as the current user.
///
/// # Errors
/// `PermissionDenied` for another user; an OS error if the client can't be inspected.
pub(crate) fn client_pid_if_same_user(pipe: &NamedPipeServer) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: the raw handle belongs to `pipe`, which outlives the call; `pid` is a
    // valid out pointer.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &raw mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain call; a null handle (failure) is checked below.
    let process = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    if process.0.is_null() {
        return Err(io::Error::last_os_error());
    }
    let client = token_user(process.0)?;
    // SAFETY: as above, a pseudo handle.
    let me = token_user(unsafe { GetCurrentProcess() })?;
    // SAFETY: both SIDs are valid and live in their buffers for the call.
    if unsafe { EqualSid(client.sid(), me.sid()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the agent pipe client runs as another user",
        ));
    }
    Ok(pid)
}
