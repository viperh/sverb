//! M7-05: Windows process hardening (best effort): no fault dialogs, no heap in Windows
//! Error Reporting dumps, and `VirtualLock` for key pages.
//!
//! One of the two documented `unsafe` exceptions (SPEC §17; `scripts/check-unsafe.py`).
//! Every block is a plain Win32 call with integer arguments or a pointer to a value we
//! own for the duration of the call; none of them retains a pointer.
#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    },
    ErrorReporting::{WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags},
    Memory::{VirtualLock, VirtualUnlock},
    SystemInformation::{GetSystemInfo, SYSTEM_INFO},
};

use super::HardeningReport;

pub(super) fn harden_process() -> HardeningReport {
    let mut report = HardeningReport::default();

    // SAFETY: both calls take and return plain flags; no memory is involved.
    unsafe {
        let mode = GetErrorMode();
        SetErrorMode(mode | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }

    // SAFETY: `WerSetFlags` takes a flag word and returns an HRESULT.
    let hr = unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };
    if hr >= 0 {
        report.core_dumps_disabled = true;
    } else {
        report
            .failures
            .push(format!("WerSetFlags(NOHEAP): HRESULT {hr:#010x}"));
    }
    report
        .failures
        .push("Windows has no per-process ptrace/dumpable switch".to_owned());
    report
}

pub(super) fn is_dumpable() -> Option<bool> {
    None
}

pub(super) fn core_dump_limit() -> Option<u64> {
    None
}

pub(super) fn set_memlock_limit(_soft: u64) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

pub(super) fn page_size() -> usize {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: `GetSystemInfo` fills one `SYSTEM_INFO` we own and keeps no reference.
    unsafe { GetSystemInfo(&raw mut info) };
    usize::try_from(info.dwPageSize)
        .ok()
        .filter(|s| *s > 0)
        .unwrap_or(4096)
}

pub(super) fn lock_page(addr: usize, len: usize) -> io::Result<()> {
    // SAFETY: `VirtualLock` changes only the residency of committed pages in the range;
    // it never reads or writes them. The range is inside a live heap allocation the
    // caller owns.
    if unsafe { VirtualLock(addr as *const core::ffi::c_void, len) } != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn unlock_page(addr: usize, len: usize) {
    // SAFETY: as `lock_page`. A failure (already unlocked) changes nothing.
    let _ = unsafe { VirtualUnlock(addr as *const core::ffi::c_void, len) };
}
