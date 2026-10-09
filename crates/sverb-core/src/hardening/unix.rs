//! M7-05: unix process hardening: `setrlimit(RLIMIT_CORE)`, Linux
//! `prctl(PR_SET_DUMPABLE)`, `mlock`/`munlock` and `sysconf(_SC_PAGESIZE)`.
//!
//! One of the two documented `unsafe` exceptions (SPEC §17; `scripts/check-unsafe.py`).
//! Every block is a plain libc call with integer arguments or a pointer to a value we
//! own for the duration of the call; none of them retains a pointer.
#![allow(unsafe_code)]

use std::io;

use super::HardeningReport;

pub(super) fn harden_process() -> HardeningReport {
    let mut report = HardeningReport::default();

    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` reads one initialized `rlimit` that outlives the call and
    // keeps no reference to it. Lowering both limits never needs privileges.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const zero) } == 0 {
        report.core_dumps_disabled = true;
    } else {
        report.failures.push(format!(
            "setrlimit(RLIMIT_CORE, 0): {}",
            io::Error::last_os_error()
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let off: libc::c_ulong = 0;
        // SAFETY: `PR_SET_DUMPABLE` takes integer arguments only (the unused trailing
        // ones are passed as 0, as the man page asks); no memory is read or written.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off, off, off, off) } == 0 {
            report.non_dumpable = true;
            report.core_dumps_disabled = true;
        } else {
            report.failures.push(format!(
                "prctl(PR_SET_DUMPABLE, 0): {}",
                io::Error::last_os_error()
            ));
        }
    }

    report
}

pub(super) fn is_dumpable() -> Option<bool> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let off: libc::c_ulong = 0;
        // SAFETY: `PR_GET_DUMPABLE` takes no pointer and returns the flag (or -1).
        let flag = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, off, off, off, off) };
        if flag >= 0 { Some(flag != 0) } else { None }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

fn get_limit(resource: Resource) -> Option<libc::rlimit> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes one `rlimit` into memory we own and keeps no reference.
    let rc = unsafe { libc::getrlimit(resource, &raw mut limit) };
    (rc == 0).then_some(limit)
}

/// The resource argument type differs between libcs (`c_uint` on glibc, `c_int` elsewhere).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type Resource = libc::c_int;

// `rlim_t` is not `u64` on every unix.
#[allow(clippy::unnecessary_cast)]
pub(super) fn core_dump_limit() -> Option<u64> {
    get_limit(libc::RLIMIT_CORE).map(|l| l.rlim_cur as u64)
}

pub(super) fn set_memlock_limit(soft: u64) -> io::Result<()> {
    let current = get_limit(libc::RLIMIT_MEMLOCK).ok_or_else(io::Error::last_os_error)?;
    let soft = libc::rlim_t::try_from(soft).unwrap_or(libc::RLIM_INFINITY);
    let wanted = libc::rlimit {
        rlim_cur: soft.min(current.rlim_max),
        rlim_max: current.rlim_max,
    };
    // SAFETY: as in `harden_process`: one initialized `rlimit`, not retained.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const wanted) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn page_size() -> usize {
    // SAFETY: `sysconf` only reads a configuration value.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size)
        .ok()
        .filter(|s| *s > 0)
        .unwrap_or(4096)
}

pub(super) fn lock_page(addr: usize, len: usize) -> io::Result<()> {
    // SAFETY: `mlock` changes only the residency of the pages in the range; it never
    // reads or writes them. The caller passes a page-aligned range inside a live heap
    // allocation it owns (a `Locked` box), and the kernel rejects anything unmapped.
    if unsafe { libc::mlock(addr as *const libc::c_void, len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn unlock_page(addr: usize, len: usize) {
    // SAFETY: as `lock_page`; `munlock` on a page this process locked. A failure (the
    // page is already unlocked) changes nothing, so it is ignored.
    let _ = unsafe { libc::munlock(addr as *const libc::c_void, len) };
}
