//! M7-05: process hardening (SPEC §17 "Memory scraping").
//!
//! - [`harden_process`] runs once at startup, before anything secret exists:
//!   - Linux: `prctl(PR_SET_DUMPABLE, 0)`: no core dumps, and processes of the same user
//!     that are not root can't `ptrace` sverb or read its `/proc/<pid>/mem`;
//!   - every unix: `setrlimit(RLIMIT_CORE, 0)` (soft and hard), the only switch on macOS;
//!   - Windows (best effort): no fault dialogs (`SetErrorMode`) and no heap in Windows
//!     Error Reporting dumps (`WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)`).
//!
//!   Children (shells, `ProxyCommand`, `ssh-add`) are unaffected: `execve` resets the
//!   dumpable flag, and they get their own limits from their own startup.
//! - [`Locked`] holds key material (the LMK and the vault keys) on the heap in pages
//!   that are `mlock`ed (`VirtualLock` on Windows), so they are never written to swap.
//!   Best effort: when `RLIMIT_MEMLOCK` is too low the key stays usable, unlocked, and
//!   the failure is logged once at `debug`. Locks are counted per page, so dropping one
//!   key never unlocks a page another key still lives in. The value is zeroized before
//!   its pages are unlocked.
//!
//! # `unsafe`
//!
//! The OS calls need `unsafe`, so the platform files (`unix.rs`, `windows.rs`) carry
//! `#![allow(unsafe_code)]`, each block with a `SAFETY` comment. The workspace lint is
//! `unsafe_code = "deny"`; `scripts/check-unsafe.py` (CI) fails if the lint is lifted
//! anywhere but here and in the Windows agent pipe DACL module
//! (`sverb-conn/src/agent/dacl_windows.rs`). This file itself has no `unsafe`. See
//! `docs/threat-model.md`.

use std::{
    collections::BTreeMap,
    fmt, io,
    ops::{Deref, DerefMut},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use zeroize::Zeroize;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

/// Platforms without any hardening support: everything reports "unsupported".
#[cfg(not(any(unix, windows)))]
mod sys {
    use std::io;

    pub(super) fn harden_process() -> super::HardeningReport {
        super::HardeningReport {
            failures: vec!["process hardening is not supported on this platform".to_owned()],
            ..super::HardeningReport::default()
        }
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
        4096
    }

    pub(super) fn lock_page(_addr: usize, _len: usize) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(super) fn unlock_page(_addr: usize, _len: usize) {}
}

/// What [`harden_process`] managed to do. Nothing in it is secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardeningReport {
    /// Core dumps are off: `RLIMIT_CORE` is 0 (unix), or heap is excluded from Windows
    /// Error Reporting dumps.
    pub core_dumps_disabled: bool,
    /// Linux: `PR_SET_DUMPABLE` is 0 (also blocks same-user `ptrace` and `/proc/<pid>/mem`).
    pub non_dumpable: bool,
    /// Steps that failed or are unsupported here, for the debug log.
    pub failures: Vec<String>,
}

/// Disable core dumps (and, on Linux, same-user `ptrace`) for this process. Call it
/// first thing in `main`. Never fails: what could not be done is in the report.
pub fn harden_process() -> HardeningReport {
    sys::harden_process()
}

/// Linux: the process's `PR_GET_DUMPABLE` flag (`Some(false)` after
/// [`harden_process`]). `None` where the flag does not exist.
#[must_use]
pub fn is_dumpable() -> Option<bool> {
    sys::is_dumpable()
}

/// Unix: the soft `RLIMIT_CORE` in bytes (`Some(0)` after [`harden_process`]).
/// `None` where there is no such limit.
#[must_use]
pub fn core_dump_limit() -> Option<u64> {
    sys::core_dump_limit()
}

/// Unix: set the soft `RLIMIT_MEMLOCK` (capped at the hard limit). Used by tests and
/// diagnostics to exercise the [`Locked`] fallback.
///
/// # Errors
/// `setrlimit` failed, or the platform has no such limit (`Unsupported`).
pub fn set_memlock_limit(soft_bytes: u64) -> io::Result<()> {
    sys::set_memlock_limit(soft_bytes)
}

/// Pages currently locked by [`Locked`] values, with their reference counts.
static LOCKED_PAGES: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
/// The "mlock unavailable" debug line is written once per process.
static MLOCK_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

/// Lock every page of `[addr, addr + len)` that is not locked yet, and count a
/// reference on each. Returns the pages referenced and whether all of them are locked.
fn lock_range(addr: usize, len: usize) -> (Vec<usize>, bool) {
    if len == 0 {
        return (Vec::new(), true);
    }
    let page = sys::page_size().max(1);
    let first = addr - addr % page;
    let last = (addr + len - 1) - (addr + len - 1) % page;
    let mut pages = LOCKED_PAGES.lock().unwrap_or_else(PoisonError::into_inner);
    let mut held = Vec::new();
    let mut start = first;
    loop {
        let count = pages.entry(start).or_insert(0);
        if *count == 0
            && let Err(err) = sys::lock_page(start, page)
        {
            pages.remove(&start);
            drop(pages);
            if !MLOCK_FAILURE_LOGGED.swap(true, Ordering::Relaxed) {
                tracing::debug!(
                    error = %err,
                    "mlock unavailable (RLIMIT_MEMLOCK too low?); key material stays in swappable memory"
                );
            }
            return (held, false);
        }
        *count += 1;
        held.push(start);
        if start >= last {
            break;
        }
        start += page;
    }
    (held, true)
}

/// Drop the references taken by [`lock_range`], unlocking pages that reach zero.
fn unlock_pages(held: &[usize]) {
    if held.is_empty() {
        return;
    }
    let page = sys::page_size().max(1);
    let mut pages = LOCKED_PAGES.lock().unwrap_or_else(PoisonError::into_inner);
    for start in held {
        if let Some(count) = pages.get_mut(start) {
            *count -= 1;
            if *count == 0 {
                pages.remove(start);
                sys::unlock_page(*start, page);
            }
        }
    }
}

/// Number of pages currently locked by [`Locked`] values (diagnostics and tests).
#[must_use]
pub fn locked_page_count() -> usize {
    LOCKED_PAGES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len()
}

/// Key material on the heap, in `mlock`ed pages where the OS allows it. Zeroized
/// before its pages are unlocked when dropped. `Debug` never prints the value.
///
/// Moving a value in leaves the caller's copy behind; build keys straight into
/// [`Locked::new`] and let the source (a zeroize-on-drop type) clean itself up.
pub struct Locked<T: Zeroize> {
    value: Box<T>,
    pages: Vec<usize>,
    locked: bool,
}

impl<T: Zeroize> Locked<T> {
    /// Move `value` to the heap and lock its pages (best effort).
    pub fn new(value: T) -> Self {
        let value = Box::new(value);
        let len = std::mem::size_of::<T>();
        let addr = std::ptr::from_ref::<T>(&value) as usize;
        let (pages, locked) = lock_range(addr, len);
        Self {
            value,
            pages,
            locked,
        }
    }

    /// Whether every page of the value is locked in RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T: Zeroize> Deref for Locked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Zeroize> DerefMut for Locked<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: Zeroize> Drop for Locked<T> {
    fn drop(&mut self) {
        self.value.zeroize();
        unlock_pages(&self.pages);
    }
}

impl<T: Zeroize> fmt::Debug for Locked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Locked")
            .field("value", &"[REDACTED]")
            .field("locked", &self.locked)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_value_derefs_and_redacts() {
        let mut key = Locked::new([7u8; 32]);
        assert_eq!(key[0], 7);
        key[1] = 9;
        assert_eq!(key[1], 9);
        let dbg = format!("{key:?}");
        assert!(dbg.contains("[REDACTED]") && !dbg.contains('7'), "{dbg}");
    }

    #[test]
    fn page_references_are_counted() {
        // A page owned by this test alone (inside a buffer of three pages), referenced
        // twice: the first release keeps it locked, the second unlocks it.
        let page = sys::page_size();
        let buf = vec![0u8; 3 * page];
        let base = buf.as_ptr() as usize;
        let aligned = base + (page - base % page) % page;
        let (first, ok) = lock_range(aligned + 16, 32);
        if !ok {
            eprintln!("SKIP: mlock unavailable here");
            return;
        }
        assert_eq!(first, vec![aligned]);
        let (second, _) = lock_range(aligned + 64, 32);
        assert_eq!(second, vec![aligned]);
        let count = |p: usize| {
            LOCKED_PAGES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&p)
                .copied()
        };
        assert_eq!(count(aligned), Some(2));
        unlock_pages(&first);
        assert_eq!(count(aligned), Some(1));
        unlock_pages(&second);
        assert_eq!(count(aligned), None);

        // A range across a page boundary references both pages.
        let (both, ok) = lock_range(aligned + page - 8, 16);
        assert!(ok);
        assert_eq!(both, vec![aligned, aligned + page]);
        unlock_pages(&both);
        assert_eq!(count(aligned + page), None);
        drop(buf);
    }

    #[test]
    fn zero_sized_values_need_no_lock() {
        let unit = Locked::new(ZeroSized);
        assert!(unit.is_locked());
    }

    #[derive(Default)]
    struct ZeroSized;

    impl Zeroize for ZeroSized {
        fn zeroize(&mut self) {}
    }
}
