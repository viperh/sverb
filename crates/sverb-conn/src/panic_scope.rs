//! Marks code that runs inside a contained session task (M1-08, M0-05 open note).
//!
//! The global panic hook (`crates/sverb/src/panic.rs`) restores the terminal and shuts
//! logging down on every panic, which is right for the UI task but wrong for a session
//! actor: its panic is caught through the `JoinHandle` by the
//! [`SessionManager`](crate::SessionManager), the UI keeps running, and only the pane
//! shows "session crashed (see log)". The actor future is therefore wrapped in
//! [`Contained`], which sets a thread-local flag while it is polled; the hook asks
//! [`in_contained_task`] and, when it is set, only logs the panic (and writes the crash
//! report) instead of tearing the terminal down.
//!
//! The flag is set for the duration of one `poll` on the polling thread, so it is
//! still set while the hook runs (the hook runs before unwinding) and cleared by the
//! guard's `Drop` during unwinding. Work moved to other threads (`spawn_blocking`) is
//! not covered: wrap it in [`contain_blocking`] if it can panic.

use std::{
    cell::Cell,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Whether the current thread is running a contained session task right now.
pub fn in_contained_task() -> bool {
    DEPTH.try_with(|d| d.get() > 0).unwrap_or(false)
}

struct Scope;

impl Scope {
    fn enter() -> Self {
        let _ = DEPTH.try_with(|d| d.set(d.get() + 1));
        Scope
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let _ = DEPTH.try_with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// A future whose panics are contained by its owner (the session manager).
pub struct Contained<F> {
    inner: Pin<Box<F>>,
}

impl<F> Contained<F> {
    /// Wrap `fut`.
    pub fn new(fut: F) -> Self {
        Self {
            inner: Box::pin(fut),
        }
    }
}

impl<F> fmt::Debug for Contained<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Contained").finish_non_exhaustive()
    }
}

impl<F: Future> Future for Contained<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _scope = Scope::enter();
        self.inner.as_mut().poll(cx)
    }
}

/// Run blocking `f` (e.g. inside `spawn_blocking`) as contained code.
pub fn contain_blocking<T>(f: impl FnOnce() -> T) -> T {
    let _scope = Scope::enter();
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn flag_is_set_only_while_polled() {
        assert!(!in_contained_task());
        let inside = Contained::new(async { in_contained_task() }).await;
        assert!(inside);
        assert!(!in_contained_task());
        assert!(contain_blocking(in_contained_task));
    }

    #[test]
    fn flag_is_cleared_by_unwinding() {
        let r = std::panic::catch_unwind(|| {
            contain_blocking(|| {
                assert!(in_contained_task());
                std::panic::resume_unwind(Box::new("probe"));
            })
        });
        assert!(r.is_err());
        assert!(!in_contained_task());
    }
}
