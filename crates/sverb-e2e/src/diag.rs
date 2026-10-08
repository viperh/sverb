//! Failure diagnostics (M1-18 §2.3).
//!
//! Harness objects ([`Sshd`](crate::Sshd), [`Headless`](crate::Headless),
//! [`PtyApp`](crate::PtyApp)) call [`dump`] from their `Drop` when the thread is
//! panicking, so a failed assertion anywhere in a test prints the container logs and
//! the last screen. Waits that time out put the screen into their error as well.
//!
//! Dumps go to stderr (captured by the test harness and shown for failed tests).
//! [`capture`] additionally collects them on the current thread, so the harness can
//! test its own diagnostics (T-07).

use std::cell::RefCell;

thread_local! {
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Print a diagnostics section `title` with `body`.
pub fn dump(title: &str, body: &str) {
    let text = format!(
        "\n===== sverb-e2e: {title} =====\n{}\n===== end of {title} =====\n",
        body.trim_end()
    );
    eprint!("{text}");
    CAPTURE.with(|c| {
        if let Some(buf) = c.borrow_mut().as_mut() {
            buf.push(text);
        }
    });
}

/// Run `f`, collecting every [`dump`] made on this thread while it runs (also during
/// a panic unwinding out of `f`). Returns `f`'s result (`Err` with the panic payload
/// if it panicked) and the dumps.
pub fn capture<R>(f: impl FnOnce() -> R) -> (std::thread::Result<R>, Vec<String>) {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let dumps = CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default();
    (result, dumps)
}

/// Whether diagnostics should be dumped now (the thread is unwinding from a panic).
pub fn failing() -> bool {
    std::thread::panicking()
}

/// The last `max` lines of `text`.
pub fn tail(text: &str, max: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let skip = lines.len().saturating_sub(max);
    let mut out = String::new();
    if skip > 0 {
        out.push_str(&format!("[… {skip} earlier lines]\n"));
    }
    out.push_str(&lines[skip..].join("\n"));
    out
}
