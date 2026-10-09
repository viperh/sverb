//! Opening links (`Effect::OpenUrl`, SPEC §17).
//!
//! The reducer only issues `OpenUrl` after the user confirmed a dialog that shows the URL.
//! This is the second gate: only `http`, `https`, `ftp` and `mailto` links are handed to the
//! system (a remote can put any scheme in an OSC 8 link, and `file:` or custom handlers could
//! run local programs). The real opener is [`SystemOpener`] (the `open` crate); tests inject
//! their own, so no test ever opens a browser.

use std::{fmt, io};

use tracing::{debug, warn};

/// Opens a URL with the system's handler.
pub trait UrlOpener: Send + fmt::Debug {
    /// Start opening `url` (returns once the handler was launched).
    fn open(&mut self, url: &str) -> io::Result<()>;
}

/// The platform handler (`xdg-open`, `open`, `start`) through the `open` crate.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemOpener;

impl UrlOpener for SystemOpener {
    fn open(&mut self, url: &str) -> io::Result<()> {
        open::that_detached(url)
    }
}

/// Schemes that may be opened.
pub const ALLOWED_SCHEMES: &[&str] = &["http", "https", "ftp", "mailto"];

/// Whether `url` has an allowed scheme (case-insensitive) and no control characters.
#[must_use]
pub fn allowed(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once(':') else {
        return false;
    };
    !rest.is_empty()
        && !url.chars().any(char::is_control)
        && ALLOWED_SCHEMES
            .iter()
            .any(|s| s.eq_ignore_ascii_case(scheme))
}

/// Execute `Effect::OpenUrl`.
pub fn open(opener: Option<&mut (dyn UrlOpener + 'static)>, url: &str) {
    let Some(opener) = opener else {
        debug!("link not opened: no opener");
        return;
    };
    if !allowed(url) {
        warn!("refused to open a link with a disallowed scheme");
        return;
    }
    if let Err(err) = opener.open(url) {
        warn!(%err, "cannot open the link");
    } else {
        debug!(url, "opened link");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Records URLs instead of opening them.
    #[derive(Debug, Default, Clone)]
    struct Recorder(Arc<Mutex<Vec<String>>>);

    impl UrlOpener for Recorder {
        fn open(&mut self, url: &str) -> io::Result<()> {
            if let Ok(mut v) = self.0.lock() {
                v.push(url.to_owned());
            }
            Ok(())
        }
    }

    #[test]
    fn only_allowed_schemes_reach_the_opener() {
        let rec = Recorder::default();
        let mut opener = rec.clone();
        for url in [
            "https://example.com/x",
            "HTTP://example.com",
            "mailto:a@b.c",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ms-msdt:/id",
            "https://x\u{7}y",
            "https:",
            "nope",
        ] {
            open(Some(&mut opener), url);
        }
        open(None, "https://example.com/never");
        let seen = rec.0.lock().map(|v| v.clone()).unwrap_or_default();
        assert_eq!(
            seen,
            [
                "https://example.com/x",
                "HTTP://example.com",
                "mailto:a@b.c"
            ]
        );
    }

    #[test]
    fn services_execute_open_url_through_the_injected_opener() {
        let rec = Recorder::default();
        let mut services = super::super::Services::new().with_url_opener(Box::new(rec.clone()));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        services.execute(
            crate::app::Effect::OpenUrl("https://example.com/".to_owned()),
            &tx,
        );
        let seen = rec.0.lock().map(|v| v.clone()).unwrap_or_default();
        assert_eq!(seen, ["https://example.com/"]);
        // Without an opener nothing happens.
        super::super::Services::new()
            .execute(crate::app::Effect::OpenUrl("https://x/".to_owned()), &tx);
    }
}
