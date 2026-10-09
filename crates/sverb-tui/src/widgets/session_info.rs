//! What the UI knows about an SSH session (SPEC §6.1.8): negotiated algorithms,
//! server version, connected-since time and keepalive latency. Shown in the status bar
//! (`db · ssh · 23ms`) and in the session info panel (`session_info`, `leader i`).

use std::time::Duration;

use sverb_conn::SshSessionInfo;

/// Per-session SSH details kept by the reducer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshPaneInfo {
    /// From `SessionEvent::SshInfo`.
    pub info: SshSessionInfo,
    /// The last keepalive round trip (`SessionEvent::Latency`).
    pub latency: Option<Duration>,
}

/// Latency as shown: `23ms`, or `–` when keepalive is off or nothing was measured yet.
pub fn latency_text(info: &SshPaneInfo) -> String {
    match info.latency {
        Some(rtt) if info.info.keepalive_secs > 0 => format!("{}ms", rtt.as_millis()),
        _ => "–".to_owned(),
    }
}

/// The status bar's session segment: `label · ssh · 23ms`.
pub fn status_segment(label: &str, info: &SshPaneInfo) -> String {
    format!("{label} · ssh · {}", latency_text(info))
}

/// The session info panel's text. `date_format` is `ui.date_format`; `offset` is
/// seconds east of UTC (`None`: local time).
pub fn panel_body(
    label: &str,
    info: &SshPaneInfo,
    date_format: &str,
    offset: Option<i32>,
) -> String {
    let i = &info.info;
    let mut lines = vec![
        format!("Host:          {label} ({})", i.peer),
        format!("Server:        {}", i.server_version),
    ];
    if let Some(at) = i.connected_at {
        lines.push(format!(
            "Connected:     {}",
            crate::views::logs::list::format_time(at, date_format, offset)
        ));
    }
    if let Some(n) = i.shared_channels {
        let plural = if n == 1 { "" } else { "s" };
        lines.push(format!(
            "Connection:    shared connection ({n} channel{plural})"
        ));
    }
    let keepalive = if i.keepalive_secs == 0 {
        "off".to_owned()
    } else {
        format!("every {} s", i.keepalive_secs)
    };
    lines.extend([
        format!("Latency:       {}", latency_text(info)),
        format!("Keepalive:     {keepalive}"),
        format!("Key exchange:  {}", i.kex),
        format!("Host key:      {}", i.host_key),
        format!("Cipher:        {}", i.cipher),
        format!("MAC:           {}", i.mac),
        format!("Compression:   {}", i.compression),
    ]);
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(keepalive: u32, latency: Option<u64>) -> SshPaneInfo {
        SshPaneInfo {
            info: SshSessionInfo {
                server_version: "SSH-2.0-OpenSSH_9.6".into(),
                peer: "192.0.2.7:22".into(),
                kex: "curve25519-sha256".into(),
                host_key: "ssh-ed25519".into(),
                cipher: "chacha20-poly1305@openssh.com".into(),
                mac: "none".into(),
                compression: "none".into(),
                keepalive_secs: keepalive,
                connected_at: Some(sverb_core::model::UnixMillis(0)),
                shared_channels: None,
            },
            latency: latency.map(Duration::from_millis),
        }
    }

    #[test]
    fn latency_shows_ms_or_a_dash() {
        assert_eq!(status_segment("db", &info(30, Some(23))), "db · ssh · 23ms");
        assert_eq!(status_segment("db", &info(30, None)), "db · ssh · –");
        assert_eq!(status_segment("db", &info(0, Some(23))), "db · ssh · –");
    }

    #[test]
    fn panel_lists_the_negotiated_algorithms() {
        let body = panel_body("db", &info(30, Some(23)), "%Y-%m-%d %H:%M:%S", Some(0));
        assert!(
            body.contains("Server:        SSH-2.0-OpenSSH_9.6"),
            "{body}"
        );
        assert!(
            body.contains("Connected:     1970-01-01 00:00:00"),
            "{body}"
        );
        assert!(body.contains("Key exchange:  curve25519-sha256"));
        assert!(body.contains("Cipher:        chacha20-poly1305@openssh.com"));
        assert!(body.contains("Latency:       23ms"));
        assert!(body.contains("Keepalive:     every 30 s"));
        let off = panel_body("db", &info(0, None), "%H:%M", Some(0));
        assert!(off.contains("Keepalive:     off"));
        assert!(off.contains("Latency:       –"));
        assert!(!off.contains("shared connection"));
    }

    #[test]
    fn panel_shows_a_shared_connection() {
        let mut shared = info(30, None);
        shared.info.shared_channels = Some(3);
        let body = panel_body("db", &shared, "%H:%M", Some(0));
        assert!(
            body.contains("Connection:    shared connection (3 channels)"),
            "{body}"
        );
        shared.info.shared_channels = Some(1);
        let body = panel_body("db", &shared, "%H:%M", Some(0));
        assert!(body.contains("shared connection (1 channel)"), "{body}");
    }
}
