//! T-01: configuration loading and secret validation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::Path;

use sverb_server::config::{Config, ConfigError, LogFormat};

fn load(toml: Option<&str>, env: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect();
    Config::from_sources(toml.map(|t| (t, Path::new("test.toml"))), |k| {
        env.get(k).cloned()
    })
}

const URL: (&str, &str) = ("SVERB_PUBLIC_URL", "https://sync.example.test/");
const SECRET: (&str, &str) = (
    "SVERB_SERVER_SECRET",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);

#[test]
fn t01_missing_secret_is_a_startup_error() {
    let err = load(None, &[URL]).unwrap_err();
    assert!(matches!(err, ConfigError::MissingSecret), "{err:?}");
    assert!(err.to_string().contains("SVERB_SERVER_SECRET is required"));
    // Empty counts as unset.
    let err = load(None, &[URL, ("SVERB_SERVER_SECRET", "  ")]).unwrap_err();
    assert!(matches!(err, ConfigError::MissingSecret), "{err:?}");
}

#[test]
fn t01_short_secret_is_a_startup_error() {
    // 31 bytes of hex.
    let short = "ab".repeat(31);
    let err = load(None, &[URL, ("SVERB_SERVER_SECRET", &short)]).unwrap_err();
    assert!(
        matches!(err, ConfigError::SecretTooShort { len: 31 }),
        "{err:?}"
    );
    // 24 bytes of base64.
    let err = load(
        None,
        &[
            URL,
            ("SVERB_SERVER_SECRET", "c2hvcnRzaG9ydHNob3J0c2hvcnRzaG9y"),
        ],
    )
    .unwrap_err();
    assert!(
        matches!(err, ConfigError::SecretTooShort { len: 24 }),
        "{err:?}"
    );
    let err = load(None, &[URL, ("SVERB_SERVER_SECRET", "!!not-an-encoding!!")]).unwrap_err();
    assert!(matches!(err, ConfigError::SecretEncoding), "{err:?}");
}

#[test]
fn valid_env_config_and_defaults() {
    let cfg = load(None, &[URL, SECRET]).unwrap();
    assert_eq!(cfg.public_url, "https://sync.example.test");
    assert_eq!(cfg.bind.to_string(), "0.0.0.0:8080");
    assert_eq!(cfg.limits.storage_quota_mib, 100);
    assert_eq!(cfg.limits.share_max_viewers, 10);
    assert_eq!(cfg.limits.share_ttl_hours, 24);
    assert_eq!(cfg.limits.tombstone_horizon_days, 90);
    assert_eq!(cfg.log_format, LogFormat::Json);
    assert!(cfg.tls.is_none() && cfg.smtp.is_none() && cfg.metrics_token.is_none());
    assert!(cfg.trusted_proxies.is_empty() && cfg.cors_allowed_origins.is_empty());
    // Secrets never appear in Debug output.
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("0123456789abcdef"), "{dbg}");
}

#[test]
fn missing_public_url_is_an_error() {
    let err = load(None, &[SECRET]).unwrap_err();
    assert!(err.to_string().contains("SVERB_PUBLIC_URL"), "{err}");
}

#[test]
fn toml_file_with_env_overrides() {
    let toml = r#"
        bind = "127.0.0.1:9000"
        public_url = "https://file.example.test"
        server_secret = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        database_url = "postgres://file"
        storage_quota_mib = 5
        log_format = "pretty"
        trusted_proxies = ["10.0.0.0/8", "192.0.2.1"]
        metrics_token = "0123456789abcdef-token"
        [smtp]
        host = "smtp.example.test"
        from = "sverb@example.test"
    "#;
    let cfg = load(Some(toml), &[]).unwrap();
    assert_eq!(cfg.bind.to_string(), "127.0.0.1:9000");
    assert_eq!(cfg.public_url, "https://file.example.test");
    assert_eq!(cfg.limits.storage_quota_mib, 5);
    assert_eq!(cfg.log_format, LogFormat::Pretty);
    assert_eq!(cfg.trusted_proxies.len(), 2);
    let smtp = cfg.smtp.as_ref().unwrap();
    assert_eq!((smtp.port, smtp.starttls), (587, true));
    assert_eq!(cfg.require_database_url().unwrap(), "postgres://file");

    // Environment wins over the file.
    let cfg = load(
        Some(toml),
        &[
            URL,
            ("SVERB_BIND", "[::1]:7000"),
            ("SVERB_STORAGE_QUOTA_MIB", "42"),
            ("SVERB_LOG_FORMAT", "json"),
            ("DATABASE_URL", "postgres://env"),
        ],
    )
    .unwrap();
    assert_eq!(cfg.bind.to_string(), "[::1]:7000");
    assert_eq!(cfg.public_url, "https://sync.example.test");
    assert_eq!(cfg.limits.storage_quota_mib, 42);
    assert_eq!(cfg.log_format, LogFormat::Json);
    assert_eq!(cfg.require_database_url().unwrap(), "postgres://env");
}

#[test]
fn invalid_values_are_rejected() {
    assert!(load(Some("unknown_key = 1"), &[URL, SECRET]).is_err());
    assert!(load(None, &[URL, SECRET, ("SVERB_BIND", "nope")]).is_err());
    assert!(load(None, &[URL, SECRET, ("SVERB_TLS_CERT", "/c.pem")]).is_err());
    assert!(load(None, &[URL, SECRET, ("SVERB_METRICS_TOKEN", "short")]).is_err());
    assert!(
        load(
            None,
            &[URL, SECRET, ("SVERB_TRUSTED_PROXIES", "10.0.0.0/8, bogus")]
        )
        .is_err()
    );
    assert!(load(None, &[URL, SECRET, ("SMTP_HOST", "smtp.example.test")]).is_err());
    assert!(load(None, &[SECRET, ("SVERB_PUBLIC_URL", "sync.example.test")]).is_err());
    assert!(
        load(None, &[URL, SECRET])
            .unwrap()
            .require_database_url()
            .is_err()
    );
}
