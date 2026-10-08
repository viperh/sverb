//! Server configuration (SPEC §10.1, §10.5, §10.7).
//!
//! Sources, lowest to highest precedence:
//! 1. built-in defaults,
//! 2. a TOML file (`--config <path>`, else `$SVERB_SERVER_CONFIG`, else
//!    `./sverb-server.toml` when it exists),
//! 3. environment variables (`DATABASE_URL`, `SVERB_*`, `SMTP_*`).
//!
//! An empty environment variable counts as unset. Loading fails (and the
//! server refuses to start) when `SVERB_SERVER_SECRET` is missing, shorter
//! than 32 bytes or not valid hex/base64, or when `SVERB_PUBLIC_URL` is
//! missing.
//!
//! | TOML key | Environment | Default |
//! |---|---|---|
//! | `database_url` | `DATABASE_URL` | — (needed by `serve`, `migrate`, `admin`) |
//! | `bind` | `SVERB_BIND` | `0.0.0.0:8080` |
//! | `public_url` | `SVERB_PUBLIC_URL` | required |
//! | `server_secret` | `SVERB_SERVER_SECRET` | required, ≥ 32 bytes, hex or base64 |
//! | `tls_cert`, `tls_key` | `SVERB_TLS_CERT`, `SVERB_TLS_KEY` | off (both or neither) |
//! | `[smtp] host, port, user, password, from, starttls` | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | off; port 587, starttls true |
//! | `storage_quota_mib` | `SVERB_STORAGE_QUOTA_MIB` | 100 |
//! | `share_max_viewers` | `SVERB_SHARE_MAX_VIEWERS` | 10 |
//! | `share_ttl_hours` | `SVERB_SHARE_TTL_HOURS` | 24 |
//! | `tombstone_horizon_days` | `SVERB_TOMBSTONE_HORIZON_DAYS` | 90 |
//! | `gc_interval_hours` | `SVERB_GC_INTERVAL_HOURS` | 24 (0 = no background GC) |
//! | `metrics_token` | `SVERB_METRICS_TOKEN` | off |
//! | `metrics_bind` | `SVERB_METRICS_BIND` | off |
//! | `log_format` | `SVERB_LOG_FORMAT` | `json` (`pretty` for humans) |
//! | `trusted_proxies` | `SVERB_TRUSTED_PROXIES` (comma list) | none |
//! | `cors_allowed_origins` | `SVERB_CORS_ORIGINS` (comma list) | none (deny) |
//! | `request_timeout_s` | `SVERB_REQUEST_TIMEOUT_S` | 30 |

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use ipnet::IpNet;
use serde::Deserialize;
use zeroize::Zeroizing;

/// Default listen address.
pub const DEFAULT_BIND: &str = "0.0.0.0:8080";
/// Minimum decoded length of `SVERB_SERVER_SECRET`.
pub const SECRET_MIN_LEN: usize = 32;
/// Minimum length of `SVERB_METRICS_TOKEN`.
pub const METRICS_TOKEN_MIN_LEN: usize = 16;
/// Environment variable naming the TOML config file.
pub const CONFIG_PATH_ENV: &str = "SVERB_SERVER_CONFIG";
/// Config file looked up in the working directory when nothing else is given.
pub const DEFAULT_CONFIG_FILE: &str = "sverb-server.toml";

/// Configuration errors. Each message names the variable to fix.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `SVERB_SERVER_SECRET` is not set.
    #[error(
        "SVERB_SERVER_SECRET is required (at least {SECRET_MIN_LEN} random bytes, hex or base64); \
         generate one with `openssl rand -base64 48` and back it up together with the database"
    )]
    MissingSecret,
    /// `SVERB_SERVER_SECRET` decodes to fewer than 32 bytes.
    #[error(
        "SVERB_SERVER_SECRET is too short: {len} bytes after decoding, at least {SECRET_MIN_LEN} required"
    )]
    SecretTooShort {
        /// Decoded length.
        len: usize,
    },
    /// `SVERB_SERVER_SECRET` is neither hex nor base64.
    #[error("SVERB_SERVER_SECRET must be hex or base64 encoded")]
    SecretEncoding,
    /// A required setting is missing.
    #[error("{0} is required")]
    Missing(&'static str),
    /// A setting has an invalid value.
    #[error("invalid {name}: {reason}")]
    Invalid {
        /// The variable or key.
        name: &'static str,
        /// What is wrong with it.
        reason: String,
    },
    /// The TOML file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The TOML file is malformed or has unknown keys.
    #[error("invalid config file {path}: {source}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// The parse error.
        source: Box<toml::de::Error>,
    },
}

/// A value that must never show up in logs or `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct Sensitive<T>(pub T);

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// The decoded `SVERB_SERVER_SECRET` (zeroized on drop, redacted in `Debug`).
#[derive(Clone)]
pub struct ServerSecret(Zeroizing<Vec<u8>>);

impl fmt::Debug for ServerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerSecret([REDACTED])")
    }
}

impl ServerSecret {
    /// Parses a hex or base64 (standard or URL-safe, padded or not) secret.
    /// A string made only of an even number of hex digits is read as hex.
    ///
    /// # Errors
    /// [`ConfigError::MissingSecret`], [`ConfigError::SecretEncoding`] or
    /// [`ConfigError::SecretTooShort`].
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(ConfigError::MissingSecret);
        }
        let bytes = if s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(s).map_err(|_| ConfigError::SecretEncoding)?
        } else {
            use base64::engine::general_purpose::{
                STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
            };
            [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
                .iter()
                .find_map(|engine| engine.decode(s).ok())
                .ok_or(ConfigError::SecretEncoding)?
        };
        let bytes = Zeroizing::new(bytes);
        if bytes.len() < SECRET_MIN_LEN {
            return Err(ConfigError::SecretTooShort { len: bytes.len() });
        }
        Ok(Self(bytes))
    }

    /// The raw secret bytes. Only key derivation should look at them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Built-in TLS (rustls) certificate and key paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert: PathBuf,
    /// PEM private key.
    pub key: PathBuf,
}

/// SMTP settings for invite mail (optional; without them invites are
/// copy-paste links).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    /// Relay host name.
    pub host: String,
    /// Relay port.
    pub port: u16,
    /// Login user, if the relay needs authentication.
    pub user: Option<String>,
    /// Login password.
    pub password: Option<Sensitive<String>>,
    /// `From:` address.
    pub from: String,
    /// `true`: STARTTLS on a plain connection; `false`: implicit TLS.
    pub starttls: bool,
}

/// Limits from SPEC §10.5 and §12.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Per-user storage quota in MiB.
    pub storage_quota_mib: u64,
    /// Maximum viewers per share session.
    pub share_max_viewers: u32,
    /// Default share-session lifetime in hours.
    pub share_ttl_hours: u32,
    /// Tombstones older than this many days are purged by GC.
    pub tombstone_horizon_days: u32,
    /// M4-04: hours between background GC runs (`admin gc` in-process);
    /// 0 disables the job.
    pub gc_interval_hours: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            storage_quota_mib: 100,
            share_max_viewers: 10,
            share_ttl_hours: 24,
            tombstone_horizon_days: 90,
            gc_interval_hours: 24,
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line (SPEC §18).
    #[default]
    Json,
    /// Human-readable text.
    Pretty,
}

/// The validated server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection string (contains a password, hence redacted).
    pub database_url: Option<Sensitive<String>>,
    /// Listen address.
    pub bind: SocketAddr,
    /// Public base URL, without a trailing slash (invite and share links).
    pub public_url: String,
    /// The at-rest encryption secret for `server_secrets`.
    pub server_secret: ServerSecret,
    /// Built-in TLS, if configured.
    pub tls: Option<TlsConfig>,
    /// SMTP, if configured.
    pub smtp: Option<SmtpConfig>,
    /// Limits.
    pub limits: Limits,
    /// Bearer token guarding `/metrics` on the main listener.
    pub metrics_token: Option<Sensitive<String>>,
    /// Separate listener serving only `/metrics`.
    pub metrics_bind: Option<SocketAddr>,
    /// Log format.
    pub log_format: LogFormat,
    /// Reverse proxies whose `X-Forwarded-For` is trusted.
    pub trusted_proxies: Vec<IpNet>,
    /// Origins allowed by CORS (empty: deny all cross-origin requests).
    pub cors_allowed_origins: Vec<String>,
    /// Per-request timeout.
    pub request_timeout: Duration,
}

/// The TOML file shape (every key optional; unknown keys are rejected).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    database_url: Option<String>,
    bind: Option<String>,
    public_url: Option<String>,
    server_secret: Option<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    smtp: Option<FileSmtp>,
    storage_quota_mib: Option<u64>,
    share_max_viewers: Option<u32>,
    share_ttl_hours: Option<u32>,
    tombstone_horizon_days: Option<u32>,
    gc_interval_hours: Option<u32>,
    metrics_token: Option<String>,
    metrics_bind: Option<String>,
    log_format: Option<LogFormat>,
    trusted_proxies: Option<Vec<String>>,
    cors_allowed_origins: Option<Vec<String>>,
    request_timeout_s: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSmtp {
    host: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    from: Option<String>,
    starttls: Option<bool>,
}

impl Config {
    /// Loads the configuration from the process environment and the TOML
    /// file (see the module docs for the lookup order).
    ///
    /// # Errors
    /// Any [`ConfigError`].
    pub fn load(explicit_path: Option<&Path>) -> Result<Self, ConfigError> {
        let env = |name: &str| std::env::var(name).ok();
        let path = match explicit_path {
            Some(p) => Some(p.to_path_buf()),
            None => match env(CONFIG_PATH_ENV).filter(|s| !s.is_empty()) {
                Some(p) => Some(PathBuf::from(p)),
                None => {
                    let p = PathBuf::from(DEFAULT_CONFIG_FILE);
                    p.exists().then_some(p)
                }
            },
        };
        let text = match &path {
            Some(p) => Some(
                std::fs::read_to_string(p).map_err(|source| ConfigError::Read {
                    path: p.clone(),
                    source,
                })?,
            ),
            None => None,
        };
        Self::from_sources(text.as_deref().zip(path.as_deref()), |name: &str| env(name))
    }

    /// Builds the configuration from an optional `(toml_text, path)` pair
    /// and an environment lookup. Pure; used directly by tests.
    ///
    /// # Errors
    /// Any [`ConfigError`].
    pub fn from_sources(
        toml_file: Option<(&str, &Path)>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let file: FileConfig = match toml_file {
            Some((text, path)) => toml::from_str(text).map_err(|e| ConfigError::Parse {
                path: path.to_path_buf(),
                source: Box::new(e),
            })?,
            None => FileConfig::default(),
        };
        let env = |name: &str| env(name).filter(|v| !v.trim().is_empty());

        let secret_raw = env("SVERB_SERVER_SECRET")
            .or(file.server_secret)
            .ok_or(ConfigError::MissingSecret)?;
        let server_secret = ServerSecret::parse(&secret_raw)?;

        let public_url = env("SVERB_PUBLIC_URL")
            .or(file.public_url)
            .ok_or(ConfigError::Missing("SVERB_PUBLIC_URL"))?;
        let public_url = public_url.trim().trim_end_matches('/').to_owned();
        if !(public_url.starts_with("http://") || public_url.starts_with("https://")) {
            return Err(ConfigError::Invalid {
                name: "SVERB_PUBLIC_URL",
                reason: "must start with http:// or https://".into(),
            });
        }

        let bind = parse_addr(
            "SVERB_BIND",
            &env("SVERB_BIND")
                .or(file.bind)
                .unwrap_or_else(|| DEFAULT_BIND.to_owned()),
        )?;

        let tls_cert = env("SVERB_TLS_CERT").map(PathBuf::from).or(file.tls_cert);
        let tls_key = env("SVERB_TLS_KEY").map(PathBuf::from).or(file.tls_key);
        let tls = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => Some(TlsConfig { cert, key }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Invalid {
                    name: "SVERB_TLS_CERT/SVERB_TLS_KEY",
                    reason: "set both or neither".into(),
                });
            }
        };

        let fsmtp = file.smtp.unwrap_or_default();
        let smtp = match env("SMTP_HOST").or(fsmtp.host) {
            None => None,
            Some(host) => {
                let port = match env("SMTP_PORT") {
                    Some(p) => parse_num("SMTP_PORT", &p)?,
                    None => fsmtp.port.unwrap_or(587),
                };
                let starttls = match env("SMTP_STARTTLS") {
                    Some(v) => parse_bool("SMTP_STARTTLS", &v)?,
                    None => fsmtp.starttls.unwrap_or(true),
                };
                Some(SmtpConfig {
                    host,
                    port,
                    user: env("SMTP_USER").or(fsmtp.user),
                    password: env("SMTP_PASSWORD").or(fsmtp.password).map(Sensitive),
                    from: env("SMTP_FROM").or(fsmtp.from).ok_or(ConfigError::Missing(
                        "SMTP_FROM (needed when SMTP_HOST is set)",
                    ))?,
                    starttls,
                })
            }
        };

        let defaults = Limits::default();
        let limits = Limits {
            storage_quota_mib: num_or(
                &env,
                "SVERB_STORAGE_QUOTA_MIB",
                file.storage_quota_mib,
                defaults.storage_quota_mib,
            )?,
            share_max_viewers: num_or(
                &env,
                "SVERB_SHARE_MAX_VIEWERS",
                file.share_max_viewers,
                defaults.share_max_viewers,
            )?,
            share_ttl_hours: num_or(
                &env,
                "SVERB_SHARE_TTL_HOURS",
                file.share_ttl_hours,
                defaults.share_ttl_hours,
            )?,
            tombstone_horizon_days: num_or(
                &env,
                "SVERB_TOMBSTONE_HORIZON_DAYS",
                file.tombstone_horizon_days,
                defaults.tombstone_horizon_days,
            )?,
            // M4-04
            gc_interval_hours: num_or(
                &env,
                "SVERB_GC_INTERVAL_HOURS",
                file.gc_interval_hours,
                defaults.gc_interval_hours,
            )?,
        };

        let metrics_token = env("SVERB_METRICS_TOKEN").or(file.metrics_token);
        if let Some(t) = &metrics_token
            && t.len() < METRICS_TOKEN_MIN_LEN
        {
            return Err(ConfigError::Invalid {
                name: "SVERB_METRICS_TOKEN",
                reason: format!("must be at least {METRICS_TOKEN_MIN_LEN} characters"),
            });
        }
        let metrics_bind = env("SVERB_METRICS_BIND")
            .or(file.metrics_bind)
            .map(|s| parse_addr("SVERB_METRICS_BIND", &s))
            .transpose()?;

        let log_format = match env("SVERB_LOG_FORMAT") {
            Some(v) => match v.trim().to_ascii_lowercase().as_str() {
                "json" => LogFormat::Json,
                "pretty" | "text" => LogFormat::Pretty,
                other => {
                    return Err(ConfigError::Invalid {
                        name: "SVERB_LOG_FORMAT",
                        reason: format!("`{other}` (expected json or pretty)"),
                    });
                }
            },
            None => file.log_format.unwrap_or_default(),
        };

        let trusted_proxies = match env("SVERB_TRUSTED_PROXIES") {
            Some(v) => split_list(&v),
            None => file.trusted_proxies.unwrap_or_default(),
        }
        .iter()
        .map(|s| parse_net(s))
        .collect::<Result<Vec<_>, _>>()?;

        let cors_allowed_origins = match env("SVERB_CORS_ORIGINS") {
            Some(v) => split_list(&v),
            None => file.cors_allowed_origins.unwrap_or_default(),
        };

        let request_timeout = Duration::from_secs(num_or(
            &env,
            "SVERB_REQUEST_TIMEOUT_S",
            file.request_timeout_s,
            30,
        )?);

        Ok(Self {
            database_url: env("DATABASE_URL").or(file.database_url).map(Sensitive),
            bind,
            public_url,
            server_secret,
            tls,
            smtp,
            limits,
            metrics_token: metrics_token.map(Sensitive),
            metrics_bind,
            log_format,
            trusted_proxies,
            cors_allowed_origins,
            request_timeout,
        })
    }

    /// The database URL, or an error naming `DATABASE_URL`.
    ///
    /// # Errors
    /// [`ConfigError::Missing`] when unset.
    pub fn require_database_url(&self) -> Result<&str, ConfigError> {
        self.database_url
            .as_ref()
            .map(|s| s.0.as_str())
            .ok_or(ConfigError::Missing("DATABASE_URL"))
    }
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_addr(name: &'static str, v: &str) -> Result<SocketAddr, ConfigError> {
    v.trim().parse().map_err(|e| ConfigError::Invalid {
        name,
        reason: format!("`{v}`: {e}"),
    })
}

fn parse_num<T: std::str::FromStr>(name: &'static str, v: &str) -> Result<T, ConfigError>
where
    T::Err: fmt::Display,
{
    v.trim().parse().map_err(|e| ConfigError::Invalid {
        name,
        reason: format!("`{v}`: {e}"),
    })
}

fn num_or<T: std::str::FromStr>(
    env: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    file: Option<T>,
    default: T,
) -> Result<T, ConfigError>
where
    T::Err: fmt::Display,
{
    match env(name) {
        Some(v) => parse_num(name, &v),
        None => Ok(file.unwrap_or(default)),
    }
}

fn parse_bool(name: &'static str, v: &str) -> Result<bool, ConfigError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Invalid {
            name,
            reason: format!("`{v}` is not a boolean"),
        }),
    }
}

fn parse_net(s: &str) -> Result<IpNet, ConfigError> {
    let s = s.trim();
    s.parse::<IpNet>()
        .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| ConfigError::Invalid {
            name: "SVERB_TRUSTED_PROXIES",
            reason: format!("`{s}` is not an IP address or CIDR"),
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_hex_and_base64() {
        assert_eq!(
            ServerSecret::parse(&"ab".repeat(32))
                .unwrap()
                .expose()
                .len(),
            32
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 48]);
        assert_eq!(ServerSecret::parse(&b64).unwrap().expose(), &[7u8; 48]);
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xfb; 33]);
        assert_eq!(ServerSecret::parse(&b64url).unwrap().expose().len(), 33);
        assert!(matches!(
            ServerSecret::parse("abcd"),
            Err(ConfigError::SecretTooShort { len: 2 })
        ));
        assert!(matches!(
            ServerSecret::parse("not base64 at all!"),
            Err(ConfigError::SecretEncoding)
        ));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = ServerSecret::parse(&"cd".repeat(32)).unwrap();
        assert_eq!(format!("{s:?}"), "ServerSecret([REDACTED])");
    }

    #[test]
    fn trusted_proxy_parsing() {
        assert_eq!(parse_net("10.0.0.0/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(parse_net("127.0.0.1").unwrap().to_string(), "127.0.0.1/32");
        assert!(parse_net("nope").is_err());
    }
}
