//! Command-line interface (SPEC §10.6).
//!
//! ```text
//! sverb-server [--config FILE] serve [--migrate]
//! sverb-server [--config FILE] migrate
//! sverb-server [--config FILE] admin user create|disable <EMAIL>
//! sverb-server [--config FILE] admin user list
//! sverb-server [--config FILE] admin user recovery-code <EMAIL>
//! sverb-server [--config FILE] admin registration open|invite-only|closed
//! sverb-server [--config FILE] admin gc
//! sverb-server [--config FILE] admin invite <EMAIL> [--no-email]
//! sverb-server healthcheck [--addr HOST:PORT]
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use crate::admin::{self, AdminError};
use crate::config::{Config, DEFAULT_BIND};
use crate::registration::{self, RegistrationMode};
use crate::{db, healthcheck, logging, mail, serve};

/// sverb sync server.
#[derive(Debug, Parser)]
#[command(name = "sverb-server", version, about)]
pub struct Cli {
    /// TOML config file (default: $SVERB_SERVER_CONFIG, else ./sverb-server.toml if present).
    /// Environment variables override it.
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server.
    Serve {
        /// Apply pending migrations instead of refusing to start.
        #[arg(long)]
        migrate: bool,
    },
    /// Apply pending database migrations and exit.
    Migrate,
    /// Administrative commands.
    Admin {
        /// The admin command.
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Probe the local server's /healthz (for container HEALTHCHECKs).
    Healthcheck {
        /// Address to probe (default: from SVERB_BIND, wildcard → loopback).
        #[arg(long, value_name = "HOST:PORT")]
        addr: Option<SocketAddr>,
    },
}

/// `admin …`.
#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Manage users.
    User {
        /// The user command.
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Set who may register.
    Registration {
        /// The new mode.
        mode: ModeArg,
    },
    /// Purge expired tokens, invites and finished shares.
    Gc,
    /// Create a single-use registration invite for an email and print its link
    /// (also mailed when SMTP is configured).
    Invite {
        /// The invitee's email.
        email: String,
        /// Don't send mail even if SMTP is configured.
        #[arg(long)]
        no_email: bool,
    },
}

/// `admin user …`.
#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// Create a registration invite for EMAIL (the password is set client-side via OPAQUE).
    Create {
        /// The user's email.
        email: String,
    },
    /// Disable a user and revoke all their tokens.
    Disable {
        /// The user's email.
        email: String,
    },
    /// List users.
    List,
    /// Issue a one-time account-recovery code for EMAIL (valid 24 h)
    /// and print it (also mailed when SMTP is configured).
    RecoveryCode {
        /// The user's email.
        email: String,
    },
}

/// Registration modes on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ModeArg {
    /// Anyone may register.
    Open,
    /// Only with an invite (default).
    InviteOnly,
    /// Nobody may register.
    Closed,
}

impl From<ModeArg> for RegistrationMode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Open => Self::Open,
            ModeArg::InviteOnly => Self::InviteOnly,
            ModeArg::Closed => Self::Closed,
        }
    }
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("sverb-server: {msg}");
    ExitCode::FAILURE
}

/// Runs the parsed command line.
pub async fn run(cli: Cli) -> ExitCode {
    if let Command::Healthcheck { addr } = &cli.command {
        return run_healthcheck(*addr).await;
    }
    let config = match Config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match cli.command {
        Command::Serve { migrate } => {
            logging::init(config.log_format);
            match serve::run(config, migrate).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(error = %e, "refusing to start");
                    fail(e)
                }
            }
        }
        Command::Migrate => {
            logging::init(config.log_format);
            let pool = match config.require_database_url() {
                Ok(url) => db::connect(url).await,
                Err(e) => return fail(e),
            };
            let pool = match pool {
                Ok(p) => p,
                Err(e) => return fail(format!("database error: {e}")),
            };
            match db::migrate(&pool).await {
                Ok(()) => {
                    println!("migrations applied");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(format!("migration failed: {e}")),
            }
        }
        Command::Admin { command } => match run_admin(&config, command).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Healthcheck { .. } => ExitCode::SUCCESS,
    }
}

async fn run_healthcheck(addr: Option<SocketAddr>) -> ExitCode {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let addr = match addr {
        Some(a) => a,
        None => match env("SVERB_BIND")
            .unwrap_or_else(|| DEFAULT_BIND.to_owned())
            .parse()
        {
            Ok(a) => healthcheck::probe_addr(a),
            Err(e) => return fail(format!("invalid SVERB_BIND: {e}")),
        },
    };
    match healthcheck::run(addr, env("SVERB_TLS_CERT").is_some()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

async fn run_admin(config: &Config, command: AdminCommand) -> Result<(), AdminError> {
    let url = config
        .require_database_url()
        .map_err(|e| AdminError::Invalid(e.to_string()))?;
    let pool = db::connect(url).await?;
    match db::migration_status(&pool).await? {
        db::MigrationStatus::Current => {}
        other => {
            return Err(AdminError::Invalid(format!(
                "database schema is not current ({other:?}); run `sverb-server migrate` first"
            )));
        }
    }
    match command {
        AdminCommand::User { command } => match command {
            UserCommand::Create { email } => invite(config, &pool, &email, false).await,
            UserCommand::Disable { email } => {
                let out = admin::user::disable(&pool, &email).await?;
                println!("disabled {email}; revoked {} token(s)", out.tokens_revoked);
                Ok(())
            }
            UserCommand::List => {
                let users = admin::user::list(&pool).await?;
                println!(
                    "{:<40} {:<25} {:<8} {:<5} {:>7}",
                    "EMAIL", "CREATED", "DISABLED", "ADMIN", "DEVICES"
                );
                for u in users {
                    println!(
                        "{:<40} {:<25} {:<8} {:<5} {:>7}",
                        u.email,
                        u.created_at.format("%Y-%m-%dT%H:%M:%SZ"),
                        if u.disabled { "yes" } else { "no" },
                        if u.is_instance_admin { "yes" } else { "no" },
                        u.devices
                    );
                }
                Ok(())
            }
            UserCommand::RecoveryCode { email } => {
                let code = admin::user::recovery_code(&pool, &email).await?;
                println!("recovery code for {email} (valid 24 hours, single use):");
                println!("  {}", code.as_str());
                if let Some(smtp) = &config.smtp {
                    let body = format!(
                        "Your sverb server administrator issued an account recovery code.\n\n\
                         Recovery code: {}\n\n\
                         Enter it in sverb together with your recovery phrase. It expires in \
                         24 hours.\n",
                        code.as_str()
                    );
                    match mail::send(smtp, &email, "Your sverb recovery code", body).await {
                        Ok(()) => println!("  mailed to {email}"),
                        Err(e) => eprintln!("  could not send mail ({e}); hand the code over"),
                    }
                }
                Ok(())
            }
        },
        AdminCommand::Registration { mode } => {
            let mode = RegistrationMode::from(mode);
            registration::set_mode(&pool, mode).await?;
            println!("registration mode set to {mode}");
            Ok(())
        }
        AdminCommand::Gc => {
            let r = admin::gc::run(&pool, config).await?;
            println!(
                "gc: removed {} expired token(s), {} expired invite(s), {} finished share(s), \
                 {} tombstone(s) in {} vault(s), {} abandoned key rotation(s)",
                r.expired_tokens,
                r.expired_invites,
                r.finished_shares,
                r.purged_tombstones,
                r.gc_floor_vaults,
                r.abandoned_rotations
            );
            Ok(())
        }
        AdminCommand::Invite { email, no_email } => invite(config, &pool, &email, !no_email).await,
    }
}

async fn invite(
    config: &Config,
    pool: &sqlx_postgres::PgPool,
    email: &str,
    send_mail: bool,
) -> Result<(), AdminError> {
    let inv = admin::invite::create(pool, &config.public_url, email).await?;
    println!(
        "invite for {} (expires {}):",
        inv.email,
        inv.expires_at.format("%Y-%m-%d %H:%M UTC")
    );
    println!("  {}", inv.link);
    match (&config.smtp, send_mail) {
        (Some(smtp), true) => match mail::send_invite(smtp, &inv.email, &inv.link).await {
            Ok(()) => println!("  mailed to {}", inv.email),
            Err(e) => eprintln!("  could not send mail ({e}); hand the link over manually"),
        },
        _ => println!("  (no mail sent; hand the link to the user)"),
    }
    Ok(())
}
