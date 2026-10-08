//! Outgoing mail over SMTP (SPEC §10.7). Optional: without `SMTP_*`
//! settings, invites are copy-paste links. M5-01 adds org-invite mail on top
//! of [`send`].

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::SmtpConfig;

/// Mail errors.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// Bad `From`/`To` address.
    #[error("invalid address: {0}")]
    Address(#[from] lettre::address::AddressError),
    /// Message construction failed.
    #[error("cannot build message: {0}")]
    Build(#[from] lettre::error::Error),
    /// SMTP failure.
    #[error("SMTP error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),
}

fn transport(cfg: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, MailError> {
    let builder = if cfg.starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?
    };
    let builder = builder.port(cfg.port);
    let builder = match (&cfg.user, &cfg.password) {
        (Some(user), Some(pass)) => {
            builder.credentials(Credentials::new(user.clone(), pass.0.clone()))
        }
        _ => builder,
    };
    Ok(builder.build())
}

/// Sends a plain-text mail.
///
/// # Errors
/// [`MailError`].
pub async fn send(
    cfg: &SmtpConfig,
    to: &str,
    subject: &str,
    body: String,
) -> Result<(), MailError> {
    let msg = Message::builder()
        .from(cfg.from.parse::<Mailbox>()?)
        .to(to.parse::<Mailbox>()?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;
    transport(cfg)?.send(msg).await?;
    Ok(())
}

/// Mails an instance invite link.
///
/// # Errors
/// [`MailError`].
pub async fn send_invite(cfg: &SmtpConfig, to: &str, link: &str) -> Result<(), MailError> {
    let body = format!(
        "You have been invited to a sverb sync server.\n\n\
         Open this link, or paste it into sverb when registering:\n\n{link}\n\n\
         The invite can be used once and expires in 7 days.\n"
    );
    send(cfg, to, "Your sverb invite", body).await
}
