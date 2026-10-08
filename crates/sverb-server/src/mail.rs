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

// M5-01
/// Mails an org invite link.
///
/// # Errors
/// [`MailError`].
pub async fn send_org_invite(
    cfg: &SmtpConfig,
    to: &str,
    org_name: &str,
    link: &str,
) -> Result<(), MailError> {
    let body = format!(
        "You have been invited to join \"{org_name}\" on a sverb sync server.\n\n\
         Paste this link into sverb (Settings > Team, or `sverb team accept <link>`),\n\
         or use it when registering:\n\n{link}\n\n\
         The invite can be used once and expires in 7 days.\n"
    );
    send(cfg, to, "You're invited to a sverb team", body).await
}

// M5-01
/// One mail a [`Mailer::Recording`] kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMail {
    /// Recipient.
    pub to: String,
    /// Subject.
    pub subject: String,
    /// Body.
    pub body: String,
}

// M5-01
/// Where invite mail goes: SMTP, nowhere (no SMTP configured: invites are links),
/// or a recording fake (tests).
#[derive(Debug, Clone, Default)]
pub enum Mailer {
    /// No SMTP: nothing is sent.
    #[default]
    Disabled,
    /// The configured relay.
    Smtp(SmtpConfig),
    /// Keeps the mails (tests).
    Recording(std::sync::Arc<std::sync::Mutex<Vec<SentMail>>>),
}

impl Mailer {
    /// SMTP when configured, else disabled.
    #[must_use]
    pub fn from_config(smtp: Option<&SmtpConfig>) -> Self {
        smtp.map_or(Self::Disabled, |c| Self::Smtp(c.clone()))
    }

    /// Whether mail can be sent.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Mails an org invite.
    ///
    /// # Errors
    /// [`MailError`]; a disabled mailer does nothing.
    pub async fn org_invite(&self, to: &str, org_name: &str, link: &str) -> Result<(), MailError> {
        match self {
            Self::Disabled => Ok(()),
            Self::Smtp(cfg) => send_org_invite(cfg, to, org_name, link).await,
            Self::Recording(sent) => {
                if let Ok(mut s) = sent.lock() {
                    s.push(SentMail {
                        to: to.to_owned(),
                        subject: "You're invited to a sverb team".into(),
                        body: format!("Join \"{org_name}\": {link}"),
                    });
                }
                Ok(())
            }
        }
    }
}
