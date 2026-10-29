//! Inlined BYOK SMTP sink (tracer copy of the bits of `apps/core/src/email/mod.rs`
//! + `apps/core/src/smtp_auth.rs` that `send.rs` uses).
//!
//! Behavior deviation vs Core (documented port-gap): the in-process transport
//! cache (`set_transport`/`TRANSPORT`) and the `smtp_auth` preferences path are
//! DROPPED. Out-of-process, the sidecar has no access to Core's desktop-Settings
//! prefs cache, so SMTP is resolved ENV-ONLY from `RYU_SMTP_*` / `RYU_SMTP_PASSWORD`.
//! Productionization follow-up: Core passes the resolved transport to the sidecar
//! (or this and `crate::email` are factored into a shared crate). The send path
//! itself (lettre wiring, MIME assembly, threading headers) is identical.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lettre::message::header::ContentType;
use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Attachment as LettreAttachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// A wedged relay must not hang an inbox-send request forever.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Most custom headers one outbound message may carry (matches Core's `email.send`).
pub const MAX_CUSTOM_HEADERS: usize = 64;
const MAX_HEADER_NAME_BYTES: usize = 128;
const MAX_HEADER_VALUE_BYTES: usize = 4096;

/// Header names a caller may never set through `headers`. They decide the SMTP
/// envelope, the sender identity, threading, or the MIME structure, and every one
/// of those comes from a typed field the send path validates. lettre's
/// `raw_header` replaces an existing header case-insensitively, so an override
/// would silently undo that validation (a `Bcc` past the block lists, a forged
/// `From`, a stored record that no longer matches what was sent).
pub fn reserved_header_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "bcc"
            | "cc"
            | "date"
            | "from"
            | "host"
            | "in-reply-to"
            | "message-id"
            | "mime-version"
            | "received"
            | "references"
            | "reply-to"
            | "return-path"
            | "sender"
            | "subject"
            | "to"
    ) || lowered.starts_with("content-")
        || lowered.starts_with("resent-")
}

/// Whether one caller-supplied header may be sent: an RFC 5322 field name
/// (printable ASCII except `:`), not reserved, with a bounded single-line value.
pub fn custom_header_allowed(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HEADER_NAME_BYTES
        && name
            .bytes()
            .all(|byte| (33..=126).contains(&byte) && byte != b':')
        && !reserved_header_name(name)
        && value.len() <= MAX_HEADER_VALUE_BYTES
        && !value.contains(['\r', '\n'])
}

/// How the SMTP connection is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// Plain connect, then a required STARTTLS upgrade (submission, port 587).
    Starttls,
    /// TLS from the first byte (SMTPS, port 465).
    Implicit,
    /// No encryption. Credentials are only ever sent to a loopback relay.
    None,
}

/// Non-secret SMTP transport config.
#[derive(Debug, Clone)]
pub struct EmailTransportConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub tls: SmtpTls,
}

/// Resolve the TLS mode: `RYU_SMTP_TLS` (`starttls`, `implicit`, or `none`) wins;
/// otherwise port 465 means implicit TLS, the legacy `RYU_SMTP_STARTTLS=false`
/// (or `0`) means none, and anything else is STARTTLS. An unrecognised value
/// falls back to the encrypted default rather than to plaintext.
fn smtp_tls(tls: Option<&str>, legacy_starttls: Option<&str>, port: u16) -> SmtpTls {
    match tls
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("starttls") => return SmtpTls::Starttls,
        Some("implicit" | "tls" | "smtps") => return SmtpTls::Implicit,
        Some("none" | "plain") => return SmtpTls::None,
        _ => {}
    }
    if port == 465 {
        return SmtpTls::Implicit;
    }
    match legacy_starttls.map(str::trim) {
        Some(value) if value == "0" || value.eq_ignore_ascii_case("false") => SmtpTls::None,
        _ => SmtpTls::Starttls,
    }
}

fn loopback_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Why this config must not be used, if anything: SMTP AUTH over an unencrypted
/// connection hands the relay password to anyone on the path, so `none` is only
/// accepted for a relay on this host.
fn insecure_transport_reason(cfg: &EmailTransportConfig) -> Option<String> {
    (cfg.tls == SmtpTls::None && !loopback_host(&cfg.host)).then(|| {
        format!(
            "refusing to send SMTP credentials without TLS to {}; set RYU_SMTP_TLS=starttls or implicit",
            cfg.host
        )
    })
}

/// A file attached to an outbound email.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// A fully-specified outbound email.
#[derive(Debug, Clone, Default)]
pub struct OutboundEmail {
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug)]
pub enum EmailError {
    /// No relay configured — kept for parity with Core's enum (unused in the
    /// sidecar, where `resolve_transport` returns `None` before an error is built).
    #[allow(dead_code)]
    NotConfigured,
    InvalidAddress(String),
    Build(String),
    Transport(String),
    Send(String),
    Timeout,
}

impl std::fmt::Display for EmailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "email transport is not configured"),
            Self::InvalidAddress(a) => write!(f, "invalid email address: {a}"),
            Self::Build(e) => write!(f, "failed to build email: {e}"),
            Self::Transport(e) => write!(f, "failed to build SMTP transport: {e}"),
            Self::Send(e) => write!(f, "SMTP send failed: {e}"),
            Self::Timeout => write!(f, "SMTP send timed out"),
        }
    }
}

impl std::error::Error for EmailError {}

/// Resolve the SMTP password from `RYU_SMTP_PASSWORD` (env-only in the sidecar).
fn password() -> Option<String> {
    std::env::var("RYU_SMTP_PASSWORD")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
}

/// Resolve the effective transport from `RYU_SMTP_*` env. Returns `None` when no
/// host or no password is available (email disabled) — identical to the headless
/// fallback branch of Core's `resolve_transport` — and also when `RYU_SMTP_TLS=none`
/// names a remote relay, which would receive the password unencrypted.
pub fn resolve_transport() -> Option<EmailTransportConfig> {
    let password = password()?;

    let host = std::env::var("RYU_SMTP_HOST").ok()?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let port = std::env::var("RYU_SMTP_PORT")
        .ok()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .unwrap_or(587);
    let username = std::env::var("RYU_SMTP_USERNAME").unwrap_or_default();
    let from = std::env::var("RYU_SMTP_FROM").unwrap_or_else(|_| username.clone());
    let tls = smtp_tls(
        std::env::var("RYU_SMTP_TLS").ok().as_deref(),
        std::env::var("RYU_SMTP_STARTTLS").ok().as_deref(),
        port,
    );
    let config = EmailTransportConfig {
        host: host.to_string(),
        port,
        username: username.trim().to_string(),
        password,
        from: from.trim().to_string(),
        tls,
    };
    usable_transport(config)
}

/// The config, or `None` when it would send credentials unencrypted to a remote
/// relay. Disabled rather than failing at send time: a send to an unavailable
/// transport is refused before its idempotency key is claimed, whereas a
/// transport that only errors after the claim would leave that key unresolved.
fn usable_transport(config: EmailTransportConfig) -> Option<EmailTransportConfig> {
    if let Some(reason) = insecure_transport_reason(&config) {
        tracing::error!("ryu-mail SMTP transport disabled: {reason}");
        return None;
    }
    Some(config)
}

/// Build the SMTP transport for `cfg`, refusing an unencrypted remote relay.
fn smtp_transport(
    cfg: &EmailTransportConfig,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, EmailError> {
    if let Some(reason) = insecure_transport_reason(cfg) {
        return Err(EmailError::Transport(reason));
    }
    let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());
    let builder = match cfg.tls {
        SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .map_err(|e| EmailError::Transport(e.to_string()))?,
        SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
            .map_err(|e| EmailError::Transport(e.to_string()))?,
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host),
    };
    Ok(builder.port(cfg.port).credentials(creds).build())
}

fn parse_mailbox(addr: &str) -> Result<Mailbox, EmailError> {
    addr.trim()
        .parse::<Mailbox>()
        .map_err(|e| EmailError::InvalidAddress(format!("{addr}: {e}")))
}

fn generate_message_id(from: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let domain = from
        .rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('>').trim())
        .filter(|d| !d.is_empty())
        .unwrap_or("ryu.local");
    format!("<{nanos}.{seq}@{domain}>")
}

enum MultiPartOrSingle {
    Multi(MultiPart),
    Single(SinglePart),
}

fn build_body(msg: &OutboundEmail) -> Result<MultiPartOrSingle, EmailError> {
    let content = match (msg.text.as_ref(), msg.html.as_ref()) {
        (Some(text), Some(html)) => MultiPartOrSingle::Multi(MultiPart::alternative_plain_html(
            text.clone(),
            html.clone(),
        )),
        (Some(text), None) => MultiPartOrSingle::Single(SinglePart::plain(text.clone())),
        (None, Some(html)) => MultiPartOrSingle::Single(SinglePart::html(html.clone())),
        (None, None) => MultiPartOrSingle::Single(SinglePart::plain(String::new())),
    };

    if msg.attachments.is_empty() {
        return Ok(content);
    }

    let mut mixed = MultiPart::mixed().multipart(match content {
        MultiPartOrSingle::Multi(m) => m,
        MultiPartOrSingle::Single(s) => MultiPart::mixed().singlepart(s),
    });
    for att in &msg.attachments {
        let ct = ContentType::parse(&att.content_type)
            .unwrap_or(ContentType::parse("application/octet-stream").unwrap());
        mixed = mixed
            .singlepart(LettreAttachment::new(att.filename.clone()).body(att.bytes.clone(), ct));
    }
    Ok(MultiPartOrSingle::Multi(mixed))
}

/// Assemble the MIME message and its SMTP envelope. Returns the message and its
/// generated Message-ID. Pure (no network), so the envelope rules are testable.
fn build_message(
    cfg: &EmailTransportConfig,
    msg: &OutboundEmail,
) -> Result<(Message, String), EmailError> {
    if msg.to.is_empty() {
        return Err(EmailError::InvalidAddress("no recipients".to_string()));
    }
    if msg.headers.len() > MAX_CUSTOM_HEADERS {
        return Err(EmailError::Build("too many custom headers".to_owned()));
    }
    let from_addr = msg.from.as_deref().unwrap_or(cfg.from.as_str());
    let message_id = generate_message_id(from_addr);
    let from = parse_mailbox(from_addr)?;

    // The envelope (MAIL FROM / RCPT TO) is pinned to the typed, validated fields
    // rather than derived from the finished headers, so no header can add a
    // recipient or change the sender the relay sees.
    let mut recipients = Vec::with_capacity(msg.to.len() + msg.cc.len() + msg.bcc.len());
    let mut builder = Message::builder()
        .from(from.clone())
        .subject(msg.subject.clone())
        .message_id(Some(message_id.clone()));

    for to in &msg.to {
        let mailbox = parse_mailbox(to)?;
        recipients.push(mailbox.email.clone());
        builder = builder.to(mailbox);
    }
    for cc in &msg.cc {
        let mailbox = parse_mailbox(cc)?;
        recipients.push(mailbox.email.clone());
        builder = builder.cc(mailbox);
    }
    for bcc in &msg.bcc {
        let mailbox = parse_mailbox(bcc)?;
        recipients.push(mailbox.email.clone());
        builder = builder.bcc(mailbox);
    }
    let envelope = lettre::address::Envelope::new(Some(from.email), recipients)
        .map_err(|e| EmailError::Build(e.to_string()))?;
    builder = builder.envelope(envelope);
    if let Some(reply_to) = msg.reply_to.as_ref() {
        builder = builder.reply_to(parse_mailbox(reply_to)?);
    }
    if let Some(in_reply_to) = msg.in_reply_to.as_ref() {
        builder = builder.in_reply_to(in_reply_to.clone());
    }
    if let Some(references) = msg.references.as_ref() {
        builder = builder.references(references.clone());
    }
    for (name, value) in &msg.headers {
        if !custom_header_allowed(name, value) {
            return Err(EmailError::Build(format!("header not allowed: {name}")));
        }
        let header_name = HeaderName::new_from_ascii(name.clone())
            .map_err(|_| EmailError::Build(format!("invalid header name: {name}")))?;
        builder = builder.raw_header(HeaderValue::new(header_name, value.clone()));
    }

    let body = build_body(msg)?;
    let email = match body {
        MultiPartOrSingle::Multi(m) => builder.multipart(m),
        MultiPartOrSingle::Single(s) => builder.singlepart(s),
    }
    .map_err(|e| EmailError::Build(e.to_string()))?;
    Ok((email, message_id))
}

/// Send a fully-specified email over the given BYO SMTP transport. Returns the
/// Message-ID on success. Bounded by [`SEND_TIMEOUT`].
pub async fn send_email(
    cfg: &EmailTransportConfig,
    msg: &OutboundEmail,
) -> Result<String, EmailError> {
    let (email, message_id) = build_message(cfg, msg)?;

    let transport = smtp_transport(cfg)?;

    match tokio::time::timeout(SEND_TIMEOUT, transport.send(email)).await {
        Err(_) => Err(EmailError::Timeout),
        Ok(Err(e)) => Err(EmailError::Send(e.to_string())),
        Ok(Ok(_response)) => Ok(message_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate_message_id: domain extraction ──────────────────────────────

    #[test]
    fn message_id_uses_the_from_domain() {
        let id = generate_message_id("alice@example.com");
        assert!(id.starts_with('<'), "id: {id}");
        assert!(id.ends_with("@example.com>"), "id: {id}");
    }

    #[test]
    fn message_id_falls_back_to_ryu_local_without_at() {
        let id = generate_message_id("noatsign");
        assert!(id.ends_with("@ryu.local>"), "id: {id}");
    }

    #[test]
    fn message_id_strips_trailing_angle_bracket_from_domain() {
        // A bare "<local@domain>" style input: the domain part still trims '>'.
        let id = generate_message_id("bob@node.example>");
        assert!(id.ends_with("@node.example>"), "id: {id}");
    }

    #[test]
    fn message_ids_are_unique_across_calls() {
        let a = generate_message_id("x@y.com");
        let b = generate_message_id("x@y.com");
        assert_ne!(a, b, "sequence counter must differentiate ids");
    }

    // ── parse_mailbox ───────────────────────────────────────────────────────

    #[test]
    fn parse_mailbox_accepts_a_plain_address() {
        assert!(parse_mailbox("user@example.com").is_ok());
        // Surrounding whitespace is trimmed.
        assert!(parse_mailbox("  user@example.com  ").is_ok());
    }

    #[test]
    fn parse_mailbox_rejects_garbage_with_invalid_address_error() {
        let err = parse_mailbox("this is not an email").unwrap_err();
        assert!(matches!(err, EmailError::InvalidAddress(_)));
    }

    // ── build_body: text/html/attachment branch selection ───────────────────

    fn base() -> OutboundEmail {
        OutboundEmail {
            to: vec!["a@b.com".to_string()],
            subject: "s".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn build_body_text_and_html_is_multipart_alternative() {
        let mut m = base();
        m.text = Some("t".to_string());
        m.html = Some("<p>h</p>".to_string());
        assert!(matches!(
            build_body(&m).unwrap(),
            MultiPartOrSingle::Multi(_)
        ));
    }

    #[test]
    fn build_body_text_only_is_single() {
        let mut m = base();
        m.text = Some("t".to_string());
        assert!(matches!(
            build_body(&m).unwrap(),
            MultiPartOrSingle::Single(_)
        ));
    }

    #[test]
    fn build_body_html_only_is_single() {
        let mut m = base();
        m.html = Some("<p>h</p>".to_string());
        assert!(matches!(
            build_body(&m).unwrap(),
            MultiPartOrSingle::Single(_)
        ));
    }

    #[test]
    fn build_body_empty_is_single_plain() {
        let m = base();
        assert!(matches!(
            build_body(&m).unwrap(),
            MultiPartOrSingle::Single(_)
        ));
    }

    #[test]
    fn build_body_with_attachment_promotes_to_mixed_multipart() {
        let mut m = base();
        m.text = Some("t".to_string());
        m.attachments = vec![Attachment {
            filename: "f.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            bytes: vec![1, 2, 3],
        }];
        assert!(matches!(
            build_body(&m).unwrap(),
            MultiPartOrSingle::Multi(_)
        ));
    }

    fn transport() -> EmailTransportConfig {
        EmailTransportConfig {
            host: "smtp.example.test".to_owned(),
            port: 587,
            username: "relay".to_owned(),
            password: "secret".to_owned(),
            from: "relay@example.test".to_owned(),
            tls: SmtpTls::Starttls,
        }
    }

    #[test]
    fn smtp_tls_mode_prefers_encryption() {
        assert_eq!(smtp_tls(None, None, 587), SmtpTls::Starttls);
        assert_eq!(smtp_tls(None, None, 465), SmtpTls::Implicit);
        assert_eq!(smtp_tls(Some("implicit"), None, 2465), SmtpTls::Implicit);
        assert_eq!(smtp_tls(Some("NONE"), None, 25), SmtpTls::None);
        assert_eq!(
            smtp_tls(Some("starttls"), Some("false"), 587),
            SmtpTls::Starttls
        );
        // Legacy opt-out still reads as plaintext, except on the SMTPS port.
        assert_eq!(smtp_tls(None, Some("false"), 25), SmtpTls::None);
        assert_eq!(smtp_tls(None, Some("0"), 465), SmtpTls::Implicit);
        // A typo never downgrades to plaintext.
        assert_eq!(smtp_tls(Some("startls"), None, 587), SmtpTls::Starttls);
    }

    #[test]
    fn credentials_never_cross_an_unencrypted_remote_connection() {
        let mut cfg = transport();
        cfg.tls = SmtpTls::None;
        assert!(matches!(
            smtp_transport(&cfg),
            Err(EmailError::Transport(_))
        ));
        for host in ["127.0.0.1", "localhost", "::1", "[::1]"] {
            cfg.host = host.to_owned();
            assert!(smtp_transport(&cfg).is_ok(), "{host} is a local relay");
        }
        let mut cfg = transport();
        cfg.tls = SmtpTls::Implicit;
        assert!(smtp_transport(&cfg).is_ok());
        cfg.tls = SmtpTls::Starttls;
        assert!(smtp_transport(&cfg).is_ok());
    }

    #[test]
    fn an_unencrypted_remote_relay_leaves_the_transport_unconfigured() {
        // Unconfigured (not a send-time error), so a keyed send is refused before
        // its idempotency key is claimed.
        let mut cfg = transport();
        cfg.tls = SmtpTls::None;
        assert!(usable_transport(cfg.clone()).is_none());
        cfg.host = "127.0.0.1".to_owned();
        assert!(usable_transport(cfg).is_some());
        assert!(usable_transport(transport()).is_some());
    }

    #[test]
    fn reserved_and_malformed_headers_are_refused() {
        for name in [
            "From",
            "sender",
            "BCC",
            "Reply-To",
            "Return-Path",
            "Message-ID",
            "Content-Type",
            "Resent-To",
        ] {
            assert!(!custom_header_allowed(name, "x"), "{name} must be reserved");
        }
        assert!(!custom_header_allowed("X-A\r\nX-Injected", "v"));
        assert!(!custom_header_allowed("X A", "v"));
        assert!(!custom_header_allowed("X-A:", "v"));
        assert!(!custom_header_allowed(
            "X-A",
            "v\r\nBcc: exfil@evil.example"
        ));
        assert!(custom_header_allowed("X-Campaign", "spring"));
    }

    #[test]
    fn a_header_cannot_add_a_recipient_or_change_the_sender() {
        let mut m = base();
        m.from = Some("agent@node.example".to_owned());
        m.cc = vec!["copy@ok.example".to_owned()];
        m.bcc = vec!["Hidden <hidden@ok.example>".to_owned()];
        for header in ["Bcc", "From", "Sender"] {
            let mut forged = m.clone();
            forged
                .headers
                .insert(header.to_owned(), "exfil@evil.example".to_owned());
            assert!(
                matches!(
                    build_message(&transport(), &forged),
                    Err(EmailError::Build(_))
                ),
                "{header} override must be refused"
            );
        }
        m.headers
            .insert("X-Campaign".to_owned(), "spring".to_owned());
        let (message, _) = build_message(&transport(), &m).unwrap();
        let envelope = message.envelope();
        assert_eq!(
            envelope.from().map(ToString::to_string).as_deref(),
            Some("agent@node.example")
        );
        let recipients: Vec<String> = envelope.to().iter().map(ToString::to_string).collect();
        assert_eq!(
            recipients,
            ["a@b.com", "copy@ok.example", "hidden@ok.example"]
        );
    }

    #[test]
    fn build_body_tolerates_a_bogus_attachment_content_type() {
        // ContentType::parse failure falls back to octet-stream rather than erroring.
        let mut m = base();
        m.attachments = vec![Attachment {
            filename: "f.bin".to_string(),
            content_type: "not/a/valid/type/at/all".to_string(),
            bytes: vec![9],
        }];
        assert!(build_body(&m).is_ok());
    }
}
