//! Outbound send for self-host inboxes — reuses the inlined SMTP sink.
//! Tracer copy of `apps/core/src/mail/send.rs` (verbatim; `crate::email` is now
//! the inlined sink instead of Core's).

use anyhow::{anyhow, Result};
use chrono::Utc;

use super::store::MailStore;
use super::EmailMessage;
use crate::email::{self, OutboundEmail};

/// A compose/send request against an inbox.
pub struct SendRequest {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub in_reply_to: Option<String>,
}

/// Send a message from an inbox and record the outbound row. Returns the stored
/// message (with its provider message id).
pub async fn send_from_inbox(
    store: &MailStore,
    inbox_id: &str,
    req: SendRequest,
) -> Result<EmailMessage> {
    let inbox = store
        .get_inbox(inbox_id)
        .await?
        .ok_or_else(|| anyhow!("inbox not found"))?;
    let cfg = email::resolve_transport()
        .ok_or_else(|| anyhow!("email transport not configured (set RYU_SMTP_* env)"))?;

    let from = inbox.address.clone();
    let outbound = OutboundEmail {
        from: Some(from.clone()),
        to: req.to.clone(),
        cc: req.cc.clone(),
        subject: req.subject.clone(),
        text: req.text.clone(),
        html: req.html.clone(),
        in_reply_to: req.in_reply_to.clone(),
        ..Default::default()
    };
    let provider_message_id = email::send_email(&cfg, &outbound)
        .await
        .map_err(|e| anyhow!(e.to_string()))?;

    let msg = EmailMessage {
        id: uuid::Uuid::new_v4().to_string(),
        inbox_id: inbox_id.to_string(),
        direction: "outbound".to_string(),
        message_id: provider_message_id.clone(),
        in_reply_to: req.in_reply_to,
        from_addr: from,
        to_addrs: req.to,
        cc_addrs: req.cc,
        subject: req.subject,
        text: req.text,
        html: req.html,
        provider_message_id: Some(provider_message_id),
        attachments: Vec::new(),
        created_at: Utc::now().to_rfc3339(),
    };
    store.insert_message(msg, Vec::new()).await
}

#[cfg(test)]
mod tests {
    use super::{send_from_inbox, SendRequest};
    use crate::store::fresh_store;

    fn req() -> SendRequest {
        SendRequest {
            to: vec!["dest@x.com".to_string()],
            cc: Vec::new(),
            subject: "s".to_string(),
            text: Some("t".to_string()),
            html: None,
            in_reply_to: None,
        }
    }

    #[tokio::test]
    async fn send_from_unknown_inbox_errors_before_touching_smtp() {
        // The inbox lookup fails first, so this never resolves a transport and is
        // hermetic regardless of the RYU_SMTP_* environment.
        let store = fresh_store();
        let err = send_from_inbox(&store, "no-such-inbox", req())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("inbox not found"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn send_without_configured_transport_errors() {
        // Only assert the not-configured branch when the env genuinely has no SMTP
        // transport — never actually attempt a network send from a test.
        if crate::email::resolve_transport().is_some() {
            return;
        }
        let store = fresh_store();
        let inbox = store
            .create_inbox("Out", "out@node.example", crate::InboxProvider::Webhook)
            .await
            .unwrap();
        let err = send_from_inbox(&store, &inbox.id, req()).await.unwrap_err();
        assert!(
            err.to_string().contains("transport not configured"),
            "unexpected error: {err}"
        );
    }
}
