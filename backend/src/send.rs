//! Outbound send for self-host inboxes through Ryu's node-owned email transport.

use anyhow::{anyhow, Result};
use base64::Engine as _;
use chrono::Utc;
use std::collections::BTreeMap;

use super::store::MailStore;
use super::EmailMessage;
use crate::host::{EmailHost, EmailSendAttachment, EmailSendRequest};

/// A compose/send request against an inbox.
pub struct SendRequest {
    /// Stable local id allocated before handing the message to SMTP. This lets
    /// open-tracking URLs identify the stored row even though the provider's
    /// Message-ID is only known after the relay accepts the message.
    pub record_id: String,
    pub attachments: Vec<EmailSendAttachment>,
    pub bcc: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub headers: BTreeMap<String, String>,
    pub labels: Vec<String>,
    pub reply_to: Vec<String>,
    pub references: Option<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub in_reply_to: Option<String>,
    pub track_opens: bool,
}

/// Send a message from an inbox and record the outbound row. Returns the stored
/// message (with its provider message id).
pub async fn send_from_inbox(
    store: &MailStore,
    email: &EmailHost,
    inbox_id: &str,
    req: SendRequest,
) -> Result<EmailMessage> {
    let inbox = store
        .get_inbox(inbox_id)
        .await?
        .ok_or_else(|| anyhow!("inbox not found"))?;
    let from = inbox.address.clone();
    let outbound = EmailSendRequest {
        attachments: req.attachments.clone(),
        bcc: req.bcc.clone(),
        cc: req.cc.clone(),
        from: Some(from.clone()),
        headers: req.headers.clone(),
        html: req.html.clone(),
        in_reply_to: req.in_reply_to.clone(),
        labels: req.labels.clone(),
        reply_to: req.reply_to.clone(),
        references: req.references.clone(),
        subject: req.subject.clone(),
        text: req.text.clone(),
        track_opens: req.track_opens,
        to: req.to.clone(),
    };
    let provider_message_id = email
        .send(&outbound)
        .await
        .map_err(|e| anyhow!(e.to_string()))?;

    let created_at = Utc::now().to_rfc3339();
    let references: Vec<String> = req
        .references
        .as_deref()
        .map(|value| value.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let thread_id = references
        .first()
        .cloned()
        .or_else(|| req.in_reply_to.clone())
        .or_else(|| Some(provider_message_id.clone()));
    let attachments = req
        .attachments
        .iter()
        .map(|attachment| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&attachment.content_base64)
                .map_err(|error| anyhow!("invalid attachment base64: {error}"))?;
            Ok(crate::store::RawAttachment {
                bytes,
                content_id: attachment.content_id.clone(),
                content_type: attachment.content_type.clone(),
                filename: attachment.filename.clone(),
                inline: attachment.inline,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let html = req.html;
    let text = req.text;
    let msg = EmailMessage {
        id: req.record_id,
        inbox_id: inbox_id.to_string(),
        direction: "outbound".to_string(),
        message_id: provider_message_id.clone(),
        in_reply_to: req.in_reply_to,
        thread_id,
        references,
        from_addr: from,
        to_addrs: req.to,
        cc_addrs: req.cc,
        bcc_addrs: req.bcc,
        reply_to_addrs: req.reply_to,
        subject: req.subject,
        text: text.clone(),
        html: html.clone(),
        extracted_text: None,
        extracted_html: None,
        preview: None,
        headers: req.headers,
        labels: req.labels,
        status: "sent".to_owned(),
        read: false,
        opened_at: None,
        raw_size: 0,
        provider_message_id: Some(provider_message_id),
        attachments: Vec::new(),
        created_at: created_at.clone(),
        updated_at: created_at,
    };
    store.insert_message(msg, attachments).await
}

#[cfg(test)]
mod tests {
    use super::{send_from_inbox, SendRequest};
    use crate::host::EmailHost;
    use crate::store::fresh_store;
    use std::collections::BTreeMap;

    fn req() -> SendRequest {
        SendRequest {
            record_id: uuid::Uuid::new_v4().to_string(),
            attachments: Vec::new(),
            bcc: Vec::new(),
            to: vec!["dest@x.com".to_string()],
            cc: Vec::new(),
            headers: BTreeMap::new(),
            labels: Vec::new(),
            reply_to: Vec::new(),
            references: None,
            subject: "s".to_string(),
            text: Some("t".to_string()),
            html: None,
            in_reply_to: None,
            track_opens: false,
        }
    }

    #[tokio::test]
    async fn send_from_unknown_inbox_errors_before_touching_smtp() {
        // The inbox lookup fails first, so this never resolves a transport and is
        // hermetic regardless of the RYU_SMTP_* environment.
        let store = fresh_store();
        let email = EmailHost::disabled();
        let err = send_from_inbox(&store, &email, "no-such-inbox", req())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("inbox not found"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn send_without_configured_transport_errors() {
        let store = fresh_store();
        let email = EmailHost::disabled();
        let inbox = store
            .create_inbox("Out", "out@node.example", crate::InboxProvider::Webhook)
            .await
            .unwrap();
        let err = send_from_inbox(&store, &email, &inbox.id, req())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("email transport is not configured"),
            "unexpected error: {err}"
        );
    }
}
