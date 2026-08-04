//! Raw RFC822 → normalized message, via the pure-Rust `mail-parser` crate.
//! Tracer copy of `apps/core/src/mail/mime.rs` (verbatim).
//!
//! Deliberately conservative: extract the headers/bodies the inbox UI needs and
//! best-effort attachments. Anything we cannot parse degrades to an empty/default
//! value rather than failing the whole receive.

use mail_parser::MessageParser;

use super::store::RawAttachment;

/// A parsed inbound message ready to store.
pub struct ParsedInbound {
    pub message_id: String,
    pub in_reply_to: Option<String>,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub cc_addrs: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<RawAttachment>,
}

/// Best-effort attachment filename. mail-parser's per-part filename accessor is
/// unstable across minor versions, so v1 uses a positional fallback at the call
/// site (`attachment-N`) when this returns None.
fn attachment_filename(_part: &mail_parser::MessagePart<'_>) -> Option<String> {
    None
}

fn addresses(addr: Option<&mail_parser::Address<'_>>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(a) = addr {
        for item in a.iter() {
            if let Some(email) = item.address() {
                out.push(email.to_string());
            }
        }
    }
    out
}

/// Parse a raw RFC822 body. Returns `None` only when the bytes are not a parseable
/// message at all.
pub fn parse_raw(raw: &[u8]) -> Option<ParsedInbound> {
    let msg = MessageParser::default().parse(raw)?;

    let from_addr = addresses(msg.from()).into_iter().next().unwrap_or_default();
    let to_addrs = addresses(msg.to());
    let cc_addrs = addresses(msg.cc());
    let subject = msg.subject().unwrap_or_default().to_string();
    let message_id = msg
        .message_id()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("<{}@ryu.local>", uuid::Uuid::new_v4()));
    let in_reply_to = msg.in_reply_to().as_text().map(|s| s.to_string());
    let text = msg.body_text(0).map(|c| c.to_string());
    let html = msg.body_html(0).map(|c| c.to_string());

    let mut attachments = Vec::new();
    for (idx, part) in msg.attachments().enumerate() {
        let filename = attachment_filename(part).unwrap_or_else(|| format!("attachment-{idx}"));
        attachments.push(RawAttachment {
            filename,
            content_type: "application/octet-stream".to_string(),
            bytes: part.contents().to_vec(),
        });
    }

    Some(ParsedInbound {
        message_id,
        in_reply_to,
        from_addr,
        to_addrs,
        cc_addrs,
        subject,
        text,
        html,
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_message() {
        let raw = b"From: alice@example.com\r\nTo: bob@node.example\r\nSubject: Hi\r\nMessage-ID: <abc@example.com>\r\n\r\nHello world\r\n";
        let p = parse_raw(raw).expect("parse");
        assert_eq!(p.from_addr, "alice@example.com");
        assert_eq!(p.to_addrs, vec!["bob@node.example".to_string()]);
        assert_eq!(p.subject, "Hi");
        assert_eq!(p.message_id, "abc@example.com");
        assert!(p.text.unwrap_or_default().contains("Hello world"));
    }

    #[test]
    fn parses_multiple_recipients_and_cc() {
        let raw = b"From: a@x.com\r\nTo: b@x.com, c@x.com\r\nCc: d@x.com\r\nSubject: Multi\r\nMessage-ID: <m@x.com>\r\n\r\nbody\r\n";
        let p = parse_raw(raw).expect("parse");
        assert_eq!(
            p.to_addrs,
            vec!["b@x.com".to_string(), "c@x.com".to_string()]
        );
        assert_eq!(p.cc_addrs, vec!["d@x.com".to_string()]);
    }

    #[test]
    fn synthesizes_message_id_when_absent() {
        // No Message-ID header ⇒ fall back to a generated `<uuid@ryu.local>`.
        let raw = b"From: a@x.com\r\nTo: b@x.com\r\nSubject: NoId\r\n\r\nbody\r\n";
        let p = parse_raw(raw).expect("parse");
        assert!(
            p.message_id.ends_with("@ryu.local>"),
            "expected synthesized id, got {}",
            p.message_id
        );
        assert!(p.message_id.starts_with('<'));
    }

    #[test]
    fn captures_in_reply_to() {
        let raw = b"From: a@x.com\r\nTo: b@x.com\r\nSubject: Re\r\nMessage-ID: <m2@x.com>\r\nIn-Reply-To: <parent@x.com>\r\n\r\nbody\r\n";
        let p = parse_raw(raw).expect("parse");
        // mail-parser's `in_reply_to().as_text()` normalizes away the angle
        // brackets, so the stored value is the bare id.
        assert_eq!(p.in_reply_to.as_deref(), Some("parent@x.com"));
    }

    #[test]
    fn extracts_html_body() {
        let raw = b"From: a@x.com\r\nTo: b@x.com\r\nSubject: Html\r\nMessage-ID: <m3@x.com>\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n";
        let p = parse_raw(raw).expect("parse");
        assert!(
            p.html.unwrap_or_default().contains("<p>hi</p>"),
            "html body not extracted"
        );
    }

    #[test]
    fn empty_from_when_header_missing() {
        let raw = b"To: b@x.com\r\nSubject: NoFrom\r\nMessage-ID: <m4@x.com>\r\n\r\nbody\r\n";
        let p = parse_raw(raw).expect("parse");
        assert_eq!(p.from_addr, "");
    }

    #[test]
    fn attachment_uses_positional_fallback_name_and_octet_stream() {
        // A multipart/mixed with one attachment part. `attachment_filename`
        // always returns None in v1, so the positional `attachment-0` fallback
        // and the fixed `application/octet-stream` content-type are exercised.
        let raw = concat!(
            "From: a@x.com\r\n",
            "To: b@x.com\r\n",
            "Subject: WithAtt\r\n",
            "Message-ID: <m5@x.com>\r\n",
            "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n",
            "\r\n",
            "--BOUND\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "the body\r\n",
            "--BOUND\r\n",
            "Content-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename=\"doc.pdf\"\r\n",
            "\r\n",
            "PDFBYTES\r\n",
            "--BOUND--\r\n"
        )
        .as_bytes();
        let p = parse_raw(raw).expect("parse");
        assert!(p.text.unwrap_or_default().contains("the body"));
        assert_eq!(p.attachments.len(), 1);
        assert_eq!(p.attachments[0].filename, "attachment-0");
        assert_eq!(p.attachments[0].content_type, "application/octet-stream");
        assert!(!p.attachments[0].bytes.is_empty());
    }
}
