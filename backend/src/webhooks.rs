//! Signed, durable outbound Mail event delivery.
//!
//! The inbound HMAC endpoint authenticates providers posting mail to Ryu. This
//! module is the opposite direction: it authenticates Ryu's event deliveries to
//! an agent-owned endpoint with [Standard Webhooks] signatures, which the Svix
//! and Standard Webhooks libraries verify:
//!
//! * the secret is `whsec_` + base64 of random key bytes, and the HMAC-SHA256
//!   key is the decoded bytes;
//! * the signed content is `{webhook-id}.{webhook-timestamp}.{body}`;
//! * `webhook-signature` (and its `svix-signature` alias) is `v1,<base64>`.
//!
//! Webhooks created before this scheme ([`SignatureScheme::Legacy`]) keep the
//! `svix-signature` their consumers already verify, keyed by the raw UTF-8
//! secret, until the secret is rotated. Their `webhook-signature` uses the
//! standard derivation, which their `whsec_<hex>` secret also decodes under.
//!
//! [Standard Webhooks]: https://www.standardwebhooks.com/

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::store::MailStore;
use crate::{MailEvent, Webhook};

type HmacSha256 = Hmac<Sha256>;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: u32 = 3;

/// Prefix of every webhook signing secret.
const SECRET_PREFIX: &str = "whsec_";
/// Random key bytes in a new signing secret (Svix uses 24; Standard Webhooks
/// allows 24 to 64).
const SECRET_KEY_BYTES: usize = 24;

/// Headers Mail sets on every delivery; a configured custom header can never
/// replace or duplicate them.
pub const RESERVED_DELIVERY_HEADERS: &[&str] = &[
    "content-length",
    "cookie",
    "host",
    "svix-id",
    "svix-signature",
    "svix-timestamp",
    "webhook-id",
    "webhook-signature",
    "webhook-timestamp",
];

/// Whether `name` is a header Mail owns on a delivery (case-insensitive).
pub fn is_reserved_delivery_header(name: &str) -> bool {
    RESERVED_DELIVERY_HEADERS
        .iter()
        .any(|reserved| name.trim().eq_ignore_ascii_case(reserved))
}

/// How a webhook's deliveries are signed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureScheme {
    /// Standard Webhooks: HMAC keyed by the base64-decoded secret, sent as both
    /// `webhook-*` and `svix-*` headers.
    #[default]
    Standard,
    /// Webhooks created before Standard Webhooks signing: `svix-signature` is
    /// keyed by the raw UTF-8 secret, `webhook-signature` by the decoded one.
    Legacy,
}

impl SignatureScheme {
    /// Stored and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Legacy => "legacy",
        }
    }

    /// Read the stored spelling; anything unrecognised keeps the old behaviour.
    pub fn from_stored(value: &str) -> Self {
        match value {
            "standard" => Self::Standard,
            _ => Self::Legacy,
        }
    }
}

/// Mint a Standard Webhooks signing secret: `whsec_` + base64 of 24 random bytes.
pub fn new_signing_secret() -> String {
    let mut key = [0u8; SECRET_KEY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut key);
    format!(
        "{SECRET_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(key)
    )
}

/// Validate a webhook destination before any request leaves the sidecar.
///
/// Public HTTPS endpoints are allowed. Loopback, RFC1918, link-local,
/// unique-local, and cloud metadata destinations are refused both as literal
/// addresses and after DNS resolution.
pub async fn is_safe_destination(raw: &str) -> bool {
    screened_destination(raw).await.is_some()
}

/// Resolve and classify immediately before a delivery attempt. The returned
/// addresses must be passed to reqwest's `resolve_to_addrs`; a boolean-only
/// preflight followed by a fresh hostname lookup leaves a DNS-rebinding gap.
async fn screened_destination(raw: &str) -> Option<(Url, Vec<SocketAddr>)> {
    let Ok(url) = Url::parse(raw) else {
        return None;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let Some(host) = url.host_str().map(str::to_owned) else {
        return None;
    };
    if blocked_hostname(&host) {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        let port = url.port_or_known_default().unwrap_or(443);
        return (!blocked_ip(ip)).then_some((url, vec![SocketAddr::new(ip, port)]));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let Ok(addresses) = tokio::net::lookup_host((host.as_str(), port)).await else {
        return None;
    };
    let addresses: Vec<SocketAddr> = addresses.collect();
    (!addresses.is_empty() && addresses.iter().all(|address| !blocked_ip(address.ip())))
        .then_some((url, addresses))
}

fn blocked_hostname(host: &str) -> bool {
    let lowered = host.trim_end_matches('.').to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "localhost"
            | "metadata.google.internal"
            | "metadata.goog"
            | "kubernetes.default.svc"
            | "kubernetes.default"
    ) || lowered.ends_with(".localhost")
        || lowered.ends_with(".local")
        || lowered.ends_with(".internal")
}

fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || value.is_unspecified()
                || value.octets() == [169, 254, 169, 254]
                || (value.octets()[0] == 100 && (64..=127).contains(&value.octets()[1]))
                || value.octets()[0] >= 224
                || (value.octets()[0] == 192 && value.octets()[1] == 0)
                || (value.octets()[0] == 198 && (18..=19).contains(&value.octets()[1]))
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            let octets = value.octets();
            let mapped_private = segments[..5].iter().all(|segment| *segment == 0)
                && segments[5] == 0xffff
                && blocked_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                )));
            value.is_loopback()
                || value.is_unique_local()
                || value.is_unicast_link_local()
                || value.is_unspecified()
                || value.is_multicast()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                || mapped_private
        }
    }
}

/// `v1,<base64>` HMAC-SHA256 over `id.timestamp.body` with an explicit key.
fn sign_with_key(key: &[u8], message_id: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(message_id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let encoded = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!("v1,{encoded}")
}

/// The legacy signature: HMAC-SHA256 keyed with the raw UTF-8 secret (prefix
/// included) over `id.timestamp.body`. Kept for webhooks created before
/// Standard Webhooks signing so their consumers keep verifying.
pub fn legacy_signature(secret: &str, message_id: &str, timestamp: &str, body: &[u8]) -> String {
    sign_with_key(secret.as_bytes(), message_id, timestamp, body)
}

/// The Standard Webhooks signature: HMAC-SHA256 keyed with the base64-decoded
/// part of the secret after `whsec_`. `None` when the secret does not decode.
pub fn standard_signature(
    secret: &str,
    message_id: &str,
    timestamp: &str,
    body: &[u8],
) -> Option<String> {
    let encoded = secret.strip_prefix(SECRET_PREFIX).unwrap_or(secret);
    let key = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    Some(sign_with_key(&key, message_id, timestamp, body))
}

/// The signature headers for one delivery, in the order they are sent.
pub fn signature_headers(
    scheme: SignatureScheme,
    secret: &str,
    message_id: &str,
    timestamp: &str,
    body: &[u8],
) -> Vec<(&'static str, String)> {
    let standard = standard_signature(secret, message_id, timestamp, body);
    let svix_signature = match scheme {
        SignatureScheme::Standard => standard.clone(),
        SignatureScheme::Legacy => Some(legacy_signature(secret, message_id, timestamp, body)),
    };
    let mut headers = Vec::with_capacity(6);
    if let Some(signature) = standard {
        headers.push(("webhook-id", message_id.to_owned()));
        headers.push(("webhook-timestamp", timestamp.to_owned()));
        headers.push(("webhook-signature", signature));
    }
    if let Some(signature) = svix_signature {
        headers.push(("svix-id", message_id.to_owned()));
        headers.push(("svix-timestamp", timestamp.to_owned()));
        headers.push(("svix-signature", signature));
    }
    headers
}

/// Start deliveries for one stored event. Delivery state is persisted before
/// the first request, so a process restart can identify pending attempts.
pub async fn dispatch_event(store: MailStore, event: MailEvent) {
    let pod_id = match event.inbox_id.as_deref() {
        Some(inbox_id) => store
            .get_inbox(inbox_id)
            .await
            .ok()
            .flatten()
            .and_then(|inbox| inbox.pod_id),
        None => None,
    };
    let webhooks = match store
        .matching_webhooks(
            &event.event_type,
            event.inbox_id.as_deref(),
            pod_id.as_deref(),
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!("mail webhook lookup failed: {error}");
            return;
        }
    };
    for webhook in webhooks {
        let Some(delivery_id) = store
            .create_delivery_if_new(&webhook.id, &event.event_id)
            .await
            .ok()
            .flatten()
        else {
            continue;
        };
        let store = store.clone();
        let event = event.clone();
        tokio::spawn(async move {
            deliver_one(store, webhook, event, delivery_id).await;
        });
    }
}

async fn deliver_one(store: MailStore, webhook: Webhook, event: MailEvent, delivery_id: String) {
    let body = serde_json::json!({
        "type": "event",
        "event_type": event.event_type,
        "event_id": event.event_id,
        "data": event.payload,
    });
    let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let message_id = event.event_id.clone();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signed = signature_headers(
        webhook.signature_scheme,
        &webhook.secret,
        &message_id,
        &timestamp,
        &body,
    );
    let mut last_error = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let Some((url, addresses)) = screened_destination(&webhook.url).await else {
            last_error = Some("unsafe webhook destination".to_owned());
            break;
        };
        let Some(host) = url.host_str() else {
            last_error = Some("webhook destination has no host".to_owned());
            break;
        };
        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                last_error = Some(format!("webhook client build failed: {error}"));
                break;
            }
        };
        let mut request = client
            .post(url)
            .header("content-type", "application/json")
            .timeout(DELIVERY_TIMEOUT)
            .body(body.clone());
        for (name, value) in &signed {
            request = request.header(*name, value);
        }
        // Rows stored before a name was reserved are skipped, never sent
        // alongside (and so contradicting) the signature Mail computed.
        for (name, value) in &webhook.headers {
            if !is_reserved_delivery_header(name) {
                request = request.header(name, value);
            }
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                let _ = store
                    .update_delivery(&delivery_id, "delivered", attempt, None)
                    .await;
                return;
            }
            Ok(response) => {
                last_error = Some(format!("webhook returned HTTP {}", response.status()));
            }
            Err(error) => {
                last_error = Some(error.to_string());
            }
        }
        let _ = store
            .update_delivery(&delivery_id, "retrying", attempt, last_error.as_deref())
            .await;
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt))).await;
        }
    }
    let _ = store
        .update_delivery(&delivery_id, "failed", MAX_ATTEMPTS, last_error.as_deref())
        .await;
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_hostname, blocked_ip, is_reserved_delivery_header, legacy_signature,
        new_signing_secret, signature_headers, standard_signature, SignatureScheme,
    };
    use base64::Engine as _;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// The test vector the Standard Webhooks specification and the Svix
    /// libraries publish.
    const SPEC_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"; // Test vector, not a credential. gitleaks:allow skipcq
    const SPEC_ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const SPEC_TIMESTAMP: &str = "1614265330";
    const SPEC_BODY: &[u8] = br#"{"test": 2432232314}"#;
    const SPEC_SIGNATURE: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

    fn header<'a>(headers: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn standard_signatures_match_the_published_test_vector() {
        assert_eq!(
            standard_signature(SPEC_SECRET, SPEC_ID, SPEC_TIMESTAMP, SPEC_BODY).as_deref(),
            Some(SPEC_SIGNATURE)
        );
        let headers = signature_headers(
            SignatureScheme::Standard,
            SPEC_SECRET,
            SPEC_ID,
            SPEC_TIMESTAMP,
            SPEC_BODY,
        );
        assert_eq!(header(&headers, "webhook-id"), Some(SPEC_ID));
        assert_eq!(header(&headers, "webhook-timestamp"), Some(SPEC_TIMESTAMP));
        assert_eq!(header(&headers, "webhook-signature"), Some(SPEC_SIGNATURE));
        // Svix SDKs read the svix-* spelling first; it carries the same values.
        assert_eq!(header(&headers, "svix-id"), Some(SPEC_ID));
        assert_eq!(header(&headers, "svix-timestamp"), Some(SPEC_TIMESTAMP));
        assert_eq!(header(&headers, "svix-signature"), Some(SPEC_SIGNATURE));
    }

    #[test]
    fn legacy_webhooks_keep_the_raw_key_svix_signature() {
        // Expected value computed independently (Python hmac/hashlib) with the
        // key b"whsec_test" over b"evt_1.1700000000.{}". Consumers of webhooks
        // created before Standard Webhooks signing verify exactly this.
        assert_eq!(
            legacy_signature("whsec_test", "evt_1", "1700000000", b"{}"),
            "v1,piPrAQrFObzSrke+xcVCfiFZWctGPdcjLanSzZvNixU="
        );
        // A pre-change secret is `whsec_` + 32 hex characters, which is valid
        // base64, so its webhook-signature verifies with a Standard Webhooks
        // library and the unchanged secret.
        let secret = "whsec_0123456789abcdef0123456789abcdef"; // Test vector, not a credential. gitleaks:allow skipcq
        let headers = signature_headers(
            SignatureScheme::Legacy,
            secret,
            "evt_1",
            "1700000000",
            b"{}",
        );
        assert_eq!(
            header(&headers, "svix-signature"),
            Some(legacy_signature(secret, "evt_1", "1700000000", b"{}").as_str())
        );
        let standard = standard_signature(secret, "evt_1", "1700000000", b"{}").unwrap();
        assert_eq!(
            header(&headers, "webhook-signature"),
            Some(standard.as_str())
        );
        assert_ne!(
            header(&headers, "webhook-signature"),
            header(&headers, "svix-signature")
        );
    }

    #[test]
    fn new_secrets_are_standard_webhooks_secrets() {
        let secret = new_signing_secret();
        let encoded = secret.strip_prefix("whsec_").expect("whsec_ prefix");
        let key = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64 key");
        assert_eq!(key.len(), 24);
        assert_ne!(secret, new_signing_secret());
    }

    #[test]
    fn signature_headers_are_reserved_from_custom_headers() {
        for name in [
            "svix-signature",
            "Webhook-Signature",
            "webhook-id",
            "WEBHOOK-TIMESTAMP",
            "Content-Length",
        ] {
            assert!(is_reserved_delivery_header(name), "{name}");
        }
        assert!(!is_reserved_delivery_header("x-tenant"));
    }

    #[test]
    fn private_and_metadata_destinations_are_blocked() {
        assert!(blocked_hostname("localhost"));
        assert!(blocked_hostname("metadata.google.internal"));
        assert!(blocked_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(blocked_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(blocked_ip(IpAddr::V6(
            "::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!blocked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
