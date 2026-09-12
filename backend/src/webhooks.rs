//! Signed, durable outbound Mail event delivery.
//!
//! The inbound HMAC endpoint authenticates providers posting mail to Ryu. This
//! module is the opposite direction: it authenticates Ryu's event deliveries to
//! an agent-owned endpoint using a Svix-compatible svix-* header set.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use reqwest::Url;
use sha2::Sha256;
use std::net::IpAddr;
use std::time::Duration;

use crate::store::MailStore;
use crate::{MailEvent, Webhook};

type HmacSha256 = Hmac<Sha256>;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: u32 = 3;

/// Validate a webhook destination before any request leaves the sidecar.
///
/// Public HTTPS endpoints are allowed. Loopback, RFC1918, link-local,
/// unique-local, and cloud metadata destinations are refused both as literal
/// addresses and after DNS resolution.
pub async fn is_safe_destination(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let Some(host) = url.host_str().map(str::to_owned) else {
        return false;
    };
    if blocked_hostname(&host) {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return !blocked_ip(ip);
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let Ok(addresses) = tokio::net::lookup_host((host.as_str(), port)).await else {
        return false;
    };
    let safe = addresses
        .into_iter()
        .all(|address| !blocked_ip(address.ip()));
    safe
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
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unique_local()
                || value.is_unicast_link_local()
                || value.is_unspecified()
        }
    }
}

/// Produce the Svix-compatible v1 signature value.
pub fn signature(secret: &str, message_id: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(message_id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let encoded = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!("v1,{encoded}")
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
    if !is_safe_destination(&webhook.url).await {
        let _ = store
            .update_delivery(
                &delivery_id,
                "failed",
                0,
                Some("unsafe webhook destination"),
            )
            .await;
        return;
    }
    let body = serde_json::json!({
        "type": "event",
        "event_type": event.event_type,
        "event_id": event.event_id,
        "data": event.payload,
    });
    let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let message_id = event.event_id.clone();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature = signature(&webhook.secret, &message_id, &timestamp, &body);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut last_error = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let mut request = client
            .post(&webhook.url)
            .header("content-type", "application/json")
            .header("svix-id", &message_id)
            .header("svix-timestamp", &timestamp)
            .header("svix-signature", &signature)
            .timeout(DELIVERY_TIMEOUT)
            .body(body.clone());
        for (name, value) in &webhook.headers {
            request = request.header(name, value);
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
    use super::{blocked_hostname, blocked_ip, signature};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn signature_is_stable_for_the_same_delivery() {
        assert_eq!(
            signature("whsec_test", "evt_1", "1700000000", b"{}"),
            signature("whsec_test", "evt_1", "1700000000", b"{}")
        );
        assert_ne!(
            signature("whsec_test", "evt_1", "1700000000", b"{}"),
            signature("whsec_test", "evt_2", "1700000000", b"{}")
        );
    }

    #[test]
    fn private_and_metadata_destinations_are_blocked() {
        assert!(blocked_hostname("localhost"));
        assert!(blocked_hostname("metadata.google.internal"));
        assert!(blocked_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(blocked_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(!blocked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
