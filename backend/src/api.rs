//! Axum routes for self-host inboxes. Tracer copy of `apps/core/src/mail/api.rs`,
//! adapted for the out-of-process sidecar:
//!   - `State<ServerState>` → `State<MailState>` (a local single-field state).
//!   - `crate::composio_triggers::hmac_sha256_hex` → inlined `hmac_sha256_hex`
//!     below (same HMAC-SHA256 construction over `sha2::Sha256`).
//!
//! The route PATHS (`/api/mail/*`) are byte-identical to Core's so Core can proxy
//! straight through.
//!
//! ## Auth (shared-secret bearer, mirrors the gateway sidecar)
//! The `protected_routes()` are guarded by [`require_mail_token`], a small
//! shared-secret bearer middleware layered in `main`: Core injects `RYU_MAIL_TOKEN`
//! into the child's spawn env (the way the gateway sidecar receives `CORE_TOKEN`)
//! and re-stamps `Authorization: Bearer <RYU_MAIL_TOKEN>` on every proxied hop, so
//! a request that did NOT come through Core (any other loopback process on a shared
//! host) is rejected with 401. The gate is **fail-closed**: with no token
//! configured every protected route rejects. The inbound webhook stays on its own
//! per-inbox HMAC (public in Core too), so it is reachable tokenless.

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use super::send::{self, SendRequest};
use super::store::MailStore;
use super::{mime, EmailMessage, InboxProvider};
use crate::MailState;

/// Max inbound body we accept (25 MiB).
const MAX_INBOUND_BYTES: usize = 26_214_400;

/// Shared-secret bearer gate for the protected mail routes.
///
/// `expected` is the `RYU_MAIL_TOKEN` Core resolved and injected into this child's
/// env (resolved in `main`). The request must carry `Authorization: Bearer <token>`
/// equal to it — Core re-stamps exactly this header on every proxied hop, so only
/// requests that passed through Core's own `require_auth` reach the handlers.
///
/// **Fail-closed:** `expected == None` (no token configured) rejects every request
/// with 401 rather than falling open, so a bare-run or misconfigured sidecar never
/// serves stored mail unauthenticated. (The inbound webhook is on `public_routes`
/// and is not layered with this gate, so it stays reachable via its per-inbox HMAC.)
pub(crate) async fn require_mail_token(
    req: Request,
    next: Next,
    expected: Option<&str>,
) -> Response {
    let auth = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if bearer_ok(auth, expected) {
        next.run(req).await
    } else {
        err(StatusCode::UNAUTHORIZED, "unauthorized")
    }
}

/// Pure bearer check behind [`require_mail_token`] (factored out so the auth
/// decision is unit-testable without constructing an axum `Request`/`Next`).
///
/// Returns `true` only when `expected` is a non-empty token AND `auth_header` is
/// exactly `Bearer <expected>` (constant-time compared). A `None`/empty `expected`
/// is the **fail-closed** case → always `false`.
pub(crate) fn bearer_ok(auth_header: Option<&str>, expected: Option<&str>) -> bool {
    let Some(expected) = expected.filter(|t| !t.is_empty()) else {
        return false;
    };
    let provided = auth_header
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    ct_eq(provided.as_bytes(), expected.as_bytes())
}

/// Protected (proxied-by-Core) mail routes. Layered with [`require_mail_token`] in
/// `main`; Core stays the auth front and forwards the already-authed request with a
/// re-stamped shared-secret bearer on loopback.
pub fn protected_routes() -> Router<MailState> {
    Router::new()
        .route("/api/mail/status", get(status))
        .route("/api/mail/inboxes", get(list_inboxes).post(create_inbox))
        .route(
            "/api/mail/inboxes/:id",
            get(get_inbox).patch(patch_inbox).delete(delete_inbox),
        )
        .route("/api/mail/inboxes/:id/rotate-secret", post(rotate_secret))
        .route("/api/mail/inboxes/:id/messages", get(list_messages))
        .route("/api/mail/inboxes/:id/send", post(send_message))
        .route("/api/mail/messages/:id", get(get_message))
        .route("/api/mail/attachments/:id", get(download_attachment))
}

/// Public, HMAC-authed inbound webhook.
pub fn public_routes() -> Router<MailState> {
    Router::new().route("/api/mail/inbound/:id", post(inbound))
}

fn store(state: &MailState) -> &MailStore {
    &state.mail
}

async fn status(State(state): State<MailState>) -> Response {
    let send_configured = crate::email::resolve_transport().is_some();
    let count = store(&state)
        .list_inboxes()
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({
            "configured": true,
            "domainMode": "byo",
            "sendConfigured": send_configured,
            "inbound": "webhook",
            "inboxCount": count,
        })),
    )
        .into_response()
}

async fn list_inboxes(State(state): State<MailState>) -> Response {
    match store(&state).list_inboxes().await {
        Ok(v) => (StatusCode::OK, Json(json!({ "inboxes": v }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
struct CreateInboxBody {
    name: String,
    address: String,
    #[serde(default)]
    provider: Option<String>,
}

async fn create_inbox(
    State(state): State<MailState>,
    Json(body): Json<CreateInboxBody>,
) -> Response {
    let provider = match body.provider.as_deref() {
        Some("imap") => InboxProvider::Imap,
        _ => InboxProvider::Webhook,
    };
    if body.address.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "address is required");
    }
    match store(&state)
        .create_inbox(body.name.trim(), body.address.trim(), provider)
        .await
    {
        Ok(inbox) => (StatusCode::OK, Json(json!({ "inbox": inbox }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn get_inbox(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_inbox(&id).await {
        Ok(Some(inbox)) => (StatusCode::OK, Json(json!({ "inbox": inbox }))).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "inbox not found"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
struct PatchInboxBody {
    name: Option<String>,
}

async fn patch_inbox(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Json(body): Json<PatchInboxBody>,
) -> Response {
    if let Some(name) = body.name.as_deref() {
        if let Err(e) = store(&state).rename_inbox(&id, name.trim()).await {
            return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    }
    match store(&state).get_inbox(&id).await {
        Ok(Some(inbox)) => (StatusCode::OK, Json(json!({ "inbox": inbox }))).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "inbox not found"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn rotate_secret(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).rotate_secret(&id).await {
        Ok(secret) => (StatusCode::OK, Json(json!({ "inboundSecret": secret }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn delete_inbox(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).delete_inbox(&id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn list_messages(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).list_messages(&id, 200).await {
        Ok(v) => (StatusCode::OK, Json(json!({ "messages": v }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn get_message(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_message(&id).await {
        Ok(Some(m)) => (StatusCode::OK, Json(json!({ "message": m }))).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "message not found"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
struct SendBody {
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    subject: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default, rename = "inReplyTo")]
    in_reply_to: Option<String>,
}

async fn send_message(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Json(body): Json<SendBody>,
) -> Response {
    if body.to.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "at least one recipient is required",
        );
    }
    let req = SendRequest {
        to: body.to,
        cc: body.cc,
        subject: body.subject,
        text: body.text,
        html: body.html,
        in_reply_to: body.in_reply_to,
    };
    match send::send_from_inbox(store(&state), &id, req).await {
        Ok(m) => (StatusCode::OK, Json(json!({ "message": m }))).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

/// Public inbound webhook. HMAC-authed with the inbox's `inbound_secret` over the
/// raw body (`X-Ryu-Signature: sha256=<hex>`).
async fn inbound(
    State(state): State<MailState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_INBOUND_BYTES {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "message too large");
    }
    let inbox = match store(&state).get_inbox(&id).await {
        Ok(Some(inbox)) => inbox,
        Ok(None) => return err(StatusCode::NOT_FOUND, "inbox not found"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let provided = headers
        .get("x-ryu-signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().trim_start_matches("sha256=").to_string())
        .unwrap_or_default();
    let expected = hmac_sha256_hex(inbox.inbound_secret.as_bytes(), &body);
    if !ct_eq(provided.as_bytes(), expected.as_bytes()) {
        return err(StatusCode::UNAUTHORIZED, "invalid signature");
    }

    let Some(parsed) = mime::parse_raw(&body) else {
        return err(StatusCode::BAD_REQUEST, "unparseable message");
    };
    let msg = EmailMessage {
        id: uuid::Uuid::new_v4().to_string(),
        inbox_id: id,
        direction: "inbound".to_string(),
        message_id: parsed.message_id,
        in_reply_to: parsed.in_reply_to,
        from_addr: parsed.from_addr,
        to_addrs: parsed.to_addrs,
        cc_addrs: parsed.cc_addrs,
        subject: parsed.subject,
        text: parsed.text,
        html: parsed.html,
        provider_message_id: None,
        attachments: Vec::new(),
        created_at: Utc::now().to_rfc3339(),
    };
    match store(&state).insert_message(msg, parsed.attachments).await {
        Ok(m) => (StatusCode::OK, Json(json!({ "id": m.id }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Serve an attachment as a forced download (always octet-stream, never inline).
async fn download_attachment(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    let Some((meta, path)) = store(&state).attachment_path(&id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "attachment not found");
    };
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return err(StatusCode::NOT_FOUND, "attachment blob missing");
    };
    let safe_name = meta.filename.replace(['"', '\r', '\n'], "_");
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{safe_name}\""),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// Constant-time byte comparison (avoid leaking the HMAC via early-exit timing).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Inlined from `apps/core/src/composio_triggers::hmac_sha256_hex`. Standard HMAC
/// construction over `sha2::Sha256`, lowercase-hex encoded. (Uses `format!("{:x}")`
/// on the digest instead of the `hex` crate to avoid pulling a new dependency.)
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    const BLOCK_SIZE: usize = 64;
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        block_key[..hashed.len()].copy_from_slice(&hashed);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

fn err(code: StatusCode, message: &str) -> Response {
    (code, Json(json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::bearer_ok;

    // ── Route-handler tests ─────────────────────────────────────────────────
    // The handlers are called directly (no HTTP server / tower dep — no sibling
    // backend uses one). Extractors are constructed by hand; responses are
    // asserted on their status + decoded JSON body. Every store is built via
    // `fresh_store`, which pins `RYU_DIR` at a temp dir so attachment blobs never
    // touch the real `~/.ryu`.
    mod routes {
        use crate::store::fresh_store;
        use crate::{EmailMessage, InboxProvider, MailState};
        use axum::body::Bytes;
        use axum::extract::{Path, State};
        use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
        use axum::response::Response;
        use axum::Json;
        use serde_json::Value;

        fn state() -> MailState {
            MailState { mail: fresh_store() }
        }

        async fn json(resp: Response) -> Value {
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }

        fn create_body(name: &str, address: &str) -> super::super::CreateInboxBody {
            super::super::CreateInboxBody {
                name: name.to_string(),
                address: address.to_string(),
                provider: None,
            }
        }

        #[tokio::test]
        async fn status_reports_configured_and_inbox_count() {
            let st = state();
            st.mail
                .create_inbox("a", "a@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            st.mail
                .create_inbox("b", "b@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = super::super::status(State(st)).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            assert_eq!(body["configured"], true);
            assert_eq!(body["domainMode"], "byo");
            assert_eq!(body["inboxCount"], 2);
        }

        #[tokio::test]
        async fn create_inbox_rejects_empty_address() {
            let resp = super::super::create_inbox(
                State(state()),
                Json(create_body("x", "   ")),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn create_then_list_inbox_via_handlers() {
            let st = state();
            let resp =
                super::super::create_inbox(State(st.clone()), Json(create_body("Team", "t@x.com")))
                    .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let created = json(resp).await;
            assert_eq!(created["inbox"]["name"], "Team");

            let list = super::super::list_inboxes(State(st)).await;
            let body = json(list).await;
            assert_eq!(body["inboxes"].as_array().unwrap().len(), 1);
        }

        #[tokio::test]
        async fn get_inbox_handler_not_found_is_404() {
            let resp =
                super::super::get_inbox(State(state()), Path("missing".to_string())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn patch_inbox_renames() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("Old", "x@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = super::super::patch_inbox(
                State(st),
                Path(inbox.id.clone()),
                Json(super::super::PatchInboxBody {
                    name: Some("New".to_string()),
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            assert_eq!(body["inbox"]["name"], "New");
        }

        #[tokio::test]
        async fn delete_inbox_handler_then_get_is_404() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("D", "x@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let del = super::super::delete_inbox(State(st.clone()), Path(inbox.id.clone())).await;
            assert_eq!(del.status(), StatusCode::OK);
            let got = super::super::get_inbox(State(st), Path(inbox.id)).await;
            assert_eq!(got.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn rotate_secret_handler_returns_a_fresh_secret() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("R", "x@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = super::super::rotate_secret(State(st), Path(inbox.id.clone())).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            let new_secret = body["inboundSecret"].as_str().unwrap();
            assert!(!new_secret.is_empty());
            assert_ne!(new_secret, inbox.inbound_secret);
        }

        #[tokio::test]
        async fn send_message_rejects_empty_recipient_list() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("S", "s@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = super::super::send_message(
                State(st),
                Path(inbox.id),
                Json(super::super::SendBody {
                    to: Vec::new(),
                    cc: Vec::new(),
                    subject: "s".to_string(),
                    text: None,
                    html: None,
                    in_reply_to: None,
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn send_message_without_transport_is_bad_request() {
            // Only when the env has no SMTP transport (never a real network send).
            if crate::email::resolve_transport().is_some() {
                return;
            }
            let st = state();
            let inbox = st
                .mail
                .create_inbox("S", "s@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = super::super::send_message(
                State(st),
                Path(inbox.id),
                Json(super::super::SendBody {
                    to: vec!["dest@x.com".to_string()],
                    cc: Vec::new(),
                    subject: "s".to_string(),
                    text: Some("t".to_string()),
                    html: None,
                    in_reply_to: None,
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn get_message_handler_not_found_is_404() {
            let resp =
                super::super::get_message(State(state()), Path("nope".to_string())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn list_messages_handler_returns_stored_rows() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("L", "l@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let msg = EmailMessage {
                id: uuid::Uuid::new_v4().to_string(),
                inbox_id: inbox.id.clone(),
                direction: "inbound".to_string(),
                message_id: "<a@x.com>".to_string(),
                in_reply_to: None,
                from_addr: "a@x.com".to_string(),
                to_addrs: vec!["b@x.com".to_string()],
                cc_addrs: Vec::new(),
                subject: "hello".to_string(),
                text: Some("body".to_string()),
                html: None,
                provider_message_id: None,
                attachments: Vec::new(),
                created_at: "2020-01-01T00:00:00Z".to_string(),
            };
            st.mail.insert_message(msg, Vec::new()).await.unwrap();
            let resp = super::super::list_messages(State(st), Path(inbox.id)).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            let arr = body["messages"].as_array().unwrap();
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0]["subject"], "hello");
        }

        // ── Inbound webhook: the security-critical HMAC path ────────────────

        fn signed_headers(secret: &str, body: &[u8]) -> HeaderMap {
            let sig = super::super::hmac_sha256_hex(secret.as_bytes(), body);
            let mut h = HeaderMap::new();
            h.insert(
                "x-ryu-signature",
                HeaderValue::from_str(&format!("sha256={sig}")).unwrap(),
            );
            h
        }

        const RAW_MSG: &[u8] =
            b"From: a@x.com\r\nTo: b@x.com\r\nSubject: Hi\r\nMessage-ID: <m@x.com>\r\n\r\nHello\r\n";

        #[tokio::test]
        async fn inbound_valid_signature_stores_the_message() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("In", "in@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let headers = signed_headers(&inbox.inbound_secret, RAW_MSG);
            let resp = super::super::inbound(
                State(st.clone()),
                Path(inbox.id.clone()),
                headers,
                Bytes::from(RAW_MSG),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            // The parsed message is now stored & listable.
            let stored = st.mail.list_messages(&inbox.id, 200).await.unwrap();
            assert_eq!(stored.len(), 1);
            assert_eq!(stored[0].subject, "Hi");
            assert_eq!(stored[0].direction, "inbound");
        }

        #[tokio::test]
        async fn inbound_wrong_signature_is_401_and_stores_nothing() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("In", "in@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            // Sign with the WRONG secret.
            let headers = signed_headers("attacker-secret", RAW_MSG);
            let resp = super::super::inbound(
                State(st.clone()),
                Path(inbox.id.clone()),
                headers,
                Bytes::from(RAW_MSG),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert!(st.mail.list_messages(&inbox.id, 200).await.unwrap().is_empty());
        }

        #[tokio::test]
        async fn inbound_missing_signature_is_401() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("In", "in@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = super::super::inbound(
                State(st),
                Path(inbox.id),
                HeaderMap::new(),
                Bytes::from(RAW_MSG),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn inbound_unknown_inbox_is_404() {
            let st = state();
            let headers = signed_headers("whatever", RAW_MSG);
            let resp = super::super::inbound(
                State(st),
                Path("no-inbox".to_string()),
                headers,
                Bytes::from(RAW_MSG),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn inbound_oversize_body_is_413() {
            // Size guard runs before inbox lookup / signature check.
            let big = vec![0u8; super::super::MAX_INBOUND_BYTES + 1];
            let resp = super::super::inbound(
                State(state()),
                Path("any".to_string()),
                HeaderMap::new(),
                Bytes::from(big),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        // ── Attachment download ─────────────────────────────────────────────

        #[tokio::test]
        async fn download_attachment_serves_bytes_and_sanitizes_filename() {
            use crate::store::RawAttachment;
            let st = state();
            let msg = EmailMessage {
                id: uuid::Uuid::new_v4().to_string(),
                inbox_id: "ibx".to_string(),
                direction: "inbound".to_string(),
                message_id: "<m@x.com>".to_string(),
                in_reply_to: None,
                from_addr: "a@x.com".to_string(),
                to_addrs: Vec::new(),
                cc_addrs: Vec::new(),
                subject: "s".to_string(),
                text: None,
                html: None,
                provider_message_id: None,
                attachments: Vec::new(),
                created_at: "2020-01-01T00:00:00Z".to_string(),
            };
            let stored = st
                .mail
                .insert_message(
                    msg,
                    vec![RawAttachment {
                        // Header-injection chars must be scrubbed in the disposition.
                        filename: "ev\"il\r\n.pdf".to_string(),
                        content_type: "application/pdf".to_string(),
                        bytes: b"THEBYTES".to_vec(),
                    }],
                )
                .await
                .unwrap();
            let att_id = stored.attachments[0].id.clone();
            let resp =
                super::super::download_attachment(State(st), Path(att_id)).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let disp = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(disp, "attachment; filename=\"ev_il__.pdf\"");
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/octet-stream"
            );
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&bytes[..], b"THEBYTES");
        }

        #[tokio::test]
        async fn download_unknown_attachment_is_404() {
            let resp =
                super::super::download_attachment(State(state()), Path("nope".to_string())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
    }

    #[test]
    fn bearer_ok_fails_closed_without_a_configured_token() {
        // No token configured (bare-run / misconfigured sidecar) ⇒ reject even a
        // well-formed bearer. This is the fix: the sidecar is never open.
        assert!(!bearer_ok(Some("Bearer anything"), None));
        assert!(!bearer_ok(Some("Bearer anything"), Some("")));
        // …and of course a missing header stays rejected.
        assert!(!bearer_ok(None, None));
    }

    #[test]
    fn bearer_ok_requires_the_exact_shared_secret() {
        let expected = Some("s3cret-node-token");
        // The reviewer's attack: a direct caller with no / wrong bearer is rejected.
        assert!(!bearer_ok(None, expected));
        assert!(!bearer_ok(Some(""), expected));
        assert!(!bearer_ok(Some("s3cret-node-token"), expected)); // missing "Bearer "
        assert!(!bearer_ok(Some("Bearer wrong"), expected));
        assert!(!bearer_ok(Some("Bearer s3cret-node-token-x"), expected)); // length differs
                                                                           // Only Core's re-stamped exact bearer passes.
        assert!(bearer_ok(Some("Bearer s3cret-node-token"), expected));
    }

    // ── HMAC-SHA256 (inbound webhook signature) ─────────────────────────────
    // Expected digests are computed independently (Node's crypto / RFC 4231),
    // NOT from this implementation, so the assertions cannot be tautological.

    #[test]
    fn hmac_matches_rfc4231_test_case_2() {
        // key "Jefe", data "what do ya want for nothing?".
        let got = super::hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            got,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_empty_key_and_message() {
        let got = super::hmac_sha256_hex(b"", b"");
        assert_eq!(
            got,
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }

    #[test]
    fn hmac_key_longer_than_block_size_is_hashed_first() {
        // 80 bytes of 0xaa exceeds the 64-byte block, exercising the
        // `key.len() > BLOCK_SIZE` branch (key is SHA256'd before padding).
        let key = [0xaau8; 80];
        let got = super::hmac_sha256_hex(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            got,
            "6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f"
        );
    }

    #[test]
    fn hmac_typical_short_key() {
        let got = super::hmac_sha256_hex(b"secret", b"The quick brown fox");
        assert_eq!(
            got,
            "7a284e5025f32a846fa3e6957d10278eb5726dd4e0b04c8e0259defcd2cd0eb1"
        );
    }

    #[test]
    fn hmac_output_is_64_lowercase_hex_chars() {
        let got = super::hmac_sha256_hex(b"k", b"m");
        assert_eq!(got.len(), 64);
        assert!(got
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // ── Constant-time comparison ────────────────────────────────────────────

    #[test]
    fn ct_eq_behaves_like_equality_but_length_first() {
        assert!(super::ct_eq(b"", b""));
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"ab")); // different lengths
        assert!(!super::ct_eq(b"ab", b"abc"));
    }
}
