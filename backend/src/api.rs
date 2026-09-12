//! Axum routes for self-host inboxes. Tracer copy of `apps/core/src/mail/api.rs`,
//! adapted for the out-of-process sidecar:
//!   - `State<ServerState>` → `State<MailState>` (a local single-field state).
//!   - `ryu_crypto::hmac_sha256_hex` → the shared webhook-signature primitive.
//!
//! The route PATHS (`/api/mail/*`) are byte-identical to Core's so Core can proxy
//! straight through.
//!
//! ## Auth (shared-secret bearer, mirrors the gateway sidecar)
//! The `protected_routes()` are guarded by [`require_mail_token`], a small
//! shared-secret bearer middleware layered in `main`. Core injects its per-process
//! token for the loopback sidecar path; standalone deployments use
//! `RYU_MAIL_API_TOKEN`. The gate is **fail-closed**: with no token configured
//! every protected route rejects. The inbound webhook stays on its own per-inbox
//! HMAC, so it is reachable tokenless.

use axum::body::Bytes;
use axum::extract::{ws, Path, Query, Request, State, WebSocketUpgrade};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::send::{self, SendRequest};
use super::store::MailStore;
use super::{mime, Draft, EmailMessage, Inbox, InboxProvider};
use crate::host::EmailSendAttachment;
use crate::webhooks;
use crate::AttachmentInput;
use crate::MailState;
use futures_util::StreamExt;

/// Max inbound body we accept (25 MiB).
const MAX_INBOUND_BYTES: usize = 26_214_400;

/// Shared-secret bearer gate for the protected mail routes.
///
/// `expected` is the Core-issued or standalone API token resolved in `main`. The
/// request must carry `Authorization: Bearer <token>` equal to it. Core re-stamps
/// exactly this header on every proxied hop, while standalone callers present the
/// configured `RYU_MAIL_API_TOKEN` directly.
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
    let protocol_auth = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').map(str::trim).find_map(|protocol| {
                protocol
                    .strip_prefix("ryu-bearer.")
                    .map(|token| format!("Bearer {token}"))
            })
        });
    if bearer_ok(auth.or(protocol_auth.as_deref()), expected) {
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
    ryu_sidecar_runtime::bearer_ok(auth_header, expected)
}

/// Protected (proxied-by-Core) mail routes. Layered with [`require_mail_token`] in
/// `main`; Core stays the auth front and forwards the already-authed request with a
/// re-stamped shared-secret bearer on loopback.
///
/// `/openapi.json` is registered HERE rather than in `main`, so it cannot be added to
/// the surface without inheriting the bearer gate this function's caller layers on.
/// It sits at the server ROOT because that is the only address Core's fetcher tries
/// (`http://127.0.0.1:<port>/openapi.json`), and it is gated because the document
/// enumerates every route and body field this app accepts — including the send path.
pub fn protected_routes() -> Router<MailState> {
    Router::new()
        .route("/openapi.json", get(|| async { Json(openapi()) }))
        .route("/api/mail/status", get(status))
        .route("/api/mail/ws", get(realtime))
        .route("/api/mail/inboxes", get(list_inboxes).post(create_inbox))
        .route(
            "/api/mail/inboxes/:id",
            get(get_inbox).patch(patch_inbox).delete(delete_inbox),
        )
        .route("/api/mail/inboxes/:id/rotate-secret", post(rotate_secret))
        .route("/api/mail/inboxes/:id/messages", get(list_messages))
        .route(
            "/api/mail/inboxes/:id/messages/search",
            get(search_messages),
        )
        .route(
            "/api/mail/inboxes/:id/messages/:message_id",
            get(get_scoped_message)
                .patch(update_message)
                .delete(delete_scoped_message),
        )
        .route(
            "/api/mail/inboxes/:id/messages/:message_id/raw",
            get(download_raw_message),
        )
        .route(
            "/api/mail/inboxes/:id/messages/:message_id/attachments/:attachment_id",
            get(download_scoped_attachment),
        )
        .route(
            "/api/mail/inboxes/:id/messages/:message_id/reply",
            post(reply_message),
        )
        .route(
            "/api/mail/inboxes/:id/messages/:message_id/reply-all",
            post(reply_all_message),
        )
        .route(
            "/api/mail/inboxes/:id/messages/:message_id/forward",
            post(forward_message),
        )
        .route("/api/mail/inboxes/:id/threads", get(list_threads))
        .route("/api/mail/inboxes/:id/threads/search", get(search_threads))
        .route(
            "/api/mail/inboxes/:id/threads/:thread_id",
            get(get_thread).patch(update_thread).delete(delete_thread),
        )
        .route(
            "/api/mail/inboxes/:id/threads/:thread_id/attachments/:attachment_id",
            get(download_thread_attachment),
        )
        .route(
            "/api/mail/inboxes/:id/drafts",
            get(list_drafts).post(create_draft),
        )
        .route(
            "/api/mail/inboxes/:id/drafts/:draft_id",
            get(get_draft).patch(update_draft).delete(delete_draft),
        )
        .route(
            "/api/mail/inboxes/:id/drafts/:draft_id/send",
            post(send_draft),
        )
        .route("/api/mail/inboxes/:id/send", post(send_message))
        .route("/api/mail/messages/:id", get(get_message))
        .route(
            "/api/mail/messages/:id/raw",
            get(download_raw_message_global),
        )
        .route("/api/mail/attachments/:id", get(download_attachment))
        .route(
            "/api/mail/webhooks",
            get(list_webhooks).post(create_webhook),
        )
        .route(
            "/api/mail/webhooks/:id",
            get(get_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route(
            "/api/mail/webhooks/:id/headers",
            get(get_webhook_headers).patch(update_webhook_headers),
        )
        .route(
            "/api/mail/webhooks/:id/deliveries",
            get(list_webhook_deliveries),
        )
        .route(
            "/api/mail/inboxes/:id/webhooks",
            get(list_inbox_webhooks).post(create_inbox_webhook),
        )
        .route(
            "/api/mail/inboxes/:id/webhooks/:webhook_id",
            get(get_inbox_webhook)
                .patch(update_inbox_webhook)
                .delete(delete_inbox_webhook),
        )
        .route(
            "/api/mail/inboxes/:id/webhooks/:webhook_id/headers",
            get(get_inbox_webhook_headers).patch(update_inbox_webhook_headers),
        )
        .route(
            "/api/mail/lists/:scope/:scope_id/:direction/:list_type",
            get(list_entries).post(create_list_entry),
        )
        .route(
            "/api/mail/lists/:scope/:scope_id/:direction/:list_type/:entry",
            get(get_list_entry).delete(delete_list_entry),
        )
        .route("/api/mail/pods", get(list_pods).post(create_pod))
        .route("/api/mail/pods/:id", get(get_pod).delete(delete_pod))
        .route("/api/mail/domains", get(list_domains).post(create_domain))
        .route(
            "/api/mail/domains/:id",
            get(get_domain).patch(update_domain).delete(delete_domain),
        )
        .route("/api/mail/events", get(list_all_events))
        .route("/api/mail/inboxes/:id/events", get(list_inbox_events))
        .route(
            "/api/mail/inboxes/:id/metrics/events",
            get(query_event_metrics),
        )
        .route(
            "/api/mail/inboxes/:id/metrics/usage",
            get(query_usage_metrics),
        )
}

/// Public, HMAC-authed inbound webhook.
pub fn public_routes() -> Router<MailState> {
    Router::new()
        .route("/", get(product_dashboard_redirect))
        .route("/health", get(health))
        .route("/api/mail/inbound/:id", post(inbound))
        .route("/api/mail/track/:id", get(track_open))
}

async fn product_dashboard_redirect() -> Redirect {
    let target = std::env::var("RYU_PRODUCT_DASHBOARD_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "https://app.ryuhq.com/dashboard".to_owned());
    Redirect::temporary(&target)
}

/// Public process liveness probe. It deliberately does not expose mail
/// configuration or stored data; the authenticated `/api/mail/status` route
/// remains the service-level status endpoint.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

#[derive(Debug, Default, Deserialize)]
struct RealtimeSubscription {
    #[serde(default)]
    event_types: Vec<String>,
    #[serde(default)]
    inbox_ids: Vec<String>,
}

/// Authenticated WebSocket stream for low-latency mail events. The connection
/// starts subscribed to every event; clients can narrow it by sending a JSON
/// `{ "event_types": [...], "inbox_ids": [...] }` message. Events remain
/// replayable through `/api/mail/events`, so a dropped socket is recoverable.
async fn realtime(ws: WebSocketUpgrade, State(state): State<MailState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| stream_realtime(socket, state))
}

async fn stream_realtime(mut socket: ws::WebSocket, state: MailState) {
    let mut events = state.mail.subscribe_events();
    let mut subscription = RealtimeSubscription::default();
    let hello = serde_json::json!({
        "type": "connected",
        "event_types": [],
        "inbox_ids": [],
    });
    if socket
        .send(ws::Message::Text(hello.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            incoming = socket.next() => {
                let Some(Ok(message)) = incoming else { return; };
                match message {
                    ws::Message::Text(text) => {
                        if text.eq_ignore_ascii_case("ping") {
                            if socket.send(ws::Message::Text("pong".into())).await.is_err() {
                                return;
                            }
                            continue;
                        }
                        if let Ok(next) = serde_json::from_str::<RealtimeSubscription>(&text) {
                            subscription = next;
                            let ack = serde_json::json!({
                                "type": "subscribed",
                                "event_types": subscription.event_types,
                                "inbox_ids": subscription.inbox_ids,
                            });
                            if socket.send(ws::Message::Text(ack.to_string().into())).await.is_err() {
                                return;
                            }
                        }
                    }
                    ws::Message::Ping(payload) => {
                        if socket.send(ws::Message::Pong(payload)).await.is_err() {
                            return;
                        }
                    }
                    ws::Message::Close(_) => return,
                    ws::Message::Binary(_) | ws::Message::Pong(_) => {}
                }
            }
            received = events.recv() => {
                let event = match received {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                };
                if !subscription.event_types.is_empty()
                    && !subscription.event_types.iter().any(|value| value == &event.event_type)
                {
                    continue;
                }
                if !subscription.inbox_ids.is_empty()
                    && !event.inbox_id.as_ref().is_some_and(|id| subscription.inbox_ids.iter().any(|value| value == id))
                {
                    continue;
                }
                let payload = serde_json::json!({ "type": "event", "event": event });
                if socket.send(ws::Message::Text(payload.to_string().into())).await.is_err() {
                    return;
                }
            }
        }
    }
}

const TRACKING_PIXEL: &[u8] = &[
    71, 73, 70, 56, 57, 97, 1, 0, 1, 0, 128, 0, 0, 0, 0, 0, 255, 255, 255, 33, 249, 4, 1, 0, 0, 0,
    0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59,
];

async fn track_open(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    let before = store(&state).get_message(&id).await.ok().flatten();
    if before
        .as_ref()
        .is_some_and(|message| message.opened_at.is_none())
    {
        if let Ok(Some(message)) = store(&state).mark_message_opened(&id).await {
            let event = event(
                "message.opened",
                Some(message.inbox_id.clone()),
                Some(message.id.clone()),
                json!({
                    "open": {
                        "inbox_id": &message.inbox_id,
                        "thread_id": &message.thread_id,
                        "message_id": &message.message_id,
                        "timestamp": message.opened_at,
                    }
                }),
            );
            record_event(&state, event).await;
        }
    }
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/gif"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        TRACKING_PIXEL,
    )
        .into_response()
}

/// The OpenAPI sub-document Core fetches from `GET /openapi.json` and lowers into
/// one LLM tool per operation.
///
/// Deriving tools from this document is the ONLY path an agent has into this app, so
/// an unannotated route is not "undocumented" — it is uncallable. Core also
/// INTERSECTS the operations against `sidecars[0].http.routes[]`, so an operation
/// documented here but absent from the manifest yields nothing.
///
/// Unlike the sibling apps, this router registers ABSOLUTE paths already (it is a
/// tracer copy of Core's own mail surface, which is mounted at the root), so the
/// annotations below happen to match the router literally. That is a coincidence of
/// this app, not a rule — do not "align" the other apps' relative routers to it.
pub fn openapi() -> utoipa::openapi::OpenApi {
    <MailApiDoc as utoipa::OpenApi>::openapi()
}

/// The document itself.
///
/// `components(schemas(...))` is what makes each `request_body = T` resolve to a real
/// `#/components/schemas/T`. Without the entry the operation still carries a `$ref`
/// whose target is missing, and Core derives a write tool with ZERO visible arguments
/// — discoverable and uncallable, which for `send` would be strictly worse than
/// absent.
///
/// `inbound` is deliberately NOT here. It is the per-inbox HMAC webhook a mail relay
/// posts to, on `public_routes()` outside the bearer gate; its body is a provider
/// payload signed with a secret an agent does not hold, so a derived tool for it
/// could never succeed and would only invite the model to forge received mail.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_draft,
        create_domain,
        create_list_entry,
        create_pod,
        create_webhook,
        delete_draft,
        delete_domain,
        delete_list_entry,
        delete_pod,
        delete_scoped_message,
        delete_thread,
        delete_webhook,
        create_inbox,
        download_attachment,
        download_raw_message,
        download_raw_message_global,
        download_scoped_attachment,
        download_thread_attachment,
        delete_inbox,
        forward_message,
        get_draft,
        get_domain,
        get_inbox,
        get_message,
        get_pod,
        get_scoped_message,
        get_thread,
        get_webhook,
        get_webhook_headers,
        list_webhook_deliveries,
        list_all_events,
        list_drafts,
        list_domains,
        list_entries,
        list_inboxes,
        list_inbox_events,
        list_inbox_webhooks,
        list_messages,
        list_pods,
        list_threads,
        list_webhooks,
        patch_inbox,
        query_event_metrics,
        query_usage_metrics,
        reply_all_message,
        reply_message,
        rotate_secret,
        search_messages,
        search_threads,
        send_message,
        send_draft,
        status,
        update_domain,
        update_draft,
        update_message,
        update_thread,
        update_webhook,
        update_webhook_headers,
        create_inbox_webhook,
        get_inbox_webhook,
        update_inbox_webhook,
        delete_inbox_webhook,
        get_inbox_webhook_headers,
        update_inbox_webhook_headers,
    ),
    components(schemas(
        AttachmentInput,
        CreateInboxBody,
        DomainBody,
        DomainPatchBody,
        DraftBody,
        ForwardBody,
        HeaderUpdateBody,
        LabelUpdateBody,
        ListEntryCreateBody,
        PatchInboxBody,
        PodBody,
        ReplyBody,
        SendBody,
        WebhookBody,
        WebhookPatchBody
    ))
)]
struct MailApiDoc;

fn store(state: &MailState) -> &MailStore {
    &state.mail
}

/// Run scheduled drafts from the process-owned store. The poller is deliberately
/// small and restart-safe: a draft is marked `sent` only after the transport
/// accepts it, while a failed attempt returns to `draft` so it cannot spin.
pub fn spawn_draft_scheduler(state: MailState) {
    tokio::spawn(async move {
        loop {
            let now = Utc::now().to_rfc3339();
            match state.mail.list_due_drafts(&now, 16).await {
                Ok(drafts) => {
                    for draft in drafts {
                        send_scheduled_draft(&state, draft).await;
                    }
                }
                Err(error) => tracing::warn!("mail scheduled-draft poll failed: {error}"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

async fn send_scheduled_draft(state: &MailState, draft: crate::Draft) {
    let attachments = draft
        .attachments
        .iter()
        .map(|attachment| EmailSendAttachment {
            content_base64: attachment.content_base64.clone(),
            content_id: attachment.content_id.clone(),
            content_type: attachment.content_type.clone(),
            filename: attachment.filename.clone(),
            inline: attachment.inline,
        })
        .collect();
    let request = SendRequest {
        record_id: uuid::Uuid::new_v4().to_string(),
        attachments,
        bcc: draft.bcc_addrs.clone(),
        to: draft.to_addrs.clone(),
        cc: draft.cc_addrs.clone(),
        headers: draft.headers.clone(),
        labels: draft.labels.clone(),
        reply_to: draft.reply_to_addrs.clone(),
        references: None,
        subject: draft.subject.clone(),
        text: draft.text.clone(),
        html: draft.html.clone(),
        in_reply_to: None,
        track_opens: false,
    };
    match send::send_from_inbox(&state.mail, &state.email, &draft.inbox_id, request).await {
        Ok(message) => {
            let mut sent = draft.clone();
            sent.status = "sent".to_owned();
            sent.send_at = None;
            let _ = state.mail.update_draft(&sent).await;
            record_event(
                state,
                event(
                    "message.sent",
                    Some(message.inbox_id.clone()),
                    Some(message.id.clone()),
                    json!({ "message": message }),
                ),
            )
            .await;
        }
        Err(error) => {
            let mut retryable = draft;
            retryable.status = "draft".to_owned();
            retryable.send_at = None;
            let _ = state.mail.update_draft(&retryable).await;
            tracing::warn!("scheduled mail draft failed: {error}");
        }
    }
}

const STANDARD_EVENT_TYPES: &[&str] = &[
    "message.received",
    "message.received.spam",
    "message.received.blocked",
    "message.received.unauthenticated",
    "message.sent",
    "message.delivered",
    "message.bounced",
    "message.complained",
    "message.rejected",
    "message.opened",
    "domain.verified",
];

fn event(
    event_type: &str,
    inbox_id: Option<String>,
    message_id: Option<String>,
    payload: serde_json::Value,
) -> crate::MailEvent {
    crate::MailEvent {
        event_id: format!("evt_{}", uuid::Uuid::new_v4().simple()),
        event_type: event_type.to_owned(),
        inbox_id,
        message_id,
        payload,
        created_at: Utc::now().to_rfc3339(),
    }
}

async fn record_event(state: &MailState, event: crate::MailEvent) {
    if let Err(error) = store(state).insert_event(&event).await {
        tracing::warn!("mail event persistence failed: {error}");
        return;
    }
    store(state).publish_event(event.clone());
    webhooks::dispatch_event(store(state).clone(), event.clone()).await;
    if matches!(
        event.event_type.as_str(),
        "message.received" | "message.sent"
    ) {
        state
            .events
            .emit_with_notify(
                &format!("@ryu/mail#{}", event.event_type),
                event.payload,
                None,
            )
            .await;
    }
}

/// Public inbox projection. The signing secret is returned only by create and
/// rotate-secret; listing or reading an inbox must not expose a credential that
/// can authenticate an inbound webhook.
#[derive(serde::Serialize)]
struct PublicInbox {
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    created_at: String,
    id: String,
    metadata: std::collections::BTreeMap<String, serde_json::Value>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pod_id: Option<String>,
    provider: InboxProvider,
    updated_at: String,
}

fn public_inbox(inbox: Inbox) -> PublicInbox {
    PublicInbox {
        address: inbox.address,
        client_id: inbox.client_id,
        created_at: inbox.created_at,
        id: inbox.id,
        metadata: inbox.metadata,
        name: inbox.name,
        pod_id: inbox.pod_id,
        provider: inbox.provider,
        updated_at: inbox.updated_at,
    }
}

/// `GET /api/mail/status` — is mail usable at all, and can it send?
#[utoipa::path(
    get,
    path = "/api/mail/status",
    tag = "Mail",
    summary = "Read whether mail is configured on this node, how many inboxes exist, and whether an outbound transport is available. Read-only.",
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
async fn status(State(state): State<MailState>) -> Response {
    let send_configured = state.email.status().await.unwrap_or(false);
    let count = store(&state)
        .list_inboxes()
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({
            "apiVersion": crate::MAIL_API_VERSION,
            "configured": true,
            "domainMode": "byo",
            "sendConfigured": send_configured,
            "inbound": "webhook",
            "inboxCount": count,
        })),
    )
        .into_response()
}

/// `GET /api/mail/inboxes` — every inbox on this node.
#[utoipa::path(
    get,
    path = "/api/mail/inboxes",
    tag = "Mail",
    summary = "List the mail inboxes on this node with their names and addresses. Read-only; start here to find the inbox id every other mail call needs.",
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
async fn list_inboxes(State(state): State<MailState>) -> Response {
    match store(&state).list_inboxes().await {
        Ok(v) => (
            StatusCode::OK,
            Json(json!({
                "inboxes": v.into_iter().map(public_inbox).collect::<Vec<_>>()
            })),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// A new inbox to register on this node.
#[derive(Deserialize, utoipa::ToSchema)]
struct CreateInboxBody {
    /// Human-readable label for the inbox, shown in the UI.
    name: String,
    /// The email address this inbox owns, e.g. `support@example.com`. Required and
    /// must be non-blank.
    address: String,
    /// How mail arrives: `webhook` (a relay POSTs to this node — the default) or
    /// `imap`. Anything else is treated as `webhook`.
    #[serde(default)]
    provider: Option<String>,
    #[serde(default, alias = "client_id", alias = "clientId")]
    client_id: Option<String>,
    #[serde(default)]
    metadata: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(default, alias = "pod_id")]
    pod_id: Option<String>,
}

/// `POST /api/mail/inboxes` — register an inbox.
#[utoipa::path(
    post,
    path = "/api/mail/inboxes",
    tag = "Mail",
    summary = "Register a new mail inbox on this node. Does not send anything; it only creates the local record mail is filed under.",
    request_body = CreateInboxBody,
    responses((status = 200, description = "Created", body = serde_json::Value))
)]
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
    if body.metadata.len() > 256
        || body.metadata.iter().any(|(key, value)| {
            key.len() > 256
                || matches!(value, serde_json::Value::String(value) if value.len() > 256)
                || !value.is_string() && !value.is_number() && !value.is_boolean()
        })
    {
        return err(StatusCode::BAD_REQUEST, "metadata is invalid");
    }
    if let Some(client_id) = body.client_id.as_deref() {
        if let Ok(Some(existing)) = store(&state).list_inboxes().await.map(|inboxes| {
            inboxes
                .into_iter()
                .find(|inbox| inbox.client_id.as_deref() == Some(client_id))
        }) {
            return (
                StatusCode::OK,
                Json(json!({ "inbox": public_inbox(existing) })),
            )
                .into_response();
        }
    }
    match store(&state)
        .create_inbox_with_options(
            body.name.trim(),
            body.address.trim(),
            provider,
            body.client_id,
            body.metadata,
            body.pod_id,
        )
        .await
    {
        Ok(inbox) => (StatusCode::OK, Json(json!({ "inbox": inbox }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/mail/inboxes/:id` — one inbox.
#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}",
    tag = "Mail",
    summary = "Read one mail inbox by id. Read-only.",
    params(("id" = String, Path, description = "Inbox id, from GET /api/mail/inboxes")),
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
async fn get_inbox(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_inbox(&id).await {
        Ok(Some(inbox)) => (
            StatusCode::OK,
            Json(json!({ "inbox": public_inbox(inbox) })),
        )
            .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "inbox not found"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Partial update of an inbox. Only the display name is editable — the address is
/// immutable, because changing it would re-home mail already filed under it.
#[derive(Deserialize, utoipa::ToSchema)]
struct PatchInboxBody {
    /// New display label for the inbox. Omit to leave it unchanged.
    name: Option<String>,
    #[serde(default)]
    metadata: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    #[serde(default, alias = "podId")]
    pod_id: Option<String>,
}

/// `PATCH /api/mail/inboxes/:id` — rename an inbox.
#[utoipa::path(
    patch,
    path = "/api/mail/inboxes/{id}",
    tag = "Mail",
    summary = "Rename a mail inbox. Only its display label changes; the address, its messages, and its inbound secret are untouched.",
    params(("id" = String, Path, description = "Inbox id")),
    request_body = PatchInboxBody,
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
async fn patch_inbox(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Json(body): Json<PatchInboxBody>,
) -> Response {
    if body.metadata.as_ref().is_some_and(|metadata| {
        metadata.len() > 256
            || metadata.iter().any(|(key, value)| {
                key.len() > 256
                    || matches!(value, serde_json::Value::String(value) if value.len() > 256)
                    || !value.is_string() && !value.is_number() && !value.is_boolean()
            })
    }) {
        return err(StatusCode::BAD_REQUEST, "metadata is invalid");
    }
    let updated = match store(&state)
        .update_inbox(
            &id,
            body.name.as_deref().map(str::trim),
            body.metadata.as_ref(),
            body.pod_id.as_deref(),
        )
        .await
    {
        Ok(Some(inbox)) => inbox,
        Ok(None) => return err(StatusCode::NOT_FOUND, "inbox not found"),
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    (
        StatusCode::OK,
        Json(json!({ "inbox": public_inbox(updated) })),
    )
        .into_response()
}

/// `POST /api/mail/inboxes/:id/rotate-secret` — mint a new inbound HMAC secret.
#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/rotate-secret",
    tag = "Mail",
    summary = "Replace this inbox's inbound webhook secret and return the new one. The OLD secret stops working immediately, so incoming mail is rejected until the relay is reconfigured with the new value.",
    params(("id" = String, Path, description = "Inbox id")),
    responses((status = 200, description = "The new secret", body = serde_json::Value))
)]
async fn rotate_secret(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).rotate_secret(&id).await {
        Ok(secret) => (StatusCode::OK, Json(json!({ "inboundSecret": secret }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `DELETE /api/mail/inboxes/:id` — remove an inbox.
#[utoipa::path(
    delete,
    path = "/api/mail/inboxes/{id}",
    tag = "Mail",
    summary = "PERMANENTLY delete a mail inbox and the stored messages filed under it. This cannot be undone and the mail is not recoverable.",
    params(("id" = String, Path, description = "Inbox id")),
    responses((status = 200, description = "Deleted", body = serde_json::Value))
)]
async fn delete_inbox(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).delete_inbox(&id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/mail/inboxes/:id/messages` — the inbox's messages, newest first.
#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/messages",
    tag = "Mail",
    summary = "List the messages in one inbox, sent and received, newest first (up to 200). Read-only.",
    params(("id" = String, Path, description = "Inbox id, from GET /api/mail/inboxes")),
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
async fn list_messages(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let labels = query
        .labels
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    match store(&state)
        .list_messages_with_filters(
            &id,
            limit,
            query.before.as_deref(),
            query.after.as_deref(),
            query.direction.as_deref(),
            &labels,
            query.q.as_deref(),
        )
        .await
    {
        Ok(v) => (StatusCode::OK, Json(json!({ "messages": v }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// `GET /api/mail/messages/:id` — one message with its full body.
#[utoipa::path(
    get,
    path = "/api/mail/messages/{id}",
    tag = "Mail",
    summary = "Read one message in full — sender, recipients, subject, body, and attachment list. Read-only.",
    params(("id" = String, Path, description = "Message id, from GET /api/mail/inboxes/{id}/messages")),
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
async fn get_message(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_message(&id).await {
        Ok(Some(m)) => (StatusCode::OK, Json(json!({ "message": m }))).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "message not found"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

fn attachment_inputs(attachments: Vec<crate::AttachmentInput>) -> Vec<EmailSendAttachment> {
    attachments
        .into_iter()
        .map(|attachment| EmailSendAttachment {
            content_base64: attachment.content_base64,
            content_id: attachment.content_id,
            content_type: attachment.content_type,
            filename: attachment.filename,
            inline: attachment.inline,
        })
        .collect()
}

fn label_query(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

async fn address_allowed(
    state: &MailState,
    inbox: &Inbox,
    addresses: &[String],
    direction: &str,
) -> Result<bool, String> {
    let entries = store(state)
        .list_entries_for_direction(direction)
        .await
        .map_err(|error| error.to_string())?;
    let relevant = entries.into_iter().filter(|entry| {
        (entry.scope == "global")
            || (entry.scope == "inbox" && entry.scope_id == inbox.id)
            || (entry.scope == "pod" && inbox.pod_id.as_deref() == Some(entry.scope_id.as_str()))
    });
    let relevant = relevant.collect::<Vec<_>>();
    for address in addresses {
        let normalized = address.to_ascii_lowercase();
        if relevant.iter().any(|entry| {
            entry.list_type == "block"
                && (entry.entry_type == "domain"
                    && normalized.ends_with(&format!("@{}", entry.entry))
                    || entry.entry_type != "domain" && normalized == entry.entry)
        }) {
            return Ok(false);
        }
        let allow = relevant
            .iter()
            .filter(|entry| entry.list_type == "allow")
            .collect::<Vec<_>>();
        if !allow.is_empty()
            && !allow.iter().any(|entry| {
                (entry.entry_type == "domain" && normalized.ends_with(&format!("@{}", entry.entry)))
                    || (entry.entry_type != "domain" && normalized == entry.entry)
            })
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn sha256_json<T: serde::Serialize>(value: &T) -> String {
    let encoded = serde_json::to_vec(value).unwrap_or_default();
    format!("{:x}", Sha256::digest(encoded))
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/messages/{message_id}",
    params(("id" = String, Path), ("message_id" = String, Path)),
    responses((status = 200, description = "Message", body = serde_json::Value))
)]
async fn get_scoped_message(
    State(state): State<MailState>,
    Path((inbox_id, message_id)): Path<(String, String)>,
) -> Response {
    match store(&state).get_message(&message_id).await {
        Ok(Some(message)) if message.inbox_id == inbox_id => {
            (StatusCode::OK, Json(json!({ "message": message }))).into_response()
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "message not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/messages/search",
    params(("id" = String, Path), ("q" = Option<String>, Query), ("limit" = Option<u32>, Query)),
    responses((status = 200, description = "Matching messages", body = serde_json::Value))
)]
async fn search_messages(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let Some(q) = query.q.as_deref().filter(|value| !value.trim().is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "q is required");
    };
    let labels = label_query(query.labels.as_deref());
    match store(&state)
        .list_messages_with_filters(
            &inbox_id,
            query.limit.unwrap_or(100).clamp(1, 100),
            query.before.as_deref(),
            query.after.as_deref(),
            query.direction.as_deref(),
            &labels,
            Some(q),
        )
        .await
    {
        Ok(messages) => (StatusCode::OK, Json(json!({ "messages": messages }))).into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    patch,
    path = "/api/mail/inboxes/{id}/messages/{message_id}",
    params(("id" = String, Path), ("message_id" = String, Path)),
    request_body = LabelUpdateBody,
    responses((status = 200, description = "Message", body = serde_json::Value))
)]
async fn update_message(
    State(state): State<MailState>,
    Path((inbox_id, message_id)): Path<(String, String)>,
    Json(body): Json<LabelUpdateBody>,
) -> Response {
    let Some(message) = store(&state).get_message(&message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "message not found");
    };
    if message.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "message not found");
    }
    if body.add_labels.is_empty() && body.remove_labels.is_empty() && body.read.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            "a label or read change is required",
        );
    }
    if !body.add_labels.is_empty() || !body.remove_labels.is_empty() {
        if let Err(error) = store(&state)
            .update_message_labels(&message_id, &body.add_labels, &body.remove_labels)
            .await
        {
            return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    }
    if let Some(read) = body.read {
        if let Err(error) = store(&state).mark_message_read(&message_id, read).await {
            return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    }
    match store(&state).get_message(&message_id).await {
        Ok(Some(message)) => (StatusCode::OK, Json(json!({ "message": message }))).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "message not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    delete,
    path = "/api/mail/inboxes/{id}/messages/{message_id}",
    params(("id" = String, Path), ("message_id" = String, Path)),
    responses((status = 200, description = "Deleted", body = serde_json::Value))
)]
async fn delete_scoped_message(
    State(state): State<MailState>,
    Path((inbox_id, message_id)): Path<(String, String)>,
) -> Response {
    let Some(message) = store(&state).get_message(&message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "message not found");
    };
    if message.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "message not found");
    }
    match store(&state).delete_message(&message_id).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "message not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/messages/{message_id}/raw",
    params(("id" = String, Path), ("message_id" = String, Path)),
    responses((status = 200, description = "Raw RFC822 message", body = String))
)]
async fn download_raw_message(
    State(state): State<MailState>,
    Path((inbox_id, message_id)): Path<(String, String)>,
) -> Response {
    let Some(message) = store(&state).get_message(&message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "message not found");
    };
    if message.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "message not found");
    }
    download_raw_for_id(&state, &message_id).await
}

#[utoipa::path(
    get,
    path = "/api/mail/messages/{id}/raw",
    params(("id" = String, Path)),
    responses((status = 200, description = "Raw RFC822 message", body = String))
)]
async fn download_raw_message_global(
    State(state): State<MailState>,
    Path(message_id): Path<String>,
) -> Response {
    download_raw_for_id(&state, &message_id).await
}

async fn download_raw_for_id(state: &MailState, message_id: &str) -> Response {
    let Some((size, path)) = store(state).raw_path(message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "raw message not found");
    };
    let Ok(bytes) = tokio::fs::read(path).await else {
        return err(StatusCode::NOT_FOUND, "raw message blob missing");
    };
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "message/rfc822".to_owned(),
            ),
            (axum::http::header::CONTENT_LENGTH, size.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"message.eml\"".to_owned(),
            ),
        ],
        bytes,
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/messages/{message_id}/attachments/{attachment_id}",
    params(("id" = String, Path), ("message_id" = String, Path), ("attachment_id" = String, Path)),
    responses((status = 200, description = "Attachment bytes", body = String))
)]
async fn download_scoped_attachment(
    State(state): State<MailState>,
    Path((inbox_id, message_id, attachment_id)): Path<(String, String, String)>,
) -> Response {
    let Some(message) = store(&state).get_message(&message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "message not found");
    };
    if message.inbox_id != inbox_id
        || !message
            .attachments
            .iter()
            .any(|attachment| attachment.id == attachment_id)
    {
        return err(StatusCode::NOT_FOUND, "attachment not found");
    }
    download_attachment(State(state), Path(attachment_id)).await
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/threads/{thread_id}/attachments/{attachment_id}",
    params(("id" = String, Path), ("thread_id" = String, Path), ("attachment_id" = String, Path)),
    responses((status = 200, description = "Attachment bytes", body = String))
)]
async fn download_thread_attachment(
    State(state): State<MailState>,
    Path((inbox_id, thread_id, attachment_id)): Path<(String, String, String)>,
) -> Response {
    let messages = store(&state)
        .messages_for_thread(&inbox_id, &thread_id)
        .await
        .unwrap_or_default();
    if !messages.iter().any(|message| {
        message
            .attachments
            .iter()
            .any(|attachment| attachment.id == attachment_id)
    }) {
        return err(StatusCode::NOT_FOUND, "attachment not found");
    }
    download_attachment(State(state), Path(attachment_id)).await
}

fn thread_view(messages: &[EmailMessage], include_messages: bool) -> serde_json::Value {
    let first = messages.first();
    let last = messages.last().or(first);
    let mut labels = Vec::new();
    let mut senders = Vec::new();
    let mut recipients = Vec::new();
    let mut attachments = Vec::new();
    let mut size = 0u64;
    for message in messages {
        for label in &message.labels {
            if !labels.contains(label) {
                labels.push(label.clone());
            }
        }
        if !message.from_addr.is_empty() && !senders.contains(&message.from_addr) {
            senders.push(message.from_addr.clone());
        }
        for recipient in message
            .to_addrs
            .iter()
            .chain(message.cc_addrs.iter())
            .chain(message.bcc_addrs.iter())
        {
            if !recipients.contains(recipient) {
                recipients.push(recipient.clone());
            }
        }
        attachments.extend(message.attachments.iter().cloned());
        size = size
            .saturating_add(message.raw_size)
            .saturating_add(message.text.as_ref().map_or(0, |value| value.len() as u64))
            .saturating_add(message.html.as_ref().map_or(0, |value| value.len() as u64));
    }
    let mut view = json!({
        "inboxId": first.map(|message| &message.inbox_id),
        "threadId": first.and_then(|message| message.thread_id.clone()),
        "labels": labels,
        "senders": senders,
        "recipients": recipients,
        "lastMessageId": last.map(|message| &message.message_id),
        "messageCount": messages.len(),
        "size": size,
        "subject": last.map(|message| &message.subject),
        "preview": last.and_then(|message| message.preview.clone()),
        "attachments": attachments,
        "createdAt": first.map(|message| &message.created_at),
        "updatedAt": last.map(|message| &message.updated_at),
    });
    if include_messages {
        view["messages"] = json!(messages);
    }
    view
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/threads",
    params(("id" = String, Path), ("limit" = Option<u32>, Query), ("labels" = Option<String>, Query)),
    responses((status = 200, description = "Threads", body = serde_json::Value))
)]
async fn list_threads(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let labels = label_query(query.labels.as_deref());
    let messages = match store(&state)
        .list_messages_with_filters(
            &inbox_id,
            1000,
            query.before.as_deref(),
            query.after.as_deref(),
            query.direction.as_deref(),
            &labels,
            None,
        )
        .await
    {
        Ok(messages) => messages,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let mut grouped = std::collections::BTreeMap::<String, Vec<EmailMessage>>::new();
    for message in messages {
        let thread_id = message
            .thread_id
            .clone()
            .unwrap_or_else(|| message.message_id.clone());
        grouped.entry(thread_id).or_default().push(message);
    }
    let threads = grouped
        .values()
        .map(|messages| thread_view(messages, false))
        .take(query.limit.unwrap_or(50).clamp(1, 200) as usize)
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(json!({ "threads": threads }))).into_response()
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/threads/search",
    params(("id" = String, Path), ("q" = String, Query), ("limit" = Option<u32>, Query)),
    responses((status = 200, description = "Matching threads", body = serde_json::Value))
)]
async fn search_threads(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let Some(q) = query.q.as_deref().filter(|value| !value.trim().is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "q is required");
    };
    let messages = match store(&state)
        .list_messages_with_filters(&inbox_id, 1000, None, None, None, &[], Some(q))
        .await
    {
        Ok(messages) => messages,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let mut grouped = std::collections::BTreeMap::<String, Vec<EmailMessage>>::new();
    for message in messages {
        let thread_id = message
            .thread_id
            .clone()
            .unwrap_or_else(|| message.message_id.clone());
        grouped.entry(thread_id).or_default().push(message);
    }
    let threads = grouped
        .values()
        .map(|messages| thread_view(messages, false))
        .take(query.limit.unwrap_or(100).clamp(1, 100) as usize)
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(json!({ "threads": threads }))).into_response()
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/threads/{thread_id}",
    params(("id" = String, Path), ("thread_id" = String, Path)),
    responses((status = 200, description = "Thread", body = serde_json::Value))
)]
async fn get_thread(
    State(state): State<MailState>,
    Path((inbox_id, thread_id)): Path<(String, String)>,
) -> Response {
    match store(&state)
        .messages_for_thread(&inbox_id, &thread_id)
        .await
    {
        Ok(messages) if !messages.is_empty() => {
            (StatusCode::OK, Json(thread_view(&messages, true))).into_response()
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "thread not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    patch,
    path = "/api/mail/inboxes/{id}/threads/{thread_id}",
    params(("id" = String, Path), ("thread_id" = String, Path)),
    request_body = LabelUpdateBody,
    responses((status = 200, description = "Updated thread", body = serde_json::Value))
)]
async fn update_thread(
    State(state): State<MailState>,
    Path((inbox_id, thread_id)): Path<(String, String)>,
    Json(body): Json<LabelUpdateBody>,
) -> Response {
    let messages = match store(&state)
        .messages_for_thread(&inbox_id, &thread_id)
        .await
    {
        Ok(messages) => messages,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    if messages.is_empty() {
        return err(StatusCode::NOT_FOUND, "thread not found");
    }
    for message in &messages {
        if let Err(error) = store(&state)
            .update_message_labels(&message.id, &body.add_labels, &body.remove_labels)
            .await
        {
            return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    }
    match store(&state)
        .messages_for_thread(&inbox_id, &thread_id)
        .await
    {
        Ok(messages) => (StatusCode::OK, Json(thread_view(&messages, true))).into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    delete,
    path = "/api/mail/inboxes/{id}/threads/{thread_id}",
    params(("id" = String, Path), ("thread_id" = String, Path)),
    responses((status = 200, description = "Deleted thread", body = serde_json::Value))
)]
async fn delete_thread(
    State(state): State<MailState>,
    Path((inbox_id, thread_id)): Path<(String, String)>,
) -> Response {
    let messages = match store(&state)
        .messages_for_thread(&inbox_id, &thread_id)
        .await
    {
        Ok(messages) => messages,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    if messages.is_empty() {
        return err(StatusCode::NOT_FOUND, "thread not found");
    }
    for message in messages {
        if let Err(error) = store(&state).delete_message(&message.id).await {
            return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    }
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

fn draft_from_body(inbox_id: String, body: DraftBody) -> Draft {
    let now = Utc::now().to_rfc3339();
    let scheduled = body.send_at.is_some();
    Draft {
        id: uuid::Uuid::new_v4().to_string(),
        inbox_id,
        thread_id: body.thread_id,
        client_id: body.client_id,
        to_addrs: body.to,
        cc_addrs: body.cc,
        bcc_addrs: body.bcc,
        reply_to_addrs: body.reply_to,
        subject: body.subject,
        text: body.text,
        html: body.html,
        headers: body.headers,
        labels: body.labels,
        attachments: body.attachments,
        send_at: body.send_at,
        status: if scheduled {
            "scheduled".to_owned()
        } else {
            "draft".to_owned()
        },
        created_at: now.clone(),
        updated_at: now,
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/drafts",
    params(("id" = String, Path), ("limit" = Option<u32>, Query), ("labels" = Option<String>, Query)),
    responses((status = 200, description = "Drafts", body = serde_json::Value))
)]
async fn list_drafts(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let labels = label_query(query.labels.as_deref());
    match store(&state)
        .list_drafts(&inbox_id, &labels, query.limit.unwrap_or(50).clamp(1, 200))
        .await
    {
        Ok(drafts) => (
            StatusCode::OK,
            Json(json!({ "count": drafts.len(), "drafts": drafts })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/drafts",
    params(("id" = String, Path)),
    request_body = DraftBody,
    responses((status = 201, description = "Created draft", body = serde_json::Value))
)]
async fn create_draft(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Json(body): Json<DraftBody>,
) -> Response {
    if store(&state)
        .get_inbox(&inbox_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return err(StatusCode::NOT_FOUND, "inbox not found");
    }
    if let Some(client_id) = body.client_id.as_deref() {
        if let Ok(Some(existing)) = store(&state).draft_by_client_id(client_id).await {
            return (StatusCode::OK, Json(json!({ "draft": existing }))).into_response();
        }
    }
    let draft = draft_from_body(inbox_id, body);
    match store(&state).create_draft(draft).await {
        Ok(draft) => (StatusCode::CREATED, Json(json!({ "draft": draft }))).into_response(),
        Err(error) if error.to_string().contains("UNIQUE") => {
            err(StatusCode::CONFLICT, "draft client_id already exists")
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/drafts/{draft_id}",
    params(("id" = String, Path), ("draft_id" = String, Path)),
    responses((status = 200, description = "Draft", body = serde_json::Value))
)]
async fn get_draft(
    State(state): State<MailState>,
    Path((inbox_id, draft_id)): Path<(String, String)>,
) -> Response {
    match store(&state).get_draft(&draft_id).await {
        Ok(Some(draft)) if draft.inbox_id == inbox_id => {
            (StatusCode::OK, Json(json!({ "draft": draft }))).into_response()
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "draft not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    patch,
    path = "/api/mail/inboxes/{id}/drafts/{draft_id}",
    params(("id" = String, Path), ("draft_id" = String, Path)),
    request_body = DraftBody,
    responses((status = 200, description = "Updated draft", body = serde_json::Value))
)]
async fn update_draft(
    State(state): State<MailState>,
    Path((inbox_id, draft_id)): Path<(String, String)>,
    Json(body): Json<DraftBody>,
) -> Response {
    let Some(mut draft) = store(&state).get_draft(&draft_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "draft not found");
    };
    if draft.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "draft not found");
    }
    if draft.status == "sent" {
        return err(StatusCode::CONFLICT, "draft has already been sent");
    }
    draft.to_addrs = body.to;
    draft.cc_addrs = body.cc;
    draft.bcc_addrs = body.bcc;
    draft.reply_to_addrs = body.reply_to;
    draft.subject = body.subject;
    draft.text = body.text;
    draft.html = body.html;
    draft.headers = body.headers;
    draft.labels = body.labels;
    draft.attachments = body.attachments;
    draft.send_at = body.send_at;
    draft.status = if draft.send_at.is_some() {
        "scheduled".to_owned()
    } else {
        "draft".to_owned()
    };
    if let Some(thread_id) = body.thread_id {
        draft.thread_id = Some(thread_id);
    }
    if let Err(error) = store(&state).update_draft(&draft).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    match store(&state).get_draft(&draft_id).await {
        Ok(Some(draft)) => (StatusCode::OK, Json(json!({ "draft": draft }))).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "draft not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    delete,
    path = "/api/mail/inboxes/{id}/drafts/{draft_id}",
    params(("id" = String, Path), ("draft_id" = String, Path)),
    responses((status = 200, description = "Deleted draft", body = serde_json::Value))
)]
async fn delete_draft(
    State(state): State<MailState>,
    Path((inbox_id, draft_id)): Path<(String, String)>,
) -> Response {
    let Some(draft) = store(&state).get_draft(&draft_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "draft not found");
    };
    if draft.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "draft not found");
    }
    match store(&state).delete_draft(&draft_id).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "draft not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/drafts/{draft_id}/send",
    params(("id" = String, Path), ("draft_id" = String, Path)),
    responses((status = 200, description = "Sent draft", body = serde_json::Value))
)]
async fn send_draft(
    State(state): State<MailState>,
    Path((inbox_id, draft_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(draft) = store(&state).get_draft(&draft_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "draft not found");
    };
    if draft.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "draft not found");
    }
    if draft.status == "sent" {
        return err(StatusCode::CONFLICT, "draft has already been sent");
    }
    let mut sent = draft.clone();
    let response = send_message(
        State(state.clone()),
        Path(inbox_id),
        headers,
        Json(SendBody {
            attachments: attachment_inputs(draft.attachments),
            to: draft.to_addrs,
            cc: draft.cc_addrs,
            bcc: draft.bcc_addrs,
            headers: draft.headers,
            labels: draft.labels,
            subject: draft.subject,
            text: draft.text,
            html: draft.html,
            reply_to: draft.reply_to_addrs,
            references: None,
            track_opens: false,
            in_reply_to: None,
        }),
    )
    .await;
    if response.status().is_success() {
        sent.status = "sent".to_owned();
        let _ = store(&state).update_draft(&sent).await;
    }
    response
}

fn public_webhook(webhook: &crate::Webhook) -> serde_json::Value {
    json!({
        "webhook_id": webhook.id,
        "url": webhook.url,
        "secret": webhook.secret,
        "enabled": webhook.enabled,
        "event_types": webhook.event_types,
        "inbox_ids": webhook.inbox_ids,
        "pod_ids": webhook.pod_ids,
        "client_id": webhook.client_id,
        "header_names": webhook.headers.keys().collect::<Vec<_>>(),
        "created_at": webhook.created_at,
        "updated_at": webhook.updated_at,
    })
}

fn public_webhook_without_secret(webhook: &crate::Webhook) -> serde_json::Value {
    let mut value = public_webhook(webhook);
    value["secret"] = serde_json::Value::Null;
    value
}

fn validate_header_map(headers: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
    if headers.iter().any(|(name, value)| {
        name.trim().is_empty()
            || name.len() > 128
            || name.contains(['\r', '\n', ':', ' '])
            || value.len() > 2048
            || value.contains(['\r', '\n'])
            || matches!(
                name.to_ascii_lowercase().as_str(),
                "content-length"
                    | "cookie"
                    | "host"
                    | "svix-id"
                    | "svix-signature"
                    | "svix-timestamp"
            )
    }) {
        return Err("invalid webhook header".to_owned());
    }
    if headers.len() > 32 {
        return Err("too many webhook headers".to_owned());
    }
    Ok(())
}

fn default_event_types(event_types: Option<Vec<String>>) -> Vec<String> {
    event_types.unwrap_or_else(|| {
        STANDARD_EVENT_TYPES
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    })
}

fn validate_event_types(event_types: &[String]) -> Result<(), String> {
    if event_types.is_empty() {
        return Err("event_types must contain at least one event".to_owned());
    }
    if event_types
        .iter()
        .any(|value| !STANDARD_EVENT_TYPES.contains(&value.as_str()))
    {
        return Err("unknown webhook event type".to_owned());
    }
    Ok(())
}

fn webhook_from_body(body: WebhookBody, inbox_ids: Vec<String>) -> Result<crate::Webhook, String> {
    let inbox_ids = if inbox_ids.is_empty() {
        body.inbox_ids.clone()
    } else {
        inbox_ids
    };
    let event_types = default_event_types(body.event_types);
    validate_event_types(&event_types)?;
    validate_header_map(&body.headers)?;
    if body.url.trim().is_empty() {
        return Err("url is required".to_owned());
    }
    let now = Utc::now().to_rfc3339();
    Ok(crate::Webhook {
        id: uuid::Uuid::new_v4().to_string(),
        url: body.url.trim().to_owned(),
        secret: format!("whsec_{}", uuid::Uuid::new_v4().simple()),
        event_types,
        headers: body.headers,
        inbox_ids,
        pod_ids: body.pod_ids,
        client_id: body.client_id,
        enabled: body.enabled.unwrap_or(true),
        created_at: now.clone(),
        updated_at: now,
    })
}

#[utoipa::path(
    get,
    path = "/api/mail/webhooks",
    responses((status = 200, description = "Webhooks", body = serde_json::Value))
)]
async fn list_webhooks(State(state): State<MailState>) -> Response {
    match store(&state).list_webhooks().await {
        Ok(webhooks) => (
            StatusCode::OK,
            Json(json!({
                "count": webhooks.len(),
                "webhooks": webhooks.iter().map(public_webhook_without_secret).collect::<Vec<_>>()
            })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/api/mail/webhooks",
    request_body = WebhookBody,
    responses((status = 201, description = "Created webhook", body = serde_json::Value))
)]
async fn create_webhook(State(state): State<MailState>, Json(body): Json<WebhookBody>) -> Response {
    let webhook = match webhook_from_body(body, Vec::new()) {
        Ok(webhook) => webhook,
        Err(error) => return err(StatusCode::BAD_REQUEST, &error),
    };
    if !webhooks::is_safe_destination(&webhook.url).await {
        return err(
            StatusCode::BAD_REQUEST,
            "webhook URL must be a public HTTPS endpoint",
        );
    }
    if let Some(client_id) = webhook.client_id.as_deref() {
        if let Ok(Some(existing)) = store(&state).webhook_by_client_id(client_id).await {
            return (
                StatusCode::OK,
                Json(public_webhook_without_secret(&existing)),
            )
                .into_response();
        }
    }
    match store(&state).create_webhook(webhook).await {
        Ok(webhook) => (StatusCode::CREATED, Json(public_webhook(&webhook))).into_response(),
        Err(error) if error.to_string().contains("UNIQUE") => {
            err(StatusCode::CONFLICT, "webhook client_id already exists")
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/webhooks/{id}",
    params(("id" = String, Path)),
    responses((status = 200, description = "Webhook", body = serde_json::Value))
)]
async fn get_webhook(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_webhook(&id).await {
        Ok(Some(webhook)) => (
            StatusCode::OK,
            Json(public_webhook_without_secret(&webhook)),
        )
            .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "webhook not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct WebhookPatchBody {
    #[serde(default, rename = "addInboxIds", alias = "add_inbox_ids")]
    add_inbox_ids: Option<Vec<String>>,
    #[serde(default, rename = "addPodIds", alias = "add_pod_ids")]
    add_pod_ids: Option<Vec<String>>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default, rename = "eventTypes")]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "inboxIds")]
    inbox_ids: Option<Vec<String>>,
    #[serde(default, rename = "removeInboxIds", alias = "remove_inbox_ids")]
    remove_inbox_ids: Option<Vec<String>>,
    #[serde(default, rename = "removePodIds", alias = "remove_pod_ids")]
    remove_pod_ids: Option<Vec<String>>,
    #[serde(default, rename = "podIds")]
    pod_ids: Option<Vec<String>>,
}

async fn patch_webhook_record(
    state: &MailState,
    id: &str,
    body: WebhookPatchBody,
    required_inbox: Option<&str>,
) -> Result<crate::Webhook, (StatusCode, String)> {
    let Some(mut webhook) = store(state).get_webhook(id).await.map_err(internal_error)? else {
        return Err((StatusCode::NOT_FOUND, "webhook not found".to_owned()));
    };
    if let Some(inbox_id) = required_inbox {
        if !webhook.inbox_ids.iter().any(|value| value == inbox_id) {
            return Err((StatusCode::NOT_FOUND, "webhook not found".to_owned()));
        }
    }
    if let Some(url) = body.url {
        if !webhooks::is_safe_destination(&url).await {
            return Err((
                StatusCode::BAD_REQUEST,
                "webhook URL must be a public HTTPS endpoint".to_owned(),
            ));
        }
        webhook.url = url;
    }
    if let Some(event_types) = body.event_types {
        if event_types.is_empty() {
            // AgentMail treats an empty update as "leave subscriptions unchanged".
        } else {
            validate_event_types(&event_types).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
            webhook.event_types = event_types;
        }
    }
    if let Some(enabled) = body.enabled {
        webhook.enabled = enabled;
    }
    if let Some(inbox_ids) = body.inbox_ids {
        webhook.inbox_ids = inbox_ids;
    }
    if let Some(pod_ids) = body.pod_ids {
        webhook.pod_ids = pod_ids;
    }
    if let Some(add_inbox_ids) = body.add_inbox_ids {
        for inbox_id in add_inbox_ids {
            if !webhook.inbox_ids.iter().any(|value| value == &inbox_id) {
                webhook.inbox_ids.push(inbox_id);
            }
        }
    }
    if let Some(remove_inbox_ids) = body.remove_inbox_ids {
        webhook
            .inbox_ids
            .retain(|value| !remove_inbox_ids.iter().any(|id| id == value));
    }
    if let Some(add_pod_ids) = body.add_pod_ids {
        for pod_id in add_pod_ids {
            if !webhook.pod_ids.iter().any(|value| value == &pod_id) {
                webhook.pod_ids.push(pod_id);
            }
        }
    }
    if let Some(remove_pod_ids) = body.remove_pod_ids {
        webhook
            .pod_ids
            .retain(|value| !remove_pod_ids.iter().any(|id| id == value));
    }
    if required_inbox.is_some() {
        webhook.inbox_ids = vec![required_inbox.unwrap().to_owned()];
    }
    if let Err(error) = store(state).update_webhook(&webhook).await {
        return Err(internal_error(error));
    }
    Ok(webhook)
}

fn internal_error(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[utoipa::path(
    patch,
    path = "/api/mail/webhooks/{id}",
    params(("id" = String, Path)),
    request_body = WebhookPatchBody,
    responses((status = 200, description = "Updated webhook", body = serde_json::Value))
)]
async fn update_webhook(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Json(body): Json<WebhookPatchBody>,
) -> Response {
    match patch_webhook_record(&state, &id, body, None).await {
        Ok(webhook) => (
            StatusCode::OK,
            Json(public_webhook_without_secret(&webhook)),
        )
            .into_response(),
        Err((status, message)) => err(status, &message),
    }
}

#[utoipa::path(
    delete,
    path = "/api/mail/webhooks/{id}",
    params(("id" = String, Path)),
    responses((status = 200, description = "Deleted webhook", body = serde_json::Value))
)]
async fn delete_webhook(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).delete_webhook(&id).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "webhook not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/webhooks/{id}/headers",
    params(("id" = String, Path)),
    responses((status = 200, description = "Header names", body = serde_json::Value))
)]
async fn get_webhook_headers(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_webhook(&id).await {
        Ok(Some(webhook)) => (
            StatusCode::OK,
            Json(json!({ "header_names": webhook.headers.keys().collect::<Vec<_>>() })),
        )
            .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "webhook not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    patch,
    path = "/api/mail/webhooks/{id}/headers",
    params(("id" = String, Path)),
    request_body = HeaderUpdateBody,
    responses((status = 200, description = "Updated header names", body = serde_json::Value))
)]
async fn update_webhook_headers(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Json(body): Json<HeaderUpdateBody>,
) -> Response {
    let Some(mut webhook) = store(&state).get_webhook(&id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "webhook not found");
    };
    if let Err(error) = validate_header_map(&body.headers) {
        return err(StatusCode::BAD_REQUEST, &error);
    }
    for (name, value) in body.headers {
        webhook.headers.insert(name, value);
    }
    for name in body.remove_headers {
        webhook.headers.remove(&name);
    }
    if webhook.headers.is_empty() {
        // Empty is a valid final configuration; unlike AgentMail's update
        // request, the sidecar accepts a removal-only operation.
    }
    if let Err(error) = store(&state).update_webhook(&webhook).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    (
        StatusCode::OK,
        Json(json!({ "header_names": webhook.headers.keys().collect::<Vec<_>>() })),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/mail/webhooks/{id}/deliveries",
    params(("id" = String, Path), ("limit" = Option<u32>, Query)),
    responses((status = 200, description = "Webhook deliveries", body = serde_json::Value))
)]
async fn list_webhook_deliveries(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Response {
    match store(&state)
        .list_webhook_deliveries(&id, query.limit.unwrap_or(100).clamp(1, 1000))
        .await
    {
        Ok(deliveries) => (
            StatusCode::OK,
            Json(json!({ "count": deliveries.len(), "deliveries": deliveries })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/webhooks",
    params(("id" = String, Path)),
    responses((status = 200, description = "Inbox webhooks", body = serde_json::Value))
)]
async fn list_inbox_webhooks(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
) -> Response {
    match store(&state).list_webhooks().await {
        Ok(webhooks) => {
            let webhooks = webhooks
                .into_iter()
                .filter(|webhook| {
                    webhook.inbox_ids.is_empty()
                        || webhook.inbox_ids.iter().any(|value| value == &inbox_id)
                })
                .collect::<Vec<_>>();
            (
                StatusCode::OK,
                Json(json!({
                    "count": webhooks.len(),
                    "webhooks": webhooks.iter().map(public_webhook_without_secret).collect::<Vec<_>>()
                })),
            )
                .into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/webhooks",
    params(("id" = String, Path)),
    request_body = WebhookBody,
    responses((status = 201, description = "Created inbox webhook", body = serde_json::Value))
)]
async fn create_inbox_webhook(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Json(body): Json<WebhookBody>,
) -> Response {
    if store(&state)
        .get_inbox(&inbox_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return err(StatusCode::NOT_FOUND, "inbox not found");
    }
    let webhook = match webhook_from_body(body, vec![inbox_id]) {
        Ok(webhook) => webhook,
        Err(error) => return err(StatusCode::BAD_REQUEST, &error),
    };
    if !webhooks::is_safe_destination(&webhook.url).await {
        return err(
            StatusCode::BAD_REQUEST,
            "webhook URL must be a public HTTPS endpoint",
        );
    }
    match store(&state).create_webhook(webhook).await {
        Ok(webhook) => (StatusCode::CREATED, Json(public_webhook(&webhook))).into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/webhooks/{webhook_id}",
    params(("id" = String, Path), ("webhook_id" = String, Path)),
    responses((status = 200, description = "Inbox webhook", body = serde_json::Value))
)]
async fn get_inbox_webhook(
    State(state): State<MailState>,
    Path((_inbox_id, webhook_id)): Path<(String, String)>,
) -> Response {
    get_webhook(State(state), Path(webhook_id)).await
}

#[utoipa::path(
    patch,
    path = "/api/mail/inboxes/{id}/webhooks/{webhook_id}",
    params(("id" = String, Path), ("webhook_id" = String, Path)),
    request_body = WebhookPatchBody,
    responses((status = 200, description = "Updated inbox webhook", body = serde_json::Value))
)]
async fn update_inbox_webhook(
    State(state): State<MailState>,
    Path((inbox_id, webhook_id)): Path<(String, String)>,
    Json(body): Json<WebhookPatchBody>,
) -> Response {
    match patch_webhook_record(&state, &webhook_id, body, Some(&inbox_id)).await {
        Ok(webhook) => (
            StatusCode::OK,
            Json(public_webhook_without_secret(&webhook)),
        )
            .into_response(),
        Err((status, message)) => err(status, &message),
    }
}

#[utoipa::path(
    delete,
    path = "/api/mail/inboxes/{id}/webhooks/{webhook_id}",
    params(("id" = String, Path), ("webhook_id" = String, Path)),
    responses((status = 200, description = "Deleted inbox webhook", body = serde_json::Value))
)]
async fn delete_inbox_webhook(
    State(state): State<MailState>,
    Path((_inbox_id, webhook_id)): Path<(String, String)>,
) -> Response {
    delete_webhook(State(state), Path(webhook_id)).await
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/webhooks/{webhook_id}/headers",
    params(("id" = String, Path), ("webhook_id" = String, Path)),
    responses((status = 200, description = "Inbox webhook header names", body = serde_json::Value))
)]
async fn get_inbox_webhook_headers(
    State(state): State<MailState>,
    Path((_inbox_id, webhook_id)): Path<(String, String)>,
) -> Response {
    get_webhook_headers(State(state), Path(webhook_id)).await
}

#[utoipa::path(
    patch,
    path = "/api/mail/inboxes/{id}/webhooks/{webhook_id}/headers",
    params(("id" = String, Path), ("webhook_id" = String, Path)),
    request_body = HeaderUpdateBody,
    responses((status = 200, description = "Updated inbox webhook header names", body = serde_json::Value))
)]
async fn update_inbox_webhook_headers(
    State(state): State<MailState>,
    Path((_inbox_id, webhook_id)): Path<(String, String)>,
    Json(body): Json<HeaderUpdateBody>,
) -> Response {
    update_webhook_headers(State(state), Path(webhook_id), Json(body)).await
}

fn valid_scope(scope: &str) -> bool {
    matches!(scope, "global" | "pod" | "inbox")
}

fn valid_list_direction(direction: &str) -> bool {
    matches!(direction, "send" | "receive" | "reply")
}

fn valid_list_type(list_type: &str) -> bool {
    matches!(list_type, "allow" | "block")
}

#[utoipa::path(
    get,
    path = "/api/mail/lists/{scope}/{scope_id}/{direction}/{list_type}",
    params(
        ("scope" = String, Path),
        ("scope_id" = String, Path),
        ("direction" = String, Path),
        ("list_type" = String, Path)
    ),
    responses((status = 200, description = "List entries", body = serde_json::Value))
)]
async fn list_entries(
    State(state): State<MailState>,
    Path((scope, scope_id, direction, list_type)): Path<(String, String, String, String)>,
) -> Response {
    if !(valid_scope(&scope) && valid_list_direction(&direction) && valid_list_type(&list_type)) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid list scope, direction, or type",
        );
    }
    match store(&state)
        .list_entries(&scope, &scope_id, &direction, &list_type)
        .await
    {
        Ok(entries) => (
            StatusCode::OK,
            Json(json!({ "count": entries.len(), "entries": entries })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct ListEntryCreateBody {
    entry: String,
    #[serde(default)]
    reason: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/mail/lists/{scope}/{scope_id}/{direction}/{list_type}",
    params(
        ("scope" = String, Path),
        ("scope_id" = String, Path),
        ("direction" = String, Path),
        ("list_type" = String, Path)
    ),
    request_body = ListEntryCreateBody,
    responses((status = 201, description = "Created list entry", body = serde_json::Value))
)]
async fn create_list_entry(
    State(state): State<MailState>,
    Path((scope, scope_id, direction, list_type)): Path<(String, String, String, String)>,
    Json(body): Json<ListEntryCreateBody>,
) -> Response {
    if !(valid_scope(&scope) && valid_list_direction(&direction) && valid_list_type(&list_type)) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid list scope, direction, or type",
        );
    }
    let entry = body.entry.trim().to_ascii_lowercase();
    if entry.is_empty() || entry.contains(['\r', '\n', '/']) {
        return err(StatusCode::BAD_REQUEST, "entry is invalid");
    }
    let entry_type = if entry.contains('@') {
        "email"
    } else {
        "domain"
    };
    let now = Utc::now().to_rfc3339();
    let record = crate::ListEntry {
        id: uuid::Uuid::new_v4().to_string(),
        scope,
        scope_id,
        direction,
        list_type,
        entry,
        entry_type: entry_type.to_owned(),
        reason: body.reason,
        created_at: now,
    };
    match store(&state).create_list_entry(record).await {
        Ok(entry) => (StatusCode::CREATED, Json(json!({ "entry": entry }))).into_response(),
        Err(error) if error.to_string().contains("UNIQUE") => {
            err(StatusCode::CONFLICT, "list entry already exists")
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/lists/{scope}/{scope_id}/{direction}/{list_type}/{entry}",
    params(
        ("scope" = String, Path),
        ("scope_id" = String, Path),
        ("direction" = String, Path),
        ("list_type" = String, Path),
        ("entry" = String, Path)
    ),
    responses((status = 200, description = "List entry", body = serde_json::Value))
)]
async fn get_list_entry(
    State(state): State<MailState>,
    Path((scope, scope_id, direction, list_type, entry)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    match store(&state)
        .get_list_entry(&scope, &scope_id, &direction, &list_type, &entry)
        .await
    {
        Ok(Some(entry)) => (StatusCode::OK, Json(entry)).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "list entry not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    delete,
    path = "/api/mail/lists/{scope}/{scope_id}/{direction}/{list_type}/{entry}",
    params(
        ("scope" = String, Path),
        ("scope_id" = String, Path),
        ("direction" = String, Path),
        ("list_type" = String, Path),
        ("entry" = String, Path)
    ),
    responses((status = 200, description = "Deleted list entry", body = serde_json::Value))
)]
async fn delete_list_entry(
    State(state): State<MailState>,
    Path((scope, scope_id, direction, list_type, entry)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    match store(&state)
        .delete_list_entry(&scope, &scope_id, &direction, &list_type, &entry)
        .await
    {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "list entry not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/pods",
    responses((status = 200, description = "Pods", body = serde_json::Value))
)]
async fn list_pods(State(state): State<MailState>) -> Response {
    match store(&state).list_pods().await {
        Ok(pods) => (
            StatusCode::OK,
            Json(json!({ "count": pods.len(), "pods": pods })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/api/mail/pods",
    request_body = PodBody,
    responses((status = 201, description = "Created pod", body = serde_json::Value))
)]
async fn create_pod(State(state): State<MailState>, Json(body): Json<PodBody>) -> Response {
    if body.name.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "name is required");
    }
    if let Some(client_id) = body.client_id.as_deref() {
        if let Ok(Some(existing)) = store(&state).pod_by_client_id(client_id).await {
            return (StatusCode::OK, Json(existing)).into_response();
        }
    }
    let now = Utc::now().to_rfc3339();
    let pod = crate::MailPod {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.trim().to_owned(),
        client_id: body.client_id,
        created_at: now.clone(),
        updated_at: now,
    };
    match store(&state).create_pod(pod).await {
        Ok(pod) => (StatusCode::CREATED, Json(pod)).into_response(),
        Err(error) if error.to_string().contains("UNIQUE") => {
            err(StatusCode::CONFLICT, "pod client_id already exists")
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/pods/{id}",
    params(("id" = String, Path)),
    responses((status = 200, description = "Pod", body = serde_json::Value))
)]
async fn get_pod(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_pod(&id).await {
        Ok(Some(pod)) => (StatusCode::OK, Json(pod)).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "pod not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    delete,
    path = "/api/mail/pods/{id}",
    params(("id" = String, Path)),
    responses((status = 200, description = "Deleted pod", body = serde_json::Value))
)]
async fn delete_pod(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).delete_pod(&id).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "pod not found"),
        Err(error) if error.to_string().contains("existing inboxes") => {
            err(StatusCode::CONFLICT, &error.to_string())
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

fn domain_records(domain: &str) -> Vec<std::collections::BTreeMap<String, String>> {
    let mut record = std::collections::BTreeMap::new();
    record.insert("type".to_owned(), "TXT".to_owned());
    record.insert("name".to_owned(), format!("_ryu-verification.{domain}"));
    record.insert(
        "value".to_owned(),
        format!("ryu-mail-verification={}", uuid::Uuid::new_v4().simple()),
    );
    vec![record]
}

#[utoipa::path(
    get,
    path = "/api/mail/domains",
    responses((status = 200, description = "Domains", body = serde_json::Value))
)]
async fn list_domains(State(state): State<MailState>) -> Response {
    match store(&state).list_domains().await {
        Ok(domains) => (
            StatusCode::OK,
            Json(json!({ "count": domains.len(), "domains": domains })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/api/mail/domains",
    request_body = DomainBody,
    responses((status = 201, description = "Created domain", body = serde_json::Value))
)]
async fn create_domain(State(state): State<MailState>, Json(body): Json<DomainBody>) -> Response {
    let domain = body.domain.trim().to_ascii_lowercase();
    if domain.is_empty() || !domain.contains('.') {
        return err(StatusCode::BAD_REQUEST, "domain is invalid");
    }
    let now = Utc::now().to_rfc3339();
    let domain = crate::MailDomain {
        id: uuid::Uuid::new_v4().to_string(),
        domain: domain.clone(),
        status: "pending".to_owned(),
        subdomains_enabled: body.subdomains_enabled,
        tracking_enabled: body.tracking_enabled,
        records: domain_records(&domain),
        pod_id: body.pod_id,
        client_id: body.client_id,
        created_at: now.clone(),
        updated_at: now,
    };
    match store(&state).create_domain(domain).await {
        Ok(domain) => (StatusCode::CREATED, Json(domain)).into_response(),
        Err(error) if error.to_string().contains("UNIQUE") => {
            err(StatusCode::CONFLICT, "domain already exists")
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/domains/{id}",
    params(("id" = String, Path)),
    responses((status = 200, description = "Domain", body = serde_json::Value))
)]
async fn get_domain(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).get_domain(&id).await {
        Ok(Some(domain)) => (StatusCode::OK, Json(domain)).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "domain not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    patch,
    path = "/api/mail/domains/{id}",
    params(("id" = String, Path)),
    request_body = DomainPatchBody,
    responses((status = 200, description = "Updated domain", body = serde_json::Value))
)]
async fn update_domain(
    State(state): State<MailState>,
    Path(id): Path<String>,
    Json(body): Json<DomainPatchBody>,
) -> Response {
    let Some(mut domain) = store(&state).get_domain(&id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "domain not found");
    };
    if let Some(status) = body.status {
        if !matches!(status.as_str(), "pending" | "verified" | "failed") {
            return err(StatusCode::BAD_REQUEST, "invalid domain status");
        }
        domain.status = status;
    }
    if let Some(value) = body.subdomains_enabled {
        domain.subdomains_enabled = value;
    }
    if let Some(value) = body.tracking_enabled {
        domain.tracking_enabled = value;
    }
    if let Err(error) = store(&state).update_domain(&domain).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    (StatusCode::OK, Json(domain)).into_response()
}

#[utoipa::path(
    delete,
    path = "/api/mail/domains/{id}",
    params(("id" = String, Path)),
    responses((status = 200, description = "Deleted domain", body = serde_json::Value))
)]
async fn delete_domain(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    match store(&state).delete_domain(&id).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "domain not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/events",
    responses((status = 200, description = "Events", body = serde_json::Value))
)]
async fn list_all_events(
    State(state): State<MailState>,
    Query(query): Query<MessageQuery>,
) -> Response {
    match store(&state)
        .list_events(None, query.limit.unwrap_or(100).clamp(1, 1000))
        .await
    {
        Ok(events) => (
            StatusCode::OK,
            Json(json!({ "count": events.len(), "events": events })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/events",
    params(("id" = String, Path)),
    responses((status = 200, description = "Inbox events", body = serde_json::Value))
)]
async fn list_inbox_events(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Response {
    match store(&state)
        .list_events(Some(&inbox_id), query.limit.unwrap_or(100).clamp(1, 1000))
        .await
    {
        Ok(events) => (
            StatusCode::OK,
            Json(json!({ "count": events.len(), "events": events })),
        )
            .into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/metrics/events",
    params(("id" = String, Path)),
    responses((status = 200, description = "Event metrics", body = serde_json::Value))
)]
async fn query_event_metrics(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
) -> Response {
    let events = match store(&state).list_events(Some(&inbox_id), 10_000).await {
        Ok(events) => events,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let mut counts = std::collections::BTreeMap::<String, u64>::new();
    for event in events {
        *counts.entry(event.event_type).or_default() += 1;
    }
    (StatusCode::OK, Json(json!({ "counts": counts }))).into_response()
}

#[utoipa::path(
    get,
    path = "/api/mail/inboxes/{id}/metrics/usage",
    params(("id" = String, Path)),
    responses((status = 200, description = "Usage metrics", body = serde_json::Value))
)]
async fn query_usage_metrics(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
) -> Response {
    let messages = match store(&state).list_messages(&inbox_id, 10_000).await {
        Ok(messages) => messages,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let threads = messages
        .iter()
        .filter_map(|message| message.thread_id.as_deref())
        .collect::<std::collections::HashSet<_>>();
    let storage_bytes = messages.iter().fold(0u64, |total, message| {
        total
            .saturating_add(message.raw_size)
            .saturating_add(message.text.as_ref().map_or(0, |value| value.len() as u64))
            .saturating_add(message.html.as_ref().map_or(0, |value| value.len() as u64))
            .saturating_add(
                message
                    .attachments
                    .iter()
                    .map(|attachment| attachment.size)
                    .sum::<u64>(),
            )
    });
    (
        StatusCode::OK,
        Json(json!({
            "storage_bytes": storage_bytes,
            "message_count": messages.len(),
            "thread_count": threads.len(),
        })),
    )
        .into_response()
}

/// The outbound message. Everything in here leaves the machine.
#[derive(Deserialize, serde::Serialize, utoipa::ToSchema)]
struct SendBody {
    /// Base64 encoded outbound attachments. The attachment body stays in the
    /// request and is never interpreted as a URL by the sidecar.
    #[serde(default)]
    attachments: Vec<EmailSendAttachment>,
    /// Email addresses of the people who will RECEIVE this message. At least one is
    /// required. These are real external recipients — the mail is delivered to them.
    to: Vec<String>,
    /// Email addresses to copy, also real external recipients. Optional.
    #[serde(default)]
    cc: Vec<String>,
    /// Blind-copy recipients. These are real external recipients and are not
    /// shown in the normal rendered recipient line.
    #[serde(default)]
    bcc: Vec<String>,
    /// Optional custom RFC headers. Header names and values are validated before
    /// they reach the SMTP transport.
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    /// Labels to apply to the stored sent message.
    #[serde(default)]
    labels: Vec<String>,
    /// Subject line of the email.
    subject: String,
    /// Plain-text body of the email. Provide this, `html`, or both.
    #[serde(default)]
    text: Option<String>,
    /// HTML body of the email. Provide this, `text`, or both.
    #[serde(default)]
    html: Option<String>,
    /// Reply-to address or addresses for the outgoing message.
    #[serde(default, rename = "replyTo")]
    reply_to: Vec<String>,
    /// Full References header used to join this message to a thread.
    #[serde(default)]
    references: Option<String>,
    /// Add a single open-tracking pixel when an HTML body is supplied.
    #[serde(default, rename = "trackOpens")]
    track_opens: bool,
    /// `Message-ID` of the message being replied to, so mail clients thread this one
    /// under it. Take it from the `messageId` of a message you read; omit for a new
    /// thread.
    #[serde(default, rename = "inReplyTo")]
    in_reply_to: Option<String>,
}

fn reply_subject(subject: &str) -> String {
    if subject.trim_start().to_ascii_lowercase().starts_with("re:") {
        subject.to_owned()
    } else {
        format!("Re: {subject}")
    }
}

fn forwarding_subject(subject: &str) -> String {
    if subject
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("fwd:")
    {
        subject.to_owned()
    } else {
        format!("Fwd: {subject}")
    }
}

fn send_body_from_reply(body: ReplyBody, original: &EmailMessage, to: Vec<String>) -> SendBody {
    SendBody {
        attachments: attachment_inputs(body.attachments),
        to,
        cc: body.cc,
        bcc: body.bcc,
        headers: body.headers,
        labels: body.labels,
        subject: body
            .subject
            .unwrap_or_else(|| reply_subject(&original.subject)),
        text: body.text,
        html: body.html,
        reply_to: body.reply_to,
        references: Some(
            original
                .references
                .iter()
                .chain(std::iter::once(&original.message_id))
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
        ),
        track_opens: false,
        in_reply_to: Some(original.message_id.clone()),
    }
}

#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/messages/{message_id}/reply",
    params(("id" = String, Path), ("message_id" = String, Path)),
    request_body = ReplyBody,
    responses((status = 200, description = "Reply sent", body = serde_json::Value))
)]
async fn reply_message(
    State(state): State<MailState>,
    Path((inbox_id, message_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ReplyBody>,
) -> Response {
    let Some(original) = store(&state).get_message(&message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "message not found");
    };
    if original.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "message not found");
    }
    let to = if body.to.is_empty() {
        (!original.from_addr.is_empty())
            .then_some(vec![original.from_addr.clone()])
            .unwrap_or_default()
    } else {
        body.to.clone()
    };
    if to.is_empty() {
        return err(StatusCode::BAD_REQUEST, "reply has no recipient");
    }
    send_message(
        State(state),
        Path(inbox_id),
        headers,
        Json(send_body_from_reply(body, &original, to)),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/messages/{message_id}/reply-all",
    params(("id" = String, Path), ("message_id" = String, Path)),
    request_body = ReplyBody,
    responses((status = 200, description = "Reply sent", body = serde_json::Value))
)]
async fn reply_all_message(
    State(state): State<MailState>,
    Path((inbox_id, message_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ReplyBody>,
) -> Response {
    let Some(original) = store(&state).get_message(&message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "message not found");
    };
    if original.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "message not found");
    }
    let inbox_address = store(&state)
        .get_inbox(&inbox_id)
        .await
        .ok()
        .flatten()
        .map(|inbox| inbox.address.to_ascii_lowercase());
    let mut to = body.to.clone();
    if to.is_empty() {
        let existing = to.clone();
        let recipients = std::iter::once(original.from_addr.clone())
            .chain(original.to_addrs.clone())
            .chain(original.cc_addrs.clone())
            .filter(|address| {
                !address.is_empty()
                    && inbox_address
                        .as_deref()
                        .is_none_or(|inbox| address.to_ascii_lowercase() != inbox)
                    && !existing
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(address))
            })
            .collect::<Vec<_>>();
        to.extend(recipients);
    }
    if to.is_empty() {
        return err(StatusCode::BAD_REQUEST, "reply has no recipient");
    }
    send_message(
        State(state),
        Path(inbox_id),
        headers,
        Json(send_body_from_reply(body, &original, to)),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/messages/{message_id}/forward",
    params(("id" = String, Path), ("message_id" = String, Path)),
    request_body = ForwardBody,
    responses((status = 200, description = "Forward sent", body = serde_json::Value))
)]
async fn forward_message(
    State(state): State<MailState>,
    Path((inbox_id, message_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ForwardBody>,
) -> Response {
    let Some(original) = store(&state).get_message(&message_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "message not found");
    };
    if original.inbox_id != inbox_id {
        return err(StatusCode::NOT_FOUND, "message not found");
    }
    if body.to.is_empty() {
        return err(StatusCode::BAD_REQUEST, "forward requires a recipient");
    }
    let text = body.text.or_else(|| original.text.clone());
    let html = body.html.or_else(|| original.html.clone());
    send_message(
        State(state),
        Path(inbox_id),
        headers,
        Json(SendBody {
            attachments: attachment_inputs(body.attachments),
            to: body.to,
            cc: body.cc,
            bcc: body.bcc,
            headers: body.headers,
            labels: body.labels,
            subject: body
                .subject
                .unwrap_or_else(|| forwarding_subject(&original.subject)),
            text,
            html,
            reply_to: body.reply_to,
            references: None,
            track_opens: false,
            in_reply_to: None,
        }),
    )
    .await
}

#[derive(Debug, Default, Deserialize)]
struct MessageQuery {
    limit: Option<u32>,
    before: Option<String>,
    after: Option<String>,
    direction: Option<String>,
    q: Option<String>,
    labels: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct LabelUpdateBody {
    #[serde(default, rename = "addLabels")]
    add_labels: Vec<String>,
    #[serde(default, rename = "removeLabels")]
    remove_labels: Vec<String>,
    #[serde(default)]
    read: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct DraftBody {
    #[serde(default)]
    attachments: Vec<crate::AttachmentInput>,
    #[serde(default, rename = "bcc")]
    bcc: Vec<String>,
    #[serde(default, rename = "cc")]
    cc: Vec<String>,
    #[serde(default, rename = "clientId")]
    client_id: Option<String>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default, rename = "replyTo")]
    reply_to: Vec<String>,
    #[serde(default, rename = "sendAt")]
    send_at: Option<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default, alias = "threadId")]
    thread_id: Option<String>,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct WebhookBody {
    #[serde(default, alias = "clientId")]
    client_id: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default, rename = "eventTypes")]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "inboxIds")]
    inbox_ids: Vec<String>,
    #[serde(default, rename = "podIds")]
    pod_ids: Vec<String>,
    url: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct HeaderUpdateBody {
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "removeHeaders")]
    remove_headers: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct PodBody {
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct DomainBody {
    #[serde(default, alias = "clientId")]
    client_id: Option<String>,
    domain: String,
    #[serde(default, rename = "podId")]
    pod_id: Option<String>,
    #[serde(default, rename = "subdomainsEnabled")]
    subdomains_enabled: bool,
    #[serde(default, rename = "trackingEnabled")]
    tracking_enabled: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct DomainPatchBody {
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "subdomainsEnabled")]
    subdomains_enabled: Option<bool>,
    #[serde(default, rename = "trackingEnabled")]
    tracking_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct ReplyBody {
    #[serde(default)]
    attachments: Vec<crate::AttachmentInput>,
    #[serde(default)]
    bcc: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default, rename = "replyTo")]
    reply_to: Vec<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct ForwardBody {
    #[serde(default)]
    attachments: Vec<crate::AttachmentInput>,
    #[serde(default)]
    bcc: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default, rename = "replyTo")]
    reply_to: Vec<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    text: Option<String>,
    to: Vec<String>,
    #[serde(default)]
    labels: Vec<String>,
}

/// `POST /api/mail/inboxes/:id/send` — hand an outbound message to the transport.
//
// The summary states the irreversible act in its first clause, on purpose. Two
// readers depend on that string and neither reads the handler: the approval gate
// classifies the derived tool's risk from it, and the model decides from it whether
// this is a safe thing to try. A summary like "create a message on an inbox" would
// mislead both, and mail cannot be un-sent.
#[utoipa::path(
    post,
    path = "/api/mail/inboxes/{id}/send",
    tag = "Mail",
    summary = "SENDS an email from this inbox to the external recipients you name. This delivers real mail to real people over the internet and CANNOT be undone or recalled. Requires explicit user intent for this specific message.",
    params(("id" = String, Path, description = "Id of the inbox to send FROM, which becomes the sender address")),
    request_body = SendBody,
    responses((status = 200, description = "Handed to the transport", body = serde_json::Value))
)]
async fn send_message(
    State(state): State<MailState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SendBody>,
) -> Response {
    let recipient_count = body.to.len() + body.cc.len() + body.bcc.len();
    if body.to.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "at least one recipient is required",
        );
    }
    if recipient_count > 50 {
        return err(StatusCode::BAD_REQUEST, "at most 50 recipients are allowed");
    }
    if body.headers.iter().any(|(name, value)| {
        name.trim().is_empty() || name.contains(['\r', '\n']) || value.contains(['\r', '\n'])
    }) {
        return err(StatusCode::BAD_REQUEST, "invalid message header");
    }
    if body
        .labels
        .iter()
        .any(|label| label.trim().is_empty() || label.len() > 128)
    {
        return err(StatusCode::BAD_REQUEST, "invalid message label");
    }
    let Some(inbox) = store(&state).get_inbox(&id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "inbox not found");
    };
    let recipients = body
        .to
        .iter()
        .chain(body.cc.iter())
        .chain(body.bcc.iter())
        .cloned()
        .collect::<Vec<_>>();
    match address_allowed(&state, &inbox, &recipients, "send").await {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::FORBIDDEN, "recipient blocked by mail policy"),
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if headers.get("idempotency-key").is_some_and(|value| {
        value
            .to_str()
            .ok()
            .is_none_or(|value| value.trim().is_empty())
    }) {
        return err(StatusCode::BAD_REQUEST, "idempotency-key cannot be empty");
    }
    let request_hash = sha256_json(&body);
    if let Some(key) = idempotency_key {
        match store(&state)
            .get_idempotency(key, "messages.send", &request_hash)
            .await
        {
            Ok(Some(response)) => return (StatusCode::OK, Json(response)).into_response(),
            Err(error) if error.to_string().contains("idempotency key") => {
                return err(StatusCode::CONFLICT, &error.to_string());
            }
            Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
            Ok(None) => {}
        }
    }
    let record_id = uuid::Uuid::new_v4().to_string();
    let html = if body.track_opens {
        tracking_html(body.html, &record_id)
    } else {
        body.html
    };
    let req = SendRequest {
        record_id,
        attachments: body.attachments,
        bcc: body.bcc,
        to: body.to,
        cc: body.cc,
        headers: body.headers,
        labels: body.labels,
        reply_to: body.reply_to,
        references: body.references,
        subject: body.subject,
        text: body.text,
        html,
        in_reply_to: body.in_reply_to,
        track_opens: body.track_opens,
    };
    match send::send_from_inbox(store(&state), &state.email, &id, req).await {
        Ok(m) => {
            // Hand-off to the transport succeeded — which is all this event claims.
            // Delivery is the relay's business: `providerMessageId` is its id, and a
            // later bounce never comes back through this process, so a consumer must
            // not read this as "the recipient got it".
            record_event(
                &state,
                event(
                    "message.sent",
                    Some(m.inbox_id.clone()),
                    Some(m.id.clone()),
                    json!({
                        "send": {
                            "inbox_id": &m.inbox_id,
                            "thread_id": &m.thread_id,
                            "message_id": &m.message_id,
                            "timestamp": &m.created_at,
                            "recipients": &m.to_addrs,
                        }
                    }),
                ),
            )
            .await;
            let response = json!({ "message": &m });
            if let Some(key) = idempotency_key {
                if let Err(error) = store(&state)
                    .put_idempotency(key, "messages.send", &request_hash, &response)
                    .await
                {
                    tracing::warn!("mail send idempotency record failed: {error}");
                }
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

fn tracking_html(html: Option<String>, message_id: &str) -> Option<String> {
    let html = html?;
    let base = std::env::var("RYU_MAIL_PUBLIC_URL")
        .ok()
        .map(|value| value.trim_end_matches('/').to_owned())
        .filter(|value| value.starts_with("https://"))?;
    Some(format!(
        "{html}<img src=\"{base}/api/mail/track/{message_id}\" width=\"1\" height=\"1\" alt=\"\" />"
    ))
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
    let expected = ryu_crypto::hmac_sha256_hex(inbox.inbound_secret.as_bytes(), &body);
    if !ryu_sidecar_runtime::constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return err(StatusCode::UNAUTHORIZED, "invalid signature");
    }

    let Some(parsed) = mime::parse_raw(&body) else {
        return err(StatusCode::BAD_REQUEST, "unparseable message");
    };
    if !parsed.from_addr.is_empty() {
        let list_direction = if parsed.in_reply_to.is_some() {
            "reply"
        } else {
            "receive"
        };
        match address_allowed(&state, &inbox, &[parsed.from_addr.clone()], list_direction).await {
            Ok(true) => {}
            Ok(false) => return err(StatusCode::FORBIDDEN, "sender blocked by mail policy"),
            Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error),
        }
    }
    if let Ok(Some(existing)) = store(&state)
        .find_inbound_by_message_id(&id, &parsed.message_id)
        .await
    {
        return (
            StatusCode::OK,
            Json(json!({ "id": existing.id, "duplicate": true })),
        )
            .into_response();
    }
    let msg = EmailMessage {
        id: uuid::Uuid::new_v4().to_string(),
        inbox_id: id,
        direction: "inbound".to_string(),
        message_id: parsed.message_id,
        in_reply_to: parsed.in_reply_to.clone(),
        thread_id: parsed
            .references
            .first()
            .cloned()
            .or_else(|| parsed.in_reply_to.clone()),
        references: parsed.references,
        from_addr: parsed.from_addr,
        to_addrs: parsed.to_addrs,
        cc_addrs: parsed.cc_addrs,
        bcc_addrs: parsed.bcc_addrs,
        reply_to_addrs: parsed.reply_to_addrs,
        subject: parsed.subject,
        text: parsed.text,
        html: parsed.html,
        extracted_text: None,
        extracted_html: None,
        preview: None,
        headers: parsed.headers,
        labels: Vec::new(),
        status: "received".to_owned(),
        read: false,
        opened_at: None,
        raw_size: body.len() as u64,
        provider_message_id: None,
        attachments: Vec::new(),
        created_at: Utc::now().to_rfc3339(),
        updated_at: String::new(),
    };
    match store(&state)
        .insert_message_with_raw(msg, parsed.attachments, Some(&body))
        .await
    {
        Ok(m) => {
            // Only after the row is durable: a consumer told mail arrived has to be
            // able to fetch it. Metadata only — the body is attacker-supplied and up
            // to `MAX_INBOUND_BYTES`, and the fan-out payload is forwarded verbatim
            // to every subscriber, so bodies are read back through the authed
            // `GET /api/mail/messages/:id` instead of being pushed at everyone.
            record_event(
                &state,
                event(
                    "message.received",
                    Some(m.inbox_id.clone()),
                    Some(m.id.clone()),
                    json!({
                        "message": {
                            "inbox_id": &m.inbox_id,
                            "thread_id": &m.thread_id,
                            "message_id": &m.message_id,
                            "labels": &m.labels,
                            "timestamp": &m.created_at,
                            "from": &m.from_addr,
                            "to": &m.to_addrs,
                            "cc": &m.cc_addrs,
                            "bcc": &m.bcc_addrs,
                            "subject": &m.subject,
                            "preview": &m.preview,
                            "text": &m.text,
                            "html": &m.html,
                            "attachments": &m.attachments,
                        }
                    }),
                ),
            )
            .await;
            (StatusCode::OK, Json(json!({ "id": m.id }))).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Serve an attachment as a forced download (always octet-stream, never inline).
#[utoipa::path(
    get,
    path = "/api/mail/attachments/{id}",
    tag = "Mail",
    summary = "Download one message attachment's raw bytes. Read-only; the response is binary, not JSON.",
    params(("id" = String, Path, description = "Attachment id, from the `attachments` list on a message")),
    responses((status = 200, description = "The attachment bytes", body = String))
)]
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

fn err(code: StatusCode, message: &str) -> Response {
    (code, Json(json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod openapi_tests {

    #[test]
    fn multi_method_paths_keep_every_operation() {
        // utoipa keys `paths` by path STRING, so handlers annotated separately on the
        // same path must MERGE into one PathItem. If one overwrote another, the path key
        // would still exist and the write body would still resolve — the read tool would
        // silently never exist, which is exactly the failure this document prevents. The
        // route-coverage test above cannot see that, because it only checks the key.
        let wire = serde_json::to_value(super::openapi()).expect("the doc must serialize");
        for (path, methods) in [
            ("/api/mail/inboxes", &["get", "post"][..]),
            ("/api/mail/inboxes/{id}", &["get", "patch", "delete"][..]),
        ] {
            let item = wire
                .pointer(&format!("/paths/{}", path.replace('/', "~1")))
                .unwrap_or_else(|| panic!("{path} has no PathItem"));
            for method in methods {
                assert!(
                    item.get(method).is_some(),
                    "{path} lost its {method} operation"
                );
            }
        }
    }

    /// This app's own manifest, read at compile time. The route contract lives there,
    /// so the invariants below compare the document against the real declaration
    /// rather than against a second list that could drift from it.
    fn manifest() -> serde_json::Value {
        serde_json::from_str(include_str!("../../manifest.json")).expect("valid JSON")
    }

    /// The manifest sidecar whose HTTP surface this router serves: the one declaring an
    /// `http.mount`. Selected BY mount rather than by index so a later mountless
    /// sidecar cannot silently redirect these assertions at the wrong process.
    fn mounted_sidecar() -> serde_json::Value {
        manifest()["sidecars"]
            .as_array()
            .expect("sidecars must be an array")
            .iter()
            .find(|s| s["http"]["mount"].is_string())
            .expect("one sidecar must declare an http.mount")
            .clone()
    }

    /// A manifest route (relative to the mount, `:param` form) rewritten into the form
    /// the OpenAPI document uses (absolute, `{param}` form).
    fn doc_path_for(mount: &str, route: &str) -> String {
        let joined = if route == "/" {
            mount.to_owned()
        } else {
            format!("{mount}{route}")
        };
        joined
            .split('/')
            .map(|seg| match seg.strip_prefix(':') {
                Some(name) => format!("{{{name}}}"),
                None => seg.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    #[test]
    fn openapi_doc_covers_the_served_routes() {
        assert!(!super::openapi().paths.paths.is_empty());
    }

    #[test]
    fn every_declared_route_appears_in_the_openapi_doc() {
        // The direction that decides tool yield: Core keeps only the document
        // operations the manifest ALSO declares, so a declared route with no
        // `#[utoipa::path]` is a tool that silently never exists.
        let sidecar = mounted_sidecar();
        let mount = sidecar["http"]["mount"].as_str().expect("an http.mount");
        let doc = super::openapi();
        for route in sidecar["http"]["routes"]
            .as_array()
            .expect("routes must be an array")
        {
            let path = route["path"].as_str().expect("a route path");
            // `/inbound/:id`, `/track/:id`, and `/ws` are EXEMPT ON PURPOSE, not overlooked.
            // They are public provider/browser callbacks rather than agent tools.
            // HMAC webhook a mail relay posts to (`auth: public`, served from
            // `public_routes()` outside the bearer gate). Its body is a signed provider
            // payload an agent holds no secret for, so a derived tool could never
            // succeed — and would only offer the model a way to forge received mail.
            if path == "/inbound/:id" || path == "/track/:id" || path == "/ws" {
                continue;
            }
            let expected = doc_path_for(mount, path);
            assert!(
                doc.paths.paths.contains_key(&expected),
                "'{path}' is declared in manifest.json but the OpenAPI document has no \
                 '{expected}' operation — Core derives no tool for it"
            );
        }
    }

    #[test]
    fn the_inbound_webhook_is_not_a_derivable_tool() {
        // Guards the exemption above from being "fixed" by annotating `inbound`.
        let doc = super::openapi();
        assert!(
            !doc.paths.paths.contains_key("/api/mail/inbound/{id}"),
            "the public HMAC webhook must not appear in the tool-deriving document"
        );
    }

    #[test]
    fn write_operations_carry_a_typed_request_body() {
        // An untyped body still yields an operation, so the tool is DISCOVERABLE with
        // zero visible arguments — for `send`, a tool the model can invoke but cannot
        // populate. Assert the `$ref` resolves the way Core's `resolve_ref` will.
        let wire = serde_json::to_value(super::openapi()).expect("the doc must serialize");
        for (path, method) in [
            ("/api/mail/inboxes", "post"),
            ("/api/mail/inboxes/{id}", "patch"),
            ("/api/mail/inboxes/{id}/send", "post"),
        ] {
            let schema = wire
                .pointer(&format!(
                    "/paths/{}/{method}/requestBody/content/application~1json/schema/$ref",
                    path.replace('/', "~1")
                ))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("{method} {path} must declare a typed request body"));
            let name = schema
                .rsplit('/')
                .next()
                .expect("a $ref always has a last segment");
            assert!(
                wire.pointer(&format!("/components/schemas/{name}"))
                    .is_some(),
                "{method} {path} references {schema}, which is missing from components.schemas"
            );
        }
    }

    #[test]
    fn the_send_summary_says_it_sends() {
        // The approval gate classifies risk from this string and the model decides from
        // it whether the call is safe to try. Neither reads the handler. If a future
        // edit softens the wording into "create a message", both readers are misled
        // about an act that cannot be undone — so assert the words, not just presence.
        let wire = serde_json::to_value(super::openapi()).expect("the doc must serialize");
        let summary = wire
            .pointer("/paths/~1api~1mail~1inboxes~1{id}~1send/post/summary")
            .and_then(serde_json::Value::as_str)
            .expect("the send operation must carry a summary");
        let lowered = summary.to_lowercase();
        assert!(
            lowered.contains("send"),
            "the send summary must state that it sends: {summary:?}"
        );
        assert!(
            lowered.contains("cannot be undone") || lowered.contains("recall"),
            "the send summary must state the act is irreversible: {summary:?}"
        );
    }

    #[test]
    fn recipients_are_described_as_real_external_addresses() {
        // `to` is the field that decides who receives mail. A bare "array of strings"
        // is exactly the description under which a model fills in a plausible guess.
        let wire = serde_json::to_value(super::openapi()).expect("the doc must serialize");
        let description = wire
            .pointer("/components/schemas/SendBody/properties/to/description")
            .and_then(serde_json::Value::as_str)
            .expect("SendBody.to must carry a description");
        assert!(
            description.to_lowercase().contains("receive"),
            "SendBody.to must say these addresses receive the mail: {description:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bearer_ok;
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn service_home_redirects_to_the_portal_dashboard() {
        let response = super::product_dashboard_redirect().await.into_response();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://app.ryuhq.com/dashboard"
        );
    }

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
        use axum::extract::{Path, Query, State};
        use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
        use axum::response::{IntoResponse, Response};
        use axum::Json;
        use serde_json::Value;

        fn state() -> MailState {
            MailState {
                email: crate::host::EmailHost::disabled(),
                mail: fresh_store(),
                // No Core to emit to under tests (`RYU_CORE_PORT`/`RYU_EXT_TOKEN` unset),
                // so every emit short-circuits to a no-op and the handler assertions
                // below stay hermetic — no HTTP is attempted.
                events: ryu_app_events::EventEmitter::from_env(crate::PLUGIN_ID),
            }
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
                client_id: None,
                metadata: std::collections::BTreeMap::new(),
                pod_id: None,
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
        async fn liveness_probe_does_not_require_mail_credentials() {
            let resp = super::super::health().await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(json(resp).await["status"], "ok");
        }

        #[tokio::test]
        async fn create_inbox_rejects_empty_address() {
            let resp =
                super::super::create_inbox(State(state()), Json(create_body("x", "   "))).await;
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
            assert!(created["inbox"]["inbound_secret"].is_string());

            let list = super::super::list_inboxes(State(st.clone())).await;
            let body = json(list).await;
            assert_eq!(body["inboxes"].as_array().unwrap().len(), 1);
            assert!(body["inboxes"][0]["inbound_secret"].is_null());

            let id = created["inbox"]["id"].as_str().unwrap().to_string();
            let get = super::super::get_inbox(State(st), Path(id)).await;
            let body = json(get).await;
            assert!(body["inbox"]["inbound_secret"].is_null());
        }

        #[tokio::test]
        async fn get_inbox_handler_not_found_is_404() {
            let resp = super::super::get_inbox(State(state()), Path("missing".to_string())).await;
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
                    metadata: None,
                    pod_id: None,
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
                HeaderMap::new(),
                Json(super::super::SendBody {
                    attachments: Vec::new(),
                    to: Vec::new(),
                    cc: Vec::new(),
                    bcc: Vec::new(),
                    headers: std::collections::BTreeMap::new(),
                    labels: Vec::new(),
                    subject: "s".to_string(),
                    text: None,
                    html: None,
                    reply_to: Vec::new(),
                    references: None,
                    track_opens: false,
                    in_reply_to: None,
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn send_message_without_transport_is_bad_request() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("S", "s@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = super::super::send_message(
                State(st),
                Path(inbox.id),
                HeaderMap::new(),
                Json(super::super::SendBody {
                    attachments: Vec::new(),
                    to: vec!["dest@x.com".to_string()],
                    cc: Vec::new(),
                    bcc: Vec::new(),
                    headers: std::collections::BTreeMap::new(),
                    labels: Vec::new(),
                    subject: "s".to_string(),
                    text: Some("t".to_string()),
                    html: None,
                    reply_to: Vec::new(),
                    references: None,
                    track_opens: false,
                    in_reply_to: None,
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn get_message_handler_not_found_is_404() {
            let resp = super::super::get_message(State(state()), Path("nope".to_string())).await;
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
                thread_id: Some("<a@x.com>".to_owned()),
                references: Vec::new(),
                from_addr: "a@x.com".to_string(),
                to_addrs: vec!["b@x.com".to_string()],
                cc_addrs: Vec::new(),
                bcc_addrs: Vec::new(),
                reply_to_addrs: Vec::new(),
                subject: "hello".to_string(),
                text: Some("body".to_string()),
                html: None,
                extracted_text: None,
                extracted_html: None,
                preview: Some("body".to_owned()),
                headers: std::collections::BTreeMap::new(),
                labels: Vec::new(),
                status: "received".to_owned(),
                read: false,
                opened_at: None,
                raw_size: 0,
                provider_message_id: None,
                attachments: Vec::new(),
                created_at: "2020-01-01T00:00:00Z".to_string(),
                updated_at: "2020-01-01T00:00:00Z".to_string(),
            };
            st.mail.insert_message(msg, Vec::new()).await.unwrap();
            let resp = super::super::list_messages(
                State(st),
                Path(inbox.id),
                Query(super::super::MessageQuery::default()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            let arr = body["messages"].as_array().unwrap();
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0]["subject"], "hello");
        }

        // ── Inbound webhook: the security-critical HMAC path ────────────────

        fn signed_headers(secret: &str, body: &[u8]) -> HeaderMap {
            let sig = ryu_crypto::hmac_sha256_hex(secret.as_bytes(), body);
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
            assert!(st
                .mail
                .list_messages(&inbox.id, 200)
                .await
                .unwrap()
                .is_empty());
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
            st.mail.ensure_test_inbox("ibx").await;
            let msg = EmailMessage {
                id: uuid::Uuid::new_v4().to_string(),
                inbox_id: "ibx".to_string(),
                direction: "inbound".to_string(),
                message_id: "<m@x.com>".to_string(),
                in_reply_to: None,
                thread_id: Some("<m@x.com>".to_owned()),
                references: Vec::new(),
                from_addr: "a@x.com".to_string(),
                to_addrs: Vec::new(),
                cc_addrs: Vec::new(),
                bcc_addrs: Vec::new(),
                reply_to_addrs: Vec::new(),
                subject: "s".to_string(),
                text: None,
                html: None,
                extracted_text: None,
                extracted_html: None,
                preview: None,
                headers: std::collections::BTreeMap::new(),
                labels: Vec::new(),
                status: "received".to_owned(),
                read: false,
                opened_at: None,
                raw_size: 0,
                provider_message_id: None,
                attachments: Vec::new(),
                created_at: "2020-01-01T00:00:00Z".to_string(),
                updated_at: "2020-01-01T00:00:00Z".to_string(),
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
                        inline: false,
                        content_id: None,
                    }],
                )
                .await
                .unwrap();
            let att_id = stored.attachments[0].id.clone();
            let resp = super::super::download_attachment(State(st), Path(att_id)).await;
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
        let got = ryu_crypto::hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            got,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_empty_key_and_message() {
        let got = ryu_crypto::hmac_sha256_hex(b"", b"");
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
        let got = ryu_crypto::hmac_sha256_hex(
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
        let got = ryu_crypto::hmac_sha256_hex(b"secret", b"The quick brown fox");
        assert_eq!(
            got,
            "7a284e5025f32a846fa3e6957d10278eb5726dd4e0b04c8e0259defcd2cd0eb1"
        );
    }

    #[test]
    fn hmac_output_is_64_lowercase_hex_chars() {
        let got = ryu_crypto::hmac_sha256_hex(b"k", b"m");
        assert_eq!(got.len(), 64);
        assert!(got
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // ── Constant-time comparison ────────────────────────────────────────────

    #[test]
    fn ct_eq_behaves_like_equality_but_length_first() {
        assert!(ryu_sidecar_runtime::constant_time_eq(b"", b""));
        assert!(ryu_sidecar_runtime::constant_time_eq(b"abc", b"abc"));
        assert!(!ryu_sidecar_runtime::constant_time_eq(b"abc", b"abd"));
        assert!(!ryu_sidecar_runtime::constant_time_eq(b"abc", b"ab")); // different lengths
        assert!(!ryu_sidecar_runtime::constant_time_eq(b"ab", b"abc"));
    }
}
