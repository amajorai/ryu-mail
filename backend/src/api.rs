//! Axum routes for self-host inboxes. Tracer copy of `apps/core/src/mail/api.rs`,
//! adapted for the out-of-process sidecar:
//!   - `State<ServerState>` → `State<MailState>` (a local single-field state).
//!   - The inbound HMAC is computed locally ([`hmac_sha256_hex`]) with the `hmac`
//!     and `sha2` crates, so the standalone build needs no keyring/D-Bus stack.
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
use axum::extract::{ws, DefaultBodyLimit, Path, Query, Request, State, WebSocketUpgrade};
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
use super::store::{
    InboundInsert, InboundReplayKey, InboxOptions, MailStore, SendClaim, ThreadSummary,
};
use super::{mime, Draft, EmailMessage, Inbox, InboxProvider};
use crate::host::EmailSendAttachment;
use crate::webhooks;
use crate::AttachmentInput;
use crate::MailState;
use futures_util::StreamExt;

/// Max inbound body we accept (25 MiB).
const MAX_INBOUND_BYTES: usize = 26_214_400;

/// Decoded attachment bytes one send or scheduled draft may carry (8 MiB).
const MAX_ATTACHMENT_BYTES: usize = 8 * 1024 * 1024;

/// Request-body ceiling for the protected JSON API. Base64 inflates attachments
/// by 4/3, so the 8 MiB decoded cap is about 10.7 MiB on the wire; 12 MiB leaves
/// room for the rest of the JSON. Axum's own default (2 MiB) would reject a
/// documented-legal send before the handler ran.
const MAX_JSON_BODY_BYTES: usize = 12 * 1024 * 1024;

/// The whole HTTP surface `main` serves: the HMAC-authed public routes plus the
/// bearer-gated protected routes. Built here, not in `main`, so router-level tests
/// exercise exactly the body limits and auth layering production runs.
pub fn app(state: MailState, token: Option<String>) -> Router {
    // `from_fn` closes over the resolved token so no extra state field is needed;
    // the public routes are merged UN-layered so the inbound HMAC auth stands alone.
    let protected = protected_routes().layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let expected = token.clone();
            async move { require_mail_token(req, next, expected.as_deref()).await }
        },
    ));
    public_routes().merge(protected).with_state(state)
}

/// Shared-secret bearer gate for the protected mail routes.
///
/// `expected` is the Core-issued or standalone API token resolved in `main`. The
/// request must carry `Authorization: Bearer <token>` equal to it. Core re-stamps
/// exactly this header on every proxied hop, while standalone callers present the
/// configured `RYU_MAIL_API_TOKEN` directly. A browser offers the same token as
/// the `ryu-bearer.<token>` WebSocket subprotocol. A `?token=` query credential
/// is never accepted on any route, `/api/mail/ws` included: a URL lands in access
/// logs, history and `Referer`, and this token is not scoped to realtime.
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
    // RFC 6455 lets a client send the offered subprotocols as several header
    // lines, so read every `Sec-WebSocket-Protocol` line (as `selected_subprotocol`
    // does), not only the first.
    let protocol_auth = req
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .find_map(|protocol| {
            protocol
                .strip_prefix("ryu-bearer.")
                .map(|token| format!("Bearer {token}"))
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
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
}

/// Public, HMAC-authed inbound webhook.
pub fn public_routes() -> Router<MailState> {
    Router::new()
        .route("/", get(service_home))
        .route("/health", get(health))
        .route("/api/mail/inbound/:id", post(inbound))
        .route("/api/mail/track/:id", get(track_open))
        // Raw MIME up to the documented 25 MiB; the handler re-checks the length.
        .layer(DefaultBodyLimit::max(MAX_INBOUND_BYTES))
}

async fn service_home() -> Response {
    home_response(std::env::var("RYU_PRODUCT_DASHBOARD_URL").ok().as_deref())
}

/// `GET /`: a temporary redirect to `RYU_PRODUCT_DASHBOARD_URL` when the operator
/// sets one (Ryu's hosted deployment points it at its dashboard), otherwise a
/// neutral JSON description of this service. A self-hosted Mail never sends its
/// visitors to a Ryu-hosted page by default. Public and tokenless, like `/health`.
fn home_response(dashboard_url: Option<&str>) -> Response {
    match dashboard_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(target) => Redirect::temporary(target).into_response(),
        None => Json(json!({
            "name": "ryu-mail",
            "version": env!("CARGO_PKG_VERSION"),
            "health": "/health",
        }))
        .into_response(),
    }
}

/// Public process liveness probe. It deliberately does not expose mail
/// configuration or stored data; the authenticated `/api/mail/status` route
/// remains the service-level status endpoint.
async fn health(State(state): State<MailState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "sealing": store(&state).seal_health() })),
    )
}

/// A realtime filter message. The SDKs (`MailAPI.connectRealtime`) send the
/// camelCase spellings, so both spellings are accepted.
#[derive(Debug, Default, Deserialize)]
struct RealtimeSubscription {
    #[serde(default, alias = "eventTypes")]
    event_types: Vec<String>,
    #[serde(default, alias = "inboxIds")]
    inbox_ids: Vec<String>,
}

/// Fixed realtime subprotocol a browser can offer alongside its bearer protocol.
const REALTIME_PROTOCOL: &str = "ryu-mail.v1";

/// The subprotocol the upgrade response selects. A browser cannot set
/// `Authorization` on a WebSocket, so it authenticates with a
/// `ryu-bearer.<token>` subprotocol, and a WHATWG client aborts the handshake
/// unless the server selects one of the protocols it offered. The fixed
/// [`REALTIME_PROTOCOL`] is preferred so the credential is not echoed. Only a
/// legacy client that offered the bearer protocol alone gets it back (the auth
/// middleware has already accepted it); current SDKs always offer both.
fn selected_subprotocol(headers: &HeaderMap) -> Option<String> {
    let offered = headers
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|protocol| !protocol.is_empty())
        .collect::<Vec<_>>();
    if offered.contains(&REALTIME_PROTOCOL) {
        return Some(REALTIME_PROTOCOL.to_owned());
    }
    offered
        .into_iter()
        .find(|protocol| protocol.starts_with("ryu-bearer."))
        .map(str::to_owned)
}

/// Authenticated WebSocket stream for low-latency mail events. The connection
/// starts subscribed to every event; clients can narrow it by sending a JSON
/// `{ "event_types": [...], "inbox_ids": [...] }` message. Events remain
/// replayable through `/api/mail/events`, so a dropped socket is recoverable.
async fn realtime(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<MailState>,
) -> impl IntoResponse {
    let ws = match selected_subprotocol(&headers) {
        Some(protocol) => ws.protocols([protocol]),
        None => ws,
    };
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

/// Open tracking is opt-in per process: `RYU_MAIL_TRACKING_ENABLED=1`, plus an
/// HTTPS `RYU_MAIL_PUBLIC_URL` for the pixel to point at.
fn tracking_enabled() -> bool {
    std::env::var("RYU_MAIL_TRACKING_ENABLED").is_ok_and(|value| value.trim() == "1")
}

/// The public base URL tracking pixels point at, or `None` when tracking is off.
fn tracking_base() -> Option<String> {
    if !tracking_enabled() {
        return None;
    }
    std::env::var("RYU_MAIL_PUBLIC_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_owned())
        .filter(|value| value.starts_with("https://"))
}

fn tracking_pixel_path(message_id: &str) -> String {
    format!("/api/mail/track/{message_id}")
}

/// Always answers with the pixel; whether an open is recorded is decided by
/// [`record_open`], because this route is public.
async fn track_open(State(state): State<MailState>, Path(id): Path<String>) -> Response {
    record_open(&state, &id, tracking_enabled()).await;
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

/// Record a first open only while tracking is enabled, and only for an outbound
/// message whose stored HTML carries this process's pixel for it. Anyone holding
/// a message id can request the pixel, so an inbound id or an untracked send
/// must not turn into a `message.opened` event.
async fn record_open(state: &MailState, id: &str, enabled: bool) {
    if !enabled {
        return;
    }
    let Some(message) = store(state).get_message(id).await.ok().flatten() else {
        return;
    };
    let pixel = tracking_pixel_path(&message.id);
    if message.direction != "outbound"
        || message.opened_at.is_some()
        || !message
            .html
            .as_deref()
            .is_some_and(|html| html.contains(&pixel))
    {
        return;
    }
    if let Ok(Some(message)) = store(state).mark_message_opened(id).await {
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
        record_event(state, event, None).await;
    }
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
/// small and restart-safe: each due draft is claimed (`sending`) before the
/// transport, so a concurrent manual send cannot deliver it twice, and it is
/// marked `sent` only after the transport accepts it. A refused or failed
/// attempt is marked `failed` (never retried automatically, since a transport
/// error can follow an accepted hand-off) and recorded as a `message.rejected`
/// event, so it neither spins nor vanishes. A crash mid-send leaves it
/// `sending`, never resent.
pub fn spawn_draft_scheduler(state: MailState) {
    tokio::spawn(async move {
        loop {
            let now = Utc::now();
            match state.mail.list_due_drafts(now, 16).await {
                Ok(drafts) => {
                    for draft in drafts {
                        send_scheduled_draft(&state, &draft.id, now).await;
                    }
                }
                Err(error) => tracing::warn!("mail scheduled-draft poll failed: {error}"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

async fn send_scheduled_draft(state: &MailState, draft_id: &str, now: chrono::DateTime<Utc>) {
    // Send the claimed row, not the listed snapshot: edits made after the poll
    // win, and a draft another sender claimed (or the user unscheduled) is skipped.
    let draft = match state.mail.claim_due_draft(draft_id, now).await {
        Ok(Some(draft)) => draft,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!("claiming scheduled mail draft failed: {error}");
            return;
        }
    };
    // Re-check at fire time: the allow/block lists may have changed since the
    // draft was scheduled, and rows written before scheduling was validated may
    // carry anything, including a send time that never parsed.
    if normalize_send_at(draft.send_at.as_deref()).is_err() {
        fail_scheduled_draft(state, draft, "sendAt is not an RFC 3339 timestamp").await;
        return;
    }
    let Some(inbox) = state.mail.get_inbox(&draft.inbox_id).await.ok().flatten() else {
        fail_scheduled_draft(state, draft, "inbox not found").await;
        return;
    };
    if let Err((_, reason)) = validate_outbound(state, &inbox, &Outbound::from_draft(&draft)).await
    {
        fail_scheduled_draft(state, draft, &reason).await;
        return;
    }
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
            if let Err(error) = state.mail.finish_draft_send(&draft.id, "sent", true).await {
                tracing::warn!("scheduled mail draft sent but not marked sent: {error}");
            }
            record_event(
                state,
                sent_event(&message),
                Some(app_event_payload(&message)),
            )
            .await;
        }
        Err(error) => fail_scheduled_draft(state, draft, &error.to_string()).await,
    }
}

/// Park a scheduled draft that could not be sent. It keeps its `sendAt` so the
/// owner can see when it was due, leaves the poller's `scheduled` set, and is
/// recorded as `message.rejected` with the reason. Re-scheduling (PATCH) or
/// sending it explicitly are the only ways it goes out.
async fn fail_scheduled_draft(state: &MailState, draft: crate::Draft, reason: &str) {
    tracing::warn!("scheduled mail draft {} failed: {reason}", draft.id);
    // The scheduler claimed the draft (`sending`), so settle that claim as
    // `failed`; `sendAt` is kept.
    if let Err(error) = state
        .mail
        .finish_draft_send(&draft.id, "failed", false)
        .await
    {
        tracing::warn!("failed scheduled mail draft could not be parked: {error}");
    }
    record_event(
        state,
        event(
            "message.rejected",
            Some(draft.inbox_id.clone()),
            None,
            json!({
                "draft": {
                    "id": &draft.id,
                    "inbox_id": &draft.inbox_id,
                    "thread_id": &draft.thread_id,
                    "send_at": &draft.send_at,
                    "subject": &draft.subject,
                    "to": &draft.to_addrs,
                    "cc": &draft.cc_addrs,
                },
                "reason": reason,
            }),
        ),
        None,
    )
    .await;
}

/// The `message.sent` event for a stored outbound row, shared by direct and
/// scheduled sends so webhook consumers see one payload shape.
fn sent_event(m: &EmailMessage) -> crate::MailEvent {
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
    )
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

/// Persist an event, then fan it out. The AgentMail-style `event.payload` goes to
/// the event log, the authenticated WebSocket, and signed webhooks. The app-event
/// hooks Core forwards to plugins and workflows get `app_payload` instead (see
/// [`app_event_payload`]); `None` raises no app event.
async fn record_event(
    state: &MailState,
    event: crate::MailEvent,
    app_payload: Option<serde_json::Value>,
) {
    if let Err(error) = store(state).insert_event(&event).await {
        tracing::warn!("mail event persistence failed: {error}");
        return;
    }
    store(state).publish_event(event.clone());
    webhooks::dispatch_event(store(state).clone(), event.clone()).await;
    let Some(app_payload) = app_payload else {
        return;
    };
    if matches!(
        event.event_type.as_str(),
        "message.received" | "message.sent"
    ) {
        state
            .events
            .emit_with_notify(
                &format!("@ryu/mail#{}", event.event_type),
                app_payload,
                None,
            )
            .await;
    }
}

/// The `contributes.hook_events` payload for a stored message: metadata only, in
/// the shape `manifest.json` documents as `payload_example`. Core forwards it
/// verbatim to every subscribed plugin hook and workflow, so it never carries the
/// (for inbound mail, attacker-supplied) body. `messageId` is the store id that
/// `GET /api/mail/messages/:id` resolves.
fn app_event_payload(m: &EmailMessage) -> serde_json::Value {
    let mut payload = json!({
        "messageId": &m.id,
        "inboxId": &m.inbox_id,
        "direction": &m.direction,
        "from": &m.from_addr,
        "to": &m.to_addrs,
        "cc": &m.cc_addrs,
        "subject": &m.subject,
        "inReplyTo": &m.in_reply_to,
        "createdAt": &m.created_at,
    });
    if m.direction == "outbound" {
        payload["providerMessageId"] = json!(&m.provider_message_id);
    } else {
        payload["attachmentCount"] = json!(m.attachments.len());
    }
    payload
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
    require_timestamp: bool,
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
        require_timestamp: inbox.require_timestamp,
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
    /// Human-readable label for the inbox, shown in the UI. Required and must be
    /// non-blank.
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
    /// Refuse inbound deliveries that do not carry a signed `X-Ryu-Timestamp`
    /// (replay protection). Defaults to `false`, which also accepts the older
    /// body-only signature.
    #[serde(default, alias = "requireTimestamp")]
    require_timestamp: Option<bool>,
}

/// `POST /api/mail/inboxes` — register an inbox.
#[utoipa::path(
    post,
    path = "/api/mail/inboxes",
    tag = "Mail",
    summary = "Register a new mail inbox on this node. Does not send anything; it only creates the local record mail is filed under.",
    request_body = CreateInboxBody,
    responses(
        (status = 200, description = "Created", body = serde_json::Value),
        (status = 400, description = "Missing or malformed address", body = serde_json::Value),
        (status = 409, description = "An inbox with this address already exists", body = serde_json::Value)
    )
)]
async fn create_inbox(
    State(state): State<MailState>,
    Json(body): Json<CreateInboxBody>,
) -> Response {
    let provider = match body.provider.as_deref() {
        Some("imap") => InboxProvider::Imap,
        _ => InboxProvider::Webhook,
    };
    if body.name.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "name is required");
    }
    if body.address.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "address is required");
    }
    let Some(address) = crate::store::normalize_inbox_address(&body.address) else {
        return err(
            StatusCode::BAD_REQUEST,
            "address must be a single local@domain email address",
        );
    };
    if body.metadata.len() > 256
        || body.metadata.iter().any(|(key, value)| {
            key.len() > 256
                || matches!(value, serde_json::Value::String(value) if value.len() > 256)
                || !value.is_string() && !value.is_number() && !value.is_boolean()
        })
    {
        return err(StatusCode::BAD_REQUEST, "metadata is invalid");
    }
    // The client-id lookup and the insert are one locked step in the store, so
    // an overlapping retry gets the inbox the first create made.
    match store(&state)
        .create_inbox_once(
            body.name.trim(),
            &address,
            provider,
            InboxOptions {
                client_id: body.client_id,
                metadata: body.metadata,
                pod_id: body.pod_id,
                require_timestamp: body.require_timestamp.unwrap_or(false),
            },
        )
        .await
    {
        Ok(crate::store::InboxCreation::Created(inbox)) => {
            (StatusCode::OK, Json(json!({ "inbox": inbox }))).into_response()
        }
        Ok(crate::store::InboxCreation::Existing(existing)) => (
            StatusCode::OK,
            Json(json!({ "inbox": public_inbox(existing) })),
        )
            .into_response(),
        Err(e) if e.downcast_ref::<crate::store::AddressTaken>().is_some() => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "an inbox with this address already exists on this node",
                "code": "address_taken",
                "address": address,
            })),
        )
            .into_response(),
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
    /// `true` refuses inbound deliveries without a signed `X-Ryu-Timestamp`;
    /// `false` accepts the older body-only signature again. Omit to keep it.
    #[serde(default, alias = "requireTimestamp")]
    require_timestamp: Option<bool>,
}

/// `PATCH /api/mail/inboxes/:id` — rename an inbox.
#[utoipa::path(
    patch,
    path = "/api/mail/inboxes/{id}",
    tag = "Mail",
    summary = "Rename a mail inbox or change whether its inbound webhook requires a signed timestamp. The address, its messages, and its inbound secret are untouched.",
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
            body.require_timestamp,
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
        // `inbound_secret` matches the create response; `inboundSecret` is kept
        // for existing callers.
        Ok(secret) => (
            StatusCode::OK,
            Json(json!({ "inbound_secret": &secret, "inboundSecret": &secret })),
        )
            .into_response(),
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

/// The bare, lowercased address and domain an allow/block entry is matched
/// against. A display name (`Friend <a@b.example>`) must never change the
/// verdict, so the address is parsed rather than compared as typed.
fn list_match_key(address: &str) -> Option<(String, String)> {
    let trimmed = address.trim();
    let email = match trimmed.parse::<lettre::message::Mailbox>() {
        Ok(mailbox) => mailbox.email.to_string(),
        // Inbound senders come from a lenient MIME parser rather than lettre, so
        // fall back to the angle-bracket addr-spec (or the whole value).
        Err(_) => match (trimmed.rfind('<'), trimmed.rfind('>')) {
            (Some(start), Some(end)) if start < end => trimmed[start + 1..end].trim().to_owned(),
            _ => trimmed.to_owned(),
        },
    }
    .to_ascii_lowercase();
    let domain = email
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_owned())?;
    (!domain.is_empty()).then_some((email, domain))
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
    let relevant = entries
        .into_iter()
        .filter(|entry| {
            (entry.scope == "global")
                || (entry.scope == "inbox" && entry.scope_id == inbox.id)
                || (entry.scope == "pod"
                    && inbox.pod_id.as_deref() == Some(entry.scope_id.as_str()))
        })
        .collect::<Vec<_>>();
    if relevant.is_empty() {
        return Ok(true);
    }
    let matches = |entry: &crate::ListEntry, email: &str, domain: &str| {
        if entry.entry_type == "domain" {
            domain == entry.entry
        } else {
            email == entry.entry
        }
    };
    let allow = relevant
        .iter()
        .filter(|entry| entry.list_type == "allow")
        .collect::<Vec<_>>();
    for address in addresses {
        // An address no list entry can be evaluated against fails closed.
        let Some((email, domain)) = list_match_key(address) else {
            return Ok(false);
        };
        if relevant
            .iter()
            .any(|entry| entry.list_type == "block" && matches(entry, &email, &domain))
        {
            return Ok(false);
        }
        if !allow.is_empty() && !allow.iter().any(|entry| matches(entry, &email, &domain)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Most recipients (to + cc + bcc) one outbound message may name.
const MAX_RECIPIENTS: usize = 50;

/// The parts of an outbound message every send path validates: a direct send,
/// reply, forward, and draft send, plus a scheduled draft both when it is
/// scheduled and again when the scheduler fires it.
struct Outbound<'a> {
    to: &'a [String],
    cc: &'a [String],
    bcc: &'a [String],
    reply_to: &'a [String],
    headers: &'a std::collections::BTreeMap<String, String>,
    labels: &'a [String],
    attachments: Vec<&'a str>,
}

impl<'a> Outbound<'a> {
    fn from_send(body: &'a SendBody) -> Self {
        Self {
            to: &body.to,
            cc: &body.cc,
            bcc: &body.bcc,
            reply_to: &body.reply_to,
            headers: &body.headers,
            labels: &body.labels,
            attachments: body
                .attachments
                .iter()
                .map(|attachment| attachment.content_base64.as_str())
                .collect(),
        }
    }

    fn from_draft(draft: &'a Draft) -> Self {
        Self {
            to: &draft.to_addrs,
            cc: &draft.cc_addrs,
            bcc: &draft.bcc_addrs,
            reply_to: &draft.reply_to_addrs,
            headers: &draft.headers,
            labels: &draft.labels,
            attachments: draft
                .attachments
                .iter()
                .map(|attachment| attachment.content_base64.as_str())
                .collect(),
        }
    }

    fn recipients(&self) -> Vec<String> {
        self.to
            .iter()
            .chain(self.cc)
            .chain(self.bcc)
            .cloned()
            .collect()
    }
}

type Refusal = (StatusCode, String);

fn refuse(status: StatusCode, message: &str) -> Refusal {
    (status, message.to_owned())
}

/// Refusals that need no store access, so they run before the inbox lookup.
fn check_outbound_shape(message: &Outbound<'_>) -> Result<(), Refusal> {
    if message.to.is_empty() {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "at least one recipient is required",
        ));
    }
    if message.to.len() + message.cc.len() + message.bcc.len() > MAX_RECIPIENTS {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "at most 50 recipients are allowed",
        ));
    }
    if message.headers.len() > crate::email::MAX_CUSTOM_HEADERS
        || message
            .headers
            .iter()
            .any(|(name, value)| !crate::email::custom_header_allowed(name, value))
    {
        return Err(refuse(StatusCode::BAD_REQUEST, "invalid message header"));
    }
    if message
        .labels
        .iter()
        .any(|label| label.trim().is_empty() || label.len() > 128)
    {
        return Err(refuse(StatusCode::BAD_REQUEST, "invalid message label"));
    }
    if message
        .to
        .iter()
        .chain(message.cc)
        .chain(message.bcc)
        .chain(message.reply_to)
        .any(|address| address.trim().parse::<lettre::message::Mailbox>().is_err())
    {
        return Err(refuse(StatusCode::BAD_REQUEST, "invalid email address"));
    }
    let mut decoded_bytes = 0usize;
    for content in &message.attachments {
        use base64::Engine as _;
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(content) else {
            return Err(refuse(StatusCode::BAD_REQUEST, "invalid attachment base64"));
        };
        decoded_bytes = decoded_bytes.saturating_add(bytes.len());
    }
    if decoded_bytes > MAX_ATTACHMENT_BYTES {
        return Err(refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "attachments exceed the 8 MiB limit",
        ));
    }
    Ok(())
}

/// Refusals that depend on the sending inbox: its own address must be valid, and
/// every recipient must pass the inbox, pod, and global `send` lists.
async fn check_outbound_policy(
    state: &MailState,
    inbox: &Inbox,
    message: &Outbound<'_>,
) -> Result<(), Refusal> {
    if inbox
        .address
        .trim()
        .parse::<lettre::message::Mailbox>()
        .is_err()
    {
        return Err(refuse(StatusCode::BAD_REQUEST, "invalid email address"));
    }
    match address_allowed(state, inbox, &message.recipients(), "send").await {
        Ok(true) => Ok(()),
        Ok(false) => Err(refuse(
            StatusCode::FORBIDDEN,
            "recipient blocked by mail policy",
        )),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error)),
    }
}

async fn validate_outbound(
    state: &MailState,
    inbox: &Inbox,
    message: &Outbound<'_>,
) -> Result<(), Refusal> {
    check_outbound_shape(message)?;
    check_outbound_policy(state, inbox, message).await
}

/// Parse a draft's `sendAt` and store it as UTC with a `Z` suffix, the same
/// shape the scheduler compares against. A value without an explicit offset is
/// refused: reading local wall-clock time as UTC sends mail hours early or late.
fn normalize_send_at(value: Option<&str>) -> Result<Option<String>, Refusal> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|at| {
            Some(
                at.with_timezone(&Utc)
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
        })
        .map_err(|_| {
            refuse(
                StatusCode::BAD_REQUEST,
                "sendAt must be an RFC 3339 timestamp with an offset, e.g. 2026-10-10T09:00:00Z",
            )
        })
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
    let (size, bytes) = match store(state).read_raw(message_id).await {
        Ok(Some(raw)) => raw,
        Ok(None) => return err(StatusCode::NOT_FOUND, "raw message not found"),
        Err(error) => {
            tracing::warn!("ryu-mail: raw message {message_id} could not be read: {error:#}");
            return err(StatusCode::NOT_FOUND, "raw message blob missing");
        }
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
    let size = messages.iter().fold(0u64, |size, message| {
        size.saturating_add(message.raw_size)
            .saturating_add(message.text.as_ref().map_or(0, |value| value.len() as u64))
            .saturating_add(message.html.as_ref().map_or(0, |value| value.len() as u64))
    });
    let mut view = thread_view_sized(messages, messages.len() as u64, size);
    if include_messages {
        view["messages"] = json!(messages);
    }
    view
}

/// A thread list entry from a [`ThreadSummary`] (no bodies were opened).
fn thread_summary_view(thread: &ThreadSummary) -> serde_json::Value {
    thread_view_sized(&thread.messages, thread.message_count, thread.size)
}

fn thread_view_sized(
    messages: &[EmailMessage],
    message_count: u64,
    size: u64,
) -> serde_json::Value {
    let first = messages.first();
    let last = messages.last().or(first);
    let mut labels = Vec::new();
    let mut senders = Vec::new();
    let mut recipients = Vec::new();
    let mut attachments = Vec::new();
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
    }
    json!({
        "inboxId": first.map(|message| &message.inbox_id),
        "threadId": first.and_then(|message| message.thread_id.clone()),
        "labels": labels,
        "senders": senders,
        "recipients": recipients,
        "lastMessageId": last.map(|message| &message.message_id),
        "messageCount": message_count,
        "size": size,
        "subject": last.map(|message| &message.subject),
        "preview": last.and_then(|message| message.preview.clone()),
        "attachments": attachments,
        "createdAt": first.map(|message| &message.created_at),
        "updatedAt": last.map(|message| &message.updated_at),
    })
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
    match store(&state)
        .list_thread_summaries(
            &inbox_id,
            query.limit.unwrap_or(50).clamp(1, 200),
            query.before.as_deref(),
            query.after.as_deref(),
            query.direction.as_deref(),
            &labels,
        )
        .await
    {
        Ok(threads) => {
            let threads = threads.iter().map(thread_summary_view).collect::<Vec<_>>();
            (StatusCode::OK, Json(json!({ "threads": threads }))).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
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
    match store(&state)
        .search_thread_summaries(&inbox_id, q, query.limit.unwrap_or(100).clamp(1, 100))
        .await
    {
        Ok(threads) => {
            let threads = threads.iter().map(thread_summary_view).collect::<Vec<_>>();
            (StatusCode::OK, Json(json!({ "threads": threads }))).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
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

/// A scheduled draft is a send the scheduler performs later without another
/// request, so it must pass every check a direct send does at the moment it is
/// scheduled. (The scheduler checks again when it fires: lists can change.)
async fn validate_scheduled_draft(
    state: &MailState,
    inbox: &Inbox,
    draft: &Draft,
) -> Result<(), Refusal> {
    if draft.send_at.is_none() {
        return Ok(());
    }
    validate_outbound(state, inbox, &Outbound::from_draft(draft)).await
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
    tag = "Mail",
    summary = "Save a draft in this inbox. With sendAt set this SCHEDULES A REAL SEND: at that time the draft is delivered to its external recipients without another request, and it cannot be recalled once it fires.",
    params(("id" = String, Path)),
    request_body = DraftBody,
    responses((status = 201, description = "Created draft", body = serde_json::Value))
)]
async fn create_draft(
    State(state): State<MailState>,
    Path(inbox_id): Path<String>,
    Json(mut body): Json<DraftBody>,
) -> Response {
    let Some(inbox) = store(&state).get_inbox(&inbox_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "inbox not found");
    };
    if let Some(client_id) = body.client_id.as_deref() {
        if let Ok(Some(existing)) = store(&state).draft_by_client_id(client_id).await {
            return (StatusCode::OK, Json(json!({ "draft": existing }))).into_response();
        }
    }
    body.send_at = match normalize_send_at(body.send_at.as_deref()) {
        Ok(send_at) => send_at,
        Err((status, message)) => return err(status, &message),
    };
    let draft = draft_from_body(inbox_id, body);
    if let Err((status, message)) = validate_scheduled_draft(&state, &inbox, &draft).await {
        return err(status, &message);
    }
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
    tag = "Mail",
    summary = "Replace a draft's contents. With sendAt set this SCHEDULES A REAL SEND to the draft's external recipients at that time; omitting sendAt unschedules it.",
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
    if !draft_is_editable(&draft.status) {
        return draft_busy(&draft.status);
    }
    let send_at = match normalize_send_at(body.send_at.as_deref()) {
        Ok(send_at) => send_at,
        Err((status, message)) => return err(status, &message),
    };
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
    draft.send_at = send_at;
    draft.status = if draft.send_at.is_some() {
        "scheduled".to_owned()
    } else {
        "draft".to_owned()
    };
    if let Some(thread_id) = body.thread_id {
        draft.thread_id = Some(thread_id);
    }
    let Some(inbox) = store(&state).get_inbox(&inbox_id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "inbox not found");
    };
    if let Err((status, message)) = validate_scheduled_draft(&state, &inbox, &draft).await {
        return err(status, &message);
    }
    match store(&state).update_draft(&draft).await {
        Ok(true) => {}
        // A send claimed (or deleted) the draft after the read above; the store
        // write is guarded, so report the state that won instead of reverting it.
        Ok(false) => return draft_conflict_after_race(&state, &draft_id).await,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
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
    // Claim before the transport so the scheduler, a double-click, or an
    // unkeyed agent retry cannot deliver the same draft twice, and send the
    // claimed row so edits made after the read above are what goes out.
    let parked = draft.status == "failed";
    let draft = match store(&state).claim_draft(&draft_id).await {
        Ok(Some(draft)) => draft,
        Ok(None) => return draft_conflict_after_race(&state, &draft_id).await,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    // A parked (`failed`) draft keeps its past `sendAt`; restoring it as
    // `scheduled` would hand it straight back to the scheduler.
    let restore_status = if parked {
        "failed"
    } else if draft.send_at.is_some() {
        "scheduled"
    } else {
        "draft"
    };
    let body = draft_send_body(draft);
    // The key and request hash `send_message` claims with, so a keyed failure
    // can be told apart from one refused before it claimed the key.
    let send_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(|key| (key.to_owned(), sha256_json(&body)));
    let response = send_message(
        State(state.clone()),
        Path(inbox_id.clone()),
        headers,
        Json(body),
    )
    .await;
    let status = response.status();
    let unresolved = match &send_key {
        Some((key, request_hash)) if status == StatusCode::CONFLICT || status.is_server_error() => {
            !keyed_send_never_claimed(&state, key, &inbox_id, request_hash).await
        }
        _ => false,
    };
    let settled = if status.is_success() {
        store(&state)
            .finish_draft_send(&draft_id, "sent", true)
            .await
    } else if unresolved {
        // A keyed send can fail after the transport accepted the message (an
        // unresolved outcome, or an unsaved replay record). Leave the draft
        // `sending` rather than risk delivering it twice.
        return response;
    } else {
        // Every other failure is decided before or by the transport refusing the
        // message, so the draft becomes sendable again in its previous state.
        store(&state)
            .finish_draft_send(&draft_id, restore_status, false)
            .await
    };
    if let Err(error) = settled {
        tracing::warn!("mail draft send outcome could not be recorded: {error}");
    }
    response
}

/// The outbound message for a saved draft, exactly as `send_draft` posts it.
fn draft_send_body(draft: Draft) -> SendBody {
    SendBody {
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
    }
}

/// Whether a failed keyed draft send never claimed its key, so the transport
/// cannot have run: no claim exists for the key, or the key belongs to a
/// different request. Any other answer (a pending, legacy, or replayable claim,
/// or a claim that cannot be read) may hide a delivered message.
async fn keyed_send_never_claimed(
    state: &MailState,
    key: &str,
    inbox_id: &str,
    request_hash: &str,
) -> bool {
    matches!(
        store(state).lookup_send(key, inbox_id, request_hash).await,
        Ok(None | Some(SendClaim::Conflict))
    )
}

/// Only `draft`, `scheduled` and parked `failed` drafts may be edited or sent;
/// `sending` and `sent` belong to a claimed send.
fn draft_is_editable(status: &str) -> bool {
    matches!(status, "draft" | "scheduled" | "failed")
}

fn draft_busy(status: &str) -> Response {
    if status == "sent" {
        err(StatusCode::CONFLICT, "draft has already been sent")
    } else {
        err(StatusCode::CONFLICT, "draft is being sent")
    }
}

/// Answer a guarded draft write that matched no editable row: the draft was
/// deleted, or a send claimed or settled it first.
async fn draft_conflict_after_race(state: &MailState, draft_id: &str) -> Response {
    match store(state).get_draft(draft_id).await {
        Ok(Some(draft)) => draft_busy(&draft.status),
        Ok(None) => err(StatusCode::NOT_FOUND, "draft not found"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
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
        "signature_scheme": webhook.signature_scheme.as_str(),
        "created_at": webhook.created_at,
        "updated_at": webhook.updated_at,
    })
}

fn public_webhook_without_secret(webhook: &crate::Webhook) -> serde_json::Value {
    let mut value = public_webhook(webhook);
    value["secret"] = serde_json::Value::Null;
    if let Ok(mut url) = reqwest::Url::parse(&webhook.url) {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        value["url"] = serde_json::Value::String(url.to_string());
    }
    value
}

fn validate_header_map(headers: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
    if headers.iter().any(|(name, value)| {
        name.trim().is_empty()
            || name.len() > 128
            || name.contains(['\r', '\n', ':', ' '])
            || value.len() > 2048
            || value.contains(['\r', '\n'])
            || webhooks::is_reserved_delivery_header(name)
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
        secret: webhooks::new_signing_secret(),
        signature_scheme: webhooks::SignatureScheme::Standard,
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
    #[serde(default, rename = "eventTypes", alias = "event_types")]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "inboxIds", alias = "inbox_ids")]
    inbox_ids: Option<Vec<String>>,
    #[serde(default, rename = "removeInboxIds", alias = "remove_inbox_ids")]
    remove_inbox_ids: Option<Vec<String>>,
    #[serde(default, rename = "removePodIds", alias = "remove_pod_ids")]
    remove_pod_ids: Option<Vec<String>>,
    #[serde(default, rename = "podIds", alias = "pod_ids")]
    pod_ids: Option<Vec<String>>,
    /// `true` replaces the signing secret with a new Standard Webhooks secret,
    /// returned once as `secret`. The old secret stops verifying immediately.
    #[serde(default, rename = "rotateSecret", alias = "rotate_secret")]
    rotate_secret: Option<bool>,
}

/// A patched webhook and whether its signing secret was rotated (the only case
/// in which the response carries the secret).
struct PatchedWebhook {
    webhook: crate::Webhook,
    rotated: bool,
}

impl PatchedWebhook {
    fn respond(self) -> Response {
        let body = if self.rotated {
            public_webhook(&self.webhook)
        } else {
            public_webhook_without_secret(&self.webhook)
        };
        (StatusCode::OK, Json(body)).into_response()
    }
}

async fn patch_webhook_record(
    state: &MailState,
    id: &str,
    body: WebhookPatchBody,
    required_inbox: Option<&str>,
) -> Result<PatchedWebhook, (StatusCode, String)> {
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
    // Rotation is also the migration path for a webhook created before
    // Standard Webhooks signing: the new secret is signed the standard way.
    let rotated = body.rotate_secret == Some(true);
    if rotated {
        webhook.secret = webhooks::new_signing_secret();
        webhook.signature_scheme = webhooks::SignatureScheme::Standard;
    }
    if let Err(error) = store(state).update_webhook(&webhook).await {
        return Err(internal_error(error));
    }
    Ok(PatchedWebhook { webhook, rotated })
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
        Ok(patched) => patched.respond(),
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

/// The inbox-scoped webhook routes reach only a webhook bound to that inbox,
/// the same rule `patch_webhook_record` applies to an update: any other id
/// (another inbox's webhook, or a global one) is reported as not found.
async fn inbox_webhook_out_of_scope(
    state: &MailState,
    inbox_id: &str,
    webhook_id: &str,
) -> Option<Response> {
    match store(state).get_webhook(webhook_id).await {
        Ok(Some(webhook)) if webhook.inbox_ids.iter().any(|value| value == inbox_id) => None,
        Ok(_) => Some(err(StatusCode::NOT_FOUND, "webhook not found")),
        Err(error) => Some(err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())),
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
    Path((inbox_id, webhook_id)): Path<(String, String)>,
) -> Response {
    if let Some(refused) = inbox_webhook_out_of_scope(&state, &inbox_id, &webhook_id).await {
        return refused;
    }
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
        Ok(patched) => patched.respond(),
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
    Path((inbox_id, webhook_id)): Path<(String, String)>,
) -> Response {
    if let Some(refused) = inbox_webhook_out_of_scope(&state, &inbox_id, &webhook_id).await {
        return refused;
    }
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
    Path((inbox_id, webhook_id)): Path<(String, String)>,
) -> Response {
    if let Some(refused) = inbox_webhook_out_of_scope(&state, &inbox_id, &webhook_id).await {
        return refused;
    }
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
    Path((inbox_id, webhook_id)): Path<(String, String)>,
    Json(body): Json<HeaderUpdateBody>,
) -> Response {
    if let Some(refused) = inbox_webhook_out_of_scope(&state, &inbox_id, &webhook_id).await {
        return refused;
    }
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
    // Totals come from the stored columns: nothing is opened.
    let totals = match store(&state).usage_totals(&inbox_id).await {
        Ok(totals) => totals,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    (
        StatusCode::OK,
        Json(json!({
            "storage_bytes": totals.storage_bytes,
            "message_count": totals.message_count,
            "thread_count": totals.thread_count,
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
    /// RFC 3339 time with an offset (e.g. `2026-10-10T09:00:00Z`) at which the
    /// scheduler SENDS this draft to its recipients. Omit to keep it unsent.
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

/// A webhook subscription. The scope fields accept both the camelCase and the
/// snake_case spelling: a silently dropped scope key would widen the webhook to
/// every event in every inbox.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct WebhookBody {
    #[serde(default, alias = "clientId")]
    client_id: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default, rename = "eventTypes", alias = "event_types")]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "inboxIds", alias = "inbox_ids")]
    inbox_ids: Vec<String>,
    #[serde(default, rename = "podIds", alias = "pod_ids")]
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
    // Every definite local refusal runs before the idempotency key is claimed, so
    // a refused request never consumes its key.
    let outbound = Outbound::from_send(&body);
    if let Err((status, message)) = check_outbound_shape(&outbound) {
        return err(status, &message);
    }
    let Some(inbox) = store(&state).get_inbox(&id).await.ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "inbox not found");
    };
    if let Err((status, message)) = check_outbound_policy(&state, &inbox, &outbound).await {
        return err(status, &message);
    }
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());
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
        match store(&state).lookup_send(key, &id, &request_hash).await {
            Ok(Some(claim)) => {
                if let Some(response) = send_claim_response(claim) {
                    return response;
                }
            }
            Ok(None) => {}
            Err(error) => return send_claim_error(error),
        }
    }
    // Definite local refusals must not consume a durable send key. Generic
    // callback/transport errors after this point remain unresolved conservatively.
    if !state.email.available() {
        return err(StatusCode::BAD_REQUEST, "email transport is not configured");
    }
    if let Some(key) = idempotency_key {
        match store(&state).claim_send(key, &id, &request_hash).await {
            Ok(claim) => {
                if let Some(response) = send_claim_response(claim) {
                    return response;
                }
            }
            Err(error) => return send_claim_error(error),
        }
    }
    let record_id = uuid::Uuid::new_v4().to_string();
    let html = if body.track_opens {
        tracking_html(body.html, &record_id, tracking_base().as_deref())
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
            record_event(&state, sent_event(&m), Some(app_event_payload(&m))).await;
            let response = json!({ "message": &m });
            if let Some(key) = idempotency_key {
                match store(&state)
                    .complete_send(key, &id, &request_hash, &response)
                    .await
                {
                    Ok(true) => {}
                    result => {
                        tracing::warn!(
                            "mail send acknowledgement replay could not be persisted: {result:?}"
                        );
                        return err(StatusCode::INTERNAL_SERVER_ERROR, "Mail transport acknowledged the message but its replay record could not be saved; reconcile this request before retrying");
                    }
                }
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) if idempotency_key.is_some() => {
            tracing::warn!("keyed Mail send remains unresolved: {e}");
            err(
                StatusCode::CONFLICT,
                "mail send outcome is unresolved; reconcile this request before sending again",
            )
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

fn send_claim_response(claim: SendClaim) -> Option<Response> {
    match claim {
        SendClaim::New => None,
        SendClaim::Replay(response) => Some((StatusCode::OK, Json(response)).into_response()),
        SendClaim::Conflict => Some(err(
            StatusCode::CONFLICT,
            "idempotency key was reused with a different inbox or request",
        )),
        SendClaim::Unresolved => Some(err(
            StatusCode::CONFLICT,
            "mail send outcome is unresolved; reconcile this request before sending again",
        )),
    }
}

fn send_claim_error(error: anyhow::Error) -> Response {
    let status = if error
        .to_string()
        .contains("invalid mail send idempotency key")
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    err(status, &error.to_string())
}

/// Append the open-tracking pixel when tracking is configured (`base`). Without
/// it the HTML body goes out unchanged rather than being dropped.
fn tracking_html(html: Option<String>, message_id: &str, base: Option<&str>) -> Option<String> {
    let html = html?;
    let Some(base) = base else {
        return Some(html);
    };
    let pixel = tracking_pixel_path(message_id);
    Some(format!(
        "{html}<img src=\"{base}{pixel}\" width=\"1\" height=\"1\" alt=\"\" />"
    ))
}

/// Lowercase hex HMAC-SHA256: the inbound signature format
/// (`X-Ryu-Signature: sha256=<hex>`).
pub(crate) fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use std::fmt::Write as _;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// How far a signed `X-Ryu-Timestamp` may be from this process's clock, either way.
const INBOUND_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

// A tombstone must outlive every timestamp that could still pass the window.
const _: () =
    assert!(crate::store::INBOUND_TOMBSTONE_RETENTION_SECS > 2 * INBOUND_TIMESTAMP_TOLERANCE_SECS);

/// How an accepted inbound delivery was signed.
#[derive(Debug, PartialEq, Eq)]
enum InboundSignature {
    /// `X-Ryu-Signature` over the body alone: no expiry, no replay tombstone.
    BodyOnly,
    /// `X-Ryu-Signature` over `{timestamp}.{body}`, within the window.
    /// `digest` is the SHA-256 of that signed content, the replay tombstone key.
    Timestamped { digest: String },
}

/// Verify an inbound delivery's HMAC.
///
/// With `X-Ryu-Timestamp` (decimal Unix seconds) the signature must cover
/// `{timestamp}.{body}` and the timestamp must be within five minutes of `now`;
/// there is no fallback to the body-only form, so a stripped or altered
/// timestamp fails. Without it, the older body-only signature is accepted
/// unless the inbox requires timestamps.
fn verify_inbound_signature(
    secret: &str,
    require_timestamp: bool,
    headers: &HeaderMap,
    body: &[u8],
    now: i64,
) -> Result<InboundSignature, &'static str> {
    let provided = headers
        .get("x-ryu-signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().trim_start_matches("sha256=").to_string())
        .unwrap_or_default();
    let Some(timestamp) = headers.get("x-ryu-timestamp") else {
        if require_timestamp {
            return Err("this inbox requires a signed X-Ryu-Timestamp");
        }
        let expected = hmac_sha256_hex(secret.as_bytes(), body);
        return if ryu_sidecar_runtime::constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
            Ok(InboundSignature::BodyOnly)
        } else {
            Err("invalid signature")
        };
    };
    let timestamp = timestamp
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|value| {
            !value.is_empty() && value.len() <= 12 && value.bytes().all(|b| b.is_ascii_digit())
        })
        .ok_or("invalid X-Ryu-Timestamp")?;
    let seconds: i64 = timestamp.parse().map_err(|_| "invalid X-Ryu-Timestamp")?;
    if (now - seconds).abs() > INBOUND_TIMESTAMP_TOLERANCE_SECS {
        return Err("X-Ryu-Timestamp is outside the five-minute window");
    }
    let mut signed = Vec::with_capacity(timestamp.len() + 1 + body.len());
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    let expected = hmac_sha256_hex(secret.as_bytes(), &signed);
    if !ryu_sidecar_runtime::constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err("invalid signature");
    }
    Ok(InboundSignature::Timestamped {
        digest: format!("{:x}", Sha256::digest(&signed)),
    })
}

/// Public inbound webhook. HMAC-authed with the inbox's `inbound_secret`
/// (`X-Ryu-Signature: sha256=<hex>`) over the raw body, or over
/// `{timestamp}.{body}` when `X-Ryu-Timestamp` is sent; see
/// [`verify_inbound_signature`].
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

    let signature = match verify_inbound_signature(
        &inbox.inbound_secret,
        inbox.require_timestamp,
        &headers,
        &body,
        Utc::now().timestamp(),
    ) {
        Ok(signature) => signature,
        Err(reason) => return err(StatusCode::UNAUTHORIZED, reason),
    };

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
    // A timestamped delivery seen before is a replay even when the message it
    // stored has since been deleted. Its tombstone is written in the same
    // transaction as the message, after every check that could refuse the
    // delivery, so a delivery that was never stored leaves nothing behind and
    // the sender's retry is stored.
    let replay_key = match &signature {
        InboundSignature::Timestamped { digest } => Some(InboundReplayKey {
            digest,
            seen_at: Utc::now().timestamp(),
        }),
        InboundSignature::BodyOnly => None,
    };
    let msg = EmailMessage {
        id: uuid::Uuid::new_v4().to_string(),
        inbox_id: id.clone(),
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
    let stored = store(&state)
        .insert_inbound_message(msg, parsed.attachments, &body, replay_key)
        .await;
    match stored {
        Ok(InboundInsert::Duplicate { message_id }) => (
            StatusCode::OK,
            Json(json!({ "id": message_id, "duplicate": true })),
        )
            .into_response(),
        Ok(InboundInsert::Stored(m)) => {
            // Only after the row is durable: a consumer told mail arrived has to be
            // able to fetch it. The AgentMail-style event below (event log,
            // WebSocket, and webhooks the operator configured) carries the body;
            // the app-event hook payload Core fans out to every plugin and
            // workflow is metadata only, because the body is attacker-supplied
            // and up to `MAX_INBOUND_BYTES`. Hooks read it back through the
            // authed `GET /api/mail/messages/:id`.
            let app_payload = app_event_payload(&m);
            record_event(
                &state,
                event(
                    "message.received",
                    Some(m.inbox_id.clone()),
                    Some(m.id.clone()),
                    json!({
                        "message": {
                            "id": &m.id,
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
                Some(app_payload),
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
    let (meta, bytes) = match store(&state).read_attachment(&id).await {
        Ok(Some(found)) => found,
        Ok(None) => return err(StatusCode::NOT_FOUND, "attachment not found"),
        Err(error) => {
            tracing::warn!("ryu-mail: attachment {id} could not be read: {error:#}");
            return err(StatusCode::NOT_FOUND, "attachment blob missing");
        }
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
mod realtime_subscription_tests {
    use super::RealtimeSubscription;

    #[test]
    fn accepts_snake_and_camel_case_filters() {
        for text in [
            r#"{"event_types":["message.received"],"inbox_ids":["inb_1"]}"#,
            r#"{"eventTypes":["message.received"],"inboxIds":["inb_1"]}"#,
        ] {
            let parsed: RealtimeSubscription =
                serde_json::from_str(text).expect("a filter message must parse");
            assert_eq!(parsed.event_types, vec!["message.received".to_string()]);
            assert_eq!(parsed.inbox_ids, vec!["inb_1".to_string()]);
        }
        let empty: RealtimeSubscription = serde_json::from_str("{}").expect("empty parses");
        assert!(empty.event_types.is_empty() && empty.inbox_ids.is_empty());
    }
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

    fn message(direction: &str) -> crate::EmailMessage {
        crate::EmailMessage {
            id: "store-id".to_owned(),
            inbox_id: "inbox".to_owned(),
            direction: direction.to_owned(),
            message_id: "<rfc@example.test>".to_owned(),
            in_reply_to: None,
            from_addr: "a@example.test".to_owned(),
            to_addrs: vec!["b@example.test".to_owned()],
            cc_addrs: Vec::new(),
            bcc_addrs: vec!["hidden@example.test".to_owned()],
            reply_to_addrs: Vec::new(),
            references: Vec::new(),
            thread_id: None,
            subject: "s".to_owned(),
            text: Some("attacker body".to_owned()),
            html: Some("<p>attacker body</p>".to_owned()),
            extracted_text: None,
            extracted_html: None,
            preview: Some("attacker body".to_owned()),
            headers: std::collections::BTreeMap::new(),
            labels: Vec::new(),
            status: "received".to_owned(),
            read: false,
            opened_at: None,
            raw_size: 0,
            provider_message_id: Some("<relay@example.test>".to_owned()),
            attachments: Vec::new(),
            created_at: "2026-10-10T00:00:00Z".to_owned(),
            updated_at: "2026-10-10T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn hook_event_payloads_match_the_declared_metadata_only_examples() {
        // Core forwards this payload verbatim to every subscribed plugin hook and
        // workflow, and `payload_example` is the only contract they get.
        let manifest = manifest();
        for (event_id, direction) in [
            ("@ryu/mail#message.received", "inbound"),
            ("@ryu/mail#message.sent", "outbound"),
        ] {
            let declared = manifest["contributes"]["hook_events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| event["id"] == event_id)
                .unwrap_or_else(|| panic!("{event_id} must be declared"))["payload_example"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            let payload = super::app_event_payload(&message(direction));
            let emitted = payload
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(emitted, declared, "{event_id}");
            assert_eq!(payload["messageId"], "store-id");
            let wire = payload.to_string();
            assert!(!wire.contains("attacker body"), "{event_id} leaked a body");
            assert!(
                !wire.contains("hidden@example.test"),
                "{event_id} leaked bcc"
            );
        }
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

    #[tokio::test]
    async fn service_home_describes_the_service_without_a_dashboard_url() {
        for unset in [None, Some(""), Some("   ")] {
            let response = super::home_response(unset);
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.headers().get(header::LOCATION).is_none());
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                body,
                serde_json::json!({
                    "name": "ryu-mail",
                    "version": env!("CARGO_PKG_VERSION"),
                    "health": "/health",
                })
            );
        }
    }

    #[test]
    fn service_home_redirects_only_to_an_operator_configured_dashboard() {
        let response = super::home_response(Some(" https://dash.example.com/home "));
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://dash.example.com/home"
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
                require_timestamp: None,
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
            let resp = super::super::health(State(state())).await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json(resp).await;
            assert_eq!(body["status"], "ok");
            assert_eq!(body["sealing"]["state"], "ok");
        }

        #[tokio::test]
        async fn create_inbox_rejects_empty_address() {
            let resp =
                super::super::create_inbox(State(state()), Json(create_body("x", "   "))).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn create_inbox_rejects_malformed_addresses() {
            for address in ["no-at-sign", "a@b@c.com", "a b@x.com", "a@nodot", "@x.com"] {
                let resp =
                    super::super::create_inbox(State(state()), Json(create_body("x", address)))
                        .await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{address}");
            }
        }

        #[tokio::test]
        async fn create_inbox_refuses_an_address_already_on_the_node() {
            let st = state();
            let first = super::super::create_inbox(
                State(st.clone()),
                Json(create_body("Team", " Team@X.com ")),
            )
            .await;
            assert_eq!(first.status(), StatusCode::OK);
            assert_eq!(json(first).await["inbox"]["address"], "team@x.com");

            let again = super::super::create_inbox(
                State(st.clone()),
                Json(create_body("Dup", "team@x.com")),
            )
            .await;
            assert_eq!(again.status(), StatusCode::CONFLICT);
            let body = json(again).await;
            assert_eq!(body["code"], "address_taken");
            assert_eq!(body["address"], "team@x.com");

            let list = super::super::list_inboxes(State(st)).await;
            assert_eq!(json(list).await["inboxes"].as_array().unwrap().len(), 1);
        }

        #[tokio::test]
        async fn create_inbox_rejects_a_blank_name() {
            for name in ["", "   "] {
                let resp =
                    super::super::create_inbox(State(state()), Json(create_body(name, "a@x.com")))
                        .await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{name:?}");
                assert_eq!(json(resp).await["error"], "name is required");
            }
        }

        #[tokio::test]
        async fn overlapping_creates_with_one_client_id_make_one_inbox() {
            let st = state();
            let body = |address: &str| {
                let mut body = create_body("Agent", address);
                body.client_id = Some("run-7".to_string());
                body
            };
            // Different addresses, so only the client id can tie them together.
            let (first, second, third) = tokio::join!(
                super::super::create_inbox(State(st.clone()), Json(body("a@x.com"))),
                super::super::create_inbox(State(st.clone()), Json(body("b@x.com"))),
                super::super::create_inbox(State(st.clone()), Json(body("a@x.com"))),
            );
            let mut ids = Vec::new();
            for resp in [first, second, third] {
                assert_eq!(resp.status(), StatusCode::OK);
                let body = json(resp).await;
                ids.push(body["inbox"]["id"].as_str().unwrap().to_string());
            }
            ids.dedup();
            assert_eq!(ids.len(), 1, "every caller gets the same inbox");
            let list = super::super::list_inboxes(State(st)).await;
            assert_eq!(json(list).await["inboxes"].as_array().unwrap().len(), 1);
        }

        #[tokio::test]
        async fn store_create_inbox_once_reports_an_existing_client_id() {
            let st = state();
            let options = || crate::store::InboxOptions {
                client_id: Some("run-8".to_string()),
                ..crate::store::InboxOptions::default()
            };
            let created = st
                .mail
                .create_inbox_once("A", "a@x.com", InboxProvider::Webhook, options())
                .await
                .unwrap();
            let crate::store::InboxCreation::Created(created) = created else {
                panic!("first create stores a new inbox");
            };
            let again = st
                .mail
                .create_inbox_once("B", "b@x.com", InboxProvider::Webhook, options())
                .await
                .unwrap();
            let crate::store::InboxCreation::Existing(existing) = again else {
                panic!("a repeated client id returns the stored inbox");
            };
            assert_eq!(existing.id, created.id);
            assert_eq!(existing.address, "a@x.com");
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
                    require_timestamp: None,
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
            let new_secret = body["inbound_secret"].as_str().unwrap();
            assert!(!new_secret.is_empty());
            assert_ne!(new_secret, inbox.inbound_secret);
            assert_eq!(body["inboundSecret"], new_secret);
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

        fn keyed_headers(key: &str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert("idempotency-key", HeaderValue::from_str(key).unwrap());
            headers
        }

        fn send_body() -> super::super::SendBody {
            serde_json::from_value(serde_json::json!({"to":["recipient@example.test"],"subject":"Reviewed send","text":"Original body"})).unwrap()
        }

        #[tokio::test]
        async fn keyed_send_concurrency_replays_one_actual_transport_acknowledgement() {
            use std::sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            };
            let count = Arc::new(AtomicUsize::new(0));
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let callback = axum::Router::new().route(
                "/api/host/capability/email.send",
                axum::routing::post({
                    let count = count.clone();
                    let entered = entered.clone();
                    let release = release.clone();
                    move |Json(body): Json<Value>| {
                        let count = count.clone();
                        let entered = entered.clone();
                        let release = release.clone();
                        async move {
                            assert_eq!(body["to"], serde_json::json!(["recipient@example.test"]));
                            count.fetch_add(1, Ordering::SeqCst);
                            entered.notify_one();
                            release.notified().await;
                            Json(serde_json::json!({"messageId":"<ack@example.test>"}))
                        }
                    }
                }),
            );
            let unexpected_callbacks = Arc::new(AtomicUsize::new(0));
            let callback = callback.fallback({
                let unexpected = unexpected_callbacks.clone();
                move || {
                    let unexpected = unexpected.clone();
                    async move {
                        unexpected.fetch_add(1, Ordering::SeqCst);
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({"error":"callback status unavailable"})),
                        )
                    }
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, callback).await.unwrap();
            });
            let mut st = state();
            st.email = crate::host::EmailHost::for_test_callback(format!("http://{address}"));
            let inbox = st
                .mail
                .create_inbox("Reviewed", "sender@example.test", InboxProvider::Webhook)
                .await
                .unwrap();
            let other = st
                .mail
                .create_inbox("Other", "other@example.test", InboxProvider::Webhook)
                .await
                .unwrap();
            let original = tokio::spawn({
                let st = st.clone();
                let id = inbox.id.clone();
                async move {
                    super::super::send_message(
                        State(st),
                        Path(id),
                        keyed_headers("concurrent-key"),
                        Json(send_body()),
                    )
                    .await
                }
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            let blocked = super::super::send_message(
                State(st.clone()),
                Path(inbox.id.clone()),
                keyed_headers("concurrent-key"),
                Json(send_body()),
            )
            .await;
            assert_eq!(blocked.status(), StatusCode::CONFLICT);
            release.notify_one();
            let accepted = original.await.unwrap();
            assert_eq!(accepted.status(), StatusCode::OK);
            let accepted = json(accepted).await;
            st.email = crate::host::EmailHost::disabled();
            let replay = super::super::send_message(
                State(st.clone()),
                Path(inbox.id.clone()),
                keyed_headers("concurrent-key"),
                Json(send_body()),
            )
            .await;
            assert_eq!(replay.status(), StatusCode::OK);
            assert_eq!(json(replay).await, accepted);
            let different_inbox = super::super::send_message(
                State(st.clone()),
                Path(other.id),
                keyed_headers("concurrent-key"),
                Json(send_body()),
            )
            .await;
            assert_eq!(different_inbox.status(), StatusCode::CONFLICT);
            let mut changed = send_body();
            changed.text = Some("Changed body".into());
            assert_eq!(
                super::super::send_message(
                    State(st.clone()),
                    Path(inbox.id),
                    keyed_headers("concurrent-key"),
                    Json(changed)
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(unexpected_callbacks.load(Ordering::SeqCst), 0);
            assert!(st
                .mail
                .get_message(accepted["message"]["id"].as_str().unwrap())
                .await
                .unwrap()
                .is_some());
            server.abort();
        }

        #[tokio::test]
        async fn acknowledged_send_with_failed_completion_stays_unresolved_without_second_transport(
        ) {
            use std::sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            };
            let count = Arc::new(AtomicUsize::new(0));
            let callback = axum::Router::new().route(
                "/api/host/capability/email.send",
                axum::routing::post({
                    let count = count.clone();
                    move || {
                        let count = count.clone();
                        async move {
                            count.fetch_add(1, Ordering::SeqCst);
                            Json(serde_json::json!({"messageId":"<uncertain-ack@example.test>"}))
                        }
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, callback).await.unwrap();
            });
            let mut st = state();
            st.email = crate::host::EmailHost::for_test_callback(format!("http://{address}"));
            let inbox = st
                .mail
                .create_inbox("Uncertain", "sender@example.test", InboxProvider::Webhook)
                .await
                .unwrap();
            st.mail.reject_send_completions_for_test().await;
            let response = super::super::send_message(
                State(st.clone()),
                Path(inbox.id.clone()),
                keyed_headers("failed-completion"),
                Json(send_body()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            st.email = crate::host::EmailHost::disabled();
            assert_eq!(
                super::super::send_message(
                    State(st),
                    Path(inbox.id),
                    keyed_headers("failed-completion"),
                    Json(send_body())
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            assert_eq!(count.load(Ordering::SeqCst), 1);
            server.abort();
        }

        #[tokio::test]
        async fn definite_pretransport_refusal_preserves_key_for_configured_retry_and_replay() {
            use std::sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            };
            let count = Arc::new(AtomicUsize::new(0));
            let callback = axum::Router::new().route(
                "/api/host/capability/email.send",
                axum::routing::post({
                    let count = count.clone();
                    move || {
                        let count = count.clone();
                        async move {
                            count.fetch_add(1, Ordering::SeqCst);
                            Json(serde_json::json!({"messageId":"<configured-retry@example.test>"}))
                        }
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, callback).await.unwrap();
            });
            let mut st = state();
            let inbox = st
                .mail
                .create_inbox("Retry", "sender@example.test", InboxProvider::Webhook)
                .await
                .unwrap();
            let refused = super::super::send_message(
                State(st.clone()),
                Path(inbox.id.clone()),
                keyed_headers("configure-retry"),
                Json(send_body()),
            )
            .await;
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                json(refused).await["error"],
                "email transport is not configured"
            );
            st.email = crate::host::EmailHost::for_test_callback(format!("http://{address}"));
            let accepted = super::super::send_message(
                State(st.clone()),
                Path(inbox.id.clone()),
                keyed_headers("configure-retry"),
                Json(send_body()),
            )
            .await;
            assert_eq!(accepted.status(), StatusCode::OK);
            let accepted = json(accepted).await;
            let replay = super::super::send_message(
                State(st.clone()),
                Path(inbox.id.clone()),
                keyed_headers("configure-retry"),
                Json(send_body()),
            )
            .await;
            assert_eq!(replay.status(), StatusCode::OK);
            assert_eq!(json(replay).await, accepted);
            assert_eq!(count.load(Ordering::SeqCst), 1);

            let missing = super::super::send_message(
                State(st.clone()),
                Path("missing-inbox".into()),
                keyed_headers("missing-retry"),
                Json(send_body()),
            )
            .await;
            assert_eq!(missing.status(), StatusCode::NOT_FOUND);
            let mut invalid = send_body();
            invalid.to = vec!["not an email address".into()];
            let refused = super::super::send_message(
                State(st.clone()),
                Path(inbox.id.clone()),
                keyed_headers("invalid-retry"),
                Json(invalid),
            )
            .await;
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
            assert_eq!(json(refused).await["error"], "invalid email address");
            assert_eq!(count.load(Ordering::SeqCst), 1);
            for key in ["missing-retry", "invalid-retry"] {
                let accepted = super::super::send_message(
                    State(st.clone()),
                    Path(inbox.id.clone()),
                    keyed_headers(key),
                    Json(send_body()),
                )
                .await;
                assert_eq!(accepted.status(), StatusCode::OK);
            }
            assert_eq!(count.load(Ordering::SeqCst), 3);
            server.abort();
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
        async fn a_replayed_inbound_delivery_is_stored_once() {
            // No Message-ID: the parser invents a random one per parse, so only the
            // raw bytes can recognise the replay.
            const NO_ID: &[u8] =
                b"From: a@x.com\r\nTo: b@x.com\r\nSubject: Replay\r\n\r\nHello\r\n";
            let st = state();
            let inbox = st
                .mail
                .create_inbox("In", "in@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let first = super::super::inbound(
                State(st.clone()),
                Path(inbox.id.clone()),
                signed_headers(&inbox.inbound_secret, NO_ID),
                Bytes::from(NO_ID),
            )
            .await;
            assert_eq!(first.status(), StatusCode::OK);
            let first = json(first).await;
            let replay = super::super::inbound(
                State(st.clone()),
                Path(inbox.id.clone()),
                signed_headers(&inbox.inbound_secret, NO_ID),
                Bytes::from(NO_ID),
            )
            .await;
            assert_eq!(replay.status(), StatusCode::OK);
            let replay = json(replay).await;
            assert_eq!(replay["duplicate"], true);
            assert_eq!(replay["id"], first["id"]);
            assert_eq!(
                st.mail.list_messages(&inbox.id, 200).await.unwrap().len(),
                1
            );
            let received = st
                .mail
                .list_events(Some(&inbox.id), 10)
                .await
                .unwrap()
                .into_iter()
                .filter(|event| event.event_type == "message.received")
                .count();
            assert_eq!(received, 1, "a replay must not re-fire message.received");
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

        #[tokio::test]
        async fn webhook_scope_fields_accept_the_documented_snake_case_spelling() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("W", "w@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            // An IP literal keeps the destination check offline.
            let resp = super::super::create_webhook(
                State(st.clone()),
                Json(
                    serde_json::from_value(serde_json::json!({
                        "url": "https://93.184.216.34/hook",
                        "event_types": ["message.sent"],
                        "inbox_ids": [inbox.id],
                        "pod_ids": ["pod-1"],
                    }))
                    .unwrap(),
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            let created = json(resp).await;
            assert_eq!(created["event_types"], serde_json::json!(["message.sent"]));
            assert_eq!(created["inbox_ids"], serde_json::json!([inbox.id]));
            assert_eq!(created["pod_ids"], serde_json::json!(["pod-1"]));
            let id = created["webhook_id"].as_str().unwrap().to_owned();

            let resp = super::super::update_webhook(
                State(st.clone()),
                Path(id.clone()),
                Json(
                    serde_json::from_value(serde_json::json!({
                        "event_types": ["message.received"],
                        "pod_ids": ["pod-2"],
                    }))
                    .unwrap(),
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let stored = st.mail.get_webhook(&id).await.unwrap().unwrap();
            assert_eq!(stored.event_types, ["message.received"]);
            assert_eq!(stored.pod_ids, ["pod-2"]);
            assert_eq!(stored.inbox_ids, std::slice::from_ref(&inbox.id));

            // The camelCase spelling keeps working.
            let resp = super::super::create_webhook(
                State(st),
                Json(
                    serde_json::from_value(serde_json::json!({
                        "url": "https://93.184.216.34/other",
                        "eventTypes": ["message.opened"],
                        "inboxIds": [inbox.id],
                    }))
                    .unwrap(),
                ),
            )
            .await;
            let created = json(resp).await;
            assert_eq!(
                created["event_types"],
                serde_json::json!(["message.opened"])
            );
            assert_eq!(created["inbox_ids"], serde_json::json!([inbox.id]));
        }

        #[test]
        fn track_opens_without_tracking_keeps_the_html_body() {
            assert_eq!(
                super::super::tracking_html(Some("<p>hi</p>".to_owned()), "m1", None).as_deref(),
                Some("<p>hi</p>")
            );
            assert_eq!(
                super::super::tracking_html(
                    Some("<p>hi</p>".to_owned()),
                    "m1",
                    Some("https://mail.example.test")
                )
                .as_deref(),
                Some("<p>hi</p><img src=\"https://mail.example.test/api/mail/track/m1\" width=\"1\" height=\"1\" alt=\"\" />")
            );
        }

        #[tokio::test]
        async fn opens_are_recorded_only_for_tracked_outbound_mail_while_enabled() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("T", "t@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            let stored = |id: &str, direction: &str, html: Option<String>| EmailMessage {
                id: id.to_owned(),
                inbox_id: inbox.id.clone(),
                direction: direction.to_owned(),
                message_id: format!("<{id}@node.example>"),
                in_reply_to: None,
                thread_id: None,
                references: Vec::new(),
                from_addr: "t@node.example".to_owned(),
                to_addrs: vec!["r@ok.example".to_owned()],
                cc_addrs: Vec::new(),
                bcc_addrs: Vec::new(),
                reply_to_addrs: Vec::new(),
                subject: "s".to_owned(),
                text: None,
                html,
                extracted_text: None,
                extracted_html: None,
                preview: None,
                headers: std::collections::BTreeMap::new(),
                labels: Vec::new(),
                status: "sent".to_owned(),
                read: false,
                opened_at: None,
                raw_size: 0,
                provider_message_id: None,
                attachments: Vec::new(),
                created_at: "2026-10-10T00:00:00Z".to_owned(),
                updated_at: "2026-10-10T00:00:00Z".to_owned(),
            };
            let tracked_html = super::super::tracking_html(
                Some("<p>hi</p>".to_owned()),
                "tracked",
                Some("https://mail.example.test"),
            );
            for message in [
                stored("tracked", "outbound", tracked_html),
                stored("untracked", "outbound", Some("<p>hi</p>".to_owned())),
                stored("inbound", "inbound", Some("<p>hi</p>".to_owned())),
            ] {
                st.mail.insert_message(message, Vec::new()).await.unwrap();
            }
            let opened = |id: &'static str| {
                let st = st.clone();
                async move {
                    st.mail
                        .get_message(id)
                        .await
                        .unwrap()
                        .unwrap()
                        .opened_at
                        .is_some()
                }
            };

            super::super::record_open(&st, "tracked", false).await;
            assert!(
                !opened("tracked").await,
                "tracking disabled records nothing"
            );
            super::super::record_open(&st, "inbound", true).await;
            super::super::record_open(&st, "untracked", true).await;
            assert!(!opened("inbound").await);
            assert!(!opened("untracked").await);
            super::super::record_open(&st, "tracked", true).await;
            assert!(opened("tracked").await);
            let opens = st
                .mail
                .list_events(Some(&inbox.id), 10)
                .await
                .unwrap()
                .into_iter()
                .filter(|event| event.event_type == "message.opened")
                .count();
            assert_eq!(opens, 1);

            // The public route always answers with the pixel.
            let resp =
                super::super::track_open(State(st.clone()), Path("inbound".to_owned())).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "image/gif"
            );
        }

        // ── Outbound policy: every send path, including scheduled drafts ────

        fn send_json(value: Value) -> super::super::SendBody {
            serde_json::from_value(value).unwrap()
        }

        fn draft_json(value: Value) -> super::super::DraftBody {
            serde_json::from_value(value).unwrap()
        }

        async fn add_send_entry(st: &MailState, list_type: &str, entry: &str) {
            let resp = super::super::create_list_entry(
                State(st.clone()),
                Path((
                    "global".to_owned(),
                    "*".to_owned(),
                    "send".to_owned(),
                    list_type.to_owned(),
                )),
                Json(super::super::ListEntryCreateBody {
                    entry: entry.to_owned(),
                    reason: None,
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        async fn send_to(st: &MailState, inbox_id: &str, body: Value) -> Response {
            super::super::send_message(
                State(st.clone()),
                Path(inbox_id.to_owned()),
                HeaderMap::new(),
                Json(send_json(body)),
            )
            .await
        }

        async fn create_draft_with(st: &MailState, inbox_id: &str, body: Value) -> Response {
            super::super::create_draft(
                State(st.clone()),
                Path(inbox_id.to_owned()),
                Json(draft_json(body)),
            )
            .await
        }

        /// A stand-in for Core's `email.send` capability that only counts hand-offs.
        async fn counting_transport() -> (
            std::sync::Arc<std::sync::atomic::AtomicUsize>,
            String,
            tokio::task::JoinHandle<()>,
        ) {
            use std::sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            };
            let count = Arc::new(AtomicUsize::new(0));
            let callback = axum::Router::new().route(
                "/api/host/capability/email.send",
                axum::routing::post({
                    let count = count.clone();
                    move || {
                        let count = count.clone();
                        async move {
                            count.fetch_add(1, Ordering::SeqCst);
                            Json(serde_json::json!({"messageId":"<scheduled@example.test>"}))
                        }
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, callback).await.unwrap();
            });
            (count, format!("http://{address}"), server)
        }

        #[tokio::test]
        async fn display_name_recipients_cannot_bypass_send_block_lists() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("S", "agent@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            add_send_entry(&st, "block", "blocked@x.com").await;
            add_send_entry(&st, "block", "evil.example").await;
            for to in [
                "blocked@x.com",
                "Friend <blocked@x.com>",
                "x <ceo@evil.example>",
                "\"The CEO\" <CEO@Evil.Example>",
            ] {
                let resp = send_to(
                    &st,
                    &inbox.id,
                    serde_json::json!({"to":[to],"subject":"s","text":"t"}),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{to} must be blocked");
            }
            let resp = send_to(
                &st,
                &inbox.id,
                serde_json::json!({"to":["ok@ok.example"],"bcc":["Hidden <blocked@x.com>"],"subject":"s"}),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn send_allow_lists_match_the_parsed_address() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("S", "agent@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            add_send_entry(&st, "allow", "ok.example").await;
            let refused = send_to(
                &st,
                &inbox.id,
                serde_json::json!({"to":["Friend <x@other.example>"],"subject":"s"}),
            )
            .await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN);
            // An allowed display-name recipient passes policy and reaches the
            // transport check (no transport is configured in this test).
            let allowed = send_to(
                &st,
                &inbox.id,
                serde_json::json!({"to":["Friend <a@ok.example>"],"subject":"s"}),
            )
            .await;
            assert_eq!(allowed.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                json(allowed).await["error"],
                "email transport is not configured"
            );
        }

        #[tokio::test]
        async fn sends_refuse_headers_that_would_override_the_envelope() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("S", "agent@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            for name in [
                "From",
                "Sender",
                "Bcc",
                "reply-to",
                "X-A\r\nX-Injected-Header",
            ] {
                let resp = send_to(
                    &st,
                    &inbox.id,
                    serde_json::json!({"to":["a@ok.example"],"subject":"s","headers":{name:"exfil@evil.example"}}),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{name:?}");
                assert_eq!(json(resp).await["error"], "invalid message header");
            }
        }

        #[tokio::test]
        async fn a_scheduled_draft_must_pass_every_send_check_when_scheduled() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("D", "agent@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            add_send_entry(&st, "block", "blocked@x.com").await;
            let past = "2000-01-01T00:00:00Z";
            let many: Vec<String> = (0..51).map(|n| format!("r{n}@ok.example")).collect();
            for (body, status) in [
                (
                    serde_json::json!({"to":["Friend <blocked@x.com>"],"subject":"s","sendAt":past}),
                    StatusCode::FORBIDDEN,
                ),
                (
                    serde_json::json!({"to":many,"subject":"s","sendAt":past}),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    serde_json::json!({"to":["a@ok.example"],"headers":{"X-A\r\nX-Injected-Header":"v"},"sendAt":past}),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    serde_json::json!({"to":["a@ok.example"],"headers":{"Bcc":"blocked@x.com"},"sendAt":past}),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    serde_json::json!({"to":["a@ok.example"],"sendAt":"next tuesday"}),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    serde_json::json!({"to":["a@ok.example"],"sendAt":"2026-10-10T13:05"}),
                    StatusCode::BAD_REQUEST,
                ),
            ] {
                let resp = create_draft_with(&st, &inbox.id, body.clone()).await;
                assert_eq!(resp.status(), status, "{body}");
            }
            assert!(st
                .mail
                .list_drafts(&inbox.id, &[], 50)
                .await
                .unwrap()
                .is_empty());

            // A local offset is stored as the equivalent UTC instant.
            let resp = create_draft_with(
                &st,
                &inbox.id,
                serde_json::json!({"to":["a@ok.example"],"subject":"s","sendAt":"2026-10-10T10:30:00+02:00"}),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            let created = json(resp).await;
            assert_eq!(created["draft"]["send_at"], "2026-10-10T08:30:00Z");
            assert_eq!(created["draft"]["status"], "scheduled");

            // An unscheduled draft is not a send, so policy is applied when it is
            // scheduled (or sent), not when it is saved.
            let resp = create_draft_with(
                &st,
                &inbox.id,
                serde_json::json!({"to":["blocked@x.com"],"subject":"s"}),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            let unscheduled = json(resp).await;
            assert_eq!(unscheduled["draft"]["status"], "draft");
            let draft_id = unscheduled["draft"]["id"].as_str().unwrap().to_owned();
            let resp = super::super::update_draft(
                State(st.clone()),
                Path((inbox.id.clone(), draft_id.clone())),
                Json(draft_json(
                    serde_json::json!({"to":["blocked@x.com"],"subject":"s","sendAt":past}),
                )),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let stored = st.mail.get_draft(&draft_id).await.unwrap().unwrap();
            assert_eq!(stored.status, "draft");
            assert!(stored.send_at.is_none());
        }

        #[tokio::test]
        async fn the_scheduler_rechecks_policy_when_a_draft_fires() {
            use std::sync::atomic::Ordering;
            let (count, base, server) = counting_transport().await;
            let mut st = state();
            st.email = crate::host::EmailHost::for_test_callback(base);
            let inbox = st
                .mail
                .create_inbox("Sched", "agent@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            let resp = create_draft_with(
                &st,
                &inbox.id,
                serde_json::json!({"to":["a@later-blocked.example"],"subject":"s","text":"t","sendAt":"2000-01-01T00:00:00Z"}),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            let blocked_id = json(resp).await["draft"]["id"].as_str().unwrap().to_owned();
            add_send_entry(&st, "block", "later-blocked.example").await;

            let due = st
                .mail
                .list_due_drafts(chrono::Utc::now(), 16)
                .await
                .unwrap();
            assert_eq!(due.len(), 1);
            super::super::send_scheduled_draft(&st, &due[0].id, chrono::Utc::now()).await;
            assert_eq!(
                count.load(Ordering::SeqCst),
                0,
                "a blocked draft must never reach the transport"
            );
            let parked = st.mail.get_draft(&blocked_id).await.unwrap().unwrap();
            assert_eq!(parked.status, "failed");
            assert!(parked.send_at.is_some());
            let events = st.mail.list_events(Some(&inbox.id), 10).await.unwrap();
            assert!(events
                .iter()
                .any(|event| event.event_type == "message.rejected"
                    && event.payload["draft"]["id"] == blocked_id.as_str()
                    && event.payload["reason"] == "recipient blocked by mail policy"));
            assert!(st
                .mail
                .list_due_drafts(chrono::Utc::now(), 16)
                .await
                .unwrap()
                .is_empty());

            // A legacy row whose send time never parsed is parked, not sent now.
            let mut legacy = parked.clone();
            legacy.id = uuid::Uuid::new_v4().to_string();
            legacy.to_addrs = vec!["a@ok.example".to_owned()];
            legacy.send_at = Some("next tuesday".to_owned());
            legacy.status = "scheduled".to_owned();
            st.mail.create_draft(legacy.clone()).await.unwrap();
            let due = st
                .mail
                .list_due_drafts(chrono::Utc::now(), 16)
                .await
                .unwrap();
            assert_eq!(due.len(), 1);
            super::super::send_scheduled_draft(&st, &due[0].id, chrono::Utc::now()).await;
            assert_eq!(count.load(Ordering::SeqCst), 0);
            assert_eq!(
                st.mail.get_draft(&legacy.id).await.unwrap().unwrap().status,
                "failed"
            );

            // A draft that still passes goes out exactly once.
            let resp = create_draft_with(
                &st,
                &inbox.id,
                serde_json::json!({"to":["a@ok.example"],"subject":"s","text":"t","sendAt":"2000-01-01T00:00:00Z"}),
            )
            .await;
            let ok_id = json(resp).await["draft"]["id"].as_str().unwrap().to_owned();
            let due = st
                .mail
                .list_due_drafts(chrono::Utc::now(), 16)
                .await
                .unwrap();
            assert_eq!(due.len(), 1);
            super::super::send_scheduled_draft(&st, &due[0].id, chrono::Utc::now()).await;
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(
                st.mail.get_draft(&ok_id).await.unwrap().unwrap().status,
                "sent"
            );
            server.abort();
        }

        /// Perform a raw WebSocket upgrade against the served router and return the
        /// response head (status line plus headers, lowercased).
        async fn upgrade_head(address: std::net::SocketAddr, protocols: &str) -> String {
            upgrade_head_at(address, "/api/mail/ws", Some(protocols)).await
        }

        /// [`upgrade_head`] for any request target, with or without offered
        /// subprotocols.
        async fn upgrade_head_at(
            address: std::net::SocketAddr,
            target: &str,
            protocols: Option<&str>,
        ) -> String {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let protocol_header = protocols
                .map(|value| format!("Sec-WebSocket-Protocol: {value}\r\n"))
                .unwrap_or_default();
            let request = format!(
                "GET {target} HTTP/1.1\r\nHost: {address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{protocol_header}\r\n"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.unwrap() == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            String::from_utf8_lossy(&head).to_ascii_lowercase()
        }

        #[tokio::test]
        async fn the_realtime_upgrade_selects_an_offered_subprotocol() {
            const TOKEN: &str = "realtime-test-token";
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = super::super::app(state(), Some(TOKEN.to_owned()));
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            // A client that offers only the bearer protocol gets it echoed back
            // (deprecated: the credential then appears in the 101 response). The
            // SDK offers `ryu-mail.v1` too, covered below.
            let head = upgrade_head(address, &format!("ryu-bearer.{TOKEN}")).await;
            assert!(head.starts_with("http/1.1 101"), "{head}");
            assert!(
                head.contains(&format!("sec-websocket-protocol: ryu-bearer.{TOKEN}")),
                "{head}"
            );

            // Offering the fixed protocol too keeps the credential out of the reply.
            let head = upgrade_head(address, &format!("ryu-mail.v1, ryu-bearer.{TOKEN}")).await;
            assert!(head.starts_with("http/1.1 101"), "{head}");
            assert!(
                head.contains("sec-websocket-protocol: ryu-mail.v1"),
                "{head}"
            );
            assert!(!head.contains(TOKEN), "{head}");

            let head = upgrade_head(address, "ryu-bearer.wrong").await;
            assert!(head.starts_with("http/1.1 401"), "{head}");
            let head = upgrade_head(address, "ryu-mail.v1, ryu-bearer.wrong").await;
            assert!(head.starts_with("http/1.1 401"), "{head}");
            let head = upgrade_head_at(address, "/api/mail/ws", Some("ryu-mail.v1")).await;
            assert!(head.starts_with("http/1.1 401"), "{head}");
            server.abort();
        }

        #[tokio::test]
        async fn the_realtime_upgrade_reads_protocols_sent_as_separate_header_lines() {
            const TOKEN: &str = "realtime-split-token";
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = super::super::app(state(), Some(TOKEN.to_owned()));
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            // `upgrade_head_at` writes the value after `Sec-WebSocket-Protocol: `,
            // so an embedded CRLF yields a second, separate header line.
            let split = format!("ryu-mail.v1\r\nSec-WebSocket-Protocol: ryu-bearer.{TOKEN}");
            let head = upgrade_head_at(address, "/api/mail/ws", Some(&split)).await;
            assert!(head.starts_with("http/1.1 101"), "{head}");
            assert!(
                head.contains("sec-websocket-protocol: ryu-mail.v1"),
                "{head}"
            );
            assert!(!head.contains(TOKEN), "{head}");

            let split = "ryu-mail.v1\r\nSec-WebSocket-Protocol: ryu-bearer.wrong";
            let head = upgrade_head_at(address, "/api/mail/ws", Some(split)).await;
            assert!(head.starts_with("http/1.1 401"), "{head}");
            server.abort();
        }

        #[tokio::test]
        async fn the_realtime_upgrade_refuses_a_query_token() {
            const TOKEN: &str = "realtime-query-token";
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = super::super::app(state(), Some(TOKEN.to_owned()));
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            // A valid token in the URL is refused: the URL reaches access logs.
            let head = upgrade_head_at(address, &format!("/api/mail/ws?token={TOKEN}"), None).await;
            assert!(head.starts_with("http/1.1 401"), "{head}");
            let head = upgrade_head_at(address, "/api/mail/ws", None).await;
            assert!(head.starts_with("http/1.1 401"), "{head}");

            // A wrong header credential is not rescued by a correct query token.
            let head = upgrade_head_at(
                address,
                &format!("/api/mail/ws?token={TOKEN}"),
                Some("ryu-mail.v1, ryu-bearer.wrong"),
            )
            .await;
            assert!(head.starts_with("http/1.1 401"), "{head}");

            // The header transport still works with a stray query parameter.
            let head = upgrade_head_at(
                address,
                "/api/mail/ws?token=ignored",
                Some(&format!("ryu-mail.v1, ryu-bearer.{TOKEN}")),
            )
            .await;
            assert!(head.starts_with("http/1.1 101"), "{head}");
            server.abort();
        }

        #[tokio::test]
        async fn the_query_token_is_refused_on_other_routes() {
            use tower::ServiceExt as _;
            const TOKEN: &str = "realtime-query-token";
            let response = super::super::app(state(), Some(TOKEN.to_owned()))
                .oneshot(routed(
                    "GET",
                    &format!("/api/mail/inboxes?token={TOKEN}"),
                    None,
                    Vec::new(),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // ── The served router: body limits and auth as `main` assembles them ─

        fn routed(
            method: &str,
            uri: &str,
            bearer: Option<&str>,
            body: Vec<u8>,
        ) -> axum::http::Request<axum::body::Body> {
            let mut request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(token) = bearer {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            request.body(axum::body::Body::from(body)).unwrap()
        }

        #[tokio::test]
        async fn the_served_router_accepts_the_documented_body_sizes() {
            use base64::Engine as _;
            use tower::ServiceExt as _;
            const TOKEN: &str = "router-test-token";
            let st = state();
            let inbox = st
                .mail
                .create_inbox("Big", "big@node.example", InboxProvider::Webhook)
                .await
                .unwrap();
            let app = super::super::app(st.clone(), Some(TOKEN.to_owned()));

            // A ~3 MiB signed inbound message (over axum's 2 MiB default) is stored.
            let mut raw = b"From: a@x.com\r\nTo: big@node.example\r\nSubject: Big\r\nMessage-ID: <big@x.com>\r\n\r\n".to_vec();
            while raw.len() < 3 * 1024 * 1024 {
                raw.extend_from_slice(&[b'a'; 76]);
                raw.extend_from_slice(b"\r\n");
            }
            let mut request = routed(
                "POST",
                &format!("/api/mail/inbound/{}", inbox.id),
                None,
                raw.clone(),
            );
            request
                .headers_mut()
                .extend(signed_headers(&inbox.inbound_secret, &raw));
            let resp = app.clone().oneshot(request).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            // Past the documented 25 MiB the router refuses before the handler.
            let oversized = vec![b'a'; super::super::MAX_INBOUND_BYTES + 1];
            let resp = app
                .clone()
                .oneshot(routed(
                    "POST",
                    &format!("/api/mail/inbound/{}", inbox.id),
                    None,
                    oversized,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

            // A send carrying a 3 MiB attachment reaches the handler, which refuses
            // only because this test configures no transport.
            let attachment =
                base64::engine::general_purpose::STANDARD.encode(vec![7u8; 3 * 1024 * 1024]);
            let send = serde_json::to_vec(&serde_json::json!({
                "to": ["dest@ok.example"], "subject": "s", "text": "t",
                "attachments": [{"content": attachment, "content_type": "application/pdf", "filename": "a.pdf"}],
            }))
            .unwrap();
            let send_uri = format!("/api/mail/inboxes/{}/send", inbox.id);
            let resp = app
                .clone()
                .oneshot(routed("POST", &send_uri, Some(TOKEN), send.clone()))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                json(resp).await["error"],
                "email transport is not configured"
            );
            let resp = app
                .clone()
                .oneshot(routed("POST", &send_uri, None, send))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

            let draft = serde_json::to_vec(&serde_json::json!({
                "to": ["dest@ok.example"], "subject": "s",
                "attachments": [{"content": attachment, "filename": "a.pdf"}],
            }))
            .unwrap();
            let resp = app
                .clone()
                .oneshot(routed(
                    "POST",
                    &format!("/api/mail/inboxes/{}/drafts", inbox.id),
                    Some(TOKEN),
                    draft,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);

            // More than 8 MiB of decoded attachments is refused explicitly.
            let too_big =
                base64::engine::general_purpose::STANDARD
                    .encode(vec![7u8; 8 * 1024 * 1024 + 512 * 1024]);
            let send = serde_json::to_vec(&serde_json::json!({
                "to": ["dest@ok.example"], "subject": "s",
                "attachments": [{"content": too_big, "content_type": "application/pdf", "filename": "a.pdf"}],
            }))
            .unwrap();
            let resp = app
                .clone()
                .oneshot(routed("POST", &send_uri, Some(TOKEN), send))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(
                json(resp).await["error"],
                "attachments exceed the 8 MiB limit"
            );
        }

        #[tokio::test]
        async fn the_served_router_leaves_the_service_home_tokenless() {
            use tower::ServiceExt as _;
            let app = super::super::app(state(), Some("router-test-token".to_owned()));
            let resp = app
                .oneshot(routed("GET", "/", None, Vec::new()))
                .await
                .unwrap();
            // Outside the bearer gate either way; tests normally leave the
            // dashboard URL unset, so `/` describes the service.
            let dashboard = std::env::var("RYU_PRODUCT_DASHBOARD_URL")
                .ok()
                .filter(|value| !value.trim().is_empty());
            if dashboard.is_some() {
                assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
            } else {
                assert_eq!(resp.status(), StatusCode::OK);
                assert!(resp.headers().get(header::LOCATION).is_none());
                assert_eq!(json(resp).await["name"], "ryu-mail");
            }
        }

        // ── Timestamped inbound signatures and replay tombstones ─────────────

        fn timestamped_headers(secret: &str, timestamp: i64, body: &[u8]) -> HeaderMap {
            let mut signed = timestamp.to_string().into_bytes();
            signed.push(b'.');
            signed.extend_from_slice(body);
            let sig = super::super::hmac_sha256_hex(secret.as_bytes(), &signed);
            let mut h = HeaderMap::new();
            h.insert(
                "x-ryu-signature",
                HeaderValue::from_str(&format!("sha256={sig}")).unwrap(),
            );
            h.insert(
                "x-ryu-timestamp",
                HeaderValue::from_str(&timestamp.to_string()).unwrap(),
            );
            h
        }

        #[test]
        fn inbound_timestamps_are_signed_and_bounded() {
            use super::super::{verify_inbound_signature, InboundSignature};
            use sha2::Digest as _;
            const NOW: i64 = 1_800_000_000;
            let body: &[u8] = b"raw";
            let verify = |headers: &HeaderMap, require: bool| {
                verify_inbound_signature("s", require, headers, body, NOW)
            };
            for ts in [NOW, NOW - 300, NOW + 300] {
                assert!(
                    matches!(
                        verify(&timestamped_headers("s", ts, body), false),
                        Ok(InboundSignature::Timestamped { .. })
                    ),
                    "{ts}"
                );
            }
            for ts in [NOW - 301, NOW + 301] {
                assert_eq!(
                    verify(&timestamped_headers("s", ts, body), false),
                    Err("X-Ryu-Timestamp is outside the five-minute window"),
                    "{ts}"
                );
            }
            // A body-only signature with a timestamp attached does not fall back.
            let mut headers = signed_headers("s", body);
            headers.insert(
                "x-ryu-timestamp",
                HeaderValue::from_str(&NOW.to_string()).unwrap(),
            );
            assert_eq!(verify(&headers, false), Err("invalid signature"));
            // Re-dating a captured delivery breaks its signature.
            let mut headers = timestamped_headers("s", NOW - 200, body);
            headers.insert(
                "x-ryu-timestamp",
                HeaderValue::from_str(&NOW.to_string()).unwrap(),
            );
            assert_eq!(verify(&headers, false), Err("invalid signature"));
            for raw in ["", "abc", "-5", "1.5", "1e9", "0001800000000000"] {
                let mut headers = timestamped_headers("s", NOW, body);
                headers.insert("x-ryu-timestamp", HeaderValue::from_str(raw).unwrap());
                assert_eq!(
                    verify(&headers, false),
                    Err("invalid X-Ryu-Timestamp"),
                    "{raw}"
                );
            }
            // The older body-only form keeps working unless the inbox requires
            // timestamps; a wrong secret never passes either way.
            assert_eq!(
                verify(&signed_headers("s", body), false),
                Ok(InboundSignature::BodyOnly)
            );
            assert_eq!(
                verify(&signed_headers("s", body), true),
                Err("this inbox requires a signed X-Ryu-Timestamp")
            );
            assert_eq!(
                verify(&timestamped_headers("other", NOW, body), true),
                Err("invalid signature")
            );
            // The tombstone key is the SHA-256 of the signed content.
            let Ok(InboundSignature::Timestamped { digest }) =
                verify(&timestamped_headers("s", NOW, body), true)
            else {
                panic!("a fresh timestamped delivery verifies");
            };
            assert_eq!(
                digest,
                format!("{:x}", sha2::Sha256::digest(format!("{NOW}.raw")))
            );
        }

        #[tokio::test]
        async fn a_timestamped_delivery_cannot_be_replayed_even_after_deletion() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("In", "in@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let now = chrono::Utc::now().timestamp();
            let headers = timestamped_headers(&inbox.inbound_secret, now, RAW_MSG);
            let deliver = |headers: HeaderMap| {
                let st = st.clone();
                let id = inbox.id.clone();
                async move {
                    super::super::inbound(State(st), Path(id), headers, Bytes::from(RAW_MSG)).await
                }
            };
            let first = deliver(headers.clone()).await;
            assert_eq!(first.status(), StatusCode::OK);
            let first = json(first).await;
            assert!(first.get("duplicate").is_none());
            let message_id = first["id"].as_str().unwrap().to_owned();

            // The captured request replayed after the message is deleted is
            // recognised by its tombstone: nothing is stored or announced again.
            assert!(st.mail.delete_message(&message_id).await.unwrap());
            let replay = deliver(headers.clone()).await;
            assert_eq!(replay.status(), StatusCode::OK);
            let replay = json(replay).await;
            assert_eq!(replay["duplicate"], true);
            assert_eq!(replay["id"], message_id.as_str());
            assert!(st
                .mail
                .list_messages(&inbox.id, 200)
                .await
                .unwrap()
                .is_empty());
            let received = st
                .mail
                .list_events(Some(&inbox.id), 10)
                .await
                .unwrap()
                .into_iter()
                .filter(|event| event.event_type == "message.received")
                .count();
            assert_eq!(received, 1, "a replay must not re-fire message.received");

            // A stale copy is refused outright.
            let stale = deliver(timestamped_headers(
                &inbox.inbound_secret,
                now - 301,
                RAW_MSG,
            ))
            .await;
            assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

            // The sender re-signing the message is a new delivery, not a replay.
            let resent =
                deliver(timestamped_headers(&inbox.inbound_secret, now + 1, RAW_MSG)).await;
            assert_eq!(resent.status(), StatusCode::OK);
            assert!(json(resent).await.get("duplicate").is_none());
            assert_eq!(
                st.mail.list_messages(&inbox.id, 200).await.unwrap().len(),
                1
            );
        }

        async fn received_events(st: &MailState, inbox_id: &str) -> usize {
            st.mail
                .list_events(Some(inbox_id), 50)
                .await
                .unwrap()
                .into_iter()
                .filter(|event| event.event_type == "message.received")
                .count()
        }

        #[tokio::test]
        async fn a_timestamped_delivery_interrupted_before_storing_is_stored_on_retry() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("In", "in@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let headers = timestamped_headers(
                &inbox.inbound_secret,
                chrono::Utc::now().timestamp(),
                RAW_MSG,
            );
            let deliver = || {
                let st = st.clone();
                let id = inbox.id.clone();
                let headers = headers.clone();
                async move {
                    super::super::inbound(State(st), Path(id), headers, Bytes::from(RAW_MSG)).await
                }
            };

            // Mail stops between accepting the delivery and storing its message:
            // the insert fails, and nothing may remove a tombstone afterwards.
            st.mail
                .execute_batch_for_test(
                    "CREATE TRIGGER fail_message_insert BEFORE INSERT ON messages
                     BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;
                     CREATE TRIGGER keep_tombstones BEFORE DELETE ON inbound_replay_tombstones
                     BEGIN SELECT RAISE(ABORT, 'no cleanup after a crash'); END;",
                )
                .await;
            let failed = deliver().await;
            assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(st
                .mail
                .inbound_tombstones_for_test(&inbox.id)
                .await
                .is_empty());
            st.mail
                .execute_batch_for_test(
                    "DROP TRIGGER fail_message_insert; DROP TRIGGER keep_tombstones;",
                )
                .await;

            // The sender's retry of the same signed request is stored, not
            // acknowledged as a duplicate of a message that does not exist.
            let retry = deliver().await;
            assert_eq!(retry.status(), StatusCode::OK);
            let retry = json(retry).await;
            assert!(retry.get("duplicate").is_none());
            let message_id = retry["id"].as_str().unwrap().to_owned();
            assert!(st.mail.get_message(&message_id).await.unwrap().is_some());

            // A real replay is still a duplicate of that message.
            let replay = json(deliver().await).await;
            assert_eq!(replay["duplicate"], true);
            assert_eq!(replay["id"], message_id.as_str());
            assert_eq!(
                st.mail.list_messages(&inbox.id, 200).await.unwrap().len(),
                1
            );
            assert_eq!(received_events(&st, &inbox.id).await, 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn concurrent_copies_of_a_timestamped_delivery_store_one_message() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("In", "in@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let headers = timestamped_headers(
                &inbox.inbound_secret,
                chrono::Utc::now().timestamp(),
                RAW_MSG,
            );
            let deliveries = (0..6)
                .map(|_| {
                    let st = st.clone();
                    let id = inbox.id.clone();
                    let headers = headers.clone();
                    tokio::spawn(async move {
                        let response = super::super::inbound(
                            State(st),
                            Path(id),
                            headers,
                            Bytes::from(RAW_MSG),
                        )
                        .await;
                        assert_eq!(response.status(), StatusCode::OK);
                        json(response).await
                    })
                })
                .collect::<Vec<_>>();
            let mut stored = Vec::new();
            let mut duplicates = Vec::new();
            for delivery in deliveries {
                let body = delivery.await.unwrap();
                let id = body["id"].as_str().unwrap().to_owned();
                if body["duplicate"] == true {
                    duplicates.push(id);
                } else {
                    stored.push(id);
                }
            }
            assert_eq!(stored.len(), 1);
            assert_eq!(duplicates.len(), 5);
            assert!(duplicates.iter().all(|id| *id == stored[0]));
            assert_eq!(
                st.mail.list_messages(&inbox.id, 200).await.unwrap().len(),
                1
            );
            assert_eq!(received_events(&st, &inbox.id).await, 1);
        }

        #[tokio::test]
        async fn an_inbox_can_require_signed_timestamps() {
            let st = state();
            let mut body = create_body("Strict", "strict@x.com");
            body.require_timestamp = Some(true);
            let created =
                json(super::super::create_inbox(State(st.clone()), Json(body)).await).await;
            assert_eq!(created["inbox"]["require_timestamp"], true);
            let id = created["inbox"]["id"].as_str().unwrap().to_owned();
            let secret = created["inbox"]["inbound_secret"]
                .as_str()
                .unwrap()
                .to_owned();
            let read =
                json(super::super::get_inbox(State(st.clone()), Path(id.clone())).await).await;
            assert_eq!(read["inbox"]["require_timestamp"], true);
            assert!(read["inbox"]["inbound_secret"].is_null());

            let body_only = super::super::inbound(
                State(st.clone()),
                Path(id.clone()),
                signed_headers(&secret, RAW_MSG),
                Bytes::from(RAW_MSG),
            )
            .await;
            assert_eq!(body_only.status(), StatusCode::UNAUTHORIZED);
            assert!(st.mail.list_messages(&id, 200).await.unwrap().is_empty());
            let timestamped = super::super::inbound(
                State(st.clone()),
                Path(id.clone()),
                timestamped_headers(&secret, chrono::Utc::now().timestamp(), RAW_MSG),
                Bytes::from(RAW_MSG),
            )
            .await;
            assert_eq!(timestamped.status(), StatusCode::OK);

            // Turning the requirement off accepts the older form again.
            let patched = super::super::patch_inbox(
                State(st.clone()),
                Path(id.clone()),
                Json(super::super::PatchInboxBody {
                    name: None,
                    metadata: None,
                    pod_id: None,
                    require_timestamp: Some(false),
                }),
            )
            .await;
            assert_eq!(json(patched).await["inbox"]["require_timestamp"], false);
            const OTHER: &[u8] =
                b"From: a@x.com\r\nTo: b@x.com\r\nSubject: Again\r\nMessage-ID: <again@x.com>\r\n\r\nHi\r\n";
            let body_only = super::super::inbound(
                State(st.clone()),
                Path(id.clone()),
                signed_headers(&secret, OTHER),
                Bytes::from(OTHER),
            )
            .await;
            assert_eq!(body_only.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn sealed_secrets_still_verify_inbound_mail() {
            let mut st = state();
            st.mail = crate::store::fresh_sealed_store(&[3; 32]);
            let created = json(
                super::super::create_inbox(State(st.clone()), Json(create_body("S", "s@x.com")))
                    .await,
            )
            .await;
            let id = created["inbox"]["id"].as_str().unwrap().to_owned();
            let secret = created["inbox"]["inbound_secret"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                !secret.starts_with("enc:"),
                "the caller gets the plaintext once"
            );
            let resp = super::super::inbound(
                State(st.clone()),
                Path(id.clone()),
                signed_headers(&secret, RAW_MSG),
                Bytes::from(RAW_MSG),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let rotated =
                json(super::super::rotate_secret(State(st.clone()), Path(id.clone())).await).await;
            let rotated = rotated["inbound_secret"].as_str().unwrap().to_owned();
            const OTHER: &[u8] =
                b"From: a@x.com\r\nTo: b@x.com\r\nSubject: R\r\nMessage-ID: <r@x.com>\r\n\r\nHi\r\n";
            let resp = super::super::inbound(
                State(st.clone()),
                Path(id),
                signed_headers(&rotated, OTHER),
                Bytes::from(OTHER),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // ── Standard Webhooks secrets and rotation ──────────────────────────

        #[tokio::test]
        async fn webhook_secrets_are_standard_and_rotation_migrates_legacy_webhooks() {
            use base64::Engine as _;
            let st = state();
            let created = super::super::create_webhook(
                State(st.clone()),
                Json(
                    serde_json::from_value(serde_json::json!({
                        "url": "https://93.184.216.34/hook",
                        "event_types": ["message.received"],
                    }))
                    .unwrap(),
                ),
            )
            .await;
            assert_eq!(created.status(), StatusCode::CREATED);
            let created = json(created).await;
            assert_eq!(created["signature_scheme"], "standard");
            let secret = created["secret"].as_str().unwrap().to_owned();
            let key = base64::engine::general_purpose::STANDARD
                .decode(secret.strip_prefix("whsec_").unwrap())
                .unwrap();
            assert_eq!(key.len(), 24);
            let id = created["webhook_id"].as_str().unwrap().to_owned();

            let patch = |body: serde_json::Value| {
                let st = st.clone();
                let id = id.clone();
                async move {
                    let resp = super::super::update_webhook(
                        State(st),
                        Path(id),
                        Json(serde_json::from_value(body).unwrap()),
                    )
                    .await;
                    assert_eq!(resp.status(), StatusCode::OK);
                    json(resp).await
                }
            };
            // An ordinary update never returns the secret.
            assert!(patch(serde_json::json!({ "enabled": true })).await["secret"].is_null());
            // rotateSecret returns a new secret once and the old one stops signing.
            let rotated = patch(serde_json::json!({ "rotateSecret": true })).await;
            let new_secret = rotated["secret"].as_str().unwrap().to_owned();
            assert_ne!(new_secret, secret);
            assert_eq!(
                st.mail.get_webhook(&id).await.unwrap().unwrap().secret,
                new_secret
            );

            // A webhook created before Standard Webhooks signing reports the
            // legacy scheme until it is rotated, which moves it to the standard one.
            let mut legacy = st.mail.get_webhook(&id).await.unwrap().unwrap();
            legacy.secret = "whsec_0123456789abcdef0123456789abcdef".to_owned(); // Test vector, not a credential. gitleaks:allow skipcq
            legacy.signature_scheme = crate::webhooks::SignatureScheme::Legacy;
            assert!(st.mail.update_webhook(&legacy).await.unwrap());
            let read =
                json(super::super::get_webhook(State(st.clone()), Path(id.clone())).await).await;
            assert_eq!(read["signature_scheme"], "legacy");
            assert!(read["secret"].is_null());
            let migrated = patch(serde_json::json!({ "rotate_secret": true })).await;
            assert_eq!(migrated["signature_scheme"], "standard");
            let migrated_secret = migrated["secret"].as_str().unwrap();
            assert!(base64::engine::general_purpose::STANDARD
                .decode(migrated_secret.strip_prefix("whsec_").unwrap())
                .is_ok());
            assert_eq!(
                st.mail
                    .get_webhook(&id)
                    .await
                    .unwrap()
                    .unwrap()
                    .signature_scheme,
                crate::webhooks::SignatureScheme::Standard
            );

            // Custom headers cannot claim a signature header.
            for name in ["webhook-signature", "Webhook-Id", "svix-signature"] {
                let resp = super::super::update_webhook_headers(
                    State(st.clone()),
                    Path(id.clone()),
                    Json(
                        serde_json::from_value(serde_json::json!({ "headers": { name: "x" } }))
                            .unwrap(),
                    ),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{name}");
            }
        }

        fn draft_body(value: Value) -> super::super::DraftBody {
            serde_json::from_value(value).unwrap()
        }

        #[tokio::test]
        async fn draft_send_is_claimed_once_and_released_on_a_definite_failure() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("Drafts", "drafts@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let created = super::super::create_draft(
                State(st.clone()),
                Path(inbox.id.clone()),
                Json(draft_body(
                    serde_json::json!({ "to": ["to@x.com"], "subject": "hi", "text": "body" }),
                )),
            )
            .await;
            assert_eq!(created.status(), StatusCode::CREATED);
            let draft_id = json(created).await["draft"]["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let path = || Path((inbox.id.clone(), draft_id.clone()));

            // No transport: a definite refusal returns the draft to `draft`.
            let resp = super::super::send_draft(State(st.clone()), path(), HeaderMap::new()).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                st.mail.get_draft(&draft_id).await.unwrap().unwrap().status,
                "draft"
            );

            // While another sender (the scheduler) holds the claim, a second send
            // and an edit both conflict instead of re-sending or reverting it.
            st.mail.claim_draft(&draft_id).await.unwrap().unwrap();
            let resp = super::super::send_draft(State(st.clone()), path(), HeaderMap::new()).await;
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            assert_eq!(json(resp).await["error"], "draft is being sent");
            let resp = super::super::update_draft(
                State(st.clone()),
                path(),
                Json(draft_body(
                    serde_json::json!({ "to": ["other@x.com"], "subject": "edited" }),
                )),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            let stored = st.mail.get_draft(&draft_id).await.unwrap().unwrap();
            assert_eq!(stored.status, "sending");
            assert_eq!(stored.subject, "hi");

            assert!(st
                .mail
                .finish_draft_send(&draft_id, "sent", true)
                .await
                .unwrap());
            let resp = super::super::send_draft(State(st), path(), HeaderMap::new()).await;
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            assert_eq!(json(resp).await["error"], "draft has already been sent");
        }

        #[tokio::test]
        async fn keyed_draft_send_stays_claimed_only_when_its_key_may_have_sent() {
            let st = state();
            let inbox = st
                .mail
                .create_inbox("Keyed", "keyed@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let created = super::super::create_draft(
                State(st.clone()),
                Path(inbox.id.clone()),
                Json(draft_body(
                    serde_json::json!({ "to": ["to@x.com"], "subject": "hi", "text": "body" }),
                )),
            )
            .await;
            let draft_id = json(created).await["draft"]["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let path = || Path((inbox.id.clone(), draft_id.clone()));

            // The key belongs to a different request, so this send was refused
            // before the transport: the draft is sendable again.
            st.mail
                .claim_send("reused-key", &inbox.id, "another-request")
                .await
                .unwrap();
            let resp =
                super::super::send_draft(State(st.clone()), path(), keyed_headers("reused-key"))
                    .await;
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            assert_eq!(
                st.mail.get_draft(&draft_id).await.unwrap().unwrap().status,
                "draft"
            );

            // A pending claim for this exact request may have reached the
            // transport, so the draft stays claimed rather than risk a resend.
            let draft = st.mail.get_draft(&draft_id).await.unwrap().unwrap();
            let request_hash = super::super::sha256_json(&super::super::draft_send_body(draft));
            st.mail
                .claim_send("pending-key", &inbox.id, &request_hash)
                .await
                .unwrap();
            let resp =
                super::super::send_draft(State(st.clone()), path(), keyed_headers("pending-key"))
                    .await;
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            assert_eq!(
                st.mail.get_draft(&draft_id).await.unwrap().unwrap().status,
                "sending"
            );
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
        assert!(ryu_sidecar_runtime::constant_time_eq(b"", b""));
        assert!(ryu_sidecar_runtime::constant_time_eq(b"abc", b"abc"));
        assert!(!ryu_sidecar_runtime::constant_time_eq(b"abc", b"abd"));
        assert!(!ryu_sidecar_runtime::constant_time_eq(b"abc", b"ab")); // different lengths
        assert!(!ryu_sidecar_runtime::constant_time_eq(b"ab", b"abc"));
    }
}

#[cfg(test)]
#[path = "api_scoped_tests.rs"]
mod scoped_tests;
