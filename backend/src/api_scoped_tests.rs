//! Inbox-scoped route tests: every `/inboxes/:id/...` handler must act only on
//! that inbox's messages, threads, webhooks, and events. The handlers are called
//! directly with hand-built extractors, like the sibling `api::tests::routes`.

use super::{
    create_inbox_webhook, delete_inbox_webhook, delete_scoped_message, delete_thread,
    download_raw_message, download_scoped_attachment, forward_message, forwarding_subject,
    get_inbox_webhook, get_inbox_webhook_headers, get_scoped_message, get_thread,
    list_inbox_events, list_inbox_webhooks, list_threads, query_event_metrics, query_usage_metrics,
    reply_all_message, reply_message, reply_subject, search_messages, search_threads,
    update_inbox_webhook, update_inbox_webhook_headers, update_message, update_thread,
    MessageQuery,
};
use crate::store::{fresh_store, RawAttachment};
use crate::{EmailMessage, Inbox, InboxProvider, MailEvent, MailState};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn state() -> MailState {
    MailState {
        email: crate::host::EmailHost::disabled(),
        mail: fresh_store(),
        events: ryu_app_events::EventEmitter::from_env(crate::PLUGIN_ID),
    }
}

async fn body_json(resp: Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_bytes(resp: Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

async fn inbox(st: &MailState, address: &str) -> Inbox {
    st.mail
        .create_inbox(address, address, InboxProvider::Webhook)
        .await
        .unwrap()
}

struct Msg<'a> {
    inbox_id: &'a str,
    message_id: &'a str,
    thread_id: &'a str,
    subject: &'a str,
    from: &'a str,
    to: &'a [&'a str],
    cc: &'a [&'a str],
    references: &'a [&'a str],
    created_at: &'a str,
}

impl Default for Msg<'_> {
    fn default() -> Self {
        Self {
            inbox_id: "",
            message_id: "<m@ext.example>",
            thread_id: "<m@ext.example>",
            subject: "hello",
            from: "alice@ext.example",
            to: &["agent@node.example"],
            cc: &[],
            references: &[],
            created_at: "2026-01-01T00:00:00Z",
        }
    }
}

fn message(spec: &Msg<'_>) -> EmailMessage {
    let owned = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect();
    EmailMessage {
        id: uuid::Uuid::new_v4().to_string(),
        inbox_id: spec.inbox_id.to_owned(),
        direction: "inbound".to_owned(),
        message_id: spec.message_id.to_owned(),
        in_reply_to: None,
        thread_id: Some(spec.thread_id.to_owned()),
        references: owned(spec.references),
        from_addr: spec.from.to_owned(),
        to_addrs: owned(spec.to),
        cc_addrs: owned(spec.cc),
        bcc_addrs: Vec::new(),
        reply_to_addrs: Vec::new(),
        subject: spec.subject.to_owned(),
        text: Some(format!("body of {}", spec.subject)),
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
        created_at: spec.created_at.to_owned(),
        updated_at: spec.created_at.to_owned(),
    }
}

async fn put(st: &MailState, spec: &Msg<'_>) -> EmailMessage {
    st.mail
        .insert_message(message(spec), Vec::new())
        .await
        .unwrap()
}

fn query(value: Value) -> Query<MessageQuery> {
    Query(serde_json::from_value(value).unwrap())
}

fn label_body(value: Value) -> Json<super::LabelUpdateBody> {
    Json(serde_json::from_value(value).unwrap())
}

fn pair(a: &str, b: &str) -> Path<(String, String)> {
    Path((a.to_owned(), b.to_owned()))
}

// ── Item: inbox-scoped message read/update/delete/raw/attachment ───────────

#[tokio::test]
async fn scoped_message_routes_refuse_a_message_of_another_inbox() {
    let st = state();
    let mine = inbox(&st, "mine@node.example").await;
    let other = inbox(&st, "other@node.example").await;
    let raw = b"From: a@ext.example\r\nSubject: s\r\n\r\nraw body\r\n";
    let stored = st
        .mail
        .insert_message_with_raw(
            message(&Msg {
                inbox_id: &other.id,
                ..Msg::default()
            }),
            vec![RawAttachment {
                filename: "a.txt".to_owned(),
                content_type: "text/plain".to_owned(),
                bytes: b"attachment bytes".to_vec(),
                inline: false,
                content_id: None,
            }],
            Some(raw),
        )
        .await
        .unwrap();
    let attachment_id = stored.attachments[0].id.clone();

    // Through the wrong inbox every operation is a 404 and nothing changes.
    let resp = get_scoped_message(State(st.clone()), pair(&mine.id, &stored.id)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = update_message(
        State(st.clone()),
        pair(&mine.id, &stored.id),
        label_body(json!({"addLabels": ["stolen"], "read": true})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = delete_scoped_message(State(st.clone()), pair(&mine.id, &stored.id)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = download_raw_message(State(st.clone()), pair(&mine.id, &stored.id)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = download_scoped_attachment(
        State(st.clone()),
        Path((mine.id.clone(), stored.id.clone(), attachment_id.clone())),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let untouched = st.mail.get_message(&stored.id).await.unwrap().unwrap();
    assert!(untouched.labels.is_empty());
    assert!(!untouched.read);

    // Through the owning inbox the same calls succeed.
    let resp = get_scoped_message(State(st.clone()), pair(&other.id, &stored.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["message"]["id"], stored.id);
    let resp = download_raw_message(State(st.clone()), pair(&other.id, &stored.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, raw);
    let resp = download_scoped_attachment(
        State(st.clone()),
        Path((other.id.clone(), stored.id.clone(), attachment_id)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, b"attachment bytes");
    let resp = update_message(
        State(st.clone()),
        pair(&other.id, &stored.id),
        label_body(json!({"addLabels": ["kept"], "read": true})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let updated = st.mail.get_message(&stored.id).await.unwrap().unwrap();
    assert!(updated.labels.contains(&"kept".to_owned()));
    assert!(updated.read);
    let resp = delete_scoped_message(State(st.clone()), pair(&other.id, &stored.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(st.mail.get_message(&stored.id).await.unwrap().is_none());
}

// ── Item: inbox message search ─────────────────────────────────────────────

#[tokio::test]
async fn message_search_requires_q_stays_in_its_inbox_and_honours_limit() {
    let st = state();
    let mine = inbox(&st, "mine@node.example").await;
    let other = inbox(&st, "other@node.example").await;
    for (index, subject) in ["invoice 1", "invoice 2", "invoice 3", "lunch"]
        .iter()
        .enumerate()
    {
        let created_at = format!("2026-01-0{}T00:00:00Z", index + 1);
        put(
            &st,
            &Msg {
                inbox_id: &mine.id,
                subject,
                created_at: &created_at,
                ..Msg::default()
            },
        )
        .await;
    }
    put(
        &st,
        &Msg {
            inbox_id: &other.id,
            subject: "invoice for someone else",
            ..Msg::default()
        },
    )
    .await;

    for blank in [json!({}), json!({"q": "   "})] {
        let resp = search_messages(State(st.clone()), Path(mine.id.clone()), query(blank)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    let resp = search_messages(
        State(st.clone()),
        Path(mine.id.clone()),
        query(json!({"q": "INVOICE"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let found = body_json(resp).await["messages"]
        .as_array()
        .unwrap()
        .clone();
    let mut subjects = found
        .iter()
        .map(|m| m["subject"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    subjects.sort();
    assert_eq!(subjects, ["invoice 1", "invoice 2", "invoice 3"]);
    assert!(found.iter().all(|m| m["inbox_id"] == mine.id.as_str()));

    let resp = search_messages(
        State(st.clone()),
        Path(mine.id.clone()),
        query(json!({"q": "invoice", "limit": 2})),
    )
    .await;
    let limited = body_json(resp).await["messages"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(limited.len(), 2);
    // Newest first: the limit keeps the two most recent matches.
    assert_eq!(limited[0]["subject"], "invoice 3");
    assert_eq!(limited[1]["subject"], "invoice 2");
}

// ── Item: reply / reply-all / forward ──────────────────────────────────────

/// A stand-in for Core's `email.send` capability that records every hand-off.
async fn capturing_transport() -> (Arc<Mutex<Vec<Value>>>, String) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let callback = axum::Router::new().route(
        "/api/host/capability/email.send",
        axum::routing::post({
            let sent = sent.clone();
            move |Json(body): Json<Value>| {
                let sent = sent.clone();
                async move {
                    let count = {
                        let mut sent = sent.lock().unwrap();
                        sent.push(body);
                        sent.len()
                    };
                    Json(json!({ "messageId": format!("<sent-{count}@node.example>") }))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, callback).await.unwrap();
    });
    (sent, format!("http://{address}"))
}

fn reply_body(value: Value) -> Json<super::ReplyBody> {
    Json(serde_json::from_value(value).unwrap())
}

fn forward_body(value: Value) -> Json<super::ForwardBody> {
    Json(serde_json::from_value(value).unwrap())
}

#[tokio::test]
async fn reply_reply_all_and_forward_thread_and_address_correctly() {
    let (sent, base) = capturing_transport().await;
    let mut st = state();
    st.email = crate::host::EmailHost::for_test_callback(base);
    let mine = inbox(&st, "agent@node.example").await;
    let other = inbox(&st, "other@node.example").await;
    let original = put(
        &st,
        &Msg {
            inbox_id: &mine.id,
            message_id: "<orig@ext.example>",
            thread_id: "<root@ext.example>",
            subject: "Plans",
            from: "alice@ext.example",
            // The inbox's own address (in another case) must not be re-addressed.
            to: &["Agent@Node.Example", "bob@ext.example"],
            cc: &["carol@ext.example"],
            references: &["<root@ext.example>"],
            ..Msg::default()
        },
    )
    .await;

    let resp = reply_message(
        State(st.clone()),
        pair(&mine.id, &original.id),
        HeaderMap::new(),
        reply_body(json!({"text": "sounds good"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = body_json(resp).await["message"].clone();
    assert_eq!(stored["thread_id"], "<root@ext.example>");
    assert_eq!(stored["in_reply_to"], "<orig@ext.example>");

    let resp = reply_all_message(
        State(st.clone()),
        pair(&mine.id, &original.id),
        HeaderMap::new(),
        reply_body(json!({"text": "all of you"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = forward_message(
        State(st.clone()),
        pair(&mine.id, &original.id),
        HeaderMap::new(),
        forward_body(json!({"to": ["dave@ext.example"]})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let handed_off = sent.lock().unwrap().clone();
    assert_eq!(handed_off.len(), 3);
    let (reply, reply_all, forward) = (&handed_off[0], &handed_off[1], &handed_off[2]);
    assert_eq!(reply["from"], "agent@node.example");
    assert_eq!(reply["to"], json!(["alice@ext.example"]));
    assert_eq!(reply["subject"], "Re: Plans");
    assert_eq!(reply["in_reply_to"], "<orig@ext.example>");
    assert_eq!(reply["references"], "<root@ext.example> <orig@ext.example>");
    assert_eq!(
        reply_all["to"],
        json!(["alice@ext.example", "bob@ext.example", "carol@ext.example"])
    );
    assert_eq!(reply_all["subject"], "Re: Plans");
    assert_eq!(reply_all["in_reply_to"], "<orig@ext.example>");
    assert_eq!(forward["to"], json!(["dave@ext.example"]));
    assert_eq!(forward["subject"], "Fwd: Plans");
    assert_eq!(forward["text"], "body of Plans");
    assert_eq!(forward["in_reply_to"], Value::Null);
    assert_eq!(forward["references"], Value::Null);

    // The message belongs to `mine`: through `other` nothing is sent.
    let resp = reply_message(
        State(st.clone()),
        pair(&other.id, &original.id),
        HeaderMap::new(),
        reply_body(json!({"text": "x"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = reply_all_message(
        State(st.clone()),
        pair(&other.id, &original.id),
        HeaderMap::new(),
        reply_body(json!({"text": "x"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = forward_message(
        State(st.clone()),
        pair(&other.id, &original.id),
        HeaderMap::new(),
        forward_body(json!({"to": ["dave@ext.example"]})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(sent.lock().unwrap().len(), 3);

    // A forward without a recipient is refused before the transport.
    let resp = forward_message(
        State(st),
        pair(&mine.id, &original.id),
        HeaderMap::new(),
        forward_body(json!({"to": []})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(sent.lock().unwrap().len(), 3);
}

#[test]
fn reply_and_forward_subjects_are_prefixed_once() {
    assert_eq!(reply_subject("Plans"), "Re: Plans");
    assert_eq!(reply_subject("RE: Plans"), "RE: Plans");
    assert_eq!(forwarding_subject("Plans"), "Fwd: Plans");
    assert_eq!(forwarding_subject(" fwd: Plans"), " fwd: Plans");
}

// ── Item: threads list/search/get/update/delete ────────────────────────────

#[tokio::test]
async fn thread_routes_are_inbox_scoped_and_delete_removes_the_messages() {
    let st = state();
    let mine = inbox(&st, "mine@node.example").await;
    let other = inbox(&st, "other@node.example").await;
    let shared_thread = "<t1@ext.example>";
    let first = put(
        &st,
        &Msg {
            inbox_id: &mine.id,
            message_id: "<t1@ext.example>",
            thread_id: shared_thread,
            subject: "budget",
            created_at: "2026-01-01T00:00:00Z",
            ..Msg::default()
        },
    )
    .await;
    let second = put(
        &st,
        &Msg {
            inbox_id: &mine.id,
            message_id: "<t1b@ext.example>",
            thread_id: shared_thread,
            subject: "Re: budget",
            created_at: "2026-01-02T00:00:00Z",
            ..Msg::default()
        },
    )
    .await;
    put(
        &st,
        &Msg {
            inbox_id: &mine.id,
            message_id: "<t2@ext.example>",
            thread_id: "<t2@ext.example>",
            subject: "lunch",
            created_at: "2026-01-03T00:00:00Z",
            ..Msg::default()
        },
    )
    .await;
    // Another inbox holds a message on the same thread id.
    let foreign = put(
        &st,
        &Msg {
            inbox_id: &other.id,
            message_id: "<t1c@ext.example>",
            thread_id: shared_thread,
            subject: "budget elsewhere",
            ..Msg::default()
        },
    )
    .await;

    let resp = list_threads(State(st.clone()), Path(mine.id.clone()), query(json!({}))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let threads = body_json(resp).await["threads"].as_array().unwrap().clone();
    assert_eq!(threads.len(), 2);
    assert!(threads.iter().all(|t| t["inboxId"] == mine.id.as_str()));
    let budget = threads
        .iter()
        .find(|t| t["threadId"] == shared_thread)
        .unwrap();
    assert_eq!(budget["messageCount"], 2);

    let resp = search_threads(
        State(st.clone()),
        Path(mine.id.clone()),
        query(json!({"q": " "})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = search_threads(
        State(st.clone()),
        Path(mine.id.clone()),
        query(json!({"q": "budget"})),
    )
    .await;
    let found = body_json(resp).await["threads"].as_array().unwrap().clone();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["inboxId"], mine.id.as_str());
    assert_eq!(found[0]["threadId"], shared_thread);

    let resp = get_thread(State(st.clone()), pair(&mine.id, shared_thread)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await["messages"].as_array().unwrap().len(),
        2
    );
    let resp = get_thread(State(st.clone()), pair(&other.id, "<t2@ext.example>")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = get_thread(State(st.clone()), pair(&mine.id, "<nope@ext.example>")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = update_thread(
        State(st.clone()),
        pair(&mine.id, shared_thread),
        label_body(json!({"addLabels": ["finance"]})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    for id in [&first.id, &second.id] {
        let stored = st.mail.get_message(id).await.unwrap().unwrap();
        assert!(stored.labels.contains(&"finance".to_owned()));
    }
    let foreign_after = st.mail.get_message(&foreign.id).await.unwrap().unwrap();
    assert!(!foreign_after.labels.contains(&"finance".to_owned()));
    let resp = update_thread(
        State(st.clone()),
        pair(&mine.id, "<nope@ext.example>"),
        label_body(json!({"addLabels": ["x"]})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = delete_thread(State(st.clone()), pair(&mine.id, shared_thread)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(st.mail.get_message(&first.id).await.unwrap().is_none());
    assert!(st.mail.get_message(&second.id).await.unwrap().is_none());
    assert!(st.mail.get_message(&foreign.id).await.unwrap().is_some());
    let resp = get_thread(State(st.clone()), pair(&mine.id, shared_thread)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = delete_thread(State(st), pair(&mine.id, shared_thread)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Item: inbox webhooks CRUD and header config ────────────────────────────

fn webhook_body(value: Value) -> Json<super::WebhookBody> {
    Json(serde_json::from_value(value).unwrap())
}

fn header_body(value: Value) -> Json<super::HeaderUpdateBody> {
    Json(serde_json::from_value(value).unwrap())
}

fn patch_body(value: Value) -> Json<super::WebhookPatchBody> {
    Json(serde_json::from_value(value).unwrap())
}

#[tokio::test]
async fn inbox_webhooks_persist_keep_headers_write_only_and_stay_in_their_inbox() {
    let st = state();
    let mine = inbox(&st, "mine@node.example").await;
    let other = inbox(&st, "other@node.example").await;

    let resp = create_inbox_webhook(
        State(st.clone()),
        Path("missing".to_owned()),
        webhook_body(json!({"url": "https://93.184.216.34/hook"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // An IP literal keeps the destination check offline.
    let resp = create_inbox_webhook(
        State(st.clone()),
        Path(mine.id.clone()),
        webhook_body(json!({
            "url": "https://93.184.216.34/hook",
            "inboxIds": [other.id],
            "headers": {"Authorization": "Bearer create-secret"},
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let id = created["webhook_id"].as_str().unwrap().to_owned();
    // The path's inbox wins over a body that names another one.
    let stored = st.mail.get_webhook(&id).await.unwrap().unwrap();
    assert_eq!(stored.inbox_ids, std::slice::from_ref(&mine.id));
    assert_eq!(stored.headers["Authorization"], "Bearer create-secret");

    let resp = update_inbox_webhook_headers(
        State(st.clone()),
        pair(&mine.id, &id),
        header_body(json!({
            "headers": {"X-Api-Key": "header-secret"},
            "removeHeaders": ["Authorization"],
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(!text.contains("header-secret"));
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["header_names"],
        json!(["X-Api-Key"])
    );
    let stored = st.mail.get_webhook(&id).await.unwrap().unwrap();
    assert_eq!(stored.headers.len(), 1);
    assert_eq!(stored.headers["X-Api-Key"], "header-secret");

    for resp in [
        get_inbox_webhook_headers(State(st.clone()), pair(&mine.id, &id)).await,
        get_inbox_webhook(State(st.clone()), pair(&mine.id, &id)).await,
    ] {
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(text.contains("X-Api-Key"));
        assert!(!text.contains("header-secret"), "{text}");
        assert!(!text.contains(&stored.secret), "{text}");
    }

    let resp = list_inbox_webhooks(State(st.clone()), Path(other.id.clone())).await;
    assert_eq!(body_json(resp).await["count"], 0);
    let resp = list_inbox_webhooks(State(st.clone()), Path(mine.id.clone())).await;
    assert_eq!(body_json(resp).await["count"], 1);

    // Through another inbox the webhook does not exist, and nothing changes.
    let resp = get_inbox_webhook(State(st.clone()), pair(&other.id, &id)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = get_inbox_webhook_headers(State(st.clone()), pair(&other.id, &id)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = update_inbox_webhook(
        State(st.clone()),
        pair(&other.id, &id),
        patch_body(json!({"enabled": false})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = update_inbox_webhook_headers(
        State(st.clone()),
        pair(&other.id, &id),
        header_body(json!({"removeHeaders": ["X-Api-Key"]})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = delete_inbox_webhook(State(st.clone()), pair(&other.id, &id)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let still = st.mail.get_webhook(&id).await.unwrap().unwrap();
    assert!(still.enabled);
    assert_eq!(still.headers["X-Api-Key"], "header-secret");

    let resp = delete_inbox_webhook(State(st.clone()), pair(&mine.id, &id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(st.mail.get_webhook(&id).await.unwrap().is_none());
}

// ── Item: inbox events and usage/event metrics ─────────────────────────────

fn mail_event(event_type: &str, inbox_id: &str, created_at: &str) -> MailEvent {
    MailEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: event_type.to_owned(),
        inbox_id: Some(inbox_id.to_owned()),
        message_id: None,
        payload: json!({}),
        created_at: created_at.to_owned(),
    }
}

#[tokio::test]
async fn inbox_events_and_metrics_count_only_that_inbox() {
    let st = state();
    let mine = inbox(&st, "mine@node.example").await;
    let other = inbox(&st, "other@node.example").await;
    for (event_type, inbox_id, at) in [
        ("message.received", &mine.id, "2026-01-01T00:00:00Z"),
        ("message.received", &mine.id, "2026-01-02T00:00:00Z"),
        ("message.sent", &mine.id, "2026-01-03T00:00:00Z"),
        ("message.received", &other.id, "2026-01-01T00:00:00Z"),
        ("message.bounced", &other.id, "2026-01-01T00:00:00Z"),
    ] {
        st.mail
            .insert_event(&mail_event(event_type, inbox_id, at))
            .await
            .unwrap();
    }

    let resp = query_event_metrics(State(st.clone()), Path(mine.id.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await["counts"],
        json!({"message.received": 2, "message.sent": 1})
    );

    let resp = list_inbox_events(State(st.clone()), Path(mine.id.clone()), query(json!({}))).await;
    let events = body_json(resp).await;
    assert_eq!(events["count"], 3);
    assert!(events["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["inbox_id"] == mine.id.as_str()));
    let resp = list_inbox_events(
        State(st.clone()),
        Path(mine.id.clone()),
        query(json!({"limit": 1})),
    )
    .await;
    let newest = body_json(resp).await;
    assert_eq!(newest["count"], 1);
    assert_eq!(newest["events"][0]["event_type"], "message.sent");

    // Usage: two threads, three messages in this inbox.
    for (thread, subject) in [("<a@x>", "aa"), ("<a@x>", "bbb"), ("<b@x>", "c")] {
        put(
            &st,
            &Msg {
                inbox_id: &mine.id,
                thread_id: thread,
                subject,
                ..Msg::default()
            },
        )
        .await;
    }
    let usage =
        body_json(query_usage_metrics(State(st.clone()), Path(mine.id.clone())).await).await;
    assert_eq!(usage["message_count"], 3);
    assert_eq!(usage["thread_count"], 2);
    let before = usage["storage_bytes"].as_u64().unwrap();
    assert!(before > 0);

    // A large message in another inbox does not count here.
    let mut foreign = message(&Msg {
        inbox_id: &other.id,
        ..Msg::default()
    });
    foreign.raw_size = 5_000;
    st.mail.insert_message(foreign, Vec::new()).await.unwrap();
    let usage =
        body_json(query_usage_metrics(State(st.clone()), Path(mine.id.clone())).await).await;
    assert_eq!(usage["message_count"], 3);
    assert_eq!(usage["storage_bytes"], before);

    // A bodiless 1000-byte raw message on a new thread adds exactly its size.
    let mut sized = message(&Msg {
        inbox_id: &mine.id,
        thread_id: "<c@x>",
        ..Msg::default()
    });
    sized.raw_size = 1_000;
    sized.text = None;
    st.mail.insert_message(sized, Vec::new()).await.unwrap();
    let resp = query_usage_metrics(State(st.clone()), Path(mine.id.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let usage = body_json(resp).await;
    assert_eq!(usage["message_count"], 4);
    assert_eq!(usage["thread_count"], 3);
    assert_eq!(usage["storage_bytes"], before + 1_000);
}
