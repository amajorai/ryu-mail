//! SQLite-backed persistence for self-host inboxes (`~/.ryu/mail.db`).
//!
//! Tracer copy of `apps/core/src/mail/store.rs` — verbatim except it resolves its
//! data dir via the inlined `crate::paths::ryu_dir` (same path Core used), so the
//! sidecar OWNS the store and Core no longer opens it. Attachment bytes live on
//! the filesystem under `~/.ryu/mail-blobs/`, keyed by sha256.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use super::{
    AttachmentMeta, Draft, EmailMessage, Inbox, InboxProvider, ListEntry, MailDomain, MailEvent,
    MailPod, Webhook, WebhookDelivery,
};

fn default_db_path() -> PathBuf {
    crate::paths::ryu_dir().join("mail.db")
}

fn blobs_dir_for_db(path: &std::path::Path) -> PathBuf {
    let parent = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    // The shipped database is named `mail.db`, preserving the historical
    // `<RYU_DIR>/mail-blobs` location. Tests, migrations, and callers that open a
    // second database in the same parent get a private namespace so one store's
    // startup orphan sweep can never delete another store's attachments.
    let suffix = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| *stem != "mail")
        .map(|stem| format!("-{stem}"))
        .unwrap_or_default();
    parent.join(format!("mail-blobs{suffix}"))
}

/// SQLite-backed inbox store. Cheap to clone (wraps `Arc`s).
#[derive(Clone)]
pub struct MailStore {
    conn: Arc<Mutex<Connection>>,
    tx: broadcast::Sender<EmailMessage>,
    event_tx: broadcast::Sender<MailEvent>,
    blobs_dir: PathBuf,
}

/// A raw attachment to persist (bytes hashed + written to a blob file).
pub struct RawAttachment {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
    pub inline: bool,
    pub content_id: Option<String>,
}

impl MailStore {
    pub fn open_default() -> Result<Self> {
        Self::open(default_db_path())
    }

    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db dir {}", parent.display()))?;
        }
        let blobs_dir = blobs_dir_for_db(&path);
        std::fs::create_dir_all(&blobs_dir).ok();
        let conn = Connection::open(&path)
            .with_context(|| format!("opening mail db {}", path.display()))?;
        Self::init_schema(&conn)?;
        // Retry durable blob cleanup after crashes or transient filesystem errors.
        let _ = Self::drain_blob_cleanup_sync(&conn, &blobs_dir);
        // A blob written before a transaction failed is not in the queue because
        // its metadata never committed. The startup sweep covers that crash window
        // while retaining every path still referenced by an attachment row.
        let _ = Self::sweep_orphan_blobs_sync(&conn, &blobs_dir);
        let (tx, _rx) = broadcast::channel(128);
        let (event_tx, _event_rx) = broadcast::channel(256);
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            tx,
            event_tx,
            blobs_dir,
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS inboxes (
                 id             TEXT PRIMARY KEY,
                 name           TEXT NOT NULL,
                 address        TEXT NOT NULL,
                 provider       TEXT NOT NULL,
                 inbound_secret TEXT NOT NULL,
                 client_id      TEXT,
                 metadata_json  TEXT NOT NULL DEFAULT '{}',
                 pod_id         TEXT,
                 created_at     TEXT NOT NULL,
                 updated_at     TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS messages (
                 id                  TEXT PRIMARY KEY,
                 inbox_id            TEXT NOT NULL,
                 direction           TEXT NOT NULL,
                 message_id          TEXT NOT NULL,
                 in_reply_to         TEXT,
                 thread_id           TEXT,
                 references_json     TEXT NOT NULL DEFAULT '[]',
                 from_addr           TEXT NOT NULL,
                 to_addrs           TEXT NOT NULL,
                 cc_addrs           TEXT NOT NULL,
                 bcc_addrs           TEXT NOT NULL DEFAULT '[]',
                 reply_to_addrs      TEXT NOT NULL DEFAULT '[]',
                 subject             TEXT NOT NULL,
                 text                TEXT,
                 html                TEXT,
                 extracted_text      TEXT,
                 extracted_html      TEXT,
                 preview             TEXT,
                 headers_json        TEXT NOT NULL DEFAULT '{}',
                 labels_json         TEXT NOT NULL DEFAULT '[]',
                 status              TEXT NOT NULL DEFAULT 'received',
                 read                INTEGER NOT NULL DEFAULT 0,
                 opened_at           TEXT,
                 provider_message_id TEXT,
                 raw_blob_path       TEXT,
                 raw_size            INTEGER NOT NULL DEFAULT 0,
                 created_at          TEXT NOT NULL,
                 updated_at          TEXT NOT NULL,
                 FOREIGN KEY (inbox_id) REFERENCES inboxes(id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_messages_inbox
                 ON messages(inbox_id, created_at DESC);
             CREATE INDEX IF NOT EXISTS idx_messages_thread
                 ON messages(inbox_id, thread_id, created_at ASC);
             CREATE INDEX IF NOT EXISTS idx_messages_status
                 ON messages(inbox_id, status, created_at DESC);
             CREATE TABLE IF NOT EXISTS attachments (
                 id           TEXT PRIMARY KEY,
                 message_id   TEXT NOT NULL,
                 filename     TEXT NOT NULL,
                 content_type TEXT NOT NULL,
                 size         INTEGER NOT NULL,
                 blob_path    TEXT NOT NULL,
                 inline       INTEGER NOT NULL DEFAULT 0,
                 content_id   TEXT,
                 FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_attachments_message
                 ON attachments(message_id);
             CREATE TABLE IF NOT EXISTS mail_blob_cleanup (
                 blob_path TEXT PRIMARY KEY,
                 queued_at TEXT NOT NULL
             );",
        )
        .context("initializing mail schema")?;

        // Existing Ryu Mail databases predate the parity fields above. SQLite
        // migrations are additive and use only these internal constant names;
        // no request value reaches an ALTER TABLE statement.
        for (table, name, definition) in [
            ("inboxes", "client_id", "TEXT"),
            ("inboxes", "metadata_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("inboxes", "pod_id", "TEXT"),
            ("inboxes", "updated_at", "TEXT NOT NULL DEFAULT ''"),
            ("messages", "thread_id", "TEXT"),
            ("messages", "references_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("messages", "bcc_addrs", "TEXT NOT NULL DEFAULT '[]'"),
            ("messages", "reply_to_addrs", "TEXT NOT NULL DEFAULT '[]'"),
            ("messages", "extracted_text", "TEXT"),
            ("messages", "extracted_html", "TEXT"),
            ("messages", "preview", "TEXT"),
            ("messages", "headers_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("messages", "labels_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("messages", "status", "TEXT NOT NULL DEFAULT 'received'"),
            ("messages", "read", "INTEGER NOT NULL DEFAULT 0"),
            ("messages", "opened_at", "TEXT"),
            ("messages", "raw_blob_path", "TEXT"),
            ("messages", "raw_size", "INTEGER NOT NULL DEFAULT 0"),
            ("messages", "updated_at", "TEXT NOT NULL DEFAULT ''"),
            ("attachments", "inline", "INTEGER NOT NULL DEFAULT 0"),
            ("attachments", "content_id", "TEXT"),
        ] {
            Self::ensure_column(conn, table, name, definition)?;
        }
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_inboxes_client_id
                 ON inboxes(client_id) WHERE client_id IS NOT NULL;
             CREATE TABLE IF NOT EXISTS webhooks (
                 id           TEXT PRIMARY KEY,
                 url          TEXT NOT NULL,
                 secret       TEXT NOT NULL,
                 event_types  TEXT NOT NULL DEFAULT '[]',
                 headers_json TEXT NOT NULL DEFAULT '{}',
                 inbox_ids    TEXT NOT NULL DEFAULT '[]',
                 pod_ids      TEXT NOT NULL DEFAULT '[]',
                 client_id    TEXT,
                 enabled      INTEGER NOT NULL DEFAULT 1,
                 created_at   TEXT NOT NULL,
                 updated_at   TEXT NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_webhooks_client_id
                 ON webhooks(client_id) WHERE client_id IS NOT NULL;
             CREATE TABLE IF NOT EXISTS drafts (
                 id               TEXT PRIMARY KEY,
                 inbox_id         TEXT NOT NULL,
                 thread_id        TEXT,
                 client_id        TEXT,
                 to_addrs         TEXT NOT NULL DEFAULT '[]',
                 cc_addrs         TEXT NOT NULL DEFAULT '[]',
                 bcc_addrs        TEXT NOT NULL DEFAULT '[]',
                 reply_to_addrs   TEXT NOT NULL DEFAULT '[]',
                 subject          TEXT NOT NULL DEFAULT '',
                 text             TEXT,
                 html             TEXT,
                 headers_json     TEXT NOT NULL DEFAULT '{}',
                 labels_json      TEXT NOT NULL DEFAULT '[]',
                 attachments_json TEXT NOT NULL DEFAULT '[]',
                 send_at          TEXT,
                 status           TEXT NOT NULL DEFAULT 'draft',
                 created_at       TEXT NOT NULL,
                 updated_at       TEXT NOT NULL,
                 FOREIGN KEY (inbox_id) REFERENCES inboxes(id) ON DELETE CASCADE
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_drafts_client_id
                 ON drafts(client_id) WHERE client_id IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_drafts_inbox
                 ON drafts(inbox_id, updated_at DESC);
             CREATE TABLE IF NOT EXISTS list_entries (
                 id         TEXT PRIMARY KEY,
                 scope      TEXT NOT NULL,
                 scope_id   TEXT NOT NULL,
                 direction  TEXT NOT NULL,
                 list_type  TEXT NOT NULL,
                 entry      TEXT NOT NULL,
                 entry_type TEXT NOT NULL,
                 reason     TEXT,
                 created_at TEXT NOT NULL,
                 UNIQUE(scope, scope_id, direction, list_type, entry)
             );
             CREATE TABLE IF NOT EXISTS pods (
                 id         TEXT PRIMARY KEY,
                 name       TEXT NOT NULL,
                 client_id  TEXT,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_pods_client_id
                 ON pods(client_id) WHERE client_id IS NOT NULL;
             CREATE TABLE IF NOT EXISTS domains (
                 id                 TEXT PRIMARY KEY,
                 domain             TEXT NOT NULL UNIQUE,
                 status             TEXT NOT NULL DEFAULT 'pending',
                 subdomains_enabled INTEGER NOT NULL DEFAULT 0,
                 tracking_enabled   INTEGER NOT NULL DEFAULT 0,
                 records_json       TEXT NOT NULL DEFAULT '[]',
                 pod_id             TEXT,
                 client_id          TEXT,
                 created_at         TEXT NOT NULL,
                 updated_at         TEXT NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_client_id
                 ON domains(client_id) WHERE client_id IS NOT NULL;
             CREATE TABLE IF NOT EXISTS mail_events (
                 event_id   TEXT PRIMARY KEY,
                 event_type TEXT NOT NULL,
                 inbox_id   TEXT,
                 message_id TEXT,
                 payload    TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_mail_events_inbox
                 ON mail_events(inbox_id, created_at DESC);
             CREATE INDEX IF NOT EXISTS idx_mail_events_type
                 ON mail_events(event_type, created_at DESC);
             CREATE TABLE IF NOT EXISTS webhook_deliveries (
                 id          TEXT PRIMARY KEY,
                 webhook_id  TEXT NOT NULL,
                 event_id    TEXT NOT NULL,
                 status      TEXT NOT NULL DEFAULT 'pending',
                 attempts    INTEGER NOT NULL DEFAULT 0,
                 last_error  TEXT,
                 created_at  TEXT NOT NULL,
                 updated_at  TEXT NOT NULL,
                 UNIQUE(webhook_id, event_id)
             );
             CREATE TABLE IF NOT EXISTS mail_idempotency (
                 key           TEXT PRIMARY KEY,
                 operation     TEXT NOT NULL,
                 request_hash  TEXT NOT NULL,
                 response_json TEXT NOT NULL,
                 created_at    TEXT NOT NULL,
                 expires_at    TEXT NOT NULL
             );",
        )
        .context("initializing mail parity schema")?;
        Ok(())
    }

    fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
        let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if columns.iter().any(|name| name == column) {
            return Ok(());
        }
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
        Ok(())
    }

    /// Subscribe to freshly-stored messages for local consumers.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<EmailMessage> {
        self.tx.subscribe()
    }

    /// Subscribe to durable mail events for the authenticated realtime endpoint.
    pub fn subscribe_events(&self) -> broadcast::Receiver<MailEvent> {
        self.event_tx.subscribe()
    }

    /// Fan an event out after its durable row has been written. Lagging realtime
    /// consumers can recover from `GET /api/mail/events`; the channel is only a
    /// low-latency projection, never the source of truth.
    pub fn publish_event(&self, event: MailEvent) {
        let _ = self.event_tx.send(event);
    }

    // ── Inboxes ─────────────────────────────────────────────────────────────

    pub async fn create_inbox(
        &self,
        name: &str,
        address: &str,
        provider: InboxProvider,
    ) -> Result<Inbox> {
        self.create_inbox_with_options(name, address, provider, None, BTreeMap::new(), None)
            .await
    }

    pub async fn create_inbox_with_options(
        &self,
        name: &str,
        address: &str,
        provider: InboxProvider,
        client_id: Option<String>,
        metadata: BTreeMap<String, serde_json::Value>,
        pod_id: Option<String>,
    ) -> Result<Inbox> {
        let now = Utc::now().to_rfc3339();
        let inbox = Inbox {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            address: address.to_string(),
            provider,
            client_id,
            metadata,
            pod_id,
            inbound_secret: uuid::Uuid::new_v4().simple().to_string(),
            created_at: now.clone(),
            updated_at: now,
        };
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO inboxes
             (id, name, address, provider, inbound_secret, client_id, metadata_json,
              pod_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                inbox.id,
                inbox.name,
                inbox.address,
                inbox.provider.as_str(),
                inbox.inbound_secret,
                inbox.client_id,
                serde_json::to_string(&inbox.metadata).unwrap_or_else(|_| "{}".to_owned()),
                inbox.pod_id,
                inbox.created_at,
                inbox.updated_at,
            ],
        )
        .context("inserting inbox")?;
        Ok(inbox)
    }

    pub async fn list_inboxes(&self) -> Result<Vec<Inbox>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, address, provider, inbound_secret, client_id,
                    metadata_json, pod_id, created_at, updated_at
             FROM inboxes ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Inbox {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    address: r.get(2)?,
                    provider: InboxProvider::from_str(&r.get::<_, String>(3)?),
                    inbound_secret: r.get(4)?,
                    client_id: r.get(5)?,
                    metadata: json_map(r.get(6)?),
                    pod_id: r.get(7)?,
                    created_at: r.get(8)?,
                    updated_at: r.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_inbox(&self, id: &str) -> Result<Option<Inbox>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT id, name, address, provider, inbound_secret, client_id,
                        metadata_json, pod_id, created_at, updated_at
                 FROM inboxes WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Inbox {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        address: r.get(2)?,
                        provider: InboxProvider::from_str(&r.get::<_, String>(3)?),
                        inbound_secret: r.get(4)?,
                        client_id: r.get(5)?,
                        metadata: json_map(r.get(6)?),
                        pod_id: r.get(7)?,
                        created_at: r.get(8)?,
                        updated_at: r.get(9)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub async fn rename_inbox(&self, id: &str, name: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE inboxes SET name = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, name, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub async fn update_inbox(
        &self,
        id: &str,
        name: Option<&str>,
        metadata: Option<&BTreeMap<String, serde_json::Value>>,
        pod_id: Option<&str>,
    ) -> Result<Option<Inbox>> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE inboxes SET
                name = COALESCE(?2, name),
                metadata_json = COALESCE(?3, metadata_json),
                pod_id = COALESCE(?4, pod_id),
                updated_at = ?5
             WHERE id = ?1",
            params![
                id,
                name,
                metadata.map(json_string),
                pod_id,
                Utc::now().to_rfc3339(),
            ],
        )?;
        drop(conn);
        if changed == 0 {
            return Ok(None);
        }
        self.get_inbox(id).await
    }

    /// Rotate the inbound HMAC secret; returns the new value.
    pub async fn rotate_secret(&self, id: &str) -> Result<String> {
        let secret = uuid::Uuid::new_v4().simple().to_string();
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE inboxes SET inbound_secret = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, secret, Utc::now().to_rfc3339()],
        )?;
        Ok(secret)
    }

    pub async fn delete_inbox(&self, id: &str) -> Result<()> {
        let mut conn = self.conn.lock().await;
        let transaction = conn.transaction()?;
        let candidate_blobs = {
            let mut stmt = transaction.prepare(
                "SELECT DISTINCT attachments.blob_path
                 FROM attachments
                 INNER JOIN messages ON messages.id = attachments.message_id
                 WHERE messages.inbox_id = ?1",
            )?;
            let rows = stmt
                .query_map(params![id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        transaction.execute(
            "DELETE FROM attachments
             WHERE message_id IN (SELECT id FROM messages WHERE inbox_id = ?1)",
            params![id],
        )?;
        transaction.execute("DELETE FROM messages WHERE inbox_id = ?1", params![id])?;
        transaction.execute("DELETE FROM inboxes WHERE id = ?1", params![id])?;
        let queued_at = Utc::now().to_rfc3339();
        for blob_path in candidate_blobs {
            let remaining: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM attachments WHERE blob_path = ?1",
                params![blob_path],
                |row| row.get(0),
            )?;
            if remaining == 0 {
                transaction.execute(
                    "INSERT OR IGNORE INTO mail_blob_cleanup (blob_path, queued_at)
                     VALUES (?1, ?2)",
                    params![blob_path, queued_at],
                )?;
            }
        }
        transaction.commit()?;
        let cleanup_result = Self::drain_blob_cleanup_sync(&conn, &self.blobs_dir);
        drop(conn);
        cleanup_result
    }

    // ── Messages ────────────────────────────────────────────────────────────

    /// Persist a message + its attachment blobs, broadcast it, return the stored
    /// row (with attachment metadata).
    pub async fn insert_message(
        &self,
        msg: EmailMessage,
        attachments: Vec<RawAttachment>,
    ) -> Result<EmailMessage> {
        self.insert_message_with_raw(msg, attachments, None).await
    }

    pub async fn insert_message_with_raw(
        &self,
        mut msg: EmailMessage,
        attachments: Vec<RawAttachment>,
        raw: Option<&[u8]>,
    ) -> Result<EmailMessage> {
        if msg.thread_id.is_none() {
            msg.thread_id = Some(msg.message_id.clone());
        }
        if msg.preview.is_none() {
            msg.preview = msg
                .text
                .as_deref()
                .or(msg.extracted_text.as_deref())
                .map(|value| value.chars().take(240).collect());
        }
        if msg.updated_at.is_empty() {
            msg.updated_at = msg.created_at.clone();
        }
        // Serialize blob writes with the inbox existence check and row inserts.
        // Otherwise delete_inbox could commit between the file write and this
        // insert and a late inbound delivery would resurrect an orphan message.
        let mut conn = self.conn.lock().await;
        let transaction = conn.transaction()?;
        let inbox_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM inboxes WHERE id = ?1)",
            params![msg.inbox_id],
            |row| row.get(0),
        )?;
        if !inbox_exists {
            bail!("inbox '{}' does not exist", msg.inbox_id);
        }

        let mut metas: Vec<(AttachmentMeta, String)> = Vec::new();
        let dir = &self.blobs_dir;
        std::fs::create_dir_all(&dir).ok();
        for att in attachments {
            let mut hasher = Sha256::new();
            hasher.update(&att.bytes);
            let hash = format!("{:x}", hasher.finalize());
            let rel = hash.clone();
            let path = dir.join(&rel);
            if !path.exists() {
                std::fs::write(&path, &att.bytes)
                    .with_context(|| format!("writing blob {}", path.display()))?;
            }
            metas.push((
                AttachmentMeta {
                    id: uuid::Uuid::new_v4().to_string(),
                    filename: att.filename,
                    content_type: att.content_type,
                    size: att.bytes.len() as u64,
                    inline: att.inline,
                    content_id: att.content_id,
                },
                rel,
            ));
        }
        let raw_blob_path = if let Some(bytes) = raw {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let rel = format!("raw-{:x}", hasher.finalize());
            let path = dir.join(&rel);
            if !path.exists() {
                std::fs::write(&path, bytes)
                    .with_context(|| format!("writing raw blob {}", path.display()))?;
            }
            Some(rel)
        } else {
            None
        };
        if let Some(bytes) = raw {
            msg.raw_size = bytes.len() as u64;
        }

        transaction
            .execute(
                "INSERT INTO messages
                 (id, inbox_id, direction, message_id, in_reply_to, thread_id,
                  references_json, from_addr, to_addrs, cc_addrs, bcc_addrs,
                  reply_to_addrs, subject, text, html, extracted_text, extracted_html,
                  preview, headers_json, labels_json, status, read, opened_at,
                  provider_message_id, raw_blob_path, raw_size, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                         ?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28)",
                params![
                    msg.id,
                    msg.inbox_id,
                    msg.direction,
                    msg.message_id,
                    msg.in_reply_to,
                    msg.thread_id,
                    serde_json::to_string(&msg.references).unwrap_or_else(|_| "[]".into()),
                    msg.from_addr,
                    serde_json::to_string(&msg.to_addrs).unwrap_or_else(|_| "[]".into()),
                    serde_json::to_string(&msg.cc_addrs).unwrap_or_else(|_| "[]".into()),
                    serde_json::to_string(&msg.bcc_addrs).unwrap_or_else(|_| "[]".into()),
                    serde_json::to_string(&msg.reply_to_addrs).unwrap_or_else(|_| "[]".into()),
                    msg.subject,
                    msg.text,
                    msg.html,
                    msg.extracted_text,
                    msg.extracted_html,
                    msg.preview,
                    serde_json::to_string(&msg.headers).unwrap_or_else(|_| "{}".into()),
                    serde_json::to_string(&msg.labels).unwrap_or_else(|_| "[]".into()),
                    msg.status,
                    i64::from(msg.read),
                    msg.opened_at,
                    msg.provider_message_id,
                    raw_blob_path,
                    msg.raw_size as i64,
                    msg.created_at,
                    msg.updated_at,
                ],
            )
            .context("inserting message")?;
        for (meta, rel) in &metas {
            transaction
                .execute(
                    "INSERT INTO attachments
                 (id, message_id, filename, content_type, size, blob_path, inline, content_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        meta.id,
                        msg.id,
                        meta.filename,
                        meta.content_type,
                        meta.size as i64,
                        rel,
                        i64::from(meta.inline),
                        meta.content_id,
                    ],
                )
                .context("inserting attachment")?;
        }
        transaction.commit()?;
        drop(conn);

        msg.attachments = metas.into_iter().map(|(m, _)| m).collect();
        let _ = self.tx.send(msg.clone());
        Ok(msg)
    }

    fn drain_blob_cleanup_sync(conn: &Connection, blobs_dir: &std::path::Path) -> Result<()> {
        let transaction = conn.unchecked_transaction()?;
        let paths = {
            let mut statement = transaction
                .prepare("SELECT blob_path FROM mail_blob_cleanup ORDER BY queued_at ASC")?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut first_error = None;
        for blob_path in paths {
            let referenced: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM attachments WHERE blob_path = ?1",
                params![blob_path],
                |row| row.get(0),
            )?;
            if referenced > 0 {
                transaction.execute(
                    "DELETE FROM mail_blob_cleanup WHERE blob_path = ?1",
                    params![blob_path],
                )?;
                continue;
            }
            let path = blobs_dir.join(&blob_path);
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    transaction.execute(
                        "DELETE FROM mail_blob_cleanup WHERE blob_path = ?1",
                        params![blob_path],
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    transaction.execute(
                        "DELETE FROM mail_blob_cleanup WHERE blob_path = ?1",
                        params![blob_path],
                    )?;
                }
                Err(error) => {
                    first_error.get_or_insert_with(|| {
                        anyhow::Error::new(error)
                            .context(format!("deleting attachment blob {}", path.display()))
                    });
                }
            }
        }
        transaction.commit()?;
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    fn sweep_orphan_blobs_sync(conn: &Connection, blobs_dir: &std::path::Path) -> Result<()> {
        let mut statement = conn.prepare("SELECT DISTINCT blob_path FROM attachments")?;
        let referenced = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        let mut first_error = None;
        for entry in std::fs::read_dir(blobs_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if referenced.contains(&name) {
                continue;
            }
            if let Err(error) = std::fs::remove_file(entry.path()) {
                first_error.get_or_insert_with(|| {
                    anyhow::Error::new(error)
                        .context(format!("deleting orphan attachment blob {name}"))
                });
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    pub async fn list_messages(&self, inbox_id: &str, limit: u32) -> Result<Vec<EmailMessage>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, inbox_id, direction, message_id, in_reply_to, thread_id,
                 references_json, from_addr, to_addrs, cc_addrs, bcc_addrs,
                 reply_to_addrs, subject, text, html, extracted_text, extracted_html,
                 preview, headers_json, labels_json, status, read, opened_at,
                 provider_message_id, raw_blob_path, raw_size, created_at, updated_at
             FROM messages WHERE inbox_id = ?1 ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![inbox_id, limit], row_to_message)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        let mut out = Vec::with_capacity(rows.len());
        for mut m in rows {
            m.attachments = load_attachments(&conn, &m.id)?;
            out.push(m);
        }
        Ok(out)
    }

    pub async fn get_message(&self, id: &str) -> Result<Option<EmailMessage>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT id, inbox_id, direction, message_id, in_reply_to, thread_id,
                     references_json, from_addr, to_addrs, cc_addrs, bcc_addrs,
                     reply_to_addrs, subject, text, html, extracted_text, extracted_html,
                     preview, headers_json, labels_json, status, read, opened_at,
                     provider_message_id, raw_blob_path, raw_size, created_at, updated_at
                 FROM messages WHERE id = ?1",
                params![id],
                row_to_message,
            )
            .optional()?;
        match row {
            Some(mut m) => {
                m.attachments = load_attachments(&conn, &m.id)?;
                Ok(Some(m))
            }
            None => Ok(None),
        }
    }

    pub async fn find_inbound_by_message_id(
        &self,
        inbox_id: &str,
        message_id: &str,
    ) -> Result<Option<EmailMessage>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT id, inbox_id, direction, message_id, in_reply_to, thread_id,
                        references_json, from_addr, to_addrs, cc_addrs, bcc_addrs,
                        reply_to_addrs, subject, text, html, extracted_text, extracted_html,
                        preview, headers_json, labels_json, status, read, opened_at,
                        provider_message_id, raw_blob_path, raw_size, created_at, updated_at
                 FROM messages
                 WHERE inbox_id = ?1 AND direction = 'inbound' AND message_id = ?2
                 ORDER BY created_at ASC LIMIT 1",
                params![inbox_id, message_id],
                row_to_message,
            )
            .optional()?;
        match row {
            Some(mut message) => {
                message.attachments = load_attachments(&conn, &message.id)?;
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    pub async fn list_messages_with_filters(
        &self,
        inbox_id: &str,
        limit: u32,
        before: Option<&str>,
        after: Option<&str>,
        direction: Option<&str>,
        labels: &[String],
        query: Option<&str>,
    ) -> Result<Vec<EmailMessage>> {
        let messages = self.list_messages(inbox_id, 1000).await?;
        let query = query.map(str::to_ascii_lowercase);
        let mut filtered = messages
            .into_iter()
            .filter(|message| {
                before.is_none_or(|cursor| message.created_at.as_str() < cursor)
                    && after.is_none_or(|cursor| message.created_at.as_str() > cursor)
                    && direction.is_none_or(|value| message.direction == value)
                    && labels.iter().all(|label| message.labels.contains(label))
                    && query.as_ref().is_none_or(|needle| {
                        let haystack = format!(
                            "{} {} {} {} {} {} {}",
                            message.from_addr,
                            message.to_addrs.join(" "),
                            message.cc_addrs.join(" "),
                            message.bcc_addrs.join(" "),
                            message.subject,
                            message.text.as_deref().unwrap_or(""),
                            message.html.as_deref().unwrap_or(""),
                        )
                        .to_ascii_lowercase();
                        haystack.contains(needle)
                    })
            })
            .filter(|message| !message.labels.iter().any(|label| label == "trash"))
            .collect::<Vec<_>>();
        filtered.truncate(limit as usize);
        Ok(filtered)
    }

    pub async fn messages_for_thread(
        &self,
        inbox_id: &str,
        thread_id: &str,
    ) -> Result<Vec<EmailMessage>> {
        Ok(self
            .list_messages(inbox_id, 1000)
            .await?
            .into_iter()
            .filter(|message| message.thread_id.as_deref() == Some(thread_id))
            .collect())
    }

    pub async fn update_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> Result<Option<Vec<String>>> {
        let Some(message) = self.get_message(id).await? else {
            return Ok(None);
        };
        let mut labels = message.labels;
        for label in add_labels {
            if !labels.contains(label) {
                labels.push(label.clone());
            }
        }
        labels.retain(|label| !remove_labels.contains(label));
        labels.sort();
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE messages SET labels_json = ?2, updated_at = ?3 WHERE id = ?1",
            params![
                id,
                serde_json::to_string(&labels).unwrap_or_else(|_| "[]".to_owned()),
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok((changed > 0).then_some(labels))
    }

    pub async fn mark_message_read(&self, id: &str, read: bool) -> Result<bool> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE messages SET read = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, i64::from(read), Utc::now().to_rfc3339()],
        )?;
        Ok(changed > 0)
    }

    pub async fn mark_message_opened(&self, id: &str) -> Result<Option<EmailMessage>> {
        let Some(message) = self.get_message(id).await? else {
            return Ok(None);
        };
        if message.opened_at.is_some() {
            return Ok(Some(message));
        }
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE messages SET opened_at = ?2, labels_json = ?3, updated_at = ?2
             WHERE id = ?1 AND opened_at IS NULL",
            params![
                id,
                now,
                serde_json::to_string(&{
                    let mut labels = message.labels.clone();
                    if !labels.iter().any(|label| label == "opened") {
                        labels.push("opened".to_owned());
                    }
                    labels
                })
                .unwrap_or_else(|_| "[]".to_owned())
            ],
        )?;
        drop(conn);
        self.get_message(id).await
    }

    pub async fn raw_path(&self, id: &str) -> Result<Option<(u64, PathBuf)>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT raw_blob_path, raw_size FROM messages WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, i64>(1)? as u64,
                    ))
                },
            )
            .optional()?;
        Ok(row.and_then(|(path, size)| path.map(|path| (size, self.blobs_dir.join(path)))))
    }

    pub async fn delete_message(&self, id: &str) -> Result<bool> {
        let mut conn = self.conn.lock().await;
        let transaction = conn.transaction()?;
        let paths = {
            let mut statement = transaction.prepare(
                "SELECT blob_path FROM attachments WHERE message_id = ?1
                 UNION ALL
                 SELECT raw_blob_path FROM messages
                 WHERE id = ?1 AND raw_blob_path IS NOT NULL",
            )?;
            let rows = statement
                .query_map(params![id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let deleted = transaction.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        if deleted == 0 {
            transaction.rollback()?;
            return Ok(false);
        }
        let queued_at = Utc::now().to_rfc3339();
        for path in paths {
            transaction.execute(
                "INSERT OR IGNORE INTO mail_blob_cleanup (blob_path, queued_at)
                 VALUES (?1, ?2)",
                params![path, queued_at],
            )?;
        }
        transaction.commit()?;
        let cleanup = Self::drain_blob_cleanup_sync(&conn, &self.blobs_dir);
        drop(conn);
        cleanup?;
        Ok(true)
    }

    // ── Drafts ──────────────────────────────────────────────────────────────

    pub async fn create_draft(&self, draft: Draft) -> Result<Draft> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO drafts
             (id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
              reply_to_addrs, subject, text, html, headers_json, labels_json,
              attachments_json, send_at, status, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?17)",
            params![
                draft.id,
                draft.inbox_id,
                draft.thread_id,
                draft.client_id,
                json_string(&draft.to_addrs),
                json_string(&draft.cc_addrs),
                json_string(&draft.bcc_addrs),
                json_string(&draft.reply_to_addrs),
                draft.subject,
                draft.text,
                draft.html,
                json_string(&draft.headers),
                json_string(&draft.labels),
                json_string(&draft.attachments),
                draft.send_at,
                draft.status,
                draft.created_at,
            ],
        )
        .context("inserting draft")?;
        Ok(draft)
    }

    pub async fn draft_by_client_id(&self, client_id: &str) -> Result<Option<Draft>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
                    reply_to_addrs, subject, text, html, headers_json, labels_json,
                    attachments_json, send_at, status, created_at, updated_at
             FROM drafts WHERE client_id = ?1",
            params![client_id],
            row_to_draft,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn list_drafts(
        &self,
        inbox_id: &str,
        labels: &[String],
        limit: u32,
    ) -> Result<Vec<Draft>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
                    reply_to_addrs, subject, text, html, headers_json, labels_json,
                    attachments_json, send_at, status, created_at, updated_at
             FROM drafts WHERE inbox_id = ?1 ORDER BY updated_at DESC LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![inbox_id, limit], row_to_draft)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter(|draft| labels.iter().all(|label| draft.labels.contains(label)))
            .collect())
    }

    pub async fn list_due_drafts(&self, now: &str, limit: u32) -> Result<Vec<Draft>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
                    reply_to_addrs, subject, text, html, headers_json, labels_json,
                    attachments_json, send_at, status, created_at, updated_at
             FROM drafts
             WHERE status = 'scheduled' AND send_at IS NOT NULL AND send_at <= ?1
             ORDER BY send_at ASC LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![now, limit], row_to_draft)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_draft(&self, id: &str) -> Result<Option<Draft>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
                    reply_to_addrs, subject, text, html, headers_json, labels_json,
                    attachments_json, send_at, status, created_at, updated_at
             FROM drafts WHERE id = ?1",
            params![id],
            row_to_draft,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn update_draft(&self, draft: &Draft) -> Result<bool> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE drafts SET thread_id=?2, to_addrs=?3, cc_addrs=?4, bcc_addrs=?5,
                reply_to_addrs=?6, subject=?7, text=?8, html=?9, headers_json=?10,
                labels_json=?11, attachments_json=?12, send_at=?13, status=?14,
                updated_at=?15 WHERE id=?1",
            params![
                draft.id,
                draft.thread_id,
                json_string(&draft.to_addrs),
                json_string(&draft.cc_addrs),
                json_string(&draft.bcc_addrs),
                json_string(&draft.reply_to_addrs),
                draft.subject,
                draft.text,
                draft.html,
                json_string(&draft.headers),
                json_string(&draft.labels),
                json_string(&draft.attachments),
                draft.send_at,
                draft.status,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(changed > 0)
    }

    pub async fn delete_draft(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        Ok(conn.execute("DELETE FROM drafts WHERE id = ?1", params![id])? > 0)
    }

    // ── Webhooks ────────────────────────────────────────────────────────────

    pub async fn create_webhook(&self, webhook: Webhook) -> Result<Webhook> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO webhooks
             (id, url, secret, event_types, headers_json, inbox_ids, pod_ids,
              client_id, enabled, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
            params![
                webhook.id,
                webhook.url,
                webhook.secret,
                json_string(&webhook.event_types),
                json_string(&webhook.headers),
                json_string(&webhook.inbox_ids),
                json_string(&webhook.pod_ids),
                webhook.client_id,
                i64::from(webhook.enabled),
                webhook.created_at,
            ],
        )
        .context("inserting webhook")?;
        Ok(webhook)
    }

    pub async fn webhook_by_client_id(&self, client_id: &str) -> Result<Option<Webhook>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, url, secret, event_types, headers_json, inbox_ids, pod_ids,
                    client_id, enabled, created_at, updated_at
             FROM webhooks WHERE client_id = ?1",
            params![client_id],
            row_to_webhook,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn list_webhooks(&self) -> Result<Vec<Webhook>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, url, secret, event_types, headers_json, inbox_ids, pod_ids,
                    client_id, enabled, created_at, updated_at
             FROM webhooks ORDER BY created_at DESC",
        )?;
        let rows = statement
            .query_map([], row_to_webhook)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_webhook(&self, id: &str) -> Result<Option<Webhook>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, url, secret, event_types, headers_json, inbox_ids, pod_ids,
                    client_id, enabled, created_at, updated_at
             FROM webhooks WHERE id = ?1",
            params![id],
            row_to_webhook,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn update_webhook(&self, webhook: &Webhook) -> Result<bool> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE webhooks SET url=?2, event_types=?3, headers_json=?4, inbox_ids=?5,
                pod_ids=?6, enabled=?7, updated_at=?8 WHERE id=?1",
            params![
                webhook.id,
                webhook.url,
                json_string(&webhook.event_types),
                json_string(&webhook.headers),
                json_string(&webhook.inbox_ids),
                json_string(&webhook.pod_ids),
                i64::from(webhook.enabled),
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(changed > 0)
    }

    pub async fn delete_webhook(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        Ok(conn.execute("DELETE FROM webhooks WHERE id = ?1", params![id])? > 0)
    }

    pub async fn matching_webhooks(
        &self,
        event_type: &str,
        inbox_id: Option<&str>,
        pod_id: Option<&str>,
    ) -> Result<Vec<Webhook>> {
        let all = self.list_webhooks().await?;
        Ok(all
            .into_iter()
            .filter(|webhook| webhook.enabled)
            .filter(|webhook| {
                webhook.event_types.is_empty()
                    || webhook.event_types.iter().any(|value| value == event_type)
            })
            .filter(|webhook| {
                (webhook.inbox_ids.is_empty()
                    || inbox_id.is_some_and(|id| webhook.inbox_ids.iter().any(|v| v == id)))
                    && (webhook.pod_ids.is_empty()
                        || pod_id.is_some_and(|id| webhook.pod_ids.iter().any(|v| v == id)))
            })
            .collect())
    }

    // ── Events and webhook delivery records ─────────────────────────────────

    pub async fn insert_event(&self, event: &MailEvent) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO mail_events
             (event_id, event_type, inbox_id, message_id, payload, created_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                event.event_id,
                event.event_type,
                event.inbox_id,
                event.message_id,
                serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_owned()),
                event.created_at,
            ],
        )?;
        Ok(())
    }

    pub async fn list_events(&self, inbox_id: Option<&str>, limit: u32) -> Result<Vec<MailEvent>> {
        let conn = self.conn.lock().await;
        let mut statement = if inbox_id.is_some() {
            conn.prepare(
                "SELECT event_id, event_type, inbox_id, message_id, payload, created_at
                 FROM mail_events WHERE inbox_id = ?1
                 ORDER BY created_at DESC LIMIT ?2",
            )?
        } else {
            conn.prepare(
                "SELECT event_id, event_type, inbox_id, message_id, payload, created_at
                 FROM mail_events ORDER BY created_at DESC LIMIT ?1",
            )?
        };
        let rows = if let Some(inbox_id) = inbox_id {
            statement
                .query_map(params![inbox_id, limit], row_to_event)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            statement
                .query_map(params![limit], row_to_event)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }

    pub async fn create_delivery_if_new(
        &self,
        webhook_id: &str,
        event_id: &str,
    ) -> Result<Option<String>> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().await;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO webhook_deliveries
             (id, webhook_id, event_id, status, attempts, created_at, updated_at)
             VALUES (?1,?2,?3,'pending',0,?4,?4)",
            params![id, webhook_id, event_id, now],
        )?;
        Ok((inserted > 0).then_some(id))
    }

    pub async fn update_delivery(
        &self,
        id: &str,
        status: &str,
        attempts: u32,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE webhook_deliveries SET status=?2, attempts=?3, last_error=?4,
                updated_at=?5 WHERE id=?1",
            params![id, status, attempts, last_error, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub async fn list_webhook_deliveries(
        &self,
        webhook_id: &str,
        limit: u32,
    ) -> Result<Vec<WebhookDelivery>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, webhook_id, event_id, status, attempts, last_error,
                    created_at, updated_at
             FROM webhook_deliveries WHERE webhook_id = ?1
             ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![webhook_id, limit], |row| {
                Ok(WebhookDelivery {
                    id: row.get(0)?,
                    webhook_id: row.get(1)?,
                    event_id: row.get(2)?,
                    status: row.get(3)?,
                    attempts: row.get::<_, i64>(4)? as u32,
                    last_error: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ── Lists ───────────────────────────────────────────────────────────────

    pub async fn create_list_entry(&self, entry: ListEntry) -> Result<ListEntry> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO list_entries
             (id, scope, scope_id, direction, list_type, entry, entry_type, reason, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                entry.id,
                entry.scope,
                entry.scope_id,
                entry.direction,
                entry.list_type,
                entry.entry,
                entry.entry_type,
                entry.reason,
                entry.created_at,
            ],
        )
        .context("inserting list entry")?;
        Ok(entry)
    }

    pub async fn list_entries(
        &self,
        scope: &str,
        scope_id: &str,
        direction: &str,
        list_type: &str,
    ) -> Result<Vec<ListEntry>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, scope, scope_id, direction, list_type, entry, entry_type,
                    reason, created_at
             FROM list_entries
             WHERE scope=?1 AND scope_id=?2 AND direction=?3 AND list_type=?4
             ORDER BY entry ASC",
        )?;
        let rows = statement
            .query_map(
                params![scope, scope_id, direction, list_type],
                row_to_list_entry,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn list_entries_for_direction(&self, direction: &str) -> Result<Vec<ListEntry>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, scope, scope_id, direction, list_type, entry, entry_type,
                    reason, created_at
             FROM list_entries WHERE direction = ?1 ORDER BY created_at ASC",
        )?;
        let rows = statement
            .query_map(params![direction], row_to_list_entry)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_list_entry(
        &self,
        scope: &str,
        scope_id: &str,
        direction: &str,
        list_type: &str,
        entry: &str,
    ) -> Result<Option<ListEntry>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, scope, scope_id, direction, list_type, entry, entry_type,
                    reason, created_at
             FROM list_entries
             WHERE scope=?1 AND scope_id=?2 AND direction=?3 AND list_type=?4 AND entry=?5",
            params![scope, scope_id, direction, list_type, entry],
            row_to_list_entry,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn delete_list_entry(
        &self,
        scope: &str,
        scope_id: &str,
        direction: &str,
        list_type: &str,
        entry: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().await;
        Ok(conn.execute(
            "DELETE FROM list_entries
             WHERE scope=?1 AND scope_id=?2 AND direction=?3 AND list_type=?4 AND entry=?5",
            params![scope, scope_id, direction, list_type, entry],
        )? > 0)
    }

    pub async fn address_allowed(
        &self,
        inbox: &Inbox,
        direction: &str,
        address: &str,
    ) -> Result<bool> {
        let mut scopes = vec![("inbox", inbox.id.as_str())];
        if let Some(pod_id) = inbox.pod_id.as_deref() {
            scopes.push(("pod", pod_id));
        }
        scopes.push(("global", "*"));
        let domain = address
            .rsplit_once('@')
            .map(|(_, value)| value)
            .unwrap_or("");
        for (scope, scope_id) in scopes {
            let allow = self
                .list_entries(scope, scope_id, direction, "allow")
                .await?;
            let block = self
                .list_entries(scope, scope_id, direction, "block")
                .await?;
            let matches = |entry: &ListEntry| {
                entry.entry.eq_ignore_ascii_case(address)
                    || (entry.entry_type == "domain" && entry.entry.eq_ignore_ascii_case(domain))
            };
            if block.iter().any(matches) {
                return Ok(false);
            }
            if !allow.is_empty() {
                return Ok(allow.iter().any(matches));
            }
        }
        Ok(true)
    }

    // ── Pods and domains ────────────────────────────────────────────────────

    pub async fn create_pod(&self, pod: MailPod) -> Result<MailPod> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO pods (id, name, client_id, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?4)",
            params![pod.id, pod.name, pod.client_id, pod.created_at],
        )?;
        Ok(pod)
    }

    pub async fn pod_by_client_id(&self, client_id: &str) -> Result<Option<MailPod>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, name, client_id, created_at, updated_at
             FROM pods WHERE client_id=?1",
            params![client_id],
            row_to_pod,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn list_pods(&self) -> Result<Vec<MailPod>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, name, client_id, created_at, updated_at
             FROM pods ORDER BY created_at DESC",
        )?;
        let rows = statement
            .query_map([], row_to_pod)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_pod(&self, id: &str) -> Result<Option<MailPod>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, name, client_id, created_at, updated_at FROM pods WHERE id=?1",
            params![id],
            row_to_pod,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn delete_pod(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        let children: i64 = conn.query_row(
            "SELECT COUNT(*) FROM inboxes WHERE pod_id=?1",
            params![id],
            |row| row.get(0),
        )?;
        if children > 0 {
            bail!("pod has existing inboxes");
        }
        Ok(conn.execute("DELETE FROM pods WHERE id=?1", params![id])? > 0)
    }

    pub async fn create_domain(&self, domain: MailDomain) -> Result<MailDomain> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO domains
             (id, domain, status, subdomains_enabled, tracking_enabled, records_json,
              pod_id, client_id, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
            params![
                domain.id,
                domain.domain,
                domain.status,
                i64::from(domain.subdomains_enabled),
                i64::from(domain.tracking_enabled),
                json_string(&domain.records),
                domain.pod_id,
                domain.client_id,
                domain.created_at,
            ],
        )?;
        Ok(domain)
    }

    pub async fn list_domains(&self) -> Result<Vec<MailDomain>> {
        let conn = self.conn.lock().await;
        let mut statement = conn.prepare(
            "SELECT id, domain, status, subdomains_enabled, tracking_enabled, records_json,
                    pod_id, client_id, created_at, updated_at
             FROM domains ORDER BY created_at DESC",
        )?;
        let rows = statement
            .query_map([], row_to_domain)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_domain(&self, id: &str) -> Result<Option<MailDomain>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, domain, status, subdomains_enabled, tracking_enabled, records_json,
                    pod_id, client_id, created_at, updated_at
             FROM domains WHERE id=?1",
            params![id],
            row_to_domain,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn update_domain(&self, domain: &MailDomain) -> Result<bool> {
        let conn = self.conn.lock().await;
        Ok(conn.execute(
            "UPDATE domains SET status=?2, subdomains_enabled=?3, tracking_enabled=?4,
                records_json=?5, updated_at=?6 WHERE id=?1",
            params![
                domain.id,
                domain.status,
                i64::from(domain.subdomains_enabled),
                i64::from(domain.tracking_enabled),
                json_string(&domain.records),
                Utc::now().to_rfc3339(),
            ],
        )? > 0)
    }

    pub async fn delete_domain(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        Ok(conn.execute("DELETE FROM domains WHERE id=?1", params![id])? > 0)
    }

    // ── Idempotency ─────────────────────────────────────────────────────────

    pub async fn get_idempotency(
        &self,
        key: &str,
        operation: &str,
        request_hash: &str,
    ) -> Result<Option<serde_json::Value>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT operation, request_hash, response_json, expires_at
                 FROM mail_idempotency WHERE key=?1",
                params![key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((stored_operation, stored_hash, response, expires_at)) = row else {
            return Ok(None);
        };
        if expires_at <= Utc::now().to_rfc3339() {
            drop(conn);
            self.delete_idempotency(key).await?;
            return Ok(None);
        }
        if stored_operation != operation || stored_hash != request_hash {
            bail!("idempotency key was reused with a different request");
        }
        Ok(serde_json::from_str(&response).ok())
    }

    pub async fn put_idempotency(
        &self,
        key: &str,
        operation: &str,
        request_hash: &str,
        response: &serde_json::Value,
    ) -> Result<()> {
        let now = Utc::now();
        let expires = now + chrono::Duration::hours(24);
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO mail_idempotency
             (key, operation, request_hash, response_json, created_at, expires_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                key,
                operation,
                request_hash,
                serde_json::to_string(response).unwrap_or_else(|_| "null".to_owned()),
                now.to_rfc3339(),
                expires.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    async fn delete_idempotency(&self, key: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM mail_idempotency WHERE key=?1", params![key])?;
        Ok(())
    }

    /// Resolve an attachment's metadata + absolute blob path (for the download
    /// route). Returns `None` if the attachment id is unknown.
    pub async fn attachment_path(&self, att_id: &str) -> Result<Option<(AttachmentMeta, PathBuf)>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT id, filename, content_type, size, blob_path, inline, content_id
                 FROM attachments WHERE id = ?1",
                params![att_id],
                |r| {
                    Ok((
                        AttachmentMeta {
                            id: r.get(0)?,
                            filename: r.get(1)?,
                            content_type: r.get(2)?,
                            size: r.get::<_, i64>(3)? as u64,
                            inline: r.get::<_, i64>(5)? != 0,
                            content_id: r.get(6)?,
                        },
                        r.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        Ok(row.map(|(meta, rel)| (meta, self.blobs_dir.join(rel))))
    }
}

#[cfg(test)]
impl MailStore {
    /// Seed a deterministic inbox id for low-level tests that exercise message
    /// persistence without going through the random-id HTTP create handler.
    pub(crate) async fn ensure_test_inbox(&self, id: &str) {
        let conn = self.conn.lock().await;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR IGNORE INTO inboxes
             (id, name, address, provider, inbound_secret, metadata_json,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, 'webhook', ?4, '{}', ?5, ?5)",
            params![
                id,
                id,
                format!("{id}@x.com"),
                uuid::Uuid::new_v4().simple().to_string(),
                now,
            ],
        )
        .expect("seed test inbox");
    }
}

fn row_to_message(r: &rusqlite::Row<'_>) -> rusqlite::Result<EmailMessage> {
    let to_json: String = r.get(8)?;
    let cc_json: String = r.get(9)?;
    let bcc_json: String = r.get(10)?;
    let reply_to_json: String = r.get(11)?;
    let references_json: String = r.get(6)?;
    let headers_json: String = r.get(18)?;
    let labels_json: String = r.get(19)?;
    Ok(EmailMessage {
        id: r.get(0)?,
        inbox_id: r.get(1)?,
        direction: r.get(2)?,
        message_id: r.get(3)?,
        in_reply_to: r.get(4)?,
        thread_id: r.get(5)?,
        references: json_vec(&references_json),
        from_addr: r.get(7)?,
        to_addrs: json_vec(&to_json),
        cc_addrs: json_vec(&cc_json),
        bcc_addrs: json_vec(&bcc_json),
        reply_to_addrs: json_vec(&reply_to_json),
        subject: r.get(12)?,
        text: r.get(13)?,
        html: r.get(14)?,
        extracted_text: r.get(15)?,
        extracted_html: r.get(16)?,
        preview: r.get(17)?,
        headers: json_string_map(&headers_json),
        labels: json_vec(&labels_json),
        status: r.get(20)?,
        read: r.get::<_, i64>(21)? != 0,
        opened_at: r.get(22)?,
        provider_message_id: r.get(23)?,
        attachments: Vec::new(),
        raw_size: r.get::<_, i64>(25)? as u64,
        created_at: r.get(26)?,
        updated_at: r.get(27)?,
    })
}

fn row_to_draft(r: &rusqlite::Row<'_>) -> rusqlite::Result<Draft> {
    Ok(Draft {
        id: r.get(0)?,
        inbox_id: r.get(1)?,
        thread_id: r.get(2)?,
        client_id: r.get(3)?,
        to_addrs: json_vec(&r.get::<_, String>(4)?),
        cc_addrs: json_vec(&r.get::<_, String>(5)?),
        bcc_addrs: json_vec(&r.get::<_, String>(6)?),
        reply_to_addrs: json_vec(&r.get::<_, String>(7)?),
        subject: r.get(8)?,
        text: r.get(9)?,
        html: r.get(10)?,
        headers: json_string_map(&r.get::<_, String>(11)?),
        labels: json_vec(&r.get::<_, String>(12)?),
        attachments: json_vec(&r.get::<_, String>(13)?),
        send_at: r.get(14)?,
        status: r.get(15)?,
        created_at: r.get(16)?,
        updated_at: r.get(17)?,
    })
}

fn row_to_webhook(r: &rusqlite::Row<'_>) -> rusqlite::Result<Webhook> {
    Ok(Webhook {
        id: r.get(0)?,
        url: r.get(1)?,
        secret: r.get(2)?,
        event_types: json_vec(&r.get::<_, String>(3)?),
        headers: json_string_map(&r.get::<_, String>(4)?),
        inbox_ids: json_vec(&r.get::<_, String>(5)?),
        pod_ids: json_vec(&r.get::<_, String>(6)?),
        client_id: r.get(7)?,
        enabled: r.get::<_, i64>(8)? != 0,
        created_at: r.get(9)?,
        updated_at: r.get(10)?,
    })
}

fn row_to_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<MailEvent> {
    let raw: String = r.get(4)?;
    Ok(MailEvent {
        event_id: r.get(0)?,
        event_type: r.get(1)?,
        inbox_id: r.get(2)?,
        message_id: r.get(3)?,
        payload: serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null),
        created_at: r.get(5)?,
    })
}

fn row_to_list_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<ListEntry> {
    Ok(ListEntry {
        id: r.get(0)?,
        scope: r.get(1)?,
        scope_id: r.get(2)?,
        direction: r.get(3)?,
        list_type: r.get(4)?,
        entry: r.get(5)?,
        entry_type: r.get(6)?,
        reason: r.get(7)?,
        created_at: r.get(8)?,
    })
}

fn row_to_pod(r: &rusqlite::Row<'_>) -> rusqlite::Result<MailPod> {
    Ok(MailPod {
        id: r.get(0)?,
        name: r.get(1)?,
        client_id: r.get(2)?,
        created_at: r.get(3)?,
        updated_at: r.get(4)?,
    })
}

fn row_to_domain(r: &rusqlite::Row<'_>) -> rusqlite::Result<MailDomain> {
    Ok(MailDomain {
        id: r.get(0)?,
        domain: r.get(1)?,
        status: r.get(2)?,
        subdomains_enabled: r.get::<_, i64>(3)? != 0,
        tracking_enabled: r.get::<_, i64>(4)? != 0,
        records: json_vec(&r.get::<_, String>(5)?),
        pod_id: r.get(6)?,
        client_id: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
    })
}

fn load_attachments(conn: &Connection, message_id: &str) -> Result<Vec<AttachmentMeta>> {
    let mut stmt = conn.prepare(
        "SELECT id, filename, content_type, size, inline, content_id
         FROM attachments WHERE message_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![message_id], |r| {
            Ok(AttachmentMeta {
                id: r.get(0)?,
                filename: r.get(1)?,
                content_type: r.get(2)?,
                size: r.get::<_, i64>(3)? as u64,
                inline: r.get::<_, i64>(4)? != 0,
                content_id: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn json_vec<T: serde::de::DeserializeOwned>(value: &str) -> Vec<T> {
    serde_json::from_str(value).unwrap_or_default()
}

fn json_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "[]".to_owned())
}

fn json_map(value: String) -> BTreeMap<String, serde_json::Value> {
    serde_json::from_str(&value).unwrap_or_default()
}

fn json_string_map(value: &str) -> BTreeMap<String, String> {
    serde_json::from_str(value).unwrap_or_default()
}

/// Point `RYU_DIR` at a temp dir so the sidecar's default path never writes to the
/// real `~/.ryu`. Every test store MUST be built via [`fresh_store`] so this is set
/// before the OnceLock is first initialized.
#[cfg(test)]
pub(crate) fn test_ryu_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("ryu-mail-backend-tests");
    std::env::set_var("RYU_DIR", &dir);
    dir
}

/// A fresh store on a unique on-disk SQLite file.
#[cfg(test)]
pub(crate) fn fresh_store() -> MailStore {
    test_ryu_dir();
    let db = std::env::temp_dir().join(format!("ryu-mail-test-{}.db", uuid::Uuid::new_v4()));
    MailStore::open(db).expect("open store")
}

#[cfg(test)]
mod tests {
    use super::{fresh_store, MailStore, RawAttachment};
    use crate::{EmailMessage, InboxProvider};
    use std::collections::BTreeMap;

    fn sample_message(id: &str, inbox_id: &str, created_at: &str) -> EmailMessage {
        EmailMessage {
            id: id.to_string(),
            inbox_id: inbox_id.to_string(),
            direction: "inbound".to_string(),
            message_id: format!("<{id}@x.com>"),
            in_reply_to: None,
            thread_id: Some(format!("<{id}@x.com>")),
            references: Vec::new(),
            from_addr: "sender@x.com".to_string(),
            to_addrs: vec!["a@x.com".to_string(), "b@x.com".to_string()],
            cc_addrs: vec!["c@x.com".to_string()],
            bcc_addrs: Vec::new(),
            reply_to_addrs: Vec::new(),
            subject: "hi".to_string(),
            text: Some("body".to_string()),
            html: None,
            extracted_text: None,
            extracted_html: None,
            preview: Some("body".to_owned()),
            headers: BTreeMap::new(),
            labels: Vec::new(),
            status: "received".to_owned(),
            read: false,
            opened_at: None,
            raw_size: 0,
            provider_message_id: None,
            attachments: Vec::new(),
            created_at: created_at.to_string(),
            updated_at: created_at.to_string(),
        }
    }

    #[tokio::test]
    async fn create_and_get_inbox_round_trips_all_fields() {
        let store = fresh_store();
        let created = store
            .create_inbox("Support", "help@node.example", InboxProvider::Webhook)
            .await
            .unwrap();
        assert!(!created.id.is_empty());
        assert!(!created.inbound_secret.is_empty());
        assert_eq!(created.provider, InboxProvider::Webhook);

        let got = store.get_inbox(&created.id).await.unwrap().unwrap();
        assert_eq!(got.id, created.id);
        assert_eq!(got.name, "Support");
        assert_eq!(got.address, "help@node.example");
        assert_eq!(got.inbound_secret, created.inbound_secret);
        assert_eq!(got.provider, InboxProvider::Webhook);
    }

    #[tokio::test]
    async fn imap_provider_survives_the_string_round_trip() {
        // Exercises InboxProvider::as_str on write + from_str on read.
        let store = fresh_store();
        let created = store
            .create_inbox("Poller", "in@node.example", InboxProvider::Imap)
            .await
            .unwrap();
        let got = store.get_inbox(&created.id).await.unwrap().unwrap();
        assert_eq!(got.provider, InboxProvider::Imap);
    }

    #[tokio::test]
    async fn get_unknown_inbox_is_none() {
        let store = fresh_store();
        assert!(store.get_inbox("does-not-exist").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_inboxes_returns_every_created_inbox() {
        let store = fresh_store();
        for i in 0..3 {
            store
                .create_inbox(
                    &format!("i{i}"),
                    &format!("i{i}@x.com"),
                    InboxProvider::Webhook,
                )
                .await
                .unwrap();
        }
        let all = store.list_inboxes().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn rename_inbox_changes_the_name_only() {
        let store = fresh_store();
        let created = store
            .create_inbox("Old", "x@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        store.rename_inbox(&created.id, "New").await.unwrap();
        let got = store.get_inbox(&created.id).await.unwrap().unwrap();
        assert_eq!(got.name, "New");
        assert_eq!(got.address, "x@x.com");
        assert_eq!(got.inbound_secret, created.inbound_secret);
    }

    #[tokio::test]
    async fn rotate_secret_returns_a_new_value_and_persists_it() {
        let store = fresh_store();
        let created = store
            .create_inbox("Rot", "x@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let rotated = store.rotate_secret(&created.id).await.unwrap();
        assert_ne!(rotated, created.inbound_secret);
        let got = store.get_inbox(&created.id).await.unwrap().unwrap();
        assert_eq!(got.inbound_secret, rotated);
    }

    #[tokio::test]
    async fn delete_inbox_removes_the_inbox_and_its_messages() {
        let store = fresh_store();
        let created = store
            .create_inbox("Del", "x@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        store
            .insert_message(
                sample_message("m1", &created.id, "2020-01-01T00:00:00Z"),
                Vec::new(),
            )
            .await
            .unwrap();
        store.delete_inbox(&created.id).await.unwrap();
        assert!(store.get_inbox(&created.id).await.unwrap().is_none());
        assert!(store
            .list_messages(&created.id, 200)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn delete_inbox_removes_attachment_rows_and_only_unreferenced_blobs() {
        let store = fresh_store();
        let doomed = store
            .create_inbox("Doomed", "doomed@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let kept = store
            .create_inbox("Kept", "kept@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let shared = || RawAttachment {
            filename: "shared.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            bytes: b"shared-bytes".to_vec(),
            inline: false,
            content_id: None,
        };
        let deleted_message = store
            .insert_message(
                sample_message("deleted-message", &doomed.id, "2020-01-01T00:00:00Z"),
                vec![
                    shared(),
                    RawAttachment {
                        filename: "private.bin".to_string(),
                        content_type: "application/octet-stream".to_string(),
                        bytes: b"private-bytes".to_vec(),
                        inline: false,
                        content_id: None,
                    },
                ],
            )
            .await
            .unwrap();
        let kept_message = store
            .insert_message(
                sample_message("kept-message", &kept.id, "2020-01-01T00:00:00Z"),
                vec![shared()],
            )
            .await
            .unwrap();
        let deleted_shared_id = &deleted_message.attachments[0].id;
        let deleted_private_id = &deleted_message.attachments[1].id;
        let kept_shared_id = &kept_message.attachments[0].id;
        let shared_path = store
            .attachment_path(kept_shared_id)
            .await
            .unwrap()
            .unwrap()
            .1;
        let private_path = store
            .attachment_path(deleted_private_id)
            .await
            .unwrap()
            .unwrap()
            .1;

        store.delete_inbox(&doomed.id).await.unwrap();

        assert!(store
            .attachment_path(deleted_shared_id)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .attachment_path(deleted_private_id)
            .await
            .unwrap()
            .is_none());
        assert!(
            !private_path.exists(),
            "private attachment bytes must be deleted"
        );
        assert!(
            shared_path.exists(),
            "a still-referenced blob must be retained"
        );
        assert!(store
            .attachment_path(kept_shared_id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn insert_rejects_a_deleted_inbox_before_writing_attachment_bytes() {
        let store = fresh_store();
        let inbox = store
            .create_inbox("Race", "race@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        store.delete_inbox(&inbox.id).await.unwrap();

        let error = store
            .insert_message(
                sample_message("late", &inbox.id, "2020-01-01T00:00:00Z"),
                vec![RawAttachment {
                    filename: "late.bin".to_string(),
                    content_type: "application/octet-stream".to_string(),
                    bytes: b"late-bytes".to_vec(),
                    inline: false,
                    content_id: None,
                }],
            )
            .await
            .expect_err("a deleted inbox cannot accept a late delivery");
        assert!(error.to_string().contains("does not exist"));
        assert!(store.get_message("late").await.unwrap().is_none());
        let entries = std::fs::read_dir(&store.blobs_dir)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert!(
            entries.is_empty(),
            "the rejected delivery must not leak a blob"
        );
    }

    #[tokio::test]
    async fn insert_and_get_message_round_trips_address_lists() {
        let store = fresh_store();
        store.ensure_test_inbox("inbox1").await;
        let stored = store
            .insert_message(
                sample_message("m1", "inbox1", "2020-01-01T00:00:00Z"),
                Vec::new(),
            )
            .await
            .unwrap();
        let got = store.get_message(&stored.id).await.unwrap().unwrap();
        assert_eq!(
            got.to_addrs,
            vec!["a@x.com".to_string(), "b@x.com".to_string()]
        );
        assert_eq!(got.cc_addrs, vec!["c@x.com".to_string()]);
        assert_eq!(got.subject, "hi");
        assert_eq!(got.direction, "inbound");
        assert_eq!(got.text.as_deref(), Some("body"));
    }

    #[tokio::test]
    async fn get_unknown_message_is_none() {
        let store = fresh_store();
        assert!(store.get_message("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_messages_orders_by_created_at_descending() {
        let store = fresh_store();
        store.ensure_test_inbox("ibx").await;
        // Explicit distinct timestamps so ORDER BY is deterministic (no now()-tie).
        store
            .insert_message(
                sample_message("old", "ibx", "2020-01-01T00:00:00Z"),
                Vec::new(),
            )
            .await
            .unwrap();
        store
            .insert_message(
                sample_message("new", "ibx", "2022-01-01T00:00:00Z"),
                Vec::new(),
            )
            .await
            .unwrap();
        let list = store.list_messages("ibx", 200).await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, "new", "newest first");
        assert_eq!(list[1].id, "old");
    }

    #[tokio::test]
    async fn list_messages_respects_the_limit() {
        let store = fresh_store();
        store.ensure_test_inbox("ibx").await;
        for i in 0..5 {
            let ts = format!("2020-01-0{}T00:00:00Z", i + 1);
            store
                .insert_message(sample_message(&format!("m{i}"), "ibx", &ts), Vec::new())
                .await
                .unwrap();
        }
        assert_eq!(store.list_messages("ibx", 2).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_messages_is_scoped_to_one_inbox() {
        let store = fresh_store();
        store.ensure_test_inbox("ibx-a").await;
        store.ensure_test_inbox("ibx-b").await;
        store
            .insert_message(
                sample_message("a", "ibx-a", "2020-01-01T00:00:00Z"),
                Vec::new(),
            )
            .await
            .unwrap();
        store
            .insert_message(
                sample_message("b", "ibx-b", "2020-01-01T00:00:00Z"),
                Vec::new(),
            )
            .await
            .unwrap();
        let a = store.list_messages("ibx-a", 200).await.unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].id, "a");
    }

    #[tokio::test]
    async fn insert_message_writes_the_blob_and_attachment_metadata() {
        let store = fresh_store();
        store.ensure_test_inbox("ibx").await;
        let att = RawAttachment {
            filename: "doc.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            bytes: b"PDF-BYTES-HERE".to_vec(),
            inline: false,
            content_id: None,
        };
        let stored = store
            .insert_message(
                sample_message("m1", "ibx", "2020-01-01T00:00:00Z"),
                vec![att],
            )
            .await
            .unwrap();
        // The returned message carries the attachment meta with the byte size.
        assert_eq!(stored.attachments.len(), 1);
        assert_eq!(stored.attachments[0].filename, "doc.pdf");
        assert_eq!(stored.attachments[0].size, b"PDF-BYTES-HERE".len() as u64);

        // get_message re-loads the same metadata from the attachments table.
        let got = store.get_message(&stored.id).await.unwrap().unwrap();
        assert_eq!(got.attachments.len(), 1);
        let att_id = &got.attachments[0].id;

        // attachment_path resolves the meta + an on-disk blob whose bytes match.
        let (meta, path) = store.attachment_path(att_id).await.unwrap().unwrap();
        assert_eq!(meta.content_type, "application/pdf");
        assert_eq!(std::fs::read(&path).unwrap(), b"PDF-BYTES-HERE");
    }

    #[tokio::test]
    async fn attachment_blobs_follow_the_database_when_the_data_dir_moves() {
        let root = std::env::temp_dir().join(format!("ryu-mail-relocate-{}", uuid::Uuid::new_v4()));
        let old_dir = root.join("old");
        let new_dir = root.join("new");
        std::fs::create_dir_all(&old_dir).unwrap();
        let old_db = old_dir.join("mail.db");
        let store = MailStore::open(old_db.clone()).unwrap();
        store.ensure_test_inbox("ibx").await;
        let stored = store
            .insert_message(
                sample_message("relocated", "ibx", "2020-01-01T00:00:00Z"),
                vec![RawAttachment {
                    filename: "note.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    bytes: b"relocation-safe".to_vec(),
                    inline: false,
                    content_id: None,
                }],
            )
            .await
            .unwrap();
        let old_blob_dir = old_dir.join("mail-blobs");
        drop(store);

        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::copy(&old_db, new_dir.join("mail.db")).unwrap();
        std::fs::create_dir_all(new_dir.join("mail-blobs")).unwrap();
        for entry in std::fs::read_dir(old_blob_dir).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(
                entry.path(),
                new_dir.join("mail-blobs").join(entry.file_name()),
            )
            .unwrap();
        }

        let relocated = MailStore::open(new_dir.join("mail.db")).unwrap();
        let attachment_id = &stored.attachments[0].id;
        let (_, path) = relocated
            .attachment_path(attachment_id)
            .await
            .unwrap()
            .unwrap();
        let expected_blob_dir = new_dir.join("mail-blobs");
        assert_eq!(path.parent(), Some(expected_blob_dir.as_path()));
        assert_eq!(std::fs::read(path).unwrap(), b"relocation-safe");
        drop(relocated);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn identical_attachment_bytes_are_content_addressed_to_one_blob() {
        let store = fresh_store();
        store.ensure_test_inbox("ibx").await;
        let mk = || RawAttachment {
            filename: "same.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            bytes: vec![7, 7, 7, 7],
            inline: false,
            content_id: None,
        };
        let stored = store
            .insert_message(
                sample_message("m1", "ibx", "2020-01-01T00:00:00Z"),
                vec![mk(), mk()],
            )
            .await
            .unwrap();
        assert_eq!(stored.attachments.len(), 2);
        // Two distinct attachment rows, but both point at the same sha256 blob path.
        let p0 = store
            .attachment_path(&stored.attachments[0].id)
            .await
            .unwrap()
            .unwrap()
            .1;
        let p1 = store
            .attachment_path(&stored.attachments[1].id)
            .await
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(p0, p1, "same bytes hash to the same blob file");
    }

    #[tokio::test]
    async fn attachment_path_unknown_is_none() {
        let store = fresh_store();
        assert!(store.attachment_path("nope").await.unwrap().is_none());
    }
}
