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
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use super::{AttachmentMeta, EmailMessage, Inbox, InboxProvider};

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
    blobs_dir: PathBuf,
}

/// A raw attachment to persist (bytes hashed + written to a blob file).
pub struct RawAttachment {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
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
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            tx,
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
                 created_at     TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS messages (
                 id                  TEXT PRIMARY KEY,
                 inbox_id            TEXT NOT NULL,
                 direction           TEXT NOT NULL,
                 message_id          TEXT NOT NULL,
                 in_reply_to         TEXT,
                 from_addr           TEXT NOT NULL,
                 to_addrs            TEXT NOT NULL,
                 cc_addrs            TEXT NOT NULL,
                 subject             TEXT NOT NULL,
                 text                TEXT,
                 html                TEXT,
                 provider_message_id TEXT,
                 created_at          TEXT NOT NULL,
                 FOREIGN KEY (inbox_id) REFERENCES inboxes(id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_messages_inbox
                 ON messages(inbox_id, created_at DESC);
             CREATE TABLE IF NOT EXISTS attachments (
                 id           TEXT PRIMARY KEY,
                 message_id   TEXT NOT NULL,
                 filename     TEXT NOT NULL,
                 content_type TEXT NOT NULL,
                 size         INTEGER NOT NULL,
                 blob_path    TEXT NOT NULL,
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
        Ok(())
    }

    /// Subscribe to freshly-stored messages (SSE fan-out).
    ///
    /// NOTE (tracer): the mail contract surface (`api::public_routes` +
    /// `protected_routes`) has no SSE endpoint, so this broadcast channel compiles
    /// but is inert in the sidecar. The live-mail fan-out lived outside
    /// `mail/api.rs` in Core and is out of scope for the tracer.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<EmailMessage> {
        self.tx.subscribe()
    }

    // ── Inboxes ─────────────────────────────────────────────────────────────

    pub async fn create_inbox(
        &self,
        name: &str,
        address: &str,
        provider: InboxProvider,
    ) -> Result<Inbox> {
        let inbox = Inbox {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            address: address.to_string(),
            provider,
            inbound_secret: uuid::Uuid::new_v4().simple().to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO inboxes (id, name, address, provider, inbound_secret, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                inbox.id,
                inbox.name,
                inbox.address,
                inbox.provider.as_str(),
                inbox.inbound_secret,
                inbox.created_at,
            ],
        )
        .context("inserting inbox")?;
        Ok(inbox)
    }

    pub async fn list_inboxes(&self) -> Result<Vec<Inbox>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, address, provider, inbound_secret, created_at
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
                    created_at: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_inbox(&self, id: &str) -> Result<Option<Inbox>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT id, name, address, provider, inbound_secret, created_at
                 FROM inboxes WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Inbox {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        address: r.get(2)?,
                        provider: InboxProvider::from_str(&r.get::<_, String>(3)?),
                        inbound_secret: r.get(4)?,
                        created_at: r.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub async fn rename_inbox(&self, id: &str, name: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE inboxes SET name = ?2 WHERE id = ?1",
            params![id, name],
        )?;
        Ok(())
    }

    /// Rotate the inbound HMAC secret; returns the new value.
    pub async fn rotate_secret(&self, id: &str) -> Result<String> {
        let secret = uuid::Uuid::new_v4().simple().to_string();
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE inboxes SET inbound_secret = ?2 WHERE id = ?1",
            params![id, secret],
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
        mut msg: EmailMessage,
        attachments: Vec<RawAttachment>,
    ) -> Result<EmailMessage> {
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
                },
                rel,
            ));
        }

        transaction
            .execute(
                "INSERT INTO messages (id, inbox_id, direction, message_id, in_reply_to,
                 from_addr, to_addrs, cc_addrs, subject, text, html,
                 provider_message_id, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    msg.id,
                    msg.inbox_id,
                    msg.direction,
                    msg.message_id,
                    msg.in_reply_to,
                    msg.from_addr,
                    serde_json::to_string(&msg.to_addrs).unwrap_or_else(|_| "[]".into()),
                    serde_json::to_string(&msg.cc_addrs).unwrap_or_else(|_| "[]".into()),
                    msg.subject,
                    msg.text,
                    msg.html,
                    msg.provider_message_id,
                    msg.created_at,
                ],
            )
            .context("inserting message")?;
        for (meta, rel) in &metas {
            transaction.execute(
                "INSERT INTO attachments (id, message_id, filename, content_type, size, blob_path)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    meta.id,
                    msg.id,
                    meta.filename,
                    meta.content_type,
                    meta.size as i64,
                    rel
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
            "SELECT id, inbox_id, direction, message_id, in_reply_to, from_addr,
                 to_addrs, cc_addrs, subject, text, html, provider_message_id, created_at
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
                "SELECT id, inbox_id, direction, message_id, in_reply_to, from_addr,
                     to_addrs, cc_addrs, subject, text, html, provider_message_id, created_at
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

    /// Resolve an attachment's metadata + absolute blob path (for the download
    /// route). Returns `None` if the attachment id is unknown.
    pub async fn attachment_path(&self, att_id: &str) -> Result<Option<(AttachmentMeta, PathBuf)>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT id, filename, content_type, size, blob_path
                 FROM attachments WHERE id = ?1",
                params![att_id],
                |r| {
                    Ok((
                        AttachmentMeta {
                            id: r.get(0)?,
                            filename: r.get(1)?,
                            content_type: r.get(2)?,
                            size: r.get::<_, i64>(3)? as u64,
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
        conn.execute(
            "INSERT OR IGNORE INTO inboxes
             (id, name, address, provider, inbound_secret, created_at)
             VALUES (?1, ?2, ?3, 'webhook', ?4, ?5)",
            params![
                id,
                id,
                format!("{id}@x.com"),
                uuid::Uuid::new_v4().simple().to_string(),
                Utc::now().to_rfc3339(),
            ],
        )
        .expect("seed test inbox");
    }
}

fn row_to_message(r: &rusqlite::Row<'_>) -> rusqlite::Result<EmailMessage> {
    let to_json: String = r.get(6)?;
    let cc_json: String = r.get(7)?;
    Ok(EmailMessage {
        id: r.get(0)?,
        inbox_id: r.get(1)?,
        direction: r.get(2)?,
        message_id: r.get(3)?,
        in_reply_to: r.get(4)?,
        from_addr: r.get(5)?,
        to_addrs: serde_json::from_str(&to_json).unwrap_or_default(),
        cc_addrs: serde_json::from_str(&cc_json).unwrap_or_default(),
        subject: r.get(8)?,
        text: r.get(9)?,
        html: r.get(10)?,
        provider_message_id: r.get(11)?,
        attachments: Vec::new(),
        created_at: r.get(12)?,
    })
}

fn load_attachments(conn: &Connection, message_id: &str) -> Result<Vec<AttachmentMeta>> {
    let mut stmt = conn.prepare(
        "SELECT id, filename, content_type, size FROM attachments WHERE message_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![message_id], |r| {
            Ok(AttachmentMeta {
                id: r.get(0)?,
                filename: r.get(1)?,
                content_type: r.get(2)?,
                size: r.get::<_, i64>(3)? as u64,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
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

    fn sample_message(id: &str, inbox_id: &str, created_at: &str) -> EmailMessage {
        EmailMessage {
            id: id.to_string(),
            inbox_id: inbox_id.to_string(),
            direction: "inbound".to_string(),
            message_id: format!("<{id}@x.com>"),
            in_reply_to: None,
            from_addr: "sender@x.com".to_string(),
            to_addrs: vec!["a@x.com".to_string(), "b@x.com".to_string()],
            cc_addrs: vec!["c@x.com".to_string()],
            subject: "hi".to_string(),
            text: Some("body".to_string()),
            html: None,
            provider_message_id: None,
            attachments: Vec::new(),
            created_at: created_at.to_string(),
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
