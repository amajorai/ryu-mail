//! SQLite-backed persistence for self-host inboxes
//! (`<data dir>/plugin-data/@ryu+mail/mail.db`).
//!
//! The sidecar resolves its own plugin data dir via `crate::paths::data_dir`
//! (`RYU_PLUGIN_DATA_DIR`, injected by Core), so it OWNS the store and Core never
//! opens it. Attachment bytes live on the filesystem beside the database under
//! `blobs/`, keyed by sha256.
//!
//! At rest, message and draft content is sealed per value (`encb:v1:`, store
//! `mail.db`, AAD bound to the row id) under the `@ryu/mail` plugin subkey:
//! subject, bodies (text, html, extracted text and html), preview, headers,
//! every address list, draft attachments, attachment file names, event
//! payloads and stored send and idempotency responses. Blobs (attachments and
//! raw MIME) are write-once `RYU-SF01` files whose name stays the SHA-256 of
//! the plaintext (dedup keeps working; the name is bound in the AAD and checked
//! on read). Ids, inbox ids, Message-ID/thread headers, labels, statuses and
//! timestamps stay plaintext: every SQL filter and ordering runs on them; text
//! search already runs in memory. Legacy plaintext rows are sealed by a
//! resumable migration on open (in the background for large stores), legacy
//! blobs are sealed in place on a background thread, and every connection runs
//! `secure_delete = ON`. See [`crate::seal_keys`] for the key states.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use ryu_crypto::content_sqlite::{
    enable_secure_delete, finish_store, migrate_columns, run_pending_vacuum, ColumnPlan, KeyKind,
};
use ryu_crypto::sealed_file::seal_file_in_place;
use ryu_crypto::{ContentContext, SealedFileWriter};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use crate::seal_keys::{sqlite_store_seal, KeySource, PluginKeys, StoreSeal};

/// The registered content-store name (part of every key derivation; never rename).
pub const STORE: &str = "mail.db";

/// Message columns sealed per value.
const MESSAGE_SEALED: [&str; 12] = [
    "from_addr",
    "to_addrs",
    "cc_addrs",
    "bcc_addrs",
    "reply_to_addrs",
    "subject",
    "text",
    "html",
    "extracted_text",
    "extracted_html",
    "preview",
    "headers_json",
];
/// Draft columns sealed per value.
const DRAFT_SEALED: [&str; 9] = [
    "to_addrs",
    "cc_addrs",
    "bcc_addrs",
    "reply_to_addrs",
    "subject",
    "text",
    "html",
    "headers_json",
    "attachments_json",
];
/// Stores with more messages than this migrate on a background thread.
const SYNC_MIGRATION_MAX_ROWS: i64 = 5_000;

fn ctx(table: &str, column: &str, id: &str) -> ContentContext {
    ContentContext::for_id(format!("{table}.{column}"), id)
}

/// The AAD of one content-addressed blob file: its name (the plaintext SHA-256).
fn blob_ctx(name: &str) -> ContentContext {
    ContentContext::new("blob").with("sha256", name)
}

/// Every sealed column, for the open-time migration.
pub fn column_plans() -> Result<Vec<ColumnPlan>> {
    let mut plans = Vec::new();
    for column in MESSAGE_SEALED {
        plans.push(ColumnPlan::text("messages", column, "id", KeyKind::Text)?);
    }
    for column in DRAFT_SEALED {
        plans.push(ColumnPlan::text("drafts", column, "id", KeyKind::Text)?);
    }
    plans.push(ColumnPlan::text(
        "attachments",
        "filename",
        "id",
        KeyKind::Text,
    )?);
    plans.push(ColumnPlan::text(
        "mail_events",
        "payload",
        "event_id",
        KeyKind::Text,
    )?);
    plans.push(ColumnPlan::text(
        "mail_send_claims",
        "response_json",
        "key",
        KeyKind::Text,
    )?);
    plans.push(ColumnPlan::text(
        "mail_idempotency",
        "response_json",
        "key",
        KeyKind::Text,
    )?);
    Ok(plans)
}

/// Below this many messages the migration runs inline at open (tests lower it).
fn sync_migration_max_rows() -> i64 {
    #[cfg(test)]
    if let Some(rows) = TEST_SYNC_MIGRATION_MAX_ROWS.with(std::cell::Cell::get) {
        return rows;
    }
    SYNC_MIGRATION_MAX_ROWS
}

#[cfg(test)]
thread_local! {
    static TEST_SYNC_MIGRATION_MAX_ROWS: std::cell::Cell<Option<i64>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Runs inside `read_blob` after the file is opened and before it is read
    /// (tests race the background sealer through it).
    static BLOB_READ_HOOK: std::cell::RefCell<Option<Box<dyn Fn(&std::path::Path)>>> =
        const { std::cell::RefCell::new(None) };
}

/// How a migration ends once its values are sealed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Finish {
    /// Inline at open, before the store serves anything: scrub freed pages and
    /// vacuum now.
    Now,
    /// On the background thread while the store serves traffic: never scrub or
    /// vacuum concurrently. `migrate_columns` already marked the store
    /// `vacuum_pending`, and `run_pending_vacuum` compacts it at the next start
    /// before the store serves requests.
    NextStart,
}

/// Seal every legacy plaintext column of `mail.db` (resumable, idempotent),
/// then scrub freed pages (or leave that to the next start). Returns how many
/// values were sealed.
fn migrate_content(
    conn: &mut Connection,
    path: &std::path::Path,
    seal: &StoreSeal,
    finish: Finish,
) -> Result<u64> {
    let Some(cipher) = seal.cipher() else {
        return Ok(0);
    };
    let report =
        migrate_columns(conn, cipher, &column_plans()?).context("sealing legacy mail.db rows")?;
    if report.unreadable > 0 {
        tracing::warn!(
            count = report.unreadable,
            "mail.db: values that do not open were left untouched"
        );
    }
    if report.sealed > 0 {
        tracing::info!(count = report.sealed, "mail.db: sealed legacy values");
        match finish {
            Finish::Now => {
                if let Err(error) = finish_store(conn, path, STORE) {
                    tracing::warn!("mail.db: scrubbing freed pages deferred: {error:#}");
                }
            }
            Finish::NextStart => tracing::info!(
                "mail.db: compaction of the freed plaintext pages runs at the next start"
            ),
        }
    }
    Ok(report.sealed)
}

use super::{
    AttachmentMeta, Draft, EmailMessage, Inbox, InboxProvider, ListEntry, MailDomain, MailEvent,
    MailPod, Webhook, WebhookDelivery,
};
use crate::seal::{self, SecretSealer};
use crate::webhooks::SignatureScheme;

/// How long the SHA-256 of an accepted timestamped inbound delivery is kept.
/// It must outlive the signature window (five minutes either side of the
/// receiver clock) so a captured request is refused for as long as its
/// timestamp could still pass; a day leaves room for clock corrections.
pub const INBOUND_TOMBSTONE_RETENTION_SECS: i64 = 86_400;

/// Returned (inside `anyhow::Error`) when an inbox address is already registered
/// on this node. Addresses compare case-insensitively.
#[derive(Debug)]
pub struct AddressTaken(pub String);

impl std::fmt::Display for AddressTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "inbox address {} is already registered", self.0)
    }
}

impl std::error::Error for AddressTaken {}

/// Lower-case and validate an inbox address: one `@`, a 1–64 char local part, a
/// dotted domain, no whitespace or control characters, at most 254 chars.
/// Returns `None` when the address is unusable.
pub fn normalize_inbox_address(raw: &str) -> Option<String> {
    let address = raw.trim().to_ascii_lowercase();
    if address.is_empty()
        || address.len() > 254
        || address
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';'))
    {
        return None;
    }
    let (local, domain) = address.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.contains('@')
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return None;
    }
    Some(address)
}

/// Begin a transaction that takes the write lock up front.
///
/// A large store seals its content on a second connection while the sidecar
/// serves traffic. A deferred transaction that reads first and writes later
/// fails at once with SQLITE_BUSY when a background batch commits between the
/// read and the first write (WAL cannot upgrade a stale read snapshot, and the
/// busy timeout does not apply). `BEGIN IMMEDIATE` waits on the busy timeout
/// instead, so every read-then-write transaction on the serving connection
/// starts here.
fn write_transaction(conn: &mut Connection) -> rusqlite::Result<Transaction<'_>> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
}

/// [`write_transaction`] for callers that hold only `&Connection`.
fn write_transaction_unchecked(conn: &Connection) -> rusqlite::Result<Transaction<'_>> {
    Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
}

fn default_db_path() -> PathBuf {
    crate::paths::data_dir().join("mail.db")
}

fn blobs_dir_for_db(path: &std::path::Path) -> PathBuf {
    let parent = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    // The shipped database is named `mail.db`; its blobs live in `blobs/` beside
    // it. Tests and callers that open a second database in the same parent get a
    // private namespace so one store's startup orphan sweep can never delete
    // another store's attachments.
    let suffix = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| *stem != "mail")
        .map(|stem| format!("-{stem}"))
        .unwrap_or_default();
    parent.join(format!("blobs{suffix}"))
}

/// SQLite-backed inbox store. Cheap to clone (wraps `Arc`s).
#[derive(Clone)]
pub struct MailStore {
    conn: Arc<Mutex<Connection>>,
    tx: broadcast::Sender<EmailMessage>,
    event_tx: broadcast::Sender<MailEvent>,
    blobs_dir: PathBuf,
    /// Seals inbound secrets, webhook secrets, and webhook header values when
    /// the operator set `RYU_MASTER_KEY`; `None` stores them as before.
    sealer: Option<SecretSealer>,
    /// Seals message content (columns and blobs) under the same plugin subkey.
    content: StoreSeal,
    /// Rows a list skipped because they did not open (health `unreadable_rows`).
    unreadable: Arc<AtomicU64>,
}

/// The replay tombstone key of a timestamped inbound delivery.
#[derive(Debug, Clone, Copy)]
pub struct InboundReplayKey<'a> {
    /// SHA-256 of the signed `{timestamp}.{body}`.
    pub digest: &'a str,
    /// Unix seconds of acceptance, also the clock that prunes old tombstones.
    pub seen_at: i64,
}

/// Outcome of [`MailStore::insert_inbound_message`].
#[derive(Debug)]
pub enum InboundInsert {
    /// Stored now; the caller announces it.
    Stored(EmailMessage),
    /// This inbox already accepted the delivery: its byte-identical raw MIME is
    /// still stored, or its replay tombstone is live (the message it stored may
    /// since have been deleted).
    Duplicate { message_id: String },
}

/// Optional fields for a new inbox.
#[derive(Debug, Default)]
pub struct InboxOptions {
    pub client_id: Option<String>,
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub pod_id: Option<String>,
    pub require_timestamp: bool,
}

/// The result of [`MailStore::create_inbox_once`].
#[derive(Debug)]
pub enum InboxCreation {
    /// A new inbox was stored.
    Created(Inbox),
    /// An inbox with the same `client_id` already existed and was returned.
    Existing(Inbox),
}

/// Persisted keyed send claim. Unresolved claims never permit another transport call.
#[derive(Debug, PartialEq)]
pub enum SendClaim {
    New,
    Replay(serde_json::Value),
    Unresolved,
    Conflict,
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
    /// Open the shipped `mail.db`, sealing stored secrets with `sealer` when set.
    pub fn open_default_with_sealer(sealer: Option<SecretSealer>) -> Result<Self> {
        Self::open_with_sealer(default_db_path(), sealer)
    }

    /// Open a store sealing with a fixed test key.
    #[cfg(test)]
    pub fn open(path: PathBuf) -> Result<Self> {
        Self::open_with_sealer(path, Some(crate::seal::test_sealer(1)))
    }

    /// Open a store. With a sealer, plaintext secrets left by an older version
    /// are sealed before the store is returned; a sealed secret the key cannot
    /// open (or a sealed store opened without a key) refuses to open, so a
    /// misconfigured key is reported at startup instead of as failed mail.
    ///
    /// Message content is sealed under the sealer's plugin subkey; without a
    /// sealer the content store runs in compat mode (a store that was never
    /// sealed keeps its plaintext behaviour; one that holds sealed content
    /// refuses writes).
    pub fn open_with_sealer(path: PathBuf, sealer: Option<SecretSealer>) -> Result<Self> {
        let keys = match &sealer {
            Some(sealer) => {
                PluginKeys::sealing(sealer.plugin_cipher().clone(), KeySource::Delivered)
            }
            None => PluginKeys::compat(),
        };
        if let Some(parent) = path.parent() {
            create_private_dir(parent)
                .with_context(|| format!("creating db dir {}", parent.display()))?;
        }
        let blobs_dir = blobs_dir_for_db(&path);
        create_private_dir(&blobs_dir).ok();
        // The database holds every message body plus the inbound HMAC and webhook
        // signing secrets, and the blob dir holds attachments and raw MIME. Keep
        // both owner-only, including stores created before this was enforced.
        restrict_mode(&blobs_dir, 0o700);
        create_private_file(&path)
            .with_context(|| format!("creating mail db {}", path.display()))?;
        let mut conn = Connection::open(&path)
            .with_context(|| format!("opening mail db {}", path.display()))?;
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut sidecar = path.clone().into_os_string();
            sidecar.push(suffix);
            restrict_mode(std::path::Path::new(&sidecar), 0o600);
        }
        enable_secure_delete(&conn)?;
        Self::init_schema(&conn)?;
        Self::ensure_unique_inbox_addresses(&conn)?;
        // Check the content key first: with a key that did not seal this store,
        // refuse to open before anything (secrets included) is sealed under it.
        let content = sqlite_store_seal(&keys, &conn, STORE)?;
        if keys.can_seal() {
            if let StoreSeal::Unhealthy(reason) = &content {
                bail!("{reason}; start ryu-mail with the key that sealed it");
            }
        }
        Self::reconcile_sealed_secrets(&conn, sealer.as_ref())?;
        if content.is_sealing() {
            if let Err(error) = run_pending_vacuum(&conn, &path, STORE) {
                tracing::warn!("mail.db: deferred compaction failed: {error:#}");
            }
            let messages: i64 =
                conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?;
            if messages <= sync_migration_max_rows() {
                migrate_content(&mut conn, &path, &content, Finish::Now)?;
            } else {
                // Large stores migrate on their own connection; reads accept both
                // forms meanwhile and every batch is compare-and-swap.
                let (path, content) = (path.clone(), content.clone());
                std::thread::spawn(move || {
                    let run = || -> Result<u64> {
                        let mut conn = Connection::open(&path)?;
                        enable_secure_delete(&conn)?;
                        migrate_content(&mut conn, &path, &content, Finish::NextStart)
                    };
                    if let Err(error) = run() {
                        tracing::warn!(
                            "mail.db: background sealing stopped (resumes next start): {error:#}"
                        );
                    }
                });
            }
        }
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
            sealer,
            content,
            unreadable: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Seal legacy plaintext blob files on a background thread (the sidecar
    /// calls this once at startup).
    pub fn seal_legacy_blobs_in_background(&self) {
        if !self.content.is_sealing() {
            return;
        }
        let (blobs, content) = (self.blobs_dir.clone(), self.content.clone());
        std::thread::spawn(move || {
            let (sealed, failed) = seal_legacy_blobs(&blobs, &content);
            if sealed + failed > 0 {
                tracing::info!(sealed, failed, "mail: sealed legacy blob files");
            }
        });
    }

    /// The content-sealing health item: `{state, detail?, unreadable_rows}`.
    pub fn seal_health(&self) -> serde_json::Value {
        let mut health = self.content.health();
        health["unreadable_rows"] = self.unreadable.load(Ordering::Relaxed).into();
        health
    }

    fn skip_unreadable(&self, what: &str, error: &anyhow::Error) {
        let total = self.unreadable.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            total,
            "mail: skipping a {what} that does not open: {error:#}"
        );
    }

    /// Keep the rows that opened; count and log the rest.
    fn keep_opened<T>(&self, what: &str, rows: Vec<Result<T>>) -> Vec<T> {
        rows.into_iter()
            .filter_map(|row| row.map_err(|error| self.skip_unreadable(what, &error)).ok())
            .collect()
    }

    fn seal_col(&self, table: &str, column: &str, id: &str, value: &str) -> Result<String> {
        self.content.seal_text(value, &ctx(table, column, id))
    }

    fn seal_col_opt(
        &self,
        table: &str,
        column: &str,
        id: &str,
        value: Option<&str>,
    ) -> Result<Option<String>> {
        self.content.seal_opt(value, &ctx(table, column, id))
    }

    /// Write one content-addressed blob (`name` = plaintext digest) unless it
    /// exists: sealed (`RYU-SF01`) through an owner-only temp file and a rename;
    /// in compat mode the plaintext bytes, as before.
    fn write_blob(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.blobs_dir.join(name);
        if path.exists() {
            return Ok(());
        }
        match &self.content {
            StoreSeal::Sealing(cipher) => {
                let temp = self
                    .blobs_dir
                    .join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
                let written = (|| -> Result<()> {
                    let mut writer = SealedFileWriter::create(&temp, cipher, &blob_ctx(name))?;
                    writer.write_plain(bytes)?;
                    writer.finish()?;
                    std::fs::rename(&temp, &path)?;
                    Ok(())
                })();
                if written.is_err() {
                    let _ = std::fs::remove_file(&temp);
                }
                written.with_context(|| format!("writing blob {}", path.display()))
            }
            StoreSeal::Compat => write_private(&path, bytes)
                .with_context(|| format!("writing blob {}", path.display())),
            StoreSeal::Unhealthy(reason) => bail!("{reason}"),
        }
    }

    /// Read one blob: sealed files are decrypted and their SHA-256 checked
    /// against the name; legacy plaintext files are returned as they are.
    pub fn read_blob(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.blobs_dir.join(name);
        // One open, one read: the background sealer renames sealed files over
        // legacy ones, so deciding "sealed or legacy" and reading must use the
        // same file, never the path twice.
        let mut file =
            std::fs::File::open(&path).with_context(|| format!("reading blob {name}"))?;
        #[cfg(test)]
        BLOB_READ_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow().as_ref() {
                hook(&path);
            }
        });
        let mut stored = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut stored)
            .with_context(|| format!("reading blob {name}"))?;
        drop(file);
        let bytes = if stored.starts_with(ryu_crypto::content::SEALED_FILE_MAGIC) {
            let Some(cipher) = self.content.cipher() else {
                bail!("this blob is sealed and ryu-mail has no key for it");
            };
            ryu_crypto::sealed_file::open_file_bytes(&stored, cipher, &blob_ctx(name))
                .with_context(|| format!("opening blob {name}"))?
        } else {
            stored
        };
        // Blobs are content-addressed: whichever form was read, the plaintext
        // must match the name.
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if name.strip_prefix("raw-").unwrap_or(name) != digest {
            bail!("blob {name} does not match its content digest");
        }
        Ok(bytes)
    }

    /// The raw MIME of a message, decrypted, with its stored size.
    pub async fn read_raw(&self, id: &str) -> Result<Option<(u64, Vec<u8>)>> {
        let row: Option<(Option<String>, i64)> = {
            let conn = self.conn.lock().await;
            conn.query_row(
                "SELECT raw_blob_path, raw_size FROM messages WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
        };
        let Some((Some(name), size)) = row else {
            return Ok(None);
        };
        Ok(Some((size as u64, self.read_blob(&name)?)))
    }

    /// One attachment's metadata and decrypted bytes.
    pub async fn read_attachment(&self, att_id: &str) -> Result<Option<(AttachmentMeta, Vec<u8>)>> {
        let Some((meta, path)) = self.attachment_path(att_id).await? else {
            return Ok(None);
        };
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("attachment blob has no name")?
            .to_owned();
        Ok(Some((meta, self.read_blob(&name)?)))
    }

    /// Enforce one inbox per address (case-insensitive) at the database level.
    /// A store created before this rule may already hold duplicates; then the
    /// index is skipped (the insert-time check still refuses new duplicates) and
    /// the operator is told which addresses to resolve.
    fn ensure_unique_inbox_addresses(conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare(
            "SELECT lower(address) FROM inboxes GROUP BY lower(address) HAVING COUNT(*) > 1",
        )?;
        let duplicates = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if duplicates.is_empty() {
            conn.execute_batch(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_inboxes_address
                     ON inboxes(lower(address));",
            )?;
        } else {
            tracing::warn!(
                addresses = ?duplicates,
                "mail.db has inboxes sharing an address; delete or re-create the duplicates to enable the unique address index"
            );
        }
        Ok(())
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
            "CREATE INDEX IF NOT EXISTS idx_messages_inbox
                 ON messages(inbox_id, created_at DESC);
             CREATE INDEX IF NOT EXISTS idx_messages_thread
                 ON messages(inbox_id, thread_id, created_at ASC);
             CREATE INDEX IF NOT EXISTS idx_messages_status
                 ON messages(inbox_id, status, created_at DESC);
             CREATE INDEX IF NOT EXISTS idx_attachments_message
                 ON attachments(message_id);
             CREATE INDEX IF NOT EXISTS idx_messages_raw_blob
                 ON messages(raw_blob_path) WHERE raw_blob_path IS NOT NULL;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_inboxes_client_id
                 ON inboxes(client_id) WHERE client_id IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_inboxes_address_lookup
                 ON inboxes(lower(address));
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
             CREATE TABLE IF NOT EXISTS mail_send_claims (
                 key TEXT PRIMARY KEY,
                 inbox_id TEXT NOT NULL,
                 request_hash TEXT NOT NULL,
                 response_json TEXT,
                 created_at TEXT NOT NULL
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

        // Webhooks created before Standard Webhooks signing keep the raw-key
        // `svix-signature` their consumers verify; new rows record `standard`.
        Self::ensure_column(
            conn,
            "webhooks",
            "signature_scheme",
            "TEXT NOT NULL DEFAULT 'legacy'",
        )?;
        Self::ensure_column(
            conn,
            "inboxes",
            "require_timestamp",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        // SHA-256 of accepted timestamped inbound deliveries, kept after the
        // message is deleted so a captured signed request cannot be replayed.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS inbound_replay_tombstones (
                 inbox_id   TEXT NOT NULL,
                 digest     TEXT NOT NULL,
                 message_id TEXT,
                 seen_at    INTEGER NOT NULL,
                 PRIMARY KEY (inbox_id, digest)
             );
             CREATE INDEX IF NOT EXISTS idx_inbound_replay_tombstones_seen
                 ON inbound_replay_tombstones(seen_at);",
        )
        .context("initializing inbound replay tombstones")?;
        Ok(())
    }

    /// Bring every stored secret in line with the configured key, in one
    /// transaction: with a sealer, open sealed values (refusing a wrong key) and
    /// seal plaintext ones; without one, refuse a store that holds sealed values.
    fn reconcile_sealed_secrets(conn: &Connection, sealer: Option<&SecretSealer>) -> Result<()> {
        let inboxes = {
            let mut statement = conn.prepare("SELECT id, inbound_secret FROM inboxes")?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let webhooks = {
            let mut statement = conn.prepare("SELECT id, secret, headers_json FROM webhooks")?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let Some(sealer) = sealer else {
            let sealed = inboxes.iter().any(|(_, secret)| seal::is_sealed(secret))
                || webhooks.iter().any(|(_, secret, headers)| {
                    seal::is_sealed(secret)
                        || json_string_map(headers)
                            .values()
                            .any(|value| seal::is_sealed(value))
                });
            if sealed {
                bail!(
                    "mail.db holds sealed secrets but ryu-mail has no sealing key; run it from Ryu Core or set RYU_MASTER_KEY"
                );
            }
            return Ok(());
        };
        let transaction = write_transaction_unchecked(conn)?;
        for (id, stored) in inboxes {
            let plain = sealer.open(&stored)?;
            if !SecretSealer::is_current(&stored) {
                transaction.execute(
                    "UPDATE inboxes SET inbound_secret = ?2 WHERE id = ?1",
                    params![id, sealer.seal(&plain)?],
                )?;
            }
        }
        for (id, stored_secret, stored_headers) in webhooks {
            let secret = sealer.open(&stored_secret)?;
            let headers = json_string_map(&stored_headers);
            let mut resealed = BTreeMap::new();
            let mut changed = !SecretSealer::is_current(&stored_secret);
            for (name, value) in headers {
                let plain = sealer.open(&value)?;
                if SecretSealer::is_current(&value) {
                    resealed.insert(name, value);
                } else {
                    changed = true;
                    resealed.insert(name, sealer.seal(&plain)?);
                }
            }
            if changed {
                let secret = if SecretSealer::is_current(&stored_secret) {
                    stored_secret
                } else {
                    sealer.seal(&secret)?
                };
                transaction.execute(
                    "UPDATE webhooks SET secret = ?2, headers_json = ?3 WHERE id = ?1",
                    params![id, secret, json_string(&resealed)],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn seal_value(&self, plaintext: &str) -> Result<String> {
        seal::seal_with(self.sealer.as_ref(), plaintext)
    }

    fn open_value(&self, stored: &str) -> Result<String> {
        seal::open_with(self.sealer.as_ref(), stored)
    }

    fn seal_headers(&self, headers: &BTreeMap<String, String>) -> Result<String> {
        let mut sealed = BTreeMap::new();
        for (name, value) in headers {
            sealed.insert(name.clone(), self.seal_value(value)?);
        }
        Ok(json_string(&sealed))
    }

    fn open_inbox(&self, mut inbox: Inbox) -> Result<Inbox> {
        inbox.inbound_secret = self.open_value(&inbox.inbound_secret)?;
        Ok(inbox)
    }

    fn open_webhook(&self, mut webhook: Webhook) -> Result<Webhook> {
        webhook.secret = self.open_value(&webhook.secret)?;
        for value in webhook.headers.values_mut() {
            *value = self.open_value(value)?;
        }
        Ok(webhook)
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
        self.create_inbox_with_options(name, address, provider, InboxOptions::default())
            .await
    }

    pub async fn create_inbox_with_options(
        &self,
        name: &str,
        address: &str,
        provider: InboxProvider,
        options: InboxOptions,
    ) -> Result<Inbox> {
        match self
            .create_inbox_once(name, address, provider, options)
            .await?
        {
            InboxCreation::Created(inbox) | InboxCreation::Existing(inbox) => Ok(inbox),
        }
    }

    /// Store a new inbox, or return the one already holding `options.client_id`.
    /// The lookup and the insert run under one connection lock, so two creates
    /// with the same client id that overlap in flight yield one inbox: the
    /// second gets [`InboxCreation::Existing`] instead of `AddressTaken`.
    pub async fn create_inbox_once(
        &self,
        name: &str,
        address: &str,
        provider: InboxProvider,
        options: InboxOptions,
    ) -> Result<InboxCreation> {
        let now = Utc::now().to_rfc3339();
        let inbox = Inbox {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            address: address.to_string(),
            provider,
            client_id: options.client_id,
            metadata: options.metadata,
            pod_id: options.pod_id,
            inbound_secret: uuid::Uuid::new_v4().simple().to_string(),
            require_timestamp: options.require_timestamp,
            created_at: now.clone(),
            updated_at: now,
        };
        let stored_secret = self.seal_value(&inbox.inbound_secret)?;
        let conn = self.conn.lock().await;
        if let Some(client_id) = inbox.client_id.as_deref() {
            let existing = conn
                .query_row(
                    &format!(
                        "SELECT {INBOX_COLUMNS} FROM inboxes WHERE client_id = ?1
                         ORDER BY created_at LIMIT 1"
                    ),
                    params![client_id],
                    row_to_inbox,
                )
                .optional()
                .context("looking up inbox by client id")?;
            if let Some(existing) = existing {
                drop(conn);
                return Ok(InboxCreation::Existing(self.open_inbox(existing)?));
            }
        }
        // Checked under the connection lock, so it also holds for a legacy store
        // whose duplicates kept the unique index from being created.
        let taken: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM inboxes WHERE lower(address) = lower(?1))",
                params![inbox.address],
                |r| r.get(0),
            )
            .context("checking inbox address")?;
        if taken {
            return Err(AddressTaken(inbox.address.to_ascii_lowercase()).into());
        }
        let inserted = conn.execute(
            "INSERT INTO inboxes
             (id, name, address, provider, inbound_secret, client_id, metadata_json,
              pod_id, created_at, updated_at, require_timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                inbox.id,
                inbox.name,
                inbox.address,
                inbox.provider.as_str(),
                stored_secret,
                inbox.client_id,
                serde_json::to_string(&inbox.metadata).unwrap_or_else(|_| "{}".to_owned()),
                inbox.pod_id,
                inbox.created_at,
                inbox.updated_at,
                i64::from(inbox.require_timestamp),
            ],
        );
        match inserted {
            Ok(_) => Ok(InboxCreation::Created(inbox)),
            Err(rusqlite::Error::SqliteFailure(failure, Some(message)))
                if failure.code == rusqlite::ErrorCode::ConstraintViolation
                    && message.contains("idx_inboxes_address") =>
            {
                Err(AddressTaken(inbox.address.to_ascii_lowercase()).into())
            }
            Err(error) => Err(anyhow::Error::new(error).context("inserting inbox")),
        }
    }

    pub async fn list_inboxes(&self) -> Result<Vec<Inbox>> {
        let rows = {
            let conn = self.conn.lock().await;
            let mut stmt = conn.prepare(&format!(
                "SELECT {INBOX_COLUMNS} FROM inboxes ORDER BY created_at DESC"
            ))?;
            let rows = stmt
                .query_map([], row_to_inbox)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        rows.into_iter()
            .map(|inbox| self.open_inbox(inbox))
            .collect()
    }

    pub async fn get_inbox(&self, id: &str) -> Result<Option<Inbox>> {
        let row = {
            let conn = self.conn.lock().await;
            conn.query_row(
                &format!("SELECT {INBOX_COLUMNS} FROM inboxes WHERE id = ?1"),
                params![id],
                row_to_inbox,
            )
            .optional()?
        };
        row.map(|inbox| self.open_inbox(inbox)).transpose()
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
        require_timestamp: Option<bool>,
    ) -> Result<Option<Inbox>> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE inboxes SET
                name = COALESCE(?2, name),
                metadata_json = COALESCE(?3, metadata_json),
                pod_id = COALESCE(?4, pod_id),
                require_timestamp = COALESCE(?6, require_timestamp),
                updated_at = ?5
             WHERE id = ?1",
            params![
                id,
                name,
                metadata.map(json_string),
                pod_id,
                Utc::now().to_rfc3339(),
                require_timestamp.map(i64::from),
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
        let stored = self.seal_value(&secret)?;
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE inboxes SET inbound_secret = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, stored, Utc::now().to_rfc3339()],
        )?;
        Ok(secret)
    }

    // ── Inbound replay tombstones ───────────────────────────────────────────

    /// Record a timestamped delivery's tombstone, keyed by the SHA-256 of its
    /// signed content and pointing at `message_id`, which the caller stores in
    /// the same transaction. Returns the earlier message's id when this inbox
    /// already accepted the delivery. Expired tombstones are pruned first, so
    /// the table stays bounded by the deliveries of the retention window.
    ///
    /// A tombstone without a message id is a claim an earlier version recorded
    /// before storing its message and never finished (it crashed in between),
    /// so it is taken over instead of being answered as a duplicate.
    fn claim_inbound_tombstone(
        conn: &Connection,
        inbox_id: &str,
        key: InboundReplayKey<'_>,
        message_id: &str,
    ) -> Result<Option<String>> {
        conn.execute(
            "DELETE FROM inbound_replay_tombstones WHERE seen_at < ?1",
            params![key.seen_at - INBOUND_TOMBSTONE_RETENTION_SECS],
        )?;
        let claimed = conn.execute(
            "INSERT INTO inbound_replay_tombstones (inbox_id, digest, message_id, seen_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (inbox_id, digest) DO UPDATE
                 SET message_id = excluded.message_id, seen_at = excluded.seen_at
                 WHERE inbound_replay_tombstones.message_id IS NULL",
            params![inbox_id, key.digest, message_id, key.seen_at],
        )?;
        if claimed == 1 {
            return Ok(None);
        }
        conn.query_row(
            "SELECT message_id FROM inbound_replay_tombstones
             WHERE inbox_id = ?1 AND digest = ?2",
            params![inbox_id, key.digest],
            |row| row.get::<_, String>(0),
        )
        .map(Some)
        .context("reading inbound replay tombstone")
    }

    pub async fn delete_inbox(&self, id: &str) -> Result<()> {
        let mut conn = self.conn.lock().await;
        let transaction = write_transaction(&mut conn)?;
        let candidate_blobs = {
            let mut stmt = transaction.prepare(
                "SELECT attachments.blob_path
                 FROM attachments
                 INNER JOIN messages ON messages.id = attachments.message_id
                 WHERE messages.inbox_id = ?1
                 UNION
                 SELECT raw_blob_path FROM messages
                 WHERE inbox_id = ?1 AND raw_blob_path IS NOT NULL",
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
            if Self::blob_references_sync(&transaction, &blob_path)? == 0 {
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
        msg: EmailMessage,
        attachments: Vec<RawAttachment>,
        raw: Option<&[u8]>,
    ) -> Result<EmailMessage> {
        // Serialize blob writes with the inbox existence check and row inserts.
        // Otherwise delete_inbox could commit between the file write and this
        // insert and a late inbound delivery would resurrect an orphan message.
        let mut conn = self.conn.lock().await;
        let transaction = write_transaction(&mut conn)?;
        let msg = self.insert_message_in(&transaction, msg, attachments, raw)?;
        transaction.commit()?;
        drop(conn);
        let _ = self.tx.send(msg.clone());
        Ok(msg)
    }

    /// Store an inbound delivery unless this inbox already accepted it. The
    /// duplicate check, the replay tombstone (for a timestamped delivery), and
    /// the message rows commit in one transaction under the connection lock: a
    /// crash or a failed insert leaves none of them, so the sender's retry is
    /// stored rather than answered as a duplicate, and concurrent copies of one
    /// delivery store exactly one message.
    pub async fn insert_inbound_message(
        &self,
        msg: EmailMessage,
        attachments: Vec<RawAttachment>,
        raw: &[u8],
        replay_key: Option<InboundReplayKey<'_>>,
    ) -> Result<InboundInsert> {
        let mut conn = self.conn.lock().await;
        let transaction = write_transaction(&mut conn)?;
        // Byte-identical raw MIME is the same delivery even without a usable
        // Message-ID (the parser fills a missing one with a fresh random id) or
        // a timestamp, so a body-only replay is not stored twice either.
        let stored_copy = transaction
            .query_row(
                "SELECT id FROM messages
                 WHERE inbox_id = ?1 AND direction = 'inbound' AND raw_blob_path = ?2
                 ORDER BY created_at ASC LIMIT 1",
                params![msg.inbox_id, raw_blob_name(raw)],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(message_id) = stored_copy {
            return Ok(InboundInsert::Duplicate { message_id });
        }
        if let Some(key) = replay_key {
            if let Some(message_id) =
                Self::claim_inbound_tombstone(&transaction, &msg.inbox_id, key, &msg.id)?
            {
                return Ok(InboundInsert::Duplicate { message_id });
            }
        }
        let msg = self.insert_message_in(&transaction, msg, attachments, Some(raw))?;
        transaction.commit()?;
        drop(conn);
        let _ = self.tx.send(msg.clone());
        Ok(InboundInsert::Stored(msg))
    }

    /// Write a message's blobs and rows inside the caller's transaction, which
    /// must hold the connection lock until it commits.
    fn insert_message_in(
        &self,
        transaction: &Connection,
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
        create_private_dir(dir).ok();
        for att in attachments {
            let mut hasher = Sha256::new();
            hasher.update(&att.bytes);
            let hash = format!("{:x}", hasher.finalize());
            let rel = hash.clone();
            self.write_blob(&rel, &att.bytes)?;
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
            let rel = raw_blob_name(bytes);
            self.write_blob(&rel, bytes)?;
            Some(rel)
        } else {
            None
        };
        if let Some(bytes) = raw {
            msg.raw_size = bytes.len() as u64;
        }
        let id = msg.id.clone();
        let sealed = |column: &str, value: &str| self.seal_col("messages", column, &id, value);
        let from_addr = sealed("from_addr", &msg.from_addr)?;
        let to_addrs = sealed("to_addrs", &json_string(&msg.to_addrs))?;
        let cc_addrs = sealed("cc_addrs", &json_string(&msg.cc_addrs))?;
        let bcc_addrs = sealed("bcc_addrs", &json_string(&msg.bcc_addrs))?;
        let reply_to_addrs = sealed("reply_to_addrs", &json_string(&msg.reply_to_addrs))?;
        let subject = sealed("subject", &msg.subject)?;
        let opt =
            |column: &str, value: Option<&str>| self.seal_col_opt("messages", column, &id, value);
        let text = opt("text", msg.text.as_deref())?;
        let html = opt("html", msg.html.as_deref())?;
        let extracted_text = opt("extracted_text", msg.extracted_text.as_deref())?;
        let extracted_html = opt("extracted_html", msg.extracted_html.as_deref())?;
        let preview = opt("preview", msg.preview.as_deref())?;
        let headers_json = sealed(
            "headers_json",
            &serde_json::to_string(&msg.headers).unwrap_or_else(|_| "{}".into()),
        )?;
        let filenames = metas
            .iter()
            .map(|(meta, _)| self.seal_col("attachments", "filename", &meta.id, &meta.filename))
            .collect::<Result<Vec<_>>>()?;

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
                    from_addr,
                    to_addrs,
                    cc_addrs,
                    bcc_addrs,
                    reply_to_addrs,
                    subject,
                    text,
                    html,
                    extracted_text,
                    extracted_html,
                    preview,
                    headers_json,
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
        for ((meta, rel), filename) in metas.iter().zip(&filenames) {
            transaction
                .execute(
                    "INSERT INTO attachments
                 (id, message_id, filename, content_type, size, blob_path, inline, content_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        meta.id,
                        msg.id,
                        filename,
                        meta.content_type,
                        meta.size as i64,
                        rel,
                        i64::from(meta.inline),
                        meta.content_id,
                    ],
                )
                .context("inserting attachment")?;
        }

        msg.attachments = metas.into_iter().map(|(m, _)| m).collect();
        Ok(msg)
    }

    fn drain_blob_cleanup_sync(conn: &Connection, blobs_dir: &std::path::Path) -> Result<()> {
        let transaction = write_transaction_unchecked(conn)?;
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
            if Self::blob_references_sync(&transaction, &blob_path)? > 0 {
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
                            .context(format!("deleting mail blob {}", path.display()))
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

    /// Rows that still point at a blob file. Attachments and raw MIME share the
    /// content-addressed blob directory, so both kinds of reference count.
    fn blob_references_sync(conn: &Connection, blob_path: &str) -> Result<i64> {
        Ok(conn.query_row(
            "SELECT (SELECT COUNT(*) FROM attachments WHERE blob_path = ?1)
                  + (SELECT COUNT(*) FROM messages WHERE raw_blob_path = ?1)",
            params![blob_path],
            |row| row.get(0),
        )?)
    }

    fn sweep_orphan_blobs_sync(conn: &Connection, blobs_dir: &std::path::Path) -> Result<()> {
        let mut statement = conn.prepare(
            "SELECT blob_path FROM attachments
             UNION
             SELECT raw_blob_path FROM messages WHERE raw_blob_path IS NOT NULL",
        )?;
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
                    anyhow::Error::new(error).context(format!("deleting orphan mail blob {name}"))
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
        let rows = query_messages(
            &conn,
            &self.content,
            "inbox_id = ?1 ORDER BY created_at DESC LIMIT ?2",
            &[&inbox_id, &limit],
        )?;
        Ok(self.keep_opened("message", rows))
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
                row_to_message(&self.content),
            )
            .optional()?
            .transpose()?;
        match row {
            Some(mut m) => {
                m.attachments = load_attachments(&conn, &self.content, &m.id)?;
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
                row_to_message(&self.content),
            )
            .optional()?
            .transpose()?;
        match row {
            Some(mut message) => {
                message.attachments = load_attachments(&conn, &self.content, &message.id)?;
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    /// One page of an inbox, newest first. Direction, the `created_at`
    /// cursors and labels (plaintext columns) filter in SQL, and trashed
    /// messages are left out there too, so only the page itself is opened.
    /// A free-text `query` must open sealed columns: rows are scanned in
    /// bounded batches (the store lock is released between them), opening the
    /// addresses and subject first and the bodies only for rows still
    /// unmatched, up to [`SEARCH_SCAN_LIMIT`] rows.
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
        let (clause, values) = message_filter(inbox_id, before, after, direction, labels);
        let needle = query
            .map(str::to_ascii_lowercase)
            .filter(|needle| !needle.is_empty());
        let Some(needle) = needle else {
            let conn = self.conn.lock().await;
            let mut params = values;
            params.push(i64::from(limit).into());
            let rows = query_messages_with(
                &conn,
                &self.content,
                &format!("{clause} ORDER BY created_at DESC, id DESC LIMIT ?"),
                rusqlite::params_from_iter(params),
            )?;
            return Ok(self.keep_opened("message", rows));
        };
        let matched = self
            .search_message_ids(&clause, values, &needle, limit)
            .await?;
        if matched.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().await;
        let placeholders = vec!["?"; matched.len()].join(", ");
        let rows = query_messages_with(
            &conn,
            &self.content,
            &format!("id IN ({placeholders}) ORDER BY created_at DESC, id DESC"),
            rusqlite::params_from_iter(matched.iter()),
        )?;
        Ok(self.keep_opened("message", rows))
    }

    /// Ids of the messages matching `clause` whose addresses, subject or
    /// bodies contain `needle` (lowercase), newest first, at most `limit`.
    /// Rows are scanned in bounded batches (the store lock is released between
    /// them), up to [`SEARCH_SCAN_LIMIT`] rows.
    async fn search_message_ids(
        &self,
        clause: &str,
        values: Vec<rusqlite::types::Value>,
        needle: &str,
        limit: u32,
    ) -> Result<Vec<String>> {
        let mut matched: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        while matched.len() < limit as usize && scanned < SEARCH_SCAN_LIMIT {
            let conn = self.conn.lock().await;
            let mut params = values.clone();
            params.push((SEARCH_BATCH as i64).into());
            params.push((scanned as i64).into());
            let batch = search_batch(
                &conn,
                &self.content,
                &format!(
                    "SELECT id, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, text, html
                     FROM messages WHERE {clause}
                     ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
                ),
                params,
                needle,
            )?;
            drop(conn);
            scanned += batch.scanned;
            for row in batch.rows {
                match row {
                    Ok(Some(id)) => matched.push(id),
                    Ok(None) => {}
                    Err(error) => self.skip_unreadable("message", &error),
                }
            }
            if batch.scanned < SEARCH_BATCH {
                break;
            }
            tokio::task::yield_now().await;
        }
        matched.truncate(limit as usize);
        Ok(matched)
    }

    /// One page of an inbox's threads, newest activity first, with the same
    /// plaintext filters as [`Self::list_messages_with_filters`]. The page of
    /// threads is chosen in SQL; only its newest messages (at most
    /// [`THREAD_SUMMARY_MESSAGES`] each) are opened, and only for a summary:
    /// addresses, subject, preview and attachment names, never the bodies or
    /// headers.
    pub async fn list_thread_summaries(
        &self,
        inbox_id: &str,
        limit: u32,
        before: Option<&str>,
        after: Option<&str>,
        direction: Option<&str>,
        labels: &[String],
    ) -> Result<Vec<ThreadSummary>> {
        let (clause, values) = message_filter(inbox_id, before, after, direction, labels);
        let conn = self.conn.lock().await;
        let threads = thread_summaries(&conn, &self.content, &clause, values, limit)?;
        drop(conn);
        Ok(self.keep_opened_threads(threads))
    }

    /// The threads of the messages a free-text search matched (at most
    /// [`SEARCH_SCAN_LIMIT`] of them), summarised like
    /// [`Self::list_thread_summaries`] over the matched messages only.
    pub async fn search_thread_summaries(
        &self,
        inbox_id: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<ThreadSummary>> {
        let needle = query.to_ascii_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let (clause, values) = message_filter(inbox_id, None, None, None, &[]);
        let matched = self
            .search_message_ids(&clause, values, &needle, SEARCH_SCAN_LIMIT as u32)
            .await?;
        if matched.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; matched.len()].join(", ");
        let values = matched.into_iter().map(Into::into).collect();
        let conn = self.conn.lock().await;
        let threads = thread_summaries(
            &conn,
            &self.content,
            &format!("id IN ({placeholders})"),
            values,
            limit,
        )?;
        drop(conn);
        Ok(self.keep_opened_threads(threads))
    }

    /// Keep each thread's rows that opened (counting the rest); a thread none
    /// of whose rows opened is left out.
    fn keep_opened_threads(&self, threads: Vec<OpenedThread>) -> Vec<ThreadSummary> {
        threads
            .into_iter()
            .filter_map(|thread| {
                let messages = self.keep_opened("message", thread.rows);
                (!messages.is_empty()).then_some(ThreadSummary {
                    messages,
                    message_count: thread.message_count,
                    size: thread.size,
                })
            })
            .collect()
    }

    /// Every message of one thread, newest first (at most 1000).
    pub async fn messages_for_thread(
        &self,
        inbox_id: &str,
        thread_id: &str,
    ) -> Result<Vec<EmailMessage>> {
        let conn = self.conn.lock().await;
        let rows = query_messages(
            &conn,
            &self.content,
            "inbox_id = ?1 AND thread_id = ?2 ORDER BY created_at DESC LIMIT 1000",
            &[&inbox_id, &thread_id],
        )?;
        Ok(self.keep_opened("message", rows))
    }

    /// Message and thread counts and stored bytes of an inbox, from the stored
    /// columns (nothing is opened): the raw size, the stored body columns and
    /// the attachment sizes.
    pub async fn usage_totals(&self, inbox_id: &str) -> Result<UsageTotals> {
        let conn = self.conn.lock().await;
        let (message_count, thread_count, message_bytes): (i64, i64, i64) = conn.query_row(
            "SELECT COUNT(*), COUNT(DISTINCT thread_id),
                    COALESCE(SUM(raw_size
                        + COALESCE(length(CAST(text AS BLOB)), 0)
                        + COALESCE(length(CAST(html AS BLOB)), 0)), 0)
             FROM messages WHERE inbox_id = ?1",
            params![inbox_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let attachment_bytes: i64 = conn.query_row(
            "SELECT COALESCE(SUM(a.size), 0) FROM attachments a
             JOIN messages m ON m.id = a.message_id WHERE m.inbox_id = ?1",
            params![inbox_id],
            |row| row.get(0),
        )?;
        Ok(UsageTotals {
            message_count: message_count.max(0) as u64,
            thread_count: thread_count.max(0) as u64,
            storage_bytes: (message_bytes.max(0) as u64)
                .saturating_add(attachment_bytes.max(0) as u64),
        })
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
        let transaction = write_transaction(&mut conn)?;
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

    fn seal_draft(&self, draft: &Draft) -> Result<SealedDraft> {
        let col = |column: &str, value: &str| self.seal_col("drafts", column, &draft.id, value);
        Ok(SealedDraft {
            to_addrs: col("to_addrs", &json_string(&draft.to_addrs))?,
            cc_addrs: col("cc_addrs", &json_string(&draft.cc_addrs))?,
            bcc_addrs: col("bcc_addrs", &json_string(&draft.bcc_addrs))?,
            reply_to_addrs: col("reply_to_addrs", &json_string(&draft.reply_to_addrs))?,
            subject: col("subject", &draft.subject)?,
            text: self.seal_col_opt("drafts", "text", &draft.id, draft.text.as_deref())?,
            html: self.seal_col_opt("drafts", "html", &draft.id, draft.html.as_deref())?,
            headers_json: col("headers_json", &json_string(&draft.headers))?,
            attachments_json: col("attachments_json", &json_string(&draft.attachments))?,
        })
    }

    pub async fn create_draft(&self, draft: Draft) -> Result<Draft> {
        let sealed = self.seal_draft(&draft)?;
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
                sealed.to_addrs,
                sealed.cc_addrs,
                sealed.bcc_addrs,
                sealed.reply_to_addrs,
                sealed.subject,
                sealed.text,
                sealed.html,
                sealed.headers_json,
                json_string(&draft.labels),
                sealed.attachments_json,
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
            row_to_draft(&self.content),
        )
        .optional()?
        .transpose()
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
            .query_map(params![inbox_id, limit], row_to_draft(&self.content))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(self
            .keep_opened("draft", rows)
            .into_iter()
            .filter(|draft| labels.iter().all(|label| draft.labels.contains(label)))
            .collect())
    }

    /// Scheduled drafts whose `send_at` is at or before `now`. The instant is
    /// compared parsed, not as text: rows written before `sendAt` was normalized
    /// may carry any offset. A value that does not parse is returned as due, so
    /// the scheduler fails it visibly instead of leaving it scheduled forever.
    pub async fn list_due_drafts(
        &self,
        now: chrono::DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Draft>> {
        let conn = self.conn.lock().await;
        // Decide what is due from `(id, send_at)` alone. A scheduled draft can
        // carry megabytes of base64 attachments and this runs every few seconds
        // under the connection lock, so only the due rows are loaded in full.
        let mut due: Vec<(Option<chrono::DateTime<Utc>>, String)> = {
            let mut statement = conn.prepare(
                "SELECT id, send_at FROM drafts
                 WHERE status = 'scheduled' AND send_at IS NOT NULL",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter()
                .filter_map(
                    |(id, send_at)| match chrono::DateTime::parse_from_rfc3339(&send_at) {
                        Ok(at) => {
                            let at = at.with_timezone(&Utc);
                            (at <= now).then_some((Some(at), id))
                        }
                        Err(_) => Some((None, id)),
                    },
                )
                .collect()
        };
        // Oldest first; an unparseable time sorts first so it is failed promptly.
        due.sort();
        let mut statement = conn.prepare(
            "SELECT id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
                    reply_to_addrs, subject, text, html, headers_json, labels_json,
                    attachments_json, send_at, status, created_at, updated_at
             FROM drafts WHERE id = ?1 AND status = 'scheduled'",
        )?;
        let mut drafts = Vec::with_capacity(due.len().min(limit));
        for (_, id) in due.into_iter().take(limit) {
            match statement
                .query_row(params![id], row_to_draft(&self.content))
                .optional()?
            {
                Some(Ok(draft)) => drafts.push(draft),
                Some(Err(error)) => self.skip_unreadable("scheduled draft", &error),
                None => {}
            }
        }
        Ok(drafts)
    }

    pub async fn get_draft(&self, id: &str) -> Result<Option<Draft>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
                    reply_to_addrs, subject, text, html, headers_json, labels_json,
                    attachments_json, send_at, status, created_at, updated_at
             FROM drafts WHERE id = ?1",
            params![id],
            row_to_draft(&self.content),
        )
        .optional()?
        .transpose()
    }

    /// Replace an editable draft. The write only applies while the row is still
    /// `draft`, `scheduled` or parked `failed`, so an edit can never flip a draft
    /// that a send has claimed (`sending`) or settled (`sent`) back into a
    /// sendable state. Returns `false` when the row is missing or no longer
    /// editable.
    pub async fn update_draft(&self, draft: &Draft) -> Result<bool> {
        let sealed = self.seal_draft(draft)?;
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE drafts SET thread_id=?2, to_addrs=?3, cc_addrs=?4, bcc_addrs=?5,
                reply_to_addrs=?6, subject=?7, text=?8, html=?9, headers_json=?10,
                labels_json=?11, attachments_json=?12, send_at=?13, status=?14,
                updated_at=?15 WHERE id=?1 AND status IN ('draft','scheduled','failed')",
            params![
                draft.id,
                draft.thread_id,
                sealed.to_addrs,
                sealed.cc_addrs,
                sealed.bcc_addrs,
                sealed.reply_to_addrs,
                sealed.subject,
                sealed.text,
                sealed.html,
                sealed.headers_json,
                json_string(&draft.labels),
                sealed.attachments_json,
                draft.send_at,
                draft.status,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(changed > 0)
    }

    /// Claim an editable (`draft`, `scheduled` or parked `failed`) draft for a
    /// manual send. See [`Self::claim_draft_where`] for the claim contract.
    pub async fn claim_draft(&self, id: &str) -> Result<Option<Draft>> {
        self.claim_draft_where(id, "status IN ('draft','scheduled','failed')", None)
            .await
    }

    /// Claim a draft for the scheduler only while it is still `scheduled` and
    /// due at `now`, so a draft the user unscheduled or rescheduled after the
    /// poll listed it is left alone. Due-ness is decided as in
    /// [`Self::list_due_drafts`]: the instant is compared parsed, and a value
    /// that does not parse is due, so the scheduler fails it visibly. The claim
    /// is guarded on the `send_at` that was judged, so a reschedule between the
    /// read and the claim wins.
    pub async fn claim_due_draft(
        &self,
        id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<Draft>> {
        let send_at: Option<String> = {
            let conn = self.conn.lock().await;
            conn.query_row(
                "SELECT send_at FROM drafts
                 WHERE id = ?1 AND status = 'scheduled' AND send_at IS NOT NULL",
                params![id],
                |row| row.get(0),
            )
            .optional()?
        };
        let Some(send_at) = send_at else {
            return Ok(None);
        };
        let due = match chrono::DateTime::parse_from_rfc3339(&send_at) {
            Ok(at) => at.with_timezone(&Utc) <= now,
            Err(_) => true,
        };
        if !due {
            return Ok(None);
        }
        self.claim_draft_where(id, "status = 'scheduled' AND send_at = ?3", Some(&send_at))
            .await
    }

    /// Atomically move a draft to `sending` and return the claimed row, or `None`
    /// when another caller (the scheduler, a manual send, or a retry) already
    /// claimed or sent it. Only the winner may hand the draft to the transport.
    /// The row stays `sending` until [`Self::finish_draft_send`] settles it, so a
    /// crash mid-send is never re-sent automatically.
    async fn claim_draft_where(
        &self,
        id: &str,
        predicate: &'static str,
        due_by: Option<&str>,
    ) -> Result<Option<Draft>> {
        let mut conn = self.conn.lock().await;
        let transaction = write_transaction(&mut conn)?;
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "UPDATE drafts SET status='sending', updated_at=?2 WHERE id=?1 AND {predicate}"
        );
        let claimed = match due_by {
            Some(due_by) => transaction.execute(&sql, params![id, now, due_by])?,
            None => transaction.execute(&sql, params![id, now])?,
        };
        if claimed == 0 {
            return Ok(None);
        }
        let draft = transaction.query_row(
            "SELECT id, inbox_id, thread_id, client_id, to_addrs, cc_addrs, bcc_addrs,
                    reply_to_addrs, subject, text, html, headers_json, labels_json,
                    attachments_json, send_at, status, created_at, updated_at
             FROM drafts WHERE id = ?1",
            params![id],
            row_to_draft(&self.content),
        )??;
        transaction.commit()?;
        Ok(Some(draft))
    }

    /// Settle a draft claimed by [`Self::claim_draft`] or
    /// [`Self::claim_due_draft`]. This is a targeted status write guarded on
    /// `status='sending'`, never a full-row write from a stale snapshot, so it
    /// cannot overwrite edits or touch a row that was deleted or settled
    /// elsewhere. Returns `false` when the row is no longer `sending`.
    pub async fn finish_draft_send(
        &self,
        id: &str,
        status: &str,
        clear_send_at: bool,
    ) -> Result<bool> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE drafts
             SET status=?2,
                 send_at=CASE WHEN ?3 THEN NULL ELSE send_at END,
                 updated_at=?4
             WHERE id=?1 AND status='sending'",
            params![id, status, clear_send_at, Utc::now().to_rfc3339()],
        )?;
        Ok(changed > 0)
    }

    pub async fn delete_draft(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        Ok(conn.execute("DELETE FROM drafts WHERE id = ?1", params![id])? > 0)
    }

    // ── Webhooks ────────────────────────────────────────────────────────────

    pub async fn create_webhook(&self, webhook: Webhook) -> Result<Webhook> {
        let stored_secret = self.seal_value(&webhook.secret)?;
        let stored_headers = self.seal_headers(&webhook.headers)?;
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO webhooks
             (id, url, secret, event_types, headers_json, inbox_ids, pod_ids,
              client_id, enabled, created_at, updated_at, signature_scheme)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10,?11)",
            params![
                webhook.id,
                webhook.url,
                stored_secret,
                json_string(&webhook.event_types),
                stored_headers,
                json_string(&webhook.inbox_ids),
                json_string(&webhook.pod_ids),
                webhook.client_id,
                i64::from(webhook.enabled),
                webhook.created_at,
                webhook.signature_scheme.as_str(),
            ],
        )
        .context("inserting webhook")?;
        Ok(webhook)
    }

    pub async fn webhook_by_client_id(&self, client_id: &str) -> Result<Option<Webhook>> {
        let row = {
            let conn = self.conn.lock().await;
            conn.query_row(
                &format!("SELECT {WEBHOOK_COLUMNS} FROM webhooks WHERE client_id = ?1"),
                params![client_id],
                row_to_webhook,
            )
            .optional()?
        };
        row.map(|webhook| self.open_webhook(webhook)).transpose()
    }

    pub async fn list_webhooks(&self) -> Result<Vec<Webhook>> {
        let rows = {
            let conn = self.conn.lock().await;
            let mut statement = conn.prepare(&format!(
                "SELECT {WEBHOOK_COLUMNS} FROM webhooks ORDER BY created_at DESC"
            ))?;
            let rows = statement
                .query_map([], row_to_webhook)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        rows.into_iter()
            .map(|webhook| self.open_webhook(webhook))
            .collect()
    }

    pub async fn get_webhook(&self, id: &str) -> Result<Option<Webhook>> {
        let row = {
            let conn = self.conn.lock().await;
            conn.query_row(
                &format!("SELECT {WEBHOOK_COLUMNS} FROM webhooks WHERE id = ?1"),
                params![id],
                row_to_webhook,
            )
            .optional()?
        };
        row.map(|webhook| self.open_webhook(webhook)).transpose()
    }

    /// Persist a webhook's mutable fields, including its signing secret and
    /// scheme (changed by a rotation). Secrets and header values are re-sealed.
    pub async fn update_webhook(&self, webhook: &Webhook) -> Result<bool> {
        let stored_secret = self.seal_value(&webhook.secret)?;
        let stored_headers = self.seal_headers(&webhook.headers)?;
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE webhooks SET url=?2, event_types=?3, headers_json=?4, inbox_ids=?5,
                pod_ids=?6, enabled=?7, updated_at=?8, secret=?9, signature_scheme=?10
             WHERE id=?1",
            params![
                webhook.id,
                webhook.url,
                json_string(&webhook.event_types),
                stored_headers,
                json_string(&webhook.inbox_ids),
                json_string(&webhook.pod_ids),
                i64::from(webhook.enabled),
                Utc::now().to_rfc3339(),
                stored_secret,
                webhook.signature_scheme.as_str(),
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
                self.seal_col(
                    "mail_events",
                    "payload",
                    &event.event_id,
                    &serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_owned()),
                )?,
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
                .query_map(params![inbox_id, limit], row_to_event(&self.content))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            statement
                .query_map(params![limit], row_to_event(&self.content))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(self.keep_opened("event", rows))
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

    fn validate_send_key(key: &str) -> Result<()> {
        if key.trim().is_empty()
            || key.len() > 256
            || !key.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            bail!("invalid mail send idempotency key");
        }
        Ok(())
    }

    fn read_send_claim(
        conn: &Connection,
        content: &StoreSeal,
        key: &str,
        inbox_id: &str,
        request_hash: &str,
    ) -> Result<Option<SendClaim>> {
        let legacy: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mail_idempotency WHERE key=?1)",
            params![key],
            |row| row.get(0),
        )?;
        if legacy {
            return Ok(Some(SendClaim::Unresolved));
        }
        let row: Option<(String, String, Option<String>)> = conn
            .query_row(
                "SELECT inbox_id,request_hash,response_json FROM mail_send_claims WHERE key=?1",
                params![key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((stored_inbox, stored_hash, response)) = row else {
            return Ok(None);
        };
        if stored_inbox != inbox_id || stored_hash != request_hash {
            return Ok(Some(SendClaim::Conflict));
        }
        Ok(Some(match response {
            Some(response) => SendClaim::Replay(
                serde_json::from_str(
                    &content
                        .open_text(&response, &ctx("mail_send_claims", "response_json", key))?,
                )
                .context("corrupt mail send replay; reconciliation required")?,
            ),
            None => SendClaim::Unresolved,
        }))
    }

    /// Nonmutating lookup lets completed/uncertain requests be resolved without
    /// requiring a currently configured transport or probing a provider.
    pub async fn lookup_send(
        &self,
        key: &str,
        inbox_id: &str,
        request_hash: &str,
    ) -> Result<Option<SendClaim>> {
        Self::validate_send_key(key)?;
        let conn = self.conn.lock().await;
        Self::read_send_claim(&conn, &self.content, key, inbox_id, request_hash)
    }

    /// Persist intent before transport. Pending rows survive crashes and never expire.
    pub async fn claim_send(
        &self,
        key: &str,
        inbox_id: &str,
        request_hash: &str,
    ) -> Result<SendClaim> {
        Self::validate_send_key(key)?;
        let conn = self.conn.lock().await;
        if let Some(existing) =
            Self::read_send_claim(&conn, &self.content, key, inbox_id, request_hash)?
        {
            return Ok(existing);
        }
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO mail_send_claims (key,inbox_id,request_hash,response_json,created_at)
             VALUES (?1,?2,?3,NULL,?4)",
            params![key,inbox_id,request_hash,Utc::now().to_rfc3339()],
        )?;
        if inserted > 0 {
            return Ok(SendClaim::New);
        }
        Self::read_send_claim(&conn, &self.content, key, inbox_id, request_hash)?
            .context("mail send claim disappeared")
    }

    /// Run raw SQL against the store, e.g. to install a fault-injection trigger.
    #[cfg(test)]
    pub(crate) async fn execute_batch_for_test(&self, sql: &str) {
        self.conn.lock().await.execute_batch(sql).unwrap();
    }

    /// `(digest, message_id)` of every inbound replay tombstone of an inbox.
    #[cfg(test)]
    pub(crate) async fn inbound_tombstones_for_test(
        &self,
        inbox_id: &str,
    ) -> Vec<(String, Option<String>)> {
        let conn = self.conn.lock().await;
        let mut statement = conn
            .prepare(
                "SELECT digest, message_id FROM inbound_replay_tombstones
                 WHERE inbox_id = ?1 ORDER BY digest",
            )
            .unwrap();
        let rows = statement
            .query_map(params![inbox_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        rows
    }

    #[cfg(test)]
    pub(crate) async fn reject_send_completions_for_test(&self) {
        self.conn.lock().await.execute_batch("CREATE TRIGGER reject_send_completion BEFORE UPDATE OF response_json ON mail_send_claims BEGIN SELECT RAISE(FAIL, 'injected completion failure'); END;").unwrap();
    }

    /// Complete only the original pending claim. Never replace an acknowledged response.
    pub async fn complete_send(
        &self,
        key: &str,
        inbox_id: &str,
        request_hash: &str,
        response: &serde_json::Value,
    ) -> Result<bool> {
        let response = self.seal_col(
            "mail_send_claims",
            "response_json",
            key,
            &serde_json::to_string(response)?,
        )?;
        let conn = self.conn.lock().await;
        Ok(conn.execute(
            "UPDATE mail_send_claims SET response_json=?4
             WHERE key=?1 AND inbox_id=?2 AND request_hash=?3 AND response_json IS NULL",
            params![key, inbox_id, request_hash, response],
        )? > 0)
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
        let response = self
            .content
            .open_text(&response, &ctx("mail_idempotency", "response_json", key))?;
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
        let response = self.seal_col(
            "mail_idempotency",
            "response_json",
            key,
            &serde_json::to_string(response).unwrap_or_else(|_| "null".to_owned()),
        )?;
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO mail_idempotency
             (key, operation, request_hash, response_json, created_at, expires_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                key,
                operation,
                request_hash,
                response,
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
        let Some((mut meta, rel)) = row else {
            return Ok(None);
        };
        meta.filename = self
            .content
            .open_text(&meta.filename, &ctx("attachments", "filename", &meta.id))?;
        Ok(Some((meta, self.blobs_dir.join(rel))))
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

/// Draft columns in their sealed stored form.
struct SealedDraft {
    to_addrs: String,
    cc_addrs: String,
    bcc_addrs: String,
    reply_to_addrs: String,
    subject: String,
    text: Option<String>,
    html: Option<String>,
    headers_json: String,
    attachments_json: String,
}

/// Columns [`row_to_message`] maps, in order.
const MESSAGE_COLUMNS: &str = "id, inbox_id, direction, message_id, in_reply_to, thread_id,
    references_json, from_addr, to_addrs, cc_addrs, bcc_addrs,
    reply_to_addrs, subject, text, html, extracted_text, extracted_html,
    preview, headers_json, labels_json, status, read, opened_at,
    provider_message_id, raw_blob_path, raw_size, created_at, updated_at";
/// A message's labels as a `json_each` table (a malformed value reads as none).
const LABELS: &str =
    "json_each(CASE WHEN json_valid(messages.labels_json) THEN messages.labels_json ELSE '[]' END)";
/// Rows a free-text search opens per batch (and per hold of the store lock).
const SEARCH_BATCH: usize = 200;
/// Most rows a free-text search scans (newest first) before it stops.
const SEARCH_SCAN_LIMIT: usize = 1000;

/// Most messages of one thread a thread list opens (the newest).
pub const THREAD_SUMMARY_MESSAGES: u32 = 50;

/// Columns [`row_to_message_summary`] maps, in order: no bodies, headers or
/// reply-to addresses.
const SUMMARY_COLUMNS: &str = "id, inbox_id, direction, message_id, in_reply_to, thread_id,
    references_json, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, preview,
    labels_json, status, read, opened_at, provider_message_id, raw_size, created_at,
    updated_at";

/// The key a message is grouped under in a thread list.
const THREAD_KEY: &str = "COALESCE(thread_id, message_id)";

/// One thread of a thread list (see [`MailStore::list_thread_summaries`]).
#[derive(Clone, Debug)]
pub struct ThreadSummary {
    /// Its newest messages (at most [`THREAD_SUMMARY_MESSAGES`]), newest
    /// first, opened for a summary only: `text`, `html`, the extracted bodies
    /// and `headers` are empty, `reply_to_addrs` too.
    pub messages: Vec<EmailMessage>,
    /// Messages in the thread that the filter kept.
    pub message_count: u64,
    /// Raw size plus the stored body bytes of those messages.
    pub size: u64,
}

/// A thread before its rows are checked for opening.
struct OpenedThread {
    rows: Vec<Result<EmailMessage>>,
    message_count: u64,
    size: u64,
}

/// The `WHERE` body and values of an inbox listing: direction, `created_at`
/// cursors and labels (plaintext columns), trashed messages left out.
fn message_filter(
    inbox_id: &str,
    before: Option<&str>,
    after: Option<&str>,
    direction: Option<&str>,
    labels: &[String],
) -> (String, Vec<rusqlite::types::Value>) {
    let mut clause = String::from("inbox_id = ?");
    let mut values: Vec<rusqlite::types::Value> = vec![inbox_id.to_owned().into()];
    if let Some(cursor) = before {
        clause.push_str(" AND created_at < ?");
        values.push(cursor.to_owned().into());
    }
    if let Some(cursor) = after {
        clause.push_str(" AND created_at > ?");
        values.push(cursor.to_owned().into());
    }
    if let Some(value) = direction {
        clause.push_str(" AND direction = ?");
        values.push(value.to_owned().into());
    }
    for label in labels {
        clause.push_str(&format!(
            " AND EXISTS (SELECT 1 FROM {LABELS} WHERE value = ?)"
        ));
        values.push(label.clone().into());
    }
    clause.push_str(&format!(
        " AND NOT EXISTS (SELECT 1 FROM {LABELS} WHERE value = 'trash')"
    ));
    (clause, values)
}

/// The newest `limit` threads among the messages matching `clause` (chosen
/// and totalled in SQL from plaintext and stored lengths), then the newest
/// [`THREAD_SUMMARY_MESSAGES`] messages of each, opened for a summary, with
/// their attachment metadata loaded in one query per 500 messages.
fn thread_summaries(
    conn: &Connection,
    seal: &StoreSeal,
    clause: &str,
    values: Vec<rusqlite::types::Value>,
    limit: u32,
) -> Result<Vec<OpenedThread>> {
    let mut params = values.clone();
    params.push(i64::from(limit).into());
    let mut stmt = conn.prepare(&format!(
        "SELECT {THREAD_KEY} AS thread_key, COUNT(*),
                COALESCE(SUM(raw_size
                    + COALESCE(length(CAST(text AS BLOB)), 0)
                    + COALESCE(length(CAST(html AS BLOB)), 0)), 0)
         FROM messages WHERE {clause}
         GROUP BY thread_key
         ORDER BY MAX(created_at) DESC, thread_key DESC
         LIMIT ?"
    ))?;
    let page = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    if page.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; page.len()].join(", ");
    let mut params = values;
    params.extend(page.iter().map(|(key, _, _)| key.clone().into()));
    params.push(i64::from(THREAD_SUMMARY_MESSAGES).into());
    let mut stmt = conn.prepare(&format!(
        "SELECT {SUMMARY_COLUMNS}, {THREAD_KEY} FROM messages
         WHERE id IN (
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY {THREAD_KEY} ORDER BY created_at DESC, id DESC
                 ) AS position
                 FROM messages
                 WHERE {clause} AND {THREAD_KEY} IN ({placeholders})
             ) WHERE position <= ?
         )
         ORDER BY created_at DESC, id DESC"
    ))?;
    let summary = row_to_message_summary(seal);
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
            Ok((r.get::<_, String>(21)?, summary(r)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let ids: Vec<&str> = rows
        .iter()
        .filter_map(|(_, row)| row.as_ref().ok().map(|message| message.id.as_str()))
        .collect();
    let mut attachments = load_attachments_for(conn, seal, &ids)?;
    let mut by_thread: std::collections::HashMap<String, Vec<Result<EmailMessage>>> =
        std::collections::HashMap::new();
    for (key, row) in rows {
        let row = row.and_then(|mut message| {
            message.attachments = attachments.remove(&message.id).unwrap_or(Ok(Vec::new()))?;
            Ok(message)
        });
        by_thread.entry(key).or_default().push(row);
    }
    Ok(page
        .into_iter()
        .map(|(key, count, size)| OpenedThread {
            rows: by_thread.remove(&key).unwrap_or_default(),
            message_count: count.max(0) as u64,
            size: size.max(0) as u64,
        })
        .collect())
}

/// Maps a [`SUMMARY_COLUMNS`] row, opening only the addresses, subject and
/// preview (see [`row_to_message`] for the nested results).
fn row_to_message_summary(
    seal: &StoreSeal,
) -> impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<Result<EmailMessage>> + '_ {
    move |r| {
        let id: String = r.get(0)?;
        let raw = |index: usize| r.get::<_, String>(index);
        let (from, to, cc, bcc, subject) = (raw(7)?, raw(8)?, raw(9)?, raw(10)?, raw(11)?);
        let preview: Option<String> = r.get(12)?;
        let references_json: String = raw(6)?;
        let labels_json: String = raw(13)?;
        let message = EmailMessage {
            id: id.clone(),
            inbox_id: r.get(1)?,
            direction: r.get(2)?,
            message_id: r.get(3)?,
            in_reply_to: r.get(4)?,
            thread_id: r.get(5)?,
            references: json_vec(&references_json),
            from_addr: String::new(),
            to_addrs: Vec::new(),
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            reply_to_addrs: Vec::new(),
            subject: String::new(),
            text: None,
            html: None,
            extracted_text: None,
            extracted_html: None,
            preview: None,
            headers: BTreeMap::new(),
            labels: json_vec(&labels_json),
            status: r.get(14)?,
            read: r.get::<_, i64>(15)? != 0,
            opened_at: r.get(16)?,
            provider_message_id: r.get(17)?,
            attachments: Vec::new(),
            raw_size: r.get::<_, i64>(18)? as u64,
            created_at: r.get(19)?,
            updated_at: r.get(20)?,
        };
        Ok((|| -> Result<EmailMessage> {
            let open =
                |column: &str, value: &str| seal.open_text(value, &ctx("messages", column, &id));
            let mut message = message;
            message.from_addr = open("from_addr", &from)?;
            message.to_addrs = json_vec(&open("to_addrs", &to)?);
            message.cc_addrs = json_vec(&open("cc_addrs", &cc)?);
            message.bcc_addrs = json_vec(&open("bcc_addrs", &bcc)?);
            message.subject = open("subject", &subject)?;
            message.preview =
                seal.open_opt(preview.as_deref(), &ctx("messages", "preview", &id))?;
            Ok(message)
        })())
    }
}

/// Stored totals of one inbox (see [`MailStore::usage_totals`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsageTotals {
    pub message_count: u64,
    pub thread_count: u64,
    pub storage_bytes: u64,
}

/// Messages matching `clause` (a `WHERE` body, ordering and limit), opened,
/// with their attachment metadata loaded in one query.
fn query_messages(
    conn: &Connection,
    seal: &StoreSeal,
    clause: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<Result<EmailMessage>>> {
    query_messages_with(conn, seal, clause, params)
}

fn query_messages_with<P: rusqlite::Params>(
    conn: &Connection,
    seal: &StoreSeal,
    clause: &str,
    params: P,
) -> Result<Vec<Result<EmailMessage>>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages WHERE {clause}"
    ))?;
    let rows = stmt
        .query_map(params, row_to_message(seal))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let ids: Vec<&str> = rows
        .iter()
        .filter_map(|row| row.as_ref().ok().map(|message| message.id.as_str()))
        .collect();
    let mut attachments = load_attachments_for(conn, seal, &ids)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let mut message = row?;
            message.attachments = attachments.remove(&message.id).unwrap_or(Ok(Vec::new()))?;
            Ok(message)
        })
        .collect())
}

/// One batch of a free-text search: how many rows it read and, per row, the
/// id when it matched, `None` when not, or why it did not open.
struct SearchBatch {
    scanned: usize,
    rows: Vec<Result<Option<String>>>,
}

fn search_batch(
    conn: &Connection,
    seal: &StoreSeal,
    sql: &str,
    params: Vec<rusqlite::types::Value>,
    needle: &str,
) -> Result<SearchBatch> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    let mut stmt = conn.prepare(sql)?;
    let raw = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<Row>>>()?;
    let scanned = raw.len();
    let rows = raw
        .into_iter()
        .map(|(id, from, to, cc, bcc, subject, text, html)| {
            let open =
                |column: &str, value: &str| seal.open_text(value, &ctx("messages", column, &id));
            let hit = |value: &str| value.to_ascii_lowercase().contains(needle);
            // Addresses and subject first: most matches never open a body.
            for (column, value) in [
                ("from_addr", &from),
                ("subject", &subject),
                ("to_addrs", &to),
                ("cc_addrs", &cc),
                ("bcc_addrs", &bcc),
            ] {
                let opened = open(column, value)?;
                let opened = if column.ends_with("_addrs") {
                    json_vec::<String>(&opened).join(" ")
                } else {
                    opened
                };
                if hit(&opened) {
                    return Ok(Some(id.clone()));
                }
            }
            for (column, value) in [("text", &text), ("html", &html)] {
                if let Some(value) = value {
                    if hit(&open(column, value)?) {
                        return Ok(Some(id.clone()));
                    }
                }
            }
            Ok(None)
        })
        .collect();
    Ok(SearchBatch { scanned, rows })
}

/// Maps a message row, opening its sealed columns. The outer result is the
/// SQLite read; the inner one is whether the row opened (lists skip and count
/// a row that does not, get-by-id reports it).
fn row_to_message(
    seal: &StoreSeal,
) -> impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<Result<EmailMessage>> + '_ {
    move |r| {
        let id: String = r.get(0)?;
        let raw = |index: usize| r.get::<_, String>(index);
        let raw_opt = |index: usize| r.get::<_, Option<String>>(index);
        let (from, to, cc, bcc, reply_to, subject) =
            (raw(7)?, raw(8)?, raw(9)?, raw(10)?, raw(11)?, raw(12)?);
        let (text, html, extracted_text, extracted_html, preview) = (
            raw_opt(13)?,
            raw_opt(14)?,
            raw_opt(15)?,
            raw_opt(16)?,
            raw_opt(17)?,
        );
        let headers_json = raw(18)?;
        let references_json: String = raw(6)?;
        let labels_json: String = raw(19)?;
        let message = EmailMessage {
            id: id.clone(),
            inbox_id: r.get(1)?,
            direction: r.get(2)?,
            message_id: r.get(3)?,
            in_reply_to: r.get(4)?,
            thread_id: r.get(5)?,
            references: json_vec(&references_json),
            from_addr: String::new(),
            to_addrs: Vec::new(),
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            reply_to_addrs: Vec::new(),
            subject: String::new(),
            text: None,
            html: None,
            extracted_text: None,
            extracted_html: None,
            preview: None,
            headers: BTreeMap::new(),
            labels: json_vec(&labels_json),
            status: r.get(20)?,
            read: r.get::<_, i64>(21)? != 0,
            opened_at: r.get(22)?,
            provider_message_id: r.get(23)?,
            attachments: Vec::new(),
            raw_size: r.get::<_, i64>(25)? as u64,
            created_at: r.get(26)?,
            updated_at: r.get(27)?,
        };
        Ok((|| -> Result<EmailMessage> {
            let open =
                |column: &str, value: &str| seal.open_text(value, &ctx("messages", column, &id));
            let open_opt = |column: &str, value: Option<String>| {
                seal.open_opt(value.as_deref(), &ctx("messages", column, &id))
            };
            let mut message = message;
            message.from_addr = open("from_addr", &from)?;
            message.to_addrs = json_vec(&open("to_addrs", &to)?);
            message.cc_addrs = json_vec(&open("cc_addrs", &cc)?);
            message.bcc_addrs = json_vec(&open("bcc_addrs", &bcc)?);
            message.reply_to_addrs = json_vec(&open("reply_to_addrs", &reply_to)?);
            message.subject = open("subject", &subject)?;
            message.text = open_opt("text", text)?;
            message.html = open_opt("html", html)?;
            message.extracted_text = open_opt("extracted_text", extracted_text)?;
            message.extracted_html = open_opt("extracted_html", extracted_html)?;
            message.preview = open_opt("preview", preview)?;
            message.headers = json_string_map(&open("headers_json", &headers_json)?);
            Ok(message)
        })())
    }
}

/// Maps a draft row, opening its sealed columns (see [`row_to_message`]).
fn row_to_draft(
    seal: &StoreSeal,
) -> impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<Result<Draft>> + '_ {
    move |r| {
        let id: String = r.get(0)?;
        let raw = |index: usize| r.get::<_, String>(index);
        let raw_opt = |index: usize| r.get::<_, Option<String>>(index);
        let (to, cc, bcc, reply_to, subject) = (raw(4)?, raw(5)?, raw(6)?, raw(7)?, raw(8)?);
        let (text, html) = (raw_opt(9)?, raw_opt(10)?);
        let (headers_json, labels_json, attachments_json) = (raw(11)?, raw(12)?, raw(13)?);
        let draft = Draft {
            id: id.clone(),
            inbox_id: r.get(1)?,
            thread_id: r.get(2)?,
            client_id: r.get(3)?,
            to_addrs: Vec::new(),
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            reply_to_addrs: Vec::new(),
            subject: String::new(),
            text: None,
            html: None,
            headers: BTreeMap::new(),
            labels: json_vec(&labels_json),
            attachments: Vec::new(),
            send_at: r.get(14)?,
            status: r.get(15)?,
            created_at: r.get(16)?,
            updated_at: r.get(17)?,
        };
        Ok((|| -> Result<Draft> {
            let open =
                |column: &str, value: &str| seal.open_text(value, &ctx("drafts", column, &id));
            let mut draft = draft;
            draft.to_addrs = json_vec(&open("to_addrs", &to)?);
            draft.cc_addrs = json_vec(&open("cc_addrs", &cc)?);
            draft.bcc_addrs = json_vec(&open("bcc_addrs", &bcc)?);
            draft.reply_to_addrs = json_vec(&open("reply_to_addrs", &reply_to)?);
            draft.subject = open("subject", &subject)?;
            draft.text = seal.open_opt(text.as_deref(), &ctx("drafts", "text", &id))?;
            draft.html = seal.open_opt(html.as_deref(), &ctx("drafts", "html", &id))?;
            draft.headers = json_string_map(&open("headers_json", &headers_json)?);
            draft.attachments = json_vec(&open("attachments_json", &attachments_json)?);
            Ok(draft)
        })())
    }
}

/// Inbox columns in the order [`row_to_inbox`] reads them.
const INBOX_COLUMNS: &str = "id, name, address, provider, inbound_secret, client_id,
    metadata_json, pod_id, created_at, updated_at, require_timestamp";

/// Maps a row selected with [`INBOX_COLUMNS`]. The secret is still in its stored
/// (possibly sealed) form; [`MailStore::open_inbox`] opens it.
fn row_to_inbox(r: &rusqlite::Row<'_>) -> rusqlite::Result<Inbox> {
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
        require_timestamp: r.get::<_, i64>(10)? != 0,
    })
}

/// Webhook columns in the order [`row_to_webhook`] reads them.
const WEBHOOK_COLUMNS: &str = "id, url, secret, event_types, headers_json, inbox_ids, pod_ids,
    client_id, enabled, created_at, updated_at, signature_scheme";

/// Maps a row selected with [`WEBHOOK_COLUMNS`]. The secret and header values
/// are still in stored form; [`MailStore::open_webhook`] opens them.
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
        signature_scheme: SignatureScheme::from_stored(&r.get::<_, String>(11)?),
    })
}

fn row_to_event(
    seal: &StoreSeal,
) -> impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<Result<MailEvent>> + '_ {
    move |r| {
        let event_id: String = r.get(0)?;
        let raw: String = r.get(4)?;
        let event = MailEvent {
            event_id: event_id.clone(),
            event_type: r.get(1)?,
            inbox_id: r.get(2)?,
            message_id: r.get(3)?,
            payload: serde_json::Value::Null,
            created_at: r.get(5)?,
        };
        Ok(seal
            .open_text(&raw, &ctx("mail_events", "payload", &event_id))
            .map(|payload| MailEvent {
                payload: serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
                ..event
            }))
    }
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

fn load_attachments(
    conn: &Connection,
    seal: &StoreSeal,
    message_id: &str,
) -> Result<Vec<AttachmentMeta>> {
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
    rows.into_iter()
        .map(|mut meta| {
            meta.filename =
                seal.open_text(&meta.filename, &ctx("attachments", "filename", &meta.id))?;
            Ok(meta)
        })
        .collect()
}

/// Attachment metadata of many messages in one query per 500 ids. A message
/// whose attachment does not open maps to that error.
fn load_attachments_for(
    conn: &Connection,
    seal: &StoreSeal,
    message_ids: &[&str],
) -> Result<std::collections::HashMap<String, Result<Vec<AttachmentMeta>>>> {
    let mut by_message: std::collections::HashMap<String, Result<Vec<AttachmentMeta>>> =
        std::collections::HashMap::new();
    for chunk in message_ids.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let mut stmt = conn.prepare(&format!(
            "SELECT message_id, id, filename, content_type, size, inline, content_id
             FROM attachments WHERE message_id IN ({placeholders})"
        ))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(chunk.iter()), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    AttachmentMeta {
                        id: r.get(1)?,
                        filename: r.get(2)?,
                        content_type: r.get(3)?,
                        size: r.get::<_, i64>(4)? as u64,
                        inline: r.get::<_, i64>(5)? != 0,
                        content_id: r.get(6)?,
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (message_id, mut meta) in rows {
            let entry = by_message
                .entry(message_id)
                .or_insert_with(|| Ok(Vec::new()));
            let Ok(list) = entry else {
                continue;
            };
            match seal.open_text(&meta.filename, &ctx("attachments", "filename", &meta.id)) {
                Ok(filename) => {
                    meta.filename = filename;
                    list.push(meta);
                }
                Err(error) => *entry = Err(error),
            }
        }
    }
    Ok(by_message)
}

/// Seal every legacy plaintext blob in place, one at a time (each sealed copy
/// is verified before it replaces the original). Temp files and files that
/// are not content-addressed blobs are left alone. Returns `(sealed, failed)`;
/// failures (a file removed meanwhile, short disk space) retry next start.
fn seal_legacy_blobs(dir: &std::path::Path, seal: &StoreSeal) -> (usize, usize) {
    let Some(cipher) = seal.cipher() else {
        return (0, 0);
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let (mut sealed, mut failed) = (0, 0);
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let hex = name.strip_prefix("raw-").unwrap_or(&name);
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        match seal_file_in_place(&entry.path(), cipher, &blob_ctx(&name)) {
            Ok(ryu_crypto::sealed_file::SealInPlace::Sealed { .. }) => sealed += 1,
            Ok(_) => {}
            Err(error) => {
                failed += 1;
                tracing::warn!("mail: sealing blob {name} failed (retried next start): {error:#}");
            }
        }
    }
    (sealed, failed)
}

/// Create `dir` and any missing parents as owner-only (0700 on Unix). A directory
/// that already exists keeps its mode: the data dir can be shared with Core.
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Create an empty owner-only (0600) file if `path` does not exist yet, so the
/// database (and the WAL/SHM files SQLite gives the same mode) never starts out
/// world-readable under the default umask.
fn create_private_file(path: &std::path::Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

/// Write a blob owner-only (0600 on Unix).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// Narrow an existing mail-owned path to `mode` (best effort, Unix only).
fn restrict_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Content-addressed blob name for a message's raw MIME.
fn raw_blob_name(bytes: &[u8]) -> String {
    format!("raw-{:x}", Sha256::digest(bytes))
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

/// Point `RYU_DIR` and `RYU_PLUGIN_DATA_DIR` at a temp dir so the sidecar's default
/// path never writes to the real `~/.ryu`. Every test store MUST be built via
/// [`fresh_store`] so this is set before the OnceLock is first initialized.
#[cfg(test)]
pub(crate) fn test_ryu_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("ryu-mail-backend-tests");
    std::env::set_var("RYU_DIR", &dir);
    std::env::set_var(
        "RYU_PLUGIN_DATA_DIR",
        dir.join("plugin-data").join("@ryu+mail"),
    );
    dir
}

/// A fresh store on a unique on-disk SQLite file.
#[cfg(test)]
pub(crate) fn fresh_store() -> MailStore {
    test_ryu_dir();
    let db = std::env::temp_dir().join(format!("ryu-mail-test-{}.db", uuid::Uuid::new_v4()));
    MailStore::open(db).expect("open store")
}

/// A fresh store that seals secrets with the fixed test subkey `[byte; 32]`.
#[cfg(test)]
pub(crate) fn fresh_sealed_store(byte: &[u8; 32]) -> MailStore {
    test_ryu_dir();
    let db = std::env::temp_dir().join(format!("ryu-mail-test-{}.db", uuid::Uuid::new_v4()));
    MailStore::open_with_sealer(db, Some(crate::seal::test_sealer(byte[0])))
        .expect("open sealed store")
}

#[cfg(test)]
mod tests {
    use super::{blobs_dir_for_db, fresh_store, MailStore, RawAttachment};
    use crate::{EmailMessage, InboxProvider};
    use rusqlite::Connection;
    use std::collections::BTreeMap;

    fn blob_on_disk_contains(path: &std::path::Path, needle: &[u8]) -> bool {
        let bytes = std::fs::read(path).unwrap();
        bytes.windows(needle.len()).any(|window| window == needle)
    }

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

    #[test]
    fn normalize_inbox_address_lowercases_and_validates() {
        use super::normalize_inbox_address;
        assert_eq!(
            normalize_inbox_address("  Help@Node.Example ").as_deref(),
            Some("help@node.example")
        );
        for bad in [
            "", "plain", "a@b@c.io", "a b@c.io", "a@c", "a@.c.io", "a@c..io", "<a@c.io>",
        ] {
            assert_eq!(normalize_inbox_address(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn duplicate_addresses_are_refused_case_insensitively() {
        let store = fresh_store();
        store
            .create_inbox("A", "team@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let err = store
            .create_inbox("B", "TEAM@x.com", InboxProvider::Webhook)
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<super::AddressTaken>().is_some());
        assert_eq!(store.list_inboxes().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn legacy_duplicate_addresses_open_without_the_index_and_stay_guarded() {
        super::test_ryu_dir();
        let db = std::env::temp_dir().join(format!("ryu-mail-dups-{}.db", uuid::Uuid::new_v4()));
        {
            let store = MailStore::open(db.clone()).unwrap();
            store
                .create_inbox("A", "dup@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
        }
        {
            // A store written before the rule: drop the index and add a duplicate.
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "DROP INDEX idx_inboxes_address;
                 INSERT INTO inboxes (id, name, address, provider, inbound_secret,
                                      metadata_json, created_at, updated_at)
                 VALUES ('legacy', 'B', 'DUP@x.com', 'webhook', 's', '{}', 'now', 'now');",
            )
            .unwrap();
        }
        let store = MailStore::open(db.clone()).expect("a legacy duplicate must not block startup");
        let err = store
            .create_inbox("C", "dup@x.com", InboxProvider::Webhook)
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<super::AddressTaken>().is_some());
        let conn = Connection::open(&db).unwrap();
        let indexed: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'idx_inboxes_address')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!indexed);
    }

    #[test]
    fn legacy_schema_is_migrated_before_new_indexes_are_created() {
        let root = std::env::temp_dir().join(format!("ryu-mail-legacy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("mail.db");
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE inboxes (
                     id TEXT PRIMARY KEY,
                     name TEXT NOT NULL,
                     address TEXT NOT NULL,
                     provider TEXT NOT NULL,
                     inbound_secret TEXT NOT NULL,
                     created_at TEXT NOT NULL
                 );
                 CREATE TABLE messages (
                     id TEXT PRIMARY KEY,
                     inbox_id TEXT NOT NULL,
                     direction TEXT NOT NULL,
                     message_id TEXT NOT NULL,
                     in_reply_to TEXT,
                     from_addr TEXT NOT NULL,
                     to_addrs TEXT NOT NULL,
                     subject TEXT NOT NULL,
                     text TEXT,
                     html TEXT,
                     created_at TEXT NOT NULL
                 );",
            )
            .unwrap();
        }

        let store = MailStore::open(db.clone()).unwrap();
        drop(store);

        let conn = Connection::open(&db).unwrap();
        let has_thread_id: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'thread_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(has_thread_id, 1);
        let has_thread_index: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_messages_thread'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(has_thread_index, 1);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
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
    async fn raw_mime_survives_a_store_restart_and_orphans_do_not() {
        super::test_ryu_dir();
        let db =
            std::env::temp_dir().join(format!("ryu-mail-raw-restart-{}.db", uuid::Uuid::new_v4()));
        let raw = b"From: sender@x.com\r\nSubject: hi\r\n\r\nraw body";
        let (message_id, raw_path, stray) = {
            let store = MailStore::open(db.clone()).unwrap();
            let inbox = store
                .create_inbox("Raw", "raw@x.com", InboxProvider::Webhook)
                .await
                .unwrap();
            let stored = store
                .insert_message_with_raw(
                    sample_message("raw-kept", &inbox.id, "2020-01-01T00:00:00Z"),
                    Vec::new(),
                    Some(raw),
                )
                .await
                .unwrap();
            let (_, path) = store.raw_path(&stored.id).await.unwrap().unwrap();
            assert!(path.exists());
            // A raw blob left by a crash between the file write and the commit.
            let stray = store.blobs_dir.join("raw-0000");
            std::fs::write(&stray, b"orphan").unwrap();
            (stored.id, path, stray)
        };

        let reopened = MailStore::open(db).unwrap();
        let (size, path) = reopened.raw_path(&message_id).await.unwrap().unwrap();
        assert_eq!(path, raw_path);
        assert_eq!(size, raw.len() as u64);
        assert_eq!(
            reopened.read_raw(&message_id).await.unwrap().unwrap().1,
            raw,
            "a stored message's raw MIME must survive a restart"
        );
        assert!(
            !blob_on_disk_contains(&path, raw),
            "raw MIME is sealed at rest"
        );
        assert!(!stray.exists(), "an unreferenced raw blob is still swept");
    }

    #[tokio::test]
    async fn deleting_a_message_keeps_raw_mime_another_inbox_still_uses() {
        let store = fresh_store();
        let first = store
            .create_inbox("First", "first@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let second = store
            .create_inbox("Second", "second@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let raw = b"From: sender@x.com\r\n\r\nsame bytes to two inboxes";
        let a = store
            .insert_message_with_raw(
                sample_message("shared-a", &first.id, "2020-01-01T00:00:00Z"),
                Vec::new(),
                Some(raw),
            )
            .await
            .unwrap();
        let b = store
            .insert_message_with_raw(
                sample_message("shared-b", &second.id, "2020-01-01T00:00:00Z"),
                Vec::new(),
                Some(raw),
            )
            .await
            .unwrap();
        let (_, path) = store.raw_path(&b.id).await.unwrap().unwrap();

        assert!(store.delete_message(&a.id).await.unwrap());
        assert!(path.exists(), "the other inbox's message still needs it");
        assert_eq!(store.read_raw(&b.id).await.unwrap().unwrap().1, raw);

        assert!(store.delete_message(&b.id).await.unwrap());
        assert!(!path.exists(), "the last reference takes the blob with it");
    }

    #[tokio::test]
    async fn deleting_an_inbox_removes_only_its_unshared_raw_mime() {
        let store = fresh_store();
        let doomed = store
            .create_inbox("Doomed", "doomed-raw@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let kept = store
            .create_inbox("Kept", "kept-raw@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let private_raw = b"From: a@x.com\r\n\r\nonly in the doomed inbox";
        let shared_raw = b"From: a@x.com\r\n\r\nin both inboxes";
        let private = store
            .insert_message_with_raw(
                sample_message("doomed-private", &doomed.id, "2020-01-01T00:00:00Z"),
                Vec::new(),
                Some(private_raw),
            )
            .await
            .unwrap();
        store
            .insert_message_with_raw(
                sample_message("doomed-shared", &doomed.id, "2020-01-01T00:00:00Z"),
                Vec::new(),
                Some(shared_raw),
            )
            .await
            .unwrap();
        let survivor = store
            .insert_message_with_raw(
                sample_message("kept-shared", &kept.id, "2020-01-01T00:00:00Z"),
                Vec::new(),
                Some(shared_raw),
            )
            .await
            .unwrap();
        let (_, private_path) = store.raw_path(&private.id).await.unwrap().unwrap();
        let (_, shared_path) = store.raw_path(&survivor.id).await.unwrap().unwrap();

        store.delete_inbox(&doomed.id).await.unwrap();

        assert!(!private_path.exists(), "the deleted inbox's raw MIME goes");
        assert!(
            shared_path.exists(),
            "raw MIME still referenced elsewhere stays"
        );
        assert_eq!(
            store.read_raw(&survivor.id).await.unwrap().unwrap().1,
            shared_raw
        );
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

    /// Five messages over one inbox: labels, a trashed one, an outbound one,
    /// a body-only search term and two messages in one thread.
    async fn filter_fixture(store: &MailStore) {
        store.ensure_test_inbox("ibx").await;
        let mut seeded = Vec::new();
        for (i, labels) in [
            vec!["work"],
            vec!["work", "trash"],
            vec![],
            vec!["work"],
            vec!["home"],
        ]
        .into_iter()
        .enumerate()
        {
            let mut message = sample_message(
                &format!("m{i}"),
                "ibx",
                &format!("2020-01-0{}T00:00:00Z", i + 1),
            );
            message.labels = labels.into_iter().map(str::to_owned).collect();
            seeded.push(message);
        }
        seeded[2].direction = "outbound".to_owned();
        seeded[3].text = Some("the quarterly Invoice is attached".to_owned());
        seeded[4].thread_id = seeded[0].thread_id.clone();
        for message in seeded {
            let attachments = if message.id == "m0" {
                vec![RawAttachment {
                    filename: "a.txt".to_owned(),
                    content_type: "text/plain".to_owned(),
                    bytes: b"12345".to_vec(),
                    inline: false,
                    content_id: None,
                }]
            } else {
                Vec::new()
            };
            store.insert_message(message, attachments).await.unwrap();
        }
    }

    fn ids(messages: &[EmailMessage]) -> Vec<&str> {
        messages.iter().map(|message| message.id.as_str()).collect()
    }

    #[tokio::test]
    async fn list_filters_run_in_sql_and_open_only_the_page() {
        let store = fresh_store();
        filter_fixture(&store).await;
        let page = store
            .list_messages_with_filters("ibx", 2, None, None, None, &[], None)
            .await
            .unwrap();
        // Newest first, trash left out, limit applied.
        assert_eq!(ids(&page), ["m4", "m3"]);
        let work = store
            .list_messages_with_filters("ibx", 50, None, None, None, &["work".to_owned()], None)
            .await
            .unwrap();
        assert_eq!(ids(&work), ["m3", "m0"]);
        assert_eq!(work[1].attachments.len(), 1);
        assert_eq!(work[1].attachments[0].filename, "a.txt");
        let outbound = store
            .list_messages_with_filters("ibx", 50, None, None, Some("outbound"), &[], None)
            .await
            .unwrap();
        assert_eq!(ids(&outbound), ["m2"]);
        let window = store
            .list_messages_with_filters(
                "ibx",
                50,
                Some("2020-01-05T00:00:00Z"),
                Some("2020-01-01T00:00:00Z"),
                None,
                &[],
                None,
            )
            .await
            .unwrap();
        assert_eq!(ids(&window), ["m3", "m2"]);
    }

    #[tokio::test]
    async fn search_matches_addresses_subjects_and_bodies_within_the_limit() {
        let store = fresh_store();
        filter_fixture(&store).await;
        let body = store
            .list_messages_with_filters("ibx", 50, None, None, None, &[], Some("INVOICE"))
            .await
            .unwrap();
        assert_eq!(ids(&body), ["m3"]);
        assert_eq!(
            body[0].text.as_deref(),
            Some("the quarterly Invoice is attached")
        );
        let address = store
            .list_messages_with_filters("ibx", 2, None, None, None, &[], Some("c@x.com"))
            .await
            .unwrap();
        assert_eq!(
            ids(&address),
            ["m4", "m3"],
            "trash is excluded, limit applies"
        );
        let none = store
            .list_messages_with_filters("ibx", 50, None, None, None, &[], Some("nowhere"))
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn thread_views_and_usage_totals_read_only_what_they_need() {
        let store = fresh_store();
        filter_fixture(&store).await;
        let thread = store
            .messages_for_thread("ibx", "<m0@x.com>")
            .await
            .unwrap();
        assert_eq!(ids(&thread), ["m4", "m0"]);
        let totals = store.usage_totals("ibx").await.unwrap();
        assert_eq!(totals.message_count, 5);
        assert_eq!(totals.thread_count, 4);
        assert!(totals.storage_bytes >= 5, "{totals:?}");
        assert_eq!(
            store.usage_totals("other").await.unwrap(),
            super::UsageTotals::default()
        );
    }

    fn thread_ids(threads: &[super::ThreadSummary]) -> Vec<Vec<&str>> {
        threads.iter().map(|thread| ids(&thread.messages)).collect()
    }

    #[tokio::test]
    async fn thread_lists_page_in_sql_and_open_only_summaries() {
        let store = fresh_store();
        filter_fixture(&store).await;
        let page = store
            .list_thread_summaries("ibx", 50, None, None, None, &[])
            .await
            .unwrap();
        // Newest activity first; m0 and m4 share a thread; trash left out.
        assert_eq!(
            thread_ids(&page),
            [vec!["m4", "m0"], vec!["m3"], vec!["m2"]]
        );
        assert_eq!(page[0].message_count, 2);
        assert!(page[0].size >= page[0].messages[1].raw_size);
        assert_eq!(page[0].messages[1].attachments[0].filename, "a.txt");
        assert_eq!(page[0].messages[0].cc_addrs, ["c@x.com"]);
        let limited = store
            .list_thread_summaries("ibx", 2, None, None, None, &[])
            .await
            .unwrap();
        assert_eq!(thread_ids(&limited), [vec!["m4", "m0"], vec!["m3"]]);
        let work = store
            .list_thread_summaries("ibx", 50, None, None, None, &["work".to_owned()])
            .await
            .unwrap();
        assert_eq!(thread_ids(&work), [vec!["m3"], vec!["m0"]]);
        assert_eq!(work[1].message_count, 1);
        let outbound = store
            .list_thread_summaries("ibx", 50, None, None, Some("outbound"), &[])
            .await
            .unwrap();
        assert_eq!(thread_ids(&outbound), [vec!["m2"]]);
        // Bodies and headers are never opened: a row whose body and headers
        // do not open still lists, and its summary carries neither.
        store
            .execute_batch_for_test(
                "UPDATE messages SET
                     text = (SELECT text FROM messages WHERE id = 'm3'),
                     headers_json = (SELECT headers_json FROM messages WHERE id = 'm3')
                 WHERE id = 'm2'",
            )
            .await;
        assert!(store.get_message("m2").await.is_err());
        let page = store
            .list_thread_summaries("ibx", 50, None, None, None, &[])
            .await
            .unwrap();
        assert_eq!(page.len(), 3);
        assert_eq!(store.seal_health()["unreadable_rows"], 0);
        for thread in &page {
            for message in &thread.messages {
                assert!(message.text.is_none() && message.html.is_none());
                assert!(message.headers.is_empty());
            }
        }
        // Search groups the matched messages through the same summary path.
        let found = store
            .search_thread_summaries("ibx", "INVOICE", 50)
            .await
            .unwrap();
        assert_eq!(thread_ids(&found), [vec!["m3"]]);
        assert!(found[0].messages[0].text.is_none());
        let by_address = store
            .search_thread_summaries("ibx", "c@x.com", 1)
            .await
            .unwrap();
        assert_eq!(thread_ids(&by_address), [vec!["m4", "m0"]]);
        assert!(store
            .search_thread_summaries("ibx", "nowhere", 50)
            .await
            .unwrap()
            .is_empty());
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
        assert!(!blob_on_disk_contains(&path, b"PDF-BYTES-HERE"));
        let (_, bytes) = store.read_attachment(att_id).await.unwrap().unwrap();
        assert_eq!(bytes, b"PDF-BYTES-HERE");
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
        let old_blob_dir = old_dir.join("blobs");
        drop(store);

        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::copy(&old_db, new_dir.join("mail.db")).unwrap();
        std::fs::create_dir_all(new_dir.join("blobs")).unwrap();
        for entry in std::fs::read_dir(old_blob_dir).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), new_dir.join("blobs").join(entry.file_name())).unwrap();
        }

        let relocated = MailStore::open(new_dir.join("mail.db")).unwrap();
        let attachment_id = &stored.attachments[0].id;
        let (_, path) = relocated
            .attachment_path(attachment_id)
            .await
            .unwrap()
            .unwrap();
        let expected_blob_dir = new_dir.join("blobs");
        assert_eq!(path.parent(), Some(expected_blob_dir.as_path()));
        let (_, bytes) = relocated
            .read_attachment(attachment_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, b"relocation-safe");
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

    #[cfg(unix)]
    #[tokio::test]
    async fn the_store_keeps_mail_and_secrets_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let root = std::env::temp_dir().join(format!("ryu-mail-perms-{}", uuid::Uuid::new_v4()));
        let data = root.join("data");
        let db = data.join("mail.db");
        let blobs = blobs_dir_for_db(&db);
        let store = MailStore::open(db.clone()).unwrap();
        store.ensure_test_inbox("ibx").await;
        store
            .insert_message_with_raw(
                sample_message("m1", "ibx", "2020-01-01T00:00:00Z"),
                vec![RawAttachment {
                    filename: "doc.pdf".to_string(),
                    content_type: "application/pdf".to_string(),
                    bytes: b"PDF".to_vec(),
                    inline: false,
                    content_id: None,
                }],
                Some(b"From: a@x.com\r\n\r\nraw"),
            )
            .await
            .unwrap();
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&blobs), 0o700);
        assert_eq!(mode(&db), 0o600);
        for sidecar in ["mail.db-wal", "mail.db-shm"] {
            let path = data.join(sidecar);
            if path.exists() {
                assert_eq!(mode(&path), 0o600, "{sidecar}");
            }
        }
        let blob_files = std::fs::read_dir(&blobs).unwrap().collect::<Vec<_>>();
        assert_eq!(blob_files.len(), 2, "attachment and raw MIME blobs");
        for entry in blob_files {
            assert_eq!(mode(&entry.unwrap().path()), 0o600);
        }
        drop(store);

        // A store created before this was enforced is narrowed when reopened.
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _reopened = MailStore::open(db.clone()).unwrap();
        assert_eq!(mode(&db), 0o600);
        assert_eq!(mode(&blobs), 0o700);
    }

    #[tokio::test]
    async fn due_drafts_compare_instants_not_text() {
        let store = fresh_store();
        let inbox = store
            .create_inbox("Due", "due@node.example", InboxProvider::Webhook)
            .await
            .unwrap();
        let draft = |id: &str, send_at: &str| crate::Draft {
            id: id.to_owned(),
            inbox_id: inbox.id.clone(),
            thread_id: None,
            client_id: None,
            to_addrs: vec!["a@ok.example".to_owned()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            reply_to_addrs: Vec::new(),
            subject: "s".to_owned(),
            text: None,
            html: None,
            headers: BTreeMap::new(),
            labels: Vec::new(),
            attachments: Vec::new(),
            send_at: Some(send_at.to_owned()),
            status: "scheduled".to_owned(),
            created_at: "2026-10-10T00:00:00Z".to_owned(),
            updated_at: "2026-10-10T00:00:00Z".to_owned(),
        };
        // Legacy rows stored before `sendAt` was normalized: 10:30+02:00 is
        // 08:30Z, which is due at 09:00Z even though it sorts after it as text.
        store
            .create_draft(draft("offset", "2026-10-10T10:30:00+02:00"))
            .await
            .unwrap();
        store
            .create_draft(draft("future", "2026-10-10T09:30:00Z"))
            .await
            .unwrap();
        store
            .create_draft(draft("garbage", "next tuesday"))
            .await
            .unwrap();
        store
            .create_draft(draft("earliest", "2026-10-10T07:00:00Z"))
            .await
            .unwrap();
        let mut parked = draft("parked", "2026-10-10T06:00:00Z");
        parked.status = "failed".to_owned();
        store.create_draft(parked).await.unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-10T09:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let due = |limit| {
            let store = store.clone();
            async move {
                store
                    .list_due_drafts(now, limit)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|draft| draft.id)
                    .collect::<Vec<_>>()
            }
        };
        // The unparseable value surfaces first so the scheduler fails it visibly;
        // the rest are oldest instant first, and a parked draft is never due.
        assert_eq!(due(16).await, ["garbage", "earliest", "offset"]);
        assert_eq!(due(2).await, ["garbage", "earliest"]);
    }
    #[tokio::test]
    async fn send_claims_are_scoped_immutable_and_survive_reopen() {
        use super::SendClaim;
        let path = std::env::temp_dir().join(format!("ryu-mail-claim-{}.db", uuid::Uuid::new_v4()));
        let store = MailStore::open(path.clone()).unwrap();
        let competing_store = MailStore::open(path.clone()).unwrap();
        assert_eq!(
            store.lookup_send("retry", "inbox-a", "body").await.unwrap(),
            None
        );
        let (a, b) = tokio::join!(
            store.claim_send("retry", "inbox-a", "body"),
            competing_store.claim_send("retry", "inbox-a", "body")
        );
        let claims = [a.unwrap(), b.unwrap()];
        assert_eq!(claims.iter().filter(|c| **c == SendClaim::New).count(), 1);
        assert_eq!(
            claims
                .iter()
                .filter(|c| **c == SendClaim::Unresolved)
                .count(),
            1
        );
        assert_eq!(
            store.claim_send("retry", "inbox-b", "body").await.unwrap(),
            SendClaim::Conflict
        );
        assert_eq!(
            store
                .claim_send("retry", "inbox-a", "changed")
                .await
                .unwrap(),
            SendClaim::Conflict
        );
        assert_eq!(
            store.lookup_send("retry", "inbox-a", "body").await.unwrap(),
            Some(SendClaim::Unresolved)
        );
        let response = serde_json::json!({"message":{"id":"accepted"}});
        assert!(!store
            .complete_send("retry", "inbox-b", "body", &response)
            .await
            .unwrap());
        assert!(store
            .complete_send("retry", "inbox-a", "body", &response)
            .await
            .unwrap());
        assert!(!store
            .complete_send(
                "retry",
                "inbox-a",
                "body",
                &serde_json::json!({"replacement":true})
            )
            .await
            .unwrap());
        drop(competing_store);
        drop(store);
        let reopened = MailStore::open(path).unwrap();
        assert_eq!(
            reopened
                .claim_send("retry", "inbox-a", "body")
                .await
                .unwrap(),
            SendClaim::Replay(response)
        );
    }

    #[tokio::test]
    async fn failed_completion_and_corrupt_replay_never_release_send_claim() {
        use super::SendClaim;
        let path =
            std::env::temp_dir().join(format!("ryu-mail-uncertain-{}.db", uuid::Uuid::new_v4()));
        let store = MailStore::open(path.clone()).unwrap();
        assert_eq!(
            store
                .claim_send("uncertain", "inbox", "body")
                .await
                .unwrap(),
            SendClaim::New
        );
        store.reject_send_completions_for_test().await;
        assert!(store
            .complete_send(
                "uncertain",
                "inbox",
                "body",
                &serde_json::json!({"accepted":true})
            )
            .await
            .is_err());
        drop(store);
        let reopened = MailStore::open(path).unwrap();
        assert_eq!(
            reopened
                .claim_send("uncertain", "inbox", "body")
                .await
                .unwrap(),
            SendClaim::Unresolved
        );
        reopened.conn.lock().await.execute_batch("DROP TRIGGER reject_send_completion; UPDATE mail_send_claims SET response_json='invalid json' WHERE key='uncertain';").unwrap();
        assert!(reopened
            .claim_send("uncertain", "inbox", "body")
            .await
            .is_err());
    }
    async fn draft_fixture(store: &MailStore, send_at: Option<&str>) -> crate::Draft {
        // Inbox addresses are unique per store, so each fixture gets its own.
        let address = format!("drafts-{}@node.example", uuid::Uuid::new_v4().simple());
        let inbox = store
            .create_inbox("Drafts", &address, InboxProvider::Webhook)
            .await
            .unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        store
            .create_draft(crate::Draft {
                id: uuid::Uuid::new_v4().to_string(),
                inbox_id: inbox.id,
                thread_id: None,
                client_id: None,
                to_addrs: vec!["to@x.com".to_owned()],
                cc_addrs: Vec::new(),
                bcc_addrs: Vec::new(),
                reply_to_addrs: Vec::new(),
                subject: "original".to_owned(),
                text: Some("body".to_owned()),
                html: None,
                headers: BTreeMap::new(),
                labels: Vec::new(),
                attachments: Vec::new(),
                send_at: send_at.map(str::to_owned),
                status: if send_at.is_some() {
                    "scheduled"
                } else {
                    "draft"
                }
                .to_owned(),
                created_at: now.clone(),
                updated_at: now,
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn concurrent_draft_claims_let_exactly_one_sender_through() {
        let path =
            std::env::temp_dir().join(format!("ryu-mail-draft-claim-{}.db", uuid::Uuid::new_v4()));
        let store = MailStore::open(path.clone()).unwrap();
        let competing_store = MailStore::open(path).unwrap();
        let draft = draft_fixture(&store, Some("2000-01-01T00:00:00+00:00")).await;
        let now = chrono::Utc::now();
        // The scheduler and a manual send race for the same due draft.
        let (scheduler, manual) = tokio::join!(
            store.claim_due_draft(&draft.id, now),
            competing_store.claim_draft(&draft.id)
        );
        let claims = [scheduler.unwrap(), manual.unwrap()];
        assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
        let claimed = claims.into_iter().flatten().next().unwrap();
        assert_eq!(claimed.status, "sending");
        // Every later claim on a `sending` or `sent` draft is refused.
        assert!(store.claim_draft(&draft.id).await.unwrap().is_none());
        assert!(store
            .claim_due_draft(&draft.id, now)
            .await
            .unwrap()
            .is_none());
        assert!(store.list_due_drafts(now, 16).await.unwrap().is_empty());
        assert!(store
            .finish_draft_send(&draft.id, "sent", true)
            .await
            .unwrap());
        assert!(store.claim_draft(&draft.id).await.unwrap().is_none());
        let sent = store.get_draft(&draft.id).await.unwrap().unwrap();
        assert_eq!(sent.status, "sent");
        assert_eq!(sent.send_at, None);
    }

    #[tokio::test]
    async fn due_draft_claim_skips_drafts_that_were_unscheduled_or_not_due() {
        let store = fresh_store();
        let now = chrono::Utc::now();
        let unscheduled = draft_fixture(&store, None).await;
        assert!(store
            .claim_due_draft(&unscheduled.id, now)
            .await
            .unwrap()
            .is_none());
        let future = draft_fixture(&store, Some("2999-01-01T00:00:00+00:00")).await;
        assert!(store
            .claim_due_draft(&future.id, now)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store.get_draft(&future.id).await.unwrap().unwrap().status,
            "scheduled"
        );
    }

    #[tokio::test]
    async fn settling_or_editing_a_draft_never_overwrites_a_moved_on_row() {
        let store = fresh_store();
        let draft = draft_fixture(&store, None).await;
        // Nothing to settle while the draft is not claimed.
        assert!(!store
            .finish_draft_send(&draft.id, "sent", true)
            .await
            .unwrap());
        assert_eq!(
            store.get_draft(&draft.id).await.unwrap().unwrap().status,
            "draft"
        );

        let claimed = store.claim_draft(&draft.id).await.unwrap().unwrap();
        // A stale edit cannot flip a claimed draft back to a sendable state.
        let mut stale = draft.clone();
        stale.subject = "edited mid-send".to_owned();
        assert!(!store.update_draft(&stale).await.unwrap());
        let stored = store.get_draft(&draft.id).await.unwrap().unwrap();
        assert_eq!(stored.status, "sending");
        assert_eq!(stored.subject, claimed.subject);

        // A definite failure releases the claim in its previous state.
        assert!(store
            .finish_draft_send(&draft.id, "draft", false)
            .await
            .unwrap());
        assert!(!store
            .finish_draft_send(&draft.id, "sent", true)
            .await
            .unwrap());
        assert_eq!(
            store.get_draft(&draft.id).await.unwrap().unwrap().status,
            "draft"
        );
        assert!(store.update_draft(&stale).await.unwrap());

        // A deleted draft is never resurrected by a late settle.
        store.claim_draft(&draft.id).await.unwrap().unwrap();
        assert!(store.delete_draft(&draft.id).await.unwrap());
        assert!(!store
            .finish_draft_send(&draft.id, "sent", true)
            .await
            .unwrap());
        assert!(store.get_draft(&draft.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn legacy_and_invalid_send_keys_do_not_open_a_transport_claim() {
        use super::SendClaim;
        let store = fresh_store();
        for key in ["", "   ", "bad\nkey", "non-ascii-é"] {
            assert!(store.claim_send(key, "inbox", "body").await.is_err());
        }
        assert!(store
            .claim_send(&"x".repeat(257), "inbox", "body")
            .await
            .is_err());
        store
            .put_idempotency(
                "old-key",
                "messages.send",
                "body",
                &serde_json::json!({"message":{"id":"old"}}),
            )
            .await
            .unwrap();
        assert_eq!(
            store.claim_send("old-key", "inbox", "body").await.unwrap(),
            SendClaim::Unresolved
        );
    }

    fn sample_webhook(headers: &[(&str, &str)]) -> crate::Webhook {
        let now = chrono::Utc::now().to_rfc3339();
        crate::Webhook {
            id: uuid::Uuid::new_v4().to_string(),
            url: "https://93.184.216.34/hook".to_owned(),
            secret: crate::webhooks::new_signing_secret(),
            event_types: vec!["message.received".to_owned()],
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            inbox_ids: Vec::new(),
            pod_ids: Vec::new(),
            client_id: None,
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
            signature_scheme: crate::webhooks::SignatureScheme::Standard,
        }
    }

    fn raw_column(path: &std::path::Path, sql: &str, id: &str) -> String {
        Connection::open(path)
            .unwrap()
            .query_row(sql, [id], |row| row.get::<_, String>(0))
            .unwrap()
    }

    fn raw_update(path: &std::path::Path, sql: &str, id: &str, value: &str) {
        Connection::open(path)
            .unwrap()
            .execute(sql, rusqlite::params![id, value])
            .unwrap();
    }

    fn file_bytes_contain(path: &std::path::Path, needle: &str) -> bool {
        // Checkpoint first so the WAL copy lands in the main file too.
        Connection::open(path)
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        ["", "-wal"].iter().any(|suffix| {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            std::fs::read(std::path::Path::new(&file))
                .map(|bytes| String::from_utf8_lossy(&bytes).contains(needle))
                .unwrap_or(false)
        })
    }

    #[tokio::test]
    async fn secrets_are_sealed_at_rest_and_older_rows_upgrade() {
        use crate::seal::{legacy_seal, test_sealer};
        super::test_ryu_dir();
        let path =
            std::env::temp_dir().join(format!("ryu-mail-sealing-{}.db", uuid::Uuid::new_v4()));
        let inbox_sql = "SELECT inbound_secret FROM inboxes WHERE id = ?1";
        let secret_sql = "SELECT secret FROM webhooks WHERE id = ?1";
        let headers_sql = "SELECT headers_json FROM webhooks WHERE id = ?1";

        // Rows as older versions left them: plaintext (no key) and the older
        // RYU_MASTER_KEY scheme (`enc:v1:` under Mail's own HKDF subkey).
        let seeded = MailStore::open_with_sealer(path.clone(), Some(test_sealer(5))).unwrap();
        let inbox = seeded
            .create_inbox("Old", "old@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let old_inbox = seeded
            .create_inbox("Older", "older@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let hook = seeded
            .create_webhook(sample_webhook(&[("x-api-key", "header-secret")]))
            .await
            .unwrap();
        drop(seeded);
        raw_update(
            &path,
            "UPDATE inboxes SET inbound_secret = ?2 WHERE id = ?1",
            &inbox.id,
            &inbox.inbound_secret,
        );
        raw_update(
            &path,
            "UPDATE inboxes SET inbound_secret = ?2 WHERE id = ?1",
            &old_inbox.id,
            &legacy_seal(&[9; 32], &old_inbox.inbound_secret),
        );
        raw_update(
            &path,
            "UPDATE webhooks SET secret = ?2 WHERE id = ?1",
            &hook.id,
            &hook.secret,
        );
        raw_update(
            &path,
            "UPDATE webhooks SET headers_json = ?2 WHERE id = ?1",
            &hook.id,
            r#"{"x-api-key":"header-secret"}"#,
        );
        assert_eq!(
            raw_column(&path, inbox_sql, &inbox.id),
            inbox.inbound_secret
        );

        // An older-scheme row needs the RYU_MASTER_KEY it was sealed with.
        assert!(MailStore::open_with_sealer(path.clone(), Some(test_sealer(5))).is_err());

        // Opening reseals every stored secret; values read back intact.
        let sealer = test_sealer(5).with_legacy_master_key(&[9; 32]);
        let store = MailStore::open_with_sealer(path.clone(), Some(sealer.clone())).unwrap();
        for id in [&inbox.id, &old_inbox.id] {
            let stored = raw_column(&path, inbox_sql, id);
            assert!(stored.starts_with("encp:v1:"), "{stored}");
        }
        let stored_secret = raw_column(&path, secret_sql, &hook.id);
        assert!(stored_secret.starts_with("encp:v1:"), "{stored_secret}");
        let stored_headers = raw_column(&path, headers_sql, &hook.id);
        assert!(
            !stored_headers.contains("header-secret"),
            "{stored_headers}"
        );
        assert!(stored_headers.contains("x-api-key"), "names stay readable");
        let opened = store.get_inbox(&inbox.id).await.unwrap().unwrap();
        assert_eq!(opened.inbound_secret, inbox.inbound_secret);
        let opened_old = store.get_inbox(&old_inbox.id).await.unwrap().unwrap();
        assert_eq!(opened_old.inbound_secret, old_inbox.inbound_secret);
        let opened = store.get_webhook(&hook.id).await.unwrap().unwrap();
        assert_eq!(opened.secret, hook.secret);
        assert_eq!(opened.headers["x-api-key"], "header-secret");

        // New writes are sealed too: create, rotate, and webhook updates.
        let fresh = store
            .create_inbox("New", "new@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        assert!(raw_column(&path, inbox_sql, &fresh.id).starts_with("encp:v1:"));
        let rotated = store.rotate_secret(&fresh.id).await.unwrap();
        assert!(raw_column(&path, inbox_sql, &fresh.id).starts_with("encp:v1:"));
        assert_eq!(
            store
                .get_inbox(&fresh.id)
                .await
                .unwrap()
                .unwrap()
                .inbound_secret,
            rotated
        );
        let mut updated = opened.clone();
        updated
            .headers
            .insert("x-other".to_owned(), "second-secret".to_owned());
        assert!(store.update_webhook(&updated).await.unwrap());
        assert!(!raw_column(&path, headers_sql, &hook.id).contains("second-secret"));
        assert_eq!(
            store.list_webhooks().await.unwrap()[0].headers["x-other"],
            "second-secret"
        );
        drop(store);
        for secret in [&rotated, &hook.secret, "second-secret"] {
            assert!(!file_bytes_contain(&path, secret), "raw secret on disk");
        }

        // Without the key, or with another key, the store refuses to open
        // instead of failing every inbound delivery later; without a key no
        // secret can be written either.
        let missing = MailStore::open_with_sealer(path.clone(), None)
            .err()
            .expect("sealed store needs a key");
        assert!(missing.to_string().contains("sealing key"), "{missing}");
        assert!(MailStore::open_with_sealer(path.clone(), Some(test_sealer(6))).is_err());
        let keyless_path =
            std::env::temp_dir().join(format!("ryu-mail-keyless-{}.db", uuid::Uuid::new_v4()));
        let keyless = MailStore::open_with_sealer(keyless_path, None).unwrap();
        assert!(keyless
            .create_inbox("K", "k@x.com", InboxProvider::Webhook)
            .await
            .is_err());
        // Reopening with the right key is idempotent (no legacy key needed now).
        let again = MailStore::open_with_sealer(path.clone(), Some(test_sealer(5))).unwrap();
        assert_eq!(
            again
                .get_inbox(&old_inbox.id)
                .await
                .unwrap()
                .unwrap()
                .inbound_secret,
            old_inbox.inbound_secret
        );
    }

    #[tokio::test]
    async fn without_a_master_key_secrets_stay_as_before() {
        let store = fresh_store();
        let inbox = store
            .create_inbox("Plain", "plain@x.com", InboxProvider::Webhook)
            .await
            .unwrap();
        let got = store.get_inbox(&inbox.id).await.unwrap().unwrap();
        assert_eq!(got.inbound_secret, inbox.inbound_secret);
        assert!(!got.inbound_secret.starts_with("enc:"));
        assert!(!got.require_timestamp);
    }

    #[tokio::test]
    async fn webhooks_stored_before_standard_signing_stay_legacy() {
        super::test_ryu_dir();
        let path =
            std::env::temp_dir().join(format!("ryu-mail-legacy-hook-{}.db", uuid::Uuid::new_v4()));
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE webhooks (
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
                 INSERT INTO webhooks (id, url, secret, created_at, updated_at)
                 VALUES ('w1', 'https://93.184.216.34/h',
                         'whsec_0123456789abcdef0123456789abcdef', 't', 't');",
            )
            .unwrap();
        let store = MailStore::open(path).unwrap();
        let hook = store.get_webhook("w1").await.unwrap().unwrap();
        assert_eq!(
            hook.signature_scheme,
            crate::webhooks::SignatureScheme::Legacy
        );
        assert_eq!(hook.secret, "whsec_0123456789abcdef0123456789abcdef");
        let created = store.create_webhook(sample_webhook(&[])).await.unwrap();
        assert_eq!(
            store
                .get_webhook(&created.id)
                .await
                .unwrap()
                .unwrap()
                .signature_scheme,
            crate::webhooks::SignatureScheme::Standard
        );
    }

    /// Store `raw` as message `id` under the replay key `digest` (when given).
    async fn deliver_inbound(
        store: &MailStore,
        inbox: &str,
        id: &str,
        raw: &[u8],
        digest: Option<&str>,
        seen_at: i64,
    ) -> anyhow::Result<super::InboundInsert> {
        store
            .insert_inbound_message(
                sample_message(id, inbox, "2020-01-01T00:00:00Z"),
                Vec::new(),
                raw,
                digest.map(|digest| super::InboundReplayKey { digest, seen_at }),
            )
            .await
    }

    fn stored_id(outcome: super::InboundInsert) -> String {
        match outcome {
            super::InboundInsert::Stored(message) => message.id,
            other => panic!("expected a stored message, got {other:?}"),
        }
    }

    fn duplicate_id(outcome: super::InboundInsert) -> String {
        match outcome {
            super::InboundInsert::Duplicate { message_id } => message_id,
            other => panic!("expected a duplicate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbound_tombstones_are_written_with_their_message_and_expire() {
        use super::INBOUND_TOMBSTONE_RETENTION_SECS;
        let store = fresh_store();
        store.ensure_test_inbox("in").await;
        store.ensure_test_inbox("other").await;
        let now = 1_800_000_000;

        let first = deliver_inbound(&store, "in", "m1", b"raw one", Some("d1"), now).await;
        assert_eq!(stored_id(first.unwrap()), "m1");
        assert_eq!(
            store.inbound_tombstones_for_test("in").await,
            vec![("d1".to_owned(), Some("m1".to_owned()))]
        );
        // A tombstone answers its delivery as a duplicate of the stored id even
        // once the message is gone.
        assert!(store.delete_message("m1").await.unwrap());
        let replay = deliver_inbound(&store, "in", "m2", b"raw one", Some("d1"), now + 10).await;
        assert_eq!(duplicate_id(replay.unwrap()), "m1");
        // Scoped to one inbox.
        let other = deliver_inbound(&store, "other", "m3", b"raw one", Some("d1"), now).await;
        assert_eq!(stored_id(other.unwrap()), "m3");
        // Byte-identical raw MIME still stored is a duplicate with or without a key.
        let copy = deliver_inbound(&store, "other", "m4", b"raw one", None, now).await;
        assert_eq!(duplicate_id(copy.unwrap()), "m3");
        assert_eq!(store.list_messages("in", 10).await.unwrap().len(), 0);
        assert_eq!(store.list_messages("other", 10).await.unwrap().len(), 1);

        // Retention is bounded: past it, old tombstones are pruned.
        let later = now + INBOUND_TOMBSTONE_RETENTION_SECS + 1;
        let fresh = deliver_inbound(&store, "in", "m5", b"raw one", Some("d1"), later).await;
        assert_eq!(stored_id(fresh.unwrap()), "m5");
        assert_eq!(
            store.inbound_tombstones_for_test("in").await,
            vec![("d1".to_owned(), Some("m5".to_owned()))]
        );
    }

    #[tokio::test]
    async fn an_inbound_insert_that_dies_after_its_claim_leaves_no_tombstone() {
        let store = fresh_store();
        store.ensure_test_inbox("in").await;
        let now = 1_800_000_000;
        // The message insert fails after the tombstone row was written, and
        // nothing may delete a tombstone afterwards: this is the process dying
        // between the claim and the insert, with no chance to clean up.
        store
            .execute_batch_for_test(
                "CREATE TRIGGER fail_message_insert BEFORE INSERT ON messages
                 BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;
                 CREATE TRIGGER keep_tombstones BEFORE DELETE ON inbound_replay_tombstones
                 BEGIN SELECT RAISE(ABORT, 'no cleanup after a crash'); END;",
            )
            .await;
        let failed = deliver_inbound(&store, "in", "m1", b"raw", Some("d1"), now).await;
        assert!(failed.is_err());
        assert!(store.inbound_tombstones_for_test("in").await.is_empty());
        store
            .execute_batch_for_test(
                "DROP TRIGGER fail_message_insert; DROP TRIGGER keep_tombstones;",
            )
            .await;
        let retry = deliver_inbound(&store, "in", "m2", b"raw", Some("d1"), now + 1).await;
        assert_eq!(stored_id(retry.unwrap()), "m2");

        // A claim an earlier version left without its message is taken over by
        // the retry instead of being answered as a duplicate of nothing.
        store
            .execute_batch_for_test(&format!(
                "INSERT INTO inbound_replay_tombstones (inbox_id, digest, message_id, seen_at)
                 VALUES ('in', 'd2', NULL, {now})"
            ))
            .await;
        let reclaimed = deliver_inbound(&store, "in", "m3", b"raw two", Some("d2"), now + 2).await;
        assert_eq!(stored_id(reclaimed.unwrap()), "m3");
        assert_eq!(
            store.inbound_tombstones_for_test("in").await,
            vec![
                ("d1".to_owned(), Some("m2".to_owned())),
                ("d2".to_owned(), Some("m3".to_owned())),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_copies_of_one_inbound_delivery_store_one_message() {
        let store = fresh_store();
        store.ensure_test_inbox("in").await;
        for (digest, label) in [(Some("d1"), "timestamped"), (None, "body-only")] {
            let raw = format!("raw {label}");
            let deliveries = (0..8).map(|n| {
                let store = store.clone();
                let raw = raw.clone();
                tokio::spawn(async move {
                    deliver_inbound(
                        &store,
                        "in",
                        &format!("{label}-{n}"),
                        raw.as_bytes(),
                        digest,
                        1_800_000_000,
                    )
                    .await
                    .unwrap()
                })
            });
            let mut stored = Vec::new();
            let mut duplicates = Vec::new();
            for delivery in deliveries.collect::<Vec<_>>() {
                match delivery.await.unwrap() {
                    super::InboundInsert::Stored(message) => stored.push(message.id),
                    super::InboundInsert::Duplicate { message_id } => duplicates.push(message_id),
                }
            }
            assert_eq!(stored.len(), 1, "{label}");
            assert_eq!(duplicates.len(), 7, "{label}");
            assert!(duplicates.iter().all(|id| *id == stored[0]), "{label}");
        }
        assert_eq!(store.list_messages("in", 100).await.unwrap().len(), 2);
    }

    // ── content at rest ─────────────────────────────────────────────────────

    const SECRET: &str = "zebra-mail-marker";

    fn secret_message(id: &str, inbox_id: &str) -> EmailMessage {
        let mut message = sample_message(id, inbox_id, "2020-01-01T00:00:00Z");
        message.subject = format!("subject {SECRET}");
        message.text = Some(format!("text {SECRET}"));
        message.html = Some(format!("<p>{SECRET}</p>"));
        message.preview = Some(format!("preview {SECRET}"));
        message.from_addr = format!("{SECRET}@from.example");
        message.to_addrs = vec![format!("{SECRET}@to.example")];
        message.headers = BTreeMap::from([("X-Secret".to_owned(), SECRET.to_owned())]);
        message
    }

    fn secret_draft(inbox_id: &str) -> crate::Draft {
        crate::Draft {
            id: uuid::Uuid::new_v4().to_string(),
            inbox_id: inbox_id.to_owned(),
            thread_id: None,
            client_id: None,
            to_addrs: vec![format!("{SECRET}@draft.example")],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            reply_to_addrs: Vec::new(),
            subject: format!("draft {SECRET}"),
            text: Some(SECRET.to_owned()),
            html: None,
            headers: BTreeMap::new(),
            labels: Vec::new(),
            attachments: Vec::new(),
            send_at: None,
            status: "draft".to_owned(),
            created_at: "2020-01-01T00:00:00Z".to_owned(),
            updated_at: "2020-01-01T00:00:00Z".to_owned(),
        }
    }

    fn attachment() -> RawAttachment {
        RawAttachment {
            filename: format!("{SECRET}.pdf"),
            content_type: "application/pdf".into(),
            bytes: format!("PDF {SECRET}").into_bytes(),
            inline: false,
            content_id: None,
        }
    }

    fn db_has(path: &std::path::Path, needle: &str) -> bool {
        let mut bytes = std::fs::read(path).unwrap_or_default();
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        bytes.extend(std::fs::read(std::path::PathBuf::from(wal)).unwrap_or_default());
        bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    fn dir_has(dir: &std::path::Path, needle: &str) -> bool {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .any(|entry| blob_on_disk_contains(&entry.path(), needle.as_bytes()))
    }

    fn temp_db() -> std::path::PathBuf {
        super::test_ryu_dir();
        std::env::temp_dir().join(format!("ryu-mail-seal-{}.db", uuid::Uuid::new_v4()))
    }

    async fn seed_everything(store: &MailStore) -> (String, String) {
        store.ensure_test_inbox("ibx").await;
        let raw = format!("Subject: {SECRET}\r\n\r\nraw body");
        let message = store
            .insert_message_with_raw(
                secret_message("m1", "ibx"),
                vec![attachment()],
                Some(raw.as_bytes()),
            )
            .await
            .unwrap();
        store.create_draft(secret_draft("ibx")).await.unwrap();
        store
            .insert_event(&crate::MailEvent {
                event_id: "ev1".into(),
                event_type: "message.received".into(),
                inbox_id: Some("ibx".into()),
                message_id: Some("m1".into()),
                payload: serde_json::json!({ "subject": SECRET }),
                created_at: "2020-01-01T00:00:00Z".into(),
            })
            .await
            .unwrap();
        store
            .put_idempotency(
                "idem-1",
                "send",
                "hash",
                &serde_json::json!({ "subject": SECRET }),
            )
            .await
            .unwrap();
        (message.id, message.attachments[0].id.clone())
    }

    async fn assert_reads_back(store: &MailStore, message_id: &str, attachment_id: &str) {
        let message = store.get_message(message_id).await.unwrap().unwrap();
        assert_eq!(message.subject, format!("subject {SECRET}"));
        assert_eq!(message.to_addrs, vec![format!("{SECRET}@to.example")]);
        assert_eq!(message.headers["X-Secret"], SECRET);
        assert_eq!(message.attachments[0].filename, format!("{SECRET}.pdf"));
        let listed = store.list_messages("ibx", 10).await.unwrap();
        assert_eq!(
            listed[0].preview.as_deref(),
            Some(format!("preview {SECRET}").as_str())
        );
        let found = store
            .list_messages_with_filters("ibx", 10, None, None, None, &[], Some(SECRET))
            .await
            .unwrap();
        assert_eq!(
            found.len(),
            1,
            "in-memory text search still finds sealed mail"
        );
        let drafts = store.list_drafts("ibx", &[], 10).await.unwrap();
        assert_eq!(drafts[0].subject, format!("draft {SECRET}"));
        let events = store.list_events(Some("ibx"), 10).await.unwrap();
        assert_eq!(events[0].payload["subject"], SECRET);
        let idem = store
            .get_idempotency("idem-1", "send", "hash")
            .await
            .unwrap();
        assert_eq!(idem.unwrap()["subject"], SECRET);
        let (_, bytes) = store.read_attachment(attachment_id).await.unwrap().unwrap();
        assert_eq!(bytes, format!("PDF {SECRET}").into_bytes());
        let (_, raw) = store.read_raw(message_id).await.unwrap().unwrap();
        assert!(String::from_utf8(raw).unwrap().contains(SECRET));
    }

    async fn assert_all_sealed(store: &MailStore) {
        let conn = store.conn.lock().await;
        let cipher = store.content.cipher().unwrap();
        ryu_crypto::content_sqlite::assert_all_open(&conn, cipher, &super::column_plans().unwrap())
            .unwrap();
    }

    #[tokio::test]
    async fn message_content_and_blobs_are_sealed_at_rest_and_read_back() {
        let db = temp_db();
        let store = MailStore::open(db.clone()).unwrap();
        let (message_id, attachment_id) = seed_everything(&store).await;
        assert_reads_back(&store, &message_id, &attachment_id).await;
        assert_all_sealed(&store).await;
        assert!(!db_has(&db, SECRET), "no plaintext in mail.db or its WAL");
        assert!(!dir_has(&store.blobs_dir, SECRET), "no plaintext blob");
        assert_eq!(store.seal_health()["state"], "ok");
    }

    #[tokio::test]
    async fn legacy_plaintext_mail_is_migrated_once_and_still_reads() {
        let db = temp_db();
        let (message_id, attachment_id) = {
            // A store written before content sealing (compat mode: no key).
            let legacy = MailStore::open_with_sealer(db.clone(), None).unwrap();
            assert_eq!(legacy.seal_health()["state"], "compat");
            seed_everything(&legacy).await
        };
        assert!(db_has(&db, SECRET));
        let store = MailStore::open(db.clone()).unwrap();
        // Legacy rows and legacy blobs read before the blob pass runs.
        assert_reads_back(&store, &message_id, &attachment_id).await;
        assert_all_sealed(&store).await;
        assert!(!db_has(&db, SECRET), "migration scrubbed the plaintext");
        assert!(dir_has(&store.blobs_dir, SECRET));
        let (sealed, failed) = super::seal_legacy_blobs(&store.blobs_dir, &store.content);
        assert_eq!((sealed, failed), (2, 0));
        assert!(!dir_has(&store.blobs_dir, SECRET));
        assert_eq!(
            super::seal_legacy_blobs(&store.blobs_dir, &store.content),
            (0, 0)
        );
        assert_reads_back(&store, &message_id, &attachment_id).await;
        let snapshot = |conn: &Connection| -> Vec<String> {
            let mut stmt = conn
                .prepare("SELECT subject || text || to_addrs FROM messages UNION ALL SELECT subject FROM drafts")
                .unwrap();
            let rows = stmt.query_map([], |row| row.get(0)).unwrap();
            rows.map(Result::unwrap).collect()
        };
        let first = snapshot(&*store.conn.lock().await);
        drop(store);
        let again = MailStore::open(db).unwrap();
        assert_eq!(
            snapshot(&*again.conn.lock().await),
            first,
            "a second open changes nothing"
        );
    }

    /// What the next start leaves: `ok` once it vacuumed, `vacuum_pending`
    /// only when the disk is too full for a `VACUUM` (the freelist scrub
    /// still ran).
    fn expected_after_pending_vacuum(db: &std::path::Path) -> &'static str {
        let size = std::fs::metadata(db).map(|m| m.len()).unwrap_or(0);
        let needed = size
            .saturating_mul(2)
            .saturating_add(ryu_crypto::content_sqlite::VACUUM_HEADROOM_BYTES);
        match ryu_crypto::sealed_file::ensure_free_space(db.parent().unwrap(), needed) {
            Ok(()) => "ok",
            Err(_) => "vacuum_pending",
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_then_write_transactions_wait_for_a_writer_on_another_connection() {
        // The background content migration commits batches on a second
        // connection. A deferred transaction that read before that commit could
        // not take the write lock afterwards and failed at once with
        // SQLITE_BUSY; the serving connection now begins IMMEDIATE and waits.
        let db = temp_db();
        let store = MailStore::open(db.clone()).unwrap();
        store.ensure_test_inbox("ibx").await;
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let path = db.clone();
        let writer = std::thread::spawn(move || {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("BEGIN IMMEDIATE; CREATE TABLE other_writer(x);")
                .unwrap();
            locked_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
            conn.execute_batch("COMMIT;").unwrap();
        });
        locked_rx.recv().unwrap();
        store
            .insert_message_with_raw(
                secret_message("waits", "ibx"),
                vec![attachment()],
                Some(b"raw"),
            )
            .await
            .expect("insert waits for the other writer instead of failing");
        store
            .insert_message(secret_message("after", "ibx"), Vec::new())
            .await
            .unwrap();
        assert!(store.delete_message("after").await.unwrap());
        writer.join().unwrap();
        assert_eq!(store.list_messages("ibx", 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn background_migration_leaves_compaction_to_the_next_start_and_writes_keep_working() {
        use ryu_crypto::content_sqlite::{item_state, read_store_record};
        let db = temp_db();
        {
            let legacy = MailStore::open_with_sealer(db.clone(), None).unwrap();
            seed_everything(&legacy).await;
            for index in 0..200 {
                legacy
                    .insert_message(
                        secret_message(&format!("legacy-{index}"), "ibx"),
                        Vec::new(),
                    )
                    .await
                    .unwrap();
            }
        }
        // Every store counts as large: the migration runs on its own thread.
        super::TEST_SYNC_MIGRATION_MAX_ROWS.with(|rows| rows.set(Some(0)));
        let store = MailStore::open(db.clone()).unwrap();
        super::TEST_SYNC_MIGRATION_MAX_ROWS.with(|rows| rows.set(None));
        // Inbound mail and drafts keep landing while it runs.
        for index in 0..20 {
            store
                .insert_message(secret_message(&format!("live-{index}"), "ibx"), Vec::new())
                .await
                .unwrap();
            store.create_draft(secret_draft("ibx")).await.unwrap();
        }
        let plans = super::column_plans().unwrap();
        let watcher = Connection::open(&db).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !plans.iter().all(|plan| {
            item_state(&watcher, super::STORE, &plan.item())
                .unwrap()
                .as_deref()
                == Some("sealed")
        }) {
            assert!(
                std::time::Instant::now() < deadline,
                "background migration stalled"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let record = read_store_record(&watcher, super::STORE).unwrap().unwrap();
        assert_eq!(
            record.state, "vacuum_pending",
            "the background thread never scrubs or vacuums under traffic"
        );
        assert_eq!(store.list_messages("ibx", 500).await.unwrap().len(), 221);
        drop(watcher);
        drop(store);
        // The next start compacts before serving.
        let reopened = MailStore::open(db.clone()).unwrap();
        let state = read_store_record(&*reopened.conn.lock().await, super::STORE)
            .unwrap()
            .unwrap()
            .state;
        assert_eq!(state, expected_after_pending_vacuum(&db));
        assert!(!db_has(&db, SECRET), "compaction scrubbed the plaintext");
    }

    #[tokio::test]
    async fn a_blob_sealed_while_it_is_being_read_still_reads_as_plaintext() {
        let db = temp_db();
        let (message_id, attachment_id) = {
            let legacy = MailStore::open_with_sealer(db.clone(), None).unwrap();
            seed_everything(&legacy).await
        };
        let store = MailStore::open(db).unwrap();
        assert!(dir_has(&store.blobs_dir, SECRET), "blobs are still legacy");
        // The background sealer renames sealed files over the legacy ones
        // between `read_blob` opening the file and reading it.
        let (blobs, content) = (store.blobs_dir.clone(), store.content.clone());
        super::BLOB_READ_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_: &std::path::Path| {
                super::seal_legacy_blobs(&blobs, &content);
            }));
        });
        let (_, bytes) = store
            .read_attachment(&attachment_id)
            .await
            .unwrap()
            .unwrap();
        let (_, raw) = store.read_raw(&message_id).await.unwrap().unwrap();
        super::BLOB_READ_HOOK.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(bytes, format!("PDF {SECRET}").into_bytes());
        assert!(String::from_utf8_lossy(&raw).contains(SECRET));
        assert!(!dir_has(&store.blobs_dir, SECRET), "the race did seal them");
        // And once sealed they read through the sealed branch.
        let (_, again) = store
            .read_attachment(&attachment_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again, bytes);
    }

    #[tokio::test]
    async fn a_legacy_blob_that_does_not_match_its_name_is_refused() {
        let store = MailStore::open_with_sealer(temp_db(), None).unwrap();
        store.ensure_test_inbox("ibx").await;
        let stored = store
            .insert_message(secret_message("m", "ibx"), vec![attachment()])
            .await
            .unwrap();
        let (_, path) = store
            .attachment_path(&stored.attachments[0].id)
            .await
            .unwrap()
            .unwrap();
        std::fs::write(&path, b"other bytes").unwrap();
        assert!(store
            .read_attachment(&stored.attachments[0].id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_value_copied_to_another_row_does_not_open_and_lists_skip_it() {
        let store = fresh_store();
        store.ensure_test_inbox("ibx").await;
        store
            .insert_message(secret_message("a", "ibx"), Vec::new())
            .await
            .unwrap();
        store
            .insert_message(secret_message("b", "ibx"), Vec::new())
            .await
            .unwrap();
        store
            .execute_batch_for_test(
                "UPDATE messages SET subject = (SELECT subject FROM messages WHERE id = 'a') WHERE id = 'b'",
            )
            .await;
        assert!(store.get_message("b").await.is_err());
        assert_eq!(store.list_messages("ibx", 10).await.unwrap().len(), 1);
        assert_eq!(store.seal_health()["unreadable_rows"], 1);
    }

    #[tokio::test]
    async fn a_moved_or_truncated_blob_is_refused() {
        let store = fresh_store();
        store.ensure_test_inbox("ibx").await;
        let stored = store
            .insert_message(secret_message("m", "ibx"), vec![attachment()])
            .await
            .unwrap();
        let (_, path) = store
            .attachment_path(&stored.attachments[0].id)
            .await
            .unwrap()
            .unwrap();
        // The same sealed bytes under another content address do not open.
        let other = store.blobs_dir.join("0".repeat(64));
        std::fs::copy(&path, &other).unwrap();
        assert!(store.read_blob(&"0".repeat(64)).is_err());
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 3]).unwrap();
        assert!(store
            .read_attachment(&stored.attachments[0].id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_sealed_store_without_a_key_is_read_only_and_another_key_is_refused() {
        let db = temp_db();
        seed_everything(&MailStore::open(db.clone()).unwrap()).await;
        // Without a key the store opens unhealthy: sealed content is kept,
        // writes are refused.
        let keyless = MailStore::open_with_sealer(db.clone(), None).unwrap();
        assert_eq!(keyless.seal_health()["state"], "unhealthy");
        assert!(keyless.get_message("m1").await.is_err());
        assert!(keyless
            .insert_message(secret_message("m2", "ibx"), Vec::new())
            .await
            .is_err());
        assert!(keyless.create_draft(secret_draft("ibx")).await.is_err());
        drop(keyless);
        assert!(
            MailStore::open_with_sealer(db.clone(), Some(crate::seal::test_sealer(9))).is_err()
        );
        assert!(MailStore::open(db).is_ok());
    }
}
