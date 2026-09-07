//! `ryu-mail` — the standalone, out-of-process mail sidecar.
//!
//! The tracer bullet for "apps as microservices": the self-host Agent Inboxes
//! feature (receive + store + send agent email) runs here as a SEPARATE PROCESS
//! that Core spawns, health-checks, and proxies to — exactly like Core already
//! runs the Gateway sidecar. Core does NOT contain this code, so mail scales and
//! fails independently of the rest of the node.
//!
//! Contract surface (byte-identical paths to Core's in-process routes):
//!   - `api::public_routes()`    → `POST /api/mail/inbound/:id`  (HMAC-authed)
//!   - `api::protected_routes()` → the authed `/api/mail/*` CRUD
//!
//! SECURITY: the Core-hosted mode binds LOOPBACK ONLY (127.0.0.1) and guards its
//! protected routes with the shared-secret bearer Core injects. A separately
//! deployed service may set `RYU_MAIL_API_TOKEN` and an explicit
//! `RYU_MAIL_HOSTNAME`, which enables the same `/api/mail/*` contract outside
//! Core. A non-loopback bind without that standalone token is refused. The gate is
//! FAIL-CLOSED: with no token configured every protected route rejects. The
//! inbound webhook keeps its own per-inbox HMAC auth, so it is reachable tokenless.
//!
//! Port: `RYU_MAIL_PORT` env, default `7996`. Data dir: resolved via the inlined
//! `paths::ryu_dir` (`RYU_DIR`-env-first), so it opens the SAME `mail.db` the node
//! uses. The sidecar OWNS the store; Core no longer opens it.

mod api;
mod host;
mod mime;
mod paths;
mod send;
mod store;

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

pub use store::MailStore;

/// Default port for the mail service (overridable via `RYU_MAIL_PORT`).
const DEFAULT_PORT: u16 = 7996;

/// This app's manifest `id`. Core authorizes every app-event emit against it — the
/// caller must *be* the plugin the event is namespaced to — so it must stay
/// byte-identical to the `id` in `apps-store/mail/manifest.json`.
pub const PLUGIN_ID: &str = "@ryu/mail";

/// Axum state for the mail sidecar: the store plus the app-event emitter. Cheap to
/// clone (both wrap `Arc`s). This replaces Core's `ServerState` — the mail handlers
/// touched ONLY `state.mail`, so a near-single-field state is a faithful, decoupled
/// substitute.
#[derive(Clone)]
pub struct MailState {
    pub email: host::EmailHost,
    pub mail: MailStore,
    /// Raises the `contributes.hook_events` this app declares, so a plugin hook or
    /// workflow can react to mail arriving or going out without either side knowing
    /// the other exists.
    ///
    /// Safe to hold unconditionally: `from_env` never fails, and every emit no-ops
    /// when `RYU_CORE_PORT`/`RYU_EXT_TOKEN` are absent — which is the state under this
    /// crate's own tests and any standalone run, so no test needs a live Core.
    pub events: ryu_app_events::EventEmitter,
}

impl MailState {
    pub fn from_env(mail: MailStore, events: ryu_app_events::EventEmitter) -> Self {
        Self {
            email: host::EmailHost::from_env(),
            events,
            mail,
        }
    }
}

// ── Domain types (moved from `apps/core/src/mail/mod.rs`) ────────────────────

/// How a self-host inbox receives mail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboxProvider {
    /// A mail provider (own domain) forwards raw MIME to the node webhook.
    Webhook,
    /// The node polls an IMAP mailbox (v1: reserved; not yet driven).
    Imap,
}

impl InboxProvider {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Imap => "imap",
        }
    }
    fn from_str(s: &str) -> Self {
        match s {
            "imap" => Self::Imap,
            _ => Self::Webhook,
        }
    }
}

/// One self-host inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inbox {
    pub id: String,
    pub name: String,
    /// The address that receives mail (BYO domain, operator-supplied).
    pub address: String,
    pub provider: InboxProvider,
    /// HMAC secret the inbound forwarder signs the raw body with.
    pub inbound_secret: String,
    pub created_at: String,
}

/// A stored message (inbound or outbound).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    pub id: String,
    pub inbox_id: String,
    /// "inbound" | "outbound".
    pub direction: String,
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    #[serde(default)]
    pub cc_addrs: Vec<String>,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
    pub attachments: Vec<AttachmentMeta>,
    pub created_at: String,
}

/// Attachment metadata (the bytes live on the filesystem, keyed by sha256).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = std::env::var("RYU_MAIL_PORT")
        .ok()
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let standalone_token = std::env::var("RYU_MAIL_API_TOKEN")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let core_token = std::env::var("RYU_EXT_TOKEN")
        .ok()
        .or_else(|| std::env::var("RYU_MAIL_TOKEN").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let explicit_mode = std::env::var("RYU_MAIL_MODE")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let standalone_mode = match explicit_mode.as_deref() {
        Some("core") => {
            if standalone_token.is_some() {
                anyhow::bail!("RYU_MAIL_MODE=core cannot be combined with RYU_MAIL_API_TOKEN");
            }
            false
        }
        Some("standalone") => {
            if standalone_token.is_none() || core_token.is_some() {
                anyhow::bail!(
                    "RYU_MAIL_MODE=standalone requires RYU_MAIL_API_TOKEN and rejects Core tokens"
                );
            }
            true
        }
        Some(other) => anyhow::bail!("RYU_MAIL_MODE must be 'core' or 'standalone', got {other}"),
        None => match (standalone_token.is_some(), core_token.is_some()) {
            (true, false) => true,
            (true, true) => {
                anyhow::bail!("RYU_MAIL_API_TOKEN cannot be combined with Core mail credentials")
            }
            _ => false,
        },
    };
    let hostname = std::env::var("RYU_MAIL_HOSTNAME")
        .ok()
        .or_else(|| std::env::var("RYU_MAIL_HOST").ok())
        .unwrap_or_else(|| "127.0.0.1".to_owned());
    let host: IpAddr = hostname
        .parse()
        .map_err(|_| anyhow::anyhow!("RYU_MAIL_HOSTNAME must be an IP address"))?;
    if !host.is_loopback() && !standalone_mode {
        anyhow::bail!(
            "refusing a non-loopback mail bind without RYU_MAIL_API_TOKEN; Core tokens are not standalone credentials"
        );
    }

    // Shared-secret bearer Core injects (mirrors the gateway sidecar's CORE_TOKEN).
    // The protected routes require it; the inbound webhook stays on per-inbox HMAC.
    // Shared-secret bearer. When Core spawns this via the GENERIC ext-proxy loader it
    // injects `RYU_EXT_TOKEN` (the per-plugin minted secret it stamps on every proxied
    // hop + the health probe); the legacy hand-coded path injected `RYU_MAIL_TOKEN`.
    // Prefer the generic var, fall back to the legacy one — so ryu-mail works under
    // both spawn paths during/after the migration.
    let token = if standalone_mode {
        standalone_token.clone()
    } else {
        core_token
    };
    if standalone_mode {
        tracing::info!(
            "ryu-mail: standalone API mode enabled; protected routes require the configured bearer"
        );
    } else if token.is_some() {
        tracing::info!("ryu-mail: protected routes require the injected shared-secret bearer");
    } else {
        tracing::warn!(
            "ryu-mail: no Core or standalone API token set; protected /api/mail/* routes are FAIL-CLOSED (reject all). The inbound webhook remains available via its per-inbox HMAC."
        );
    }

    let mail = MailStore::open_default()?;
    // Built once here and cloned with the state into every handler; constructing one
    // per request would rebuild a connection pool for a fire-and-forget POST.
    let events = ryu_app_events::EventEmitter::from_env(PLUGIN_ID);
    let state = MailState::from_env(mail, events);

    // Layer the shared-secret gate onto the protected routes only. `from_fn` closes
    // over the resolved token so no extra state field is needed; the inbound webhook
    // (public_routes) is merged UN-layered so its HMAC auth stands alone.
    let protected = api::protected_routes().layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let expected = token.clone();
            async move { api::require_mail_token(req, next, expected.as_deref()).await }
        },
    ));
    let app = api::public_routes().merge(protected).with_state(state);

    // Core-hosted mode is loopback-only; standalone mode is explicit and still
    // requires its own API bearer before a non-loopback bind is allowed.
    let addr = SocketAddr::new(host, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("ryu-mail sidecar listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}
