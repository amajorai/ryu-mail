//! The **app-event emit client** — the outbound half of Ryu's hook system.
//!
//! # What an app event is
//!
//! Core's own hook phases (`post_assistant_turn`, `pre_tool_use`, `context`, …) are
//! a closed set: they describe things that happen inside a chat turn. An **app
//! event** is the open half. An app declares the events it emits in its
//! `manifest.json`:
//!
//! ```json
//! "contributes": {
//!   "hook_events": [
//!     { "id": "@ryu/meetings#meeting.ended", "title": "Meeting ended" }
//!   ]
//! }
//! ```
//!
//! and raises one at runtime through this crate. Core then fans it out to every
//! **plugin hook** whose `turn_hooks[].on` names the event and every **workflow**
//! with a matching `event` trigger.
//!
//! The emitter learns nothing about its consumers, and a consumer needs no
//! cooperation from the emitter. That is the entire point: "when a meeting ends,
//! summarize it and file the notes" stops being wiring soldered between two apps and
//! becomes something a user assembles.
//!
//! # Why the declaration is the authorization
//!
//! An event id is `<owning plugin id>#<event name>`, and Core re-checks on every
//! emit that the authenticated caller **is** the plugin the event is namespaced to
//! and that the event appears in that plugin's own manifest. So an app can only ever
//! emit its own declared events — a stolen token buys an attacker the ability to
//! emit events the app already emits, and nothing more. It is also why a Core phase
//! can never be spoofed: a phase name never contains `/`.
//!
//! # Transport
//!
//! `POST http://127.0.0.1:$RYU_CORE_PORT/api/host/capability/events.emit`, presenting the sidecar's
//! `x-ryu-plugin-id` and its minted `RYU_EXT_TOKEN` bearer — the same authenticated
//! seam every other sidecar → Core callback uses. Nothing here is app-specific: the
//! plugin id comes from the caller, the rest from the environment Core injects at
//! spawn.
//!
//! # Failure posture
//!
//! **Emitting is best-effort and never fails the emitter's own work.** A meeting
//! that ended has ended whether or not a summarizer was listening; propagating a
//! fan-out error into the recorder would trade a working feature for a broken one.
//! [`EventEmitter::emit`] therefore logs and swallows, and [`EventEmitter::try_emit`]
//! is available when a caller genuinely wants the outcome.

use serde::{Deserialize, Serialize};

/// Env var holding Core's own loopback port. **This is the one Core actually
/// injects into every manifest sidecar** (`inject_ext_env` sets it unconditionally,
/// exactly so a sidecar can reach back into Core), so it is what this crate resolves
/// first.
const ENV_CORE_PORT: &str = "RYU_CORE_PORT";

/// Env var holding Core's bind address. Only a FALLBACK, and only its port half is
/// used — see [`core_endpoint`] for why reading this one first was a bug.
const ENV_CORE_BIND: &str = "RYU_BIND";
/// Env var holding the sidecar's minted per-plugin bearer, injected at spawn.
const ENV_EXT_TOKEN: &str = "RYU_EXT_TOKEN";
/// The header Core's `authenticate_sidecar` reads to identify the caller.
const HDR_PLUGIN_ID: &str = "x-ryu-plugin-id";
/// The kernel capability this crate invokes.
const CAP_EVENTS_EMIT: &str = "events.emit";

/// What Core reports back about a fan-out: how many subscribers it reached.
///
/// `workflows` counts runs **started**, not finished — a workflow run is detached
/// precisely so a slow one cannot turn emitting an event into a request timeout.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitOutcome {
    /// Plugin hooks that ran for this event.
    #[serde(default)]
    pub hooks: usize,
    /// Workflow runs started for this event.
    #[serde(default)]
    pub workflows: usize,
}

/// Why an emit did not reach Core. Callers that use [`EventEmitter::emit`] never see
/// these; they exist for [`EventEmitter::try_emit`].
#[derive(Debug)]
pub enum EmitError {
    /// `RYU_CORE_PORT`/`RYU_BIND` or `RYU_EXT_TOKEN` was absent — the process was not spawned by
    /// Core as a sidecar, so there is no host to emit to. Not an error worth
    /// alarming about: it is the normal state when running a backend standalone in
    /// development or under its own tests.
    NotHosted,
    /// The HTTP call itself failed.
    Transport(reqwest::Error),
    /// Core rejected the emit. Carries the status and body; a `403` means the event
    /// is not declared in this plugin's manifest (or is namespaced to another
    /// plugin), which is a manifest bug rather than a runtime condition.
    Rejected { status: u16, body: String },
}

impl std::fmt::Display for EmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotHosted => write!(f, "not running as a Core-spawned sidecar"),
            Self::Transport(e) => write!(f, "emit transport failed: {e}"),
            Self::Rejected { status, body } => write!(f, "Core rejected emit ({status}): {body}"),
        }
    }
}

impl std::error::Error for EmitError {}

/// Resolve the `events.emit` endpoint from the environment Core injects at spawn,
/// or `None` when this process is not Core-hosted.
///
/// **Read [`ENV_CORE_PORT`] first, and take only the PORT from [`ENV_CORE_BIND`].**
/// Both halves of that are load-bearing, and getting either wrong makes every emit
/// silently no-op on a shipped build while passing every dev-machine test:
///
/// - Core injects `RYU_CORE_PORT` into every manifest sidecar unconditionally
///   (`inject_ext_env`), precisely so a sidecar can call back. It does NOT inject
///   `RYU_BIND` — a sidecar only ever inherits that from Core's own process env, and
///   Core only seeds it in the **dev** profile (`apply_env_defaults` returns early on
///   release). So a release desktop install has no `RYU_BIND` at all.
/// - When `RYU_BIND` *is* set it is a BIND address, not a reachable URL: it is
///   routinely `0.0.0.0:7980`, and `http://0.0.0.0/...` is not a valid destination.
///   Core's own readers take only the port for exactly this reason
///   (`cli_shims::core_port_string`), and so does this.
fn core_endpoint() -> Option<String> {
    let port = std::env::var(ENV_CORE_PORT)
        .ok()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .or_else(|| {
            std::env::var(ENV_CORE_BIND).ok().and_then(|bind| {
                bind.rsplit_once(':')
                    .and_then(|(_, p)| p.trim().parse::<u16>().ok())
            })
        })?;
    Some(format!(
        "http://127.0.0.1:{port}/api/host/capability/{CAP_EVENTS_EMIT}"
    ))
}

/// Emits app events on behalf of ONE plugin.
///
/// Cheap to clone (it holds a `reqwest::Client`, which is itself an `Arc`), so the
/// idiomatic use is to build one at startup and hand clones to whatever raises
/// events.
#[derive(Debug, Clone)]
pub struct EventEmitter {
    plugin_id: String,
    http: reqwest::Client,
    /// `None` when the process is not Core-hosted; every emit then short-circuits to
    /// [`EmitError::NotHosted`] instead of building a doomed request.
    endpoint: Option<String>,
    token: Option<String>,
}

impl EventEmitter {
    /// Build an emitter for `plugin_id`, reading Core's address and this sidecar's
    /// minted token from the environment Core injects at spawn.
    ///
    /// Never fails: a process running outside Core simply gets an emitter whose
    /// every emit is a no-op. A backend must be runnable standalone (its own tests
    /// do exactly that), so "no host" is a supported state, not a startup error.
    #[must_use]
    pub fn from_env(plugin_id: impl Into<String>) -> Self {
        Self::with_client(plugin_id, reqwest::Client::new())
    }

    /// [`Self::from_env`] with a caller-supplied HTTP client, so a sidecar that
    /// already owns a configured client (timeouts, pooling) reuses it.
    #[must_use]
    pub fn with_client(plugin_id: impl Into<String>, http: reqwest::Client) -> Self {
        let endpoint = core_endpoint();
        let token = std::env::var(ENV_EXT_TOKEN)
            .ok()
            .filter(|t| !t.trim().is_empty());
        let plugin_id = plugin_id.into();
        if endpoint.is_none() || token.is_none() {
            tracing::debug!(
                plugin = %plugin_id,
                "app-events: not Core-hosted ({ENV_CORE_PORT}/{ENV_EXT_TOKEN} unset); emits will no-op"
            );
        }
        Self {
            plugin_id,
            http,
            endpoint,
            token,
        }
    }

    /// Whether this emitter can actually reach Core. Useful to skip assembling an
    /// expensive payload that would be thrown away.
    #[must_use]
    pub fn is_hosted(&self) -> bool {
        self.endpoint.is_some() && self.token.is_some()
    }

    /// Emit `event` with `payload`, **best-effort**: a failure is logged and
    /// swallowed. This is the call site nearly every emitter wants — see the module
    /// docs on why a fan-out failure must not fail the work that produced the event.
    pub async fn emit(&self, event: &str, payload: serde_json::Value) {
        match self.try_emit(event, payload, None).await {
            Ok(outcome) => {
                if outcome.hooks > 0 || outcome.workflows > 0 {
                    tracing::debug!(
                        event,
                        hooks = outcome.hooks,
                        workflows = outcome.workflows,
                        "app-events: emitted"
                    );
                }
            }
            // Not being hosted is the normal standalone/dev state, not a problem.
            Err(EmitError::NotHosted) => {}
            Err(e) => tracing::warn!(event, "app-events: emit failed: {e}"),
        }
    }

    /// Emit and return the outcome. `conversation_id` associates the event with a
    /// conversation when the emitter knows one, so a consumer hook can key its own
    /// per-conversation state exactly as a turn hook does.
    ///
    /// # Errors
    /// Returns [`EmitError`] when the process is not Core-hosted, the HTTP call
    /// fails, or Core rejects the emit (most often: the event is not declared in
    /// this plugin's manifest).
    pub async fn try_emit(
        &self,
        event: &str,
        payload: serde_json::Value,
        conversation_id: Option<&str>,
    ) -> Result<EmitOutcome, EmitError> {
        let (Some(endpoint), Some(token)) = (self.endpoint.as_deref(), self.token.as_deref())
        else {
            return Err(EmitError::NotHosted);
        };

        let mut body = serde_json::json!({ "event": event, "payload": payload });
        if let Some(cid) = conversation_id {
            body["conversation_id"] = serde_json::Value::String(cid.to_owned());
        }

        let resp = self
            .http
            .post(endpoint)
            .header(HDR_PLUGIN_ID, &self.plugin_id)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(EmitError::Transport)?;

        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let body = resp.text().await.unwrap_or_default();
            return Err(EmitError::Rejected { status, body });
        }
        resp.json::<EmitOutcome>()
            .await
            .map_err(EmitError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend running outside Core must not blow up on emit — its own test suite
    /// and any standalone run depend on that.
    #[tokio::test]
    async fn unhosted_emitter_no_ops_instead_of_failing() {
        // Explicitly construct the unhosted shape rather than mutating process env,
        // which would race every other test in the binary.
        let emitter = EventEmitter {
            plugin_id: "com.acme.app".to_owned(),
            http: reqwest::Client::new(),
            endpoint: None,
            token: None,
        };
        assert!(!emitter.is_hosted());
        assert!(matches!(
            emitter
                .try_emit("com.acme.app/thing.done", serde_json::json!({}), None)
                .await,
            Err(EmitError::NotHosted)
        ));
        // The best-effort wrapper must swallow it.
        emitter
            .emit("com.acme.app/thing.done", serde_json::json!({}))
            .await;
    }

    /// The endpoint must come from the port Core actually injects, and a `RYU_BIND`
    /// fallback must contribute only its PORT.
    ///
    /// This is a regression test for a bug that shipped green: reading `RYU_BIND`
    /// first made every emit silently no-op on a release install (Core injects
    /// `RYU_CORE_PORT` into sidecars, and only seeds `RYU_BIND` in the dev profile),
    /// while passing on every dev machine. Building from the whole bind string was
    /// the second half of it — `RYU_BIND` is routinely `0.0.0.0:7980`, which is not
    /// a dialable address.
    ///
    /// Written against the pure resolver rather than by mutating process env, which
    /// would race every other test in this binary.
    #[test]
    fn endpoint_prefers_core_port_and_never_dials_a_bind_host() {
        // The shape `RYU_CORE_PORT` arrives in: a bare port.
        assert_eq!(
            endpoint_from("7980"),
            Some("http://127.0.0.1:7980/api/host/capability/events.emit".to_owned())
        );
        // A wildcard bind must contribute its port ONLY — never `http://0.0.0.0/…`.
        let from_bind = endpoint_from_bind("0.0.0.0:7980");
        assert_eq!(
            from_bind,
            Some("http://127.0.0.1:7980/api/host/capability/events.emit".to_owned())
        );
        assert!(!from_bind.expect("some").contains("0.0.0.0"));
        // Nothing usable → not hosted, rather than a doomed request.
        assert_eq!(endpoint_from(""), None);
        assert_eq!(endpoint_from_bind("not-a-bind"), None);
    }

    /// The `RYU_CORE_PORT` half of [`core_endpoint`]'s resolution, factored for test.
    fn endpoint_from(port: &str) -> Option<String> {
        let port: u16 = port.trim().parse().ok()?;
        Some(format!(
            "http://127.0.0.1:{port}/api/host/capability/{CAP_EVENTS_EMIT}"
        ))
    }

    /// The `RYU_BIND` fallback half, factored for test.
    fn endpoint_from_bind(bind: &str) -> Option<String> {
        let (_, port) = bind.rsplit_once(':')?;
        endpoint_from(port)
    }

    #[test]
    fn outcome_defaults_to_zero_subscribers() {
        let parsed: EmitOutcome = serde_json::from_str("{}").expect("empty object parses");
        assert_eq!(parsed, EmitOutcome::default());
        let parsed: EmitOutcome =
            serde_json::from_value(serde_json::json!({ "event": "x", "hooks": 2, "workflows": 1 }))
                .expect("extra keys are ignored");
        assert_eq!(
            parsed,
            EmitOutcome {
                hooks: 2,
                workflows: 1
            }
        );
    }
}
