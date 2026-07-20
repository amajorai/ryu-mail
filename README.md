# ryu-mail

Agent Inboxes for Ryu — email-as-a-service for agents (receive, store, and send agent email per node). The out-of-process ryu-mail sidecar; Core proxies /api/mail/* to it.

> **The public home of `ryu-mail`.** Source, builds, and releases live here —
> binaries for every platform are attached to each release.
>
> This tree is generated from the Ryu monorepo, so commits pushed here
> directly are replaced on the next sync. **Pull requests are welcome** —
> open them here and they are ported into the monorepo, then flow back out.
> Ryu as a whole: https://github.com/amajorai/ryu

## Install

- Binary: `ryu-mail` from the [Ryu releases](https://github.com/amajorai/ryu/releases).
- Crate: `cargo install ryu-mail`.

## License

Apache-2.0 — see [LICENSE](./LICENSE).

---

# com.ryu.mail — Agent Inboxes

Email-as-a-service for agents: receive, store, and send agent email per node.
This is the **tracer bullet for "apps as microservices"** — the first fully
manifest-driven app whose backend runs out-of-process, not inside Core.

## Parts

- **`backend/` — `ryu-mail` (out-of-process sidecar).** A standalone Axum binary
  (its own crate, ZERO dependency on `apps/core`) that owns `mail.db`: inbox
  registry, message store, MIME assembly, and SMTP send (`lettre`) + inbound parse
  (`mail-parser`). Core spawns it (`SidecarProcess::Local`, host/sibling binary,
  no download), health-checks `/api/mail/status`, and proxies `/api/mail/*` to it
  on loopback. Route paths are byte-identical to Core's old in-process routes so
  the proxy passes straight through.
- **`ui/` — companion (`@ryu/mail-app`).** A sandboxed full-page Companion
  (Path B, `ui_format: "html"`), built to one self-contained `dist/index.html` via
  `vite-plugin-singlefile`. A per-node mail client: list inboxes, read messages,
  compose/send, create an inbox (revealing its inbound webhook secret + forwarder
  URL). Every call goes over the `window.ryu` bridge, never `fetch`.

## Manifest (`ui/plugin.json`)

- **Capability grant:** `mail:crud` — the bridge capability the companion calls.
- **Sidecar:** `ryu-mail` on `:7996`, `command_env: RYU_MAIL_BIN`,
  `port_env: RYU_MAIL_PORT`, `http.public_mount: /api/mail` (a built-in owning a
  stable external URL), `max_body_bytes ~26MB` for attachments.
- **Runnable:** one `companion` (`Agent Inboxes`, icon `mail-01`).

## Auth / security

The sidecar binds **loopback only** and fail-closes: protected `/api/mail/*` routes
require a shared-secret bearer (`RYU_MAIL_TOKEN`, injected by Core at spawn like the
gateway sidecar's `CORE_TOKEN`); Core stays the auth front and re-stamps the bearer
on each proxied hop. The inbound webhook (`POST /api/mail/inbound/:id`) keeps its own
per-inbox HMAC-SHA256 auth and is public (reachable tokenless).

## Swap seam

Mail scales and fails independently of the node. Because the backend is a separate
process behind a stable `/api/mail/*` contract, any equivalent mail backend can
replace `ryu-mail` without touching Core.
