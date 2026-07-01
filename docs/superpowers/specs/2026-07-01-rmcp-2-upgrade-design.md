# rmcp 0.8.5 → 2.0.0 upgrade + Host allowlist

**Issue:** #97 — Security: upgrade rmcp (RUSTSEC-2026-0189 DNS rebinding)
**Date:** 2026-07-01
**Status:** Approved design

## Problem

CI's `audit` job fails on `main`: **RUSTSEC-2026-0189** — DNS-rebinding
vulnerability in the `rmcp` Streamable HTTP server transport, affecting the
pinned **`rmcp 0.8.5`**. Fixed in `rmcp >= 1.4.0`. Both binaries
(`rust-junosmcp` :30031, `rust-srxmcp` :30032) expose this transport.

## Decision & key research findings

- **Target: `rmcp 2.0.0`** (latest stable; user-chosen "longest runway").
- Research (`.superpowers/sdd/rmcp-migration-research.md`) verified against
  docs.rs 1.4.0/2.0.0 + tagged source: **our entire used API surface is
  byte-compatible 0.8.5 → 2.0.0** — the `#[tool]`/`#[tool_router]`/`#[tool_handler]`
  macros, `handler::server::wrapper::Parameters`, `rmcp::ErrorData`,
  `model::{CallToolResult, Content, Extensions, Implementation, ServerCapabilities,
  ServerInfo}`, `ServerHandler`, and `StreamableHttpService::new` (still 3-arg)
  are unchanged. The 2.0.0-specific breaks (`peer_info`, model realignment) are
  in APIs we don't touch; model types gain only additive fields and we build
  with `..Default::default()`.
- **The load-bearing auth mechanism is preserved:** the Streamable HTTP tower
  service still inserts `http::request::Parts` into rmcp's per-request
  `Extensions` in 2.0.0, so `caller_ctx()`'s `extensions.get::<http::request::Parts>()`
  bearer-auth lookup keeps working.
- All 5 feature flags (`server, macros, transport-io, schemars,
  transport-streamable-http-server`) survive unchanged in 2.0.0.

## The one mandatory behavioral change

rmcp ≥1.4 ships the RUSTSEC-2026-0189 fix as a **default-DENY, loopback-only
`Host` allowlist**:

```rust
// StreamableHttpServerConfig::default() in rmcp 2.0.0
allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "::1".into()],
allowed_origins: vec![],   // Origin check off unless opted in
```

A request whose `Host` header is not allowed gets **HTTP 403**. Our servers bind
`0.0.0.0:3003x` and bearer clients reach them at **`192.168.1.194:3003x`** (a LAN
IP, non-loopback), so a bare `::default()` after the upgrade would **403 every
LAN client**. We must supply an explicit allowlist.

### Approach: configurable via CLI, secure by default

Add two flags to **both** binaries:

- `--allowed-host <HOST[:PORT]>` — repeatable (`Vec<String>`); operator-supplied
  authorities matched against the inbound `Host` header.
- `--disable-host-check` — bool, default `false`; escape hatch → the config's
  `disable_allowed_hosts()`. Logged as a warning (bearer auth still gates, but
  this defeats the anti-rebinding fix).

Behavior in `http_transport::serve`:

- Default (no flags): `StreamableHttpServerConfig::default()` — loopback only.
- With `--allowed-host` values: start from the loopback defaults and **extend**
  with the provided authorities, then apply via `.with_allowed_hosts([...])`
  (which replaces the list, so we pass loopback + provided together). Exact
  builder call confirmed at implementation time against rmcp 2.0.0's
  `StreamableHttpServerConfig` API; `with_allowed_hosts`/`disable_allowed_hosts`
  exist per the advisory fix.
- With `--disable-host-check`: `.disable_allowed_hosts()` + `tracing::warn!`.

`--disable-host-check` and a non-empty `--allowed-host` are mutually redundant;
if both are given, `--disable-host-check` wins (with the warning).

## Components / files

| File | Change |
|---|---|
| `rust-junosmcp/Cargo.toml` | `rmcp = "0.8"` → `rmcp = "2"` (same features) |
| `rust-srxmcp/Cargo.toml` | `rmcp = "0.8"` → `rmcp = "2"` (same features) |
| `rust-junosmcp/src/cli.rs` | add `allowed_host: Vec<String>` + `disable_host_check: bool` to `Cli` |
| `rust-srxmcp/src/main.rs` | add the same two fields to the args struct |
| `rust-junosmcp/src/http_transport.rs` | `serve(...)` gains `allowed_hosts: Vec<String>, disable_host_check: bool`; build config accordingly |
| `rust-srxmcp/src/http_transport.rs` | same `serve(...)` change |
| `rust-junosmcp/src/main.rs`, `rust-srxmcp/src/main.rs` | pass the new args into `serve(...)` |
| `rust-junosmcp-core/src/cancel.rs` | refresh "rmcp 0.8.5" prose → 2.0.0 |
| `Cargo.lock` | `cargo update -p rmcp`; resolve transitive `schemars`/`http`/`axum` churn |

## Testing

- `cargo fmt -- --check`; `cargo build --workspace`; `cargo test --workspace` (0 failures).
- **`cargo audit` — no RUSTSEC-2026-0189** (the acceptance gate). Any residual
  warnings (`anyhow` unsoundness, yanked `aes`) noted but not blocking unless the
  tree resolves them.
- New integration test (junos `http_smoke`-style, and mirror for srx if cheap):
  - allowed `Host` (e.g. `127.0.0.1:<port>`, default loopback) → **200** on `initialize`;
  - a disallowed `Host` header (e.g. `evil.example.com`) → **403**;
  - with `--disable-host-check`, the disallowed `Host` → **200**.
- Existing `http_smoke`/`http_reload`/`stdio_smoke` compile-clean and pass
  (they use `127.0.0.1`, in the default loopback set) — regression guard.

## Deploy

- Update the systemd units on ct601 (pve2) to add `--allowed-host 192.168.1.194:30031`
  (junos) and `--allowed-host 192.168.1.194:30032` (srx).
- Live smoke both endpoints post-deploy: `tools/list` + one tool call each; plus a
  raw `curl` showing **200** for `Host: 192.168.1.194:3003x` and **403** for a
  bogus Host — direct proof the allowlist is active and correct.

## Risks

1. **`allowed_hosts` misconfiguration → silent 403 for all LAN clients.** Highest
   impact. Guarded by the 200/403 integration test and the live curl check;
   the deploy must include the `--allowed-host` flag or clients break.
2. **Transitive dependency churn** (`schemars`, `http`, `axum` 0.8 compat) from a
   5-major-version jump — possible version-resolution friction even though our
   direct API is stable. Resolved at `cargo update` time; watch the
   `rust-junosmcp-core` arg structs if `schemars` majors.
3. 2.0.0 default `stateful_mode: true` + SSE keep-alive defaults differ from
   0.8.5 — low risk; the live full-round-trip smoke covers it.

## Out of scope

- No move to rmcp `allowed_origins` (Origin validation) now — Host allowlist +
  bearer auth is sufficient for the advisory; can add later.
- No change to tool behavior, auth semantics, or the tool surface.
- The two non-blocking audit warnings (`anyhow` RUSTSEC-2026-0190, yanked `aes`)
  are follow-ups unless the dependency tree updates them for free.
