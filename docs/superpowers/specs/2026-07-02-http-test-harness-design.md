# Shared HTTP-test harness (#100) + srx http_smoke (#101)

**Issues:** #100 (hoist duplicated HTTP smoke harness), #101 (srx HTTP integration harness)
**Date:** 2026-07-02
**Status:** Approved design

## Problem

The streamable-HTTP integration-test harness is copy-pasted. In `rust-junosmcp/tests/`, `binary_path`/`ensure_built`/`pick_port`/`Server`(+`Drop`)/`parse_first_sse_data` are duplicated across **http_smoke.rs, http_reload.rs, http_tls.rs**, and `http_post`/`spawn` have drifted between them (http_smoke's `http_post` takes a `session_id`, http_reload's does not). Separately, `rust-srxmcp` has **no** spawn-based HTTP integration harness at all — its streamable-HTTP auth (RFC 6750 401s) and the rmcp 2.0 Host allowlist (#97) have no automated coverage; only `live_smoke.rs` (device-gated, `#[ignore]`, hits a live endpoint) touches the endpoint.

## Decision

Per-crate `tests/common/mod.rs` in each crate (no shared workspace crate). Dedups within each crate; `parse_first_sse_data` ends up once per crate (2 copies total). Chosen over a shared `test-support` crate for minimal churn (the cross-crate overlap is ~10 lines).

## Part A — #100: junos `tests/common/mod.rs`

Create `rust-junosmcp/tests/common/mod.rs` (the `tests/common/mod.rs` submodule path — NOT `tests/common.rs`, which Rust compiles as its own test binary). Top of file: `#![allow(dead_code)]` (a shared test module; not every consuming test uses every helper — standard for this pattern).

Move the genuinely-shared helpers into it (verbatim from the current http_smoke.rs versions, which are the supersets):
- `binary_path() -> PathBuf`, `ensure_built()`, `pick_port() -> u16`
- `struct Server { child, port, _stderr_drain }` + `impl Drop`
- the spawn readiness-wait + stderr-drain internals, exposed as `spawn(inv, tokens) -> Server` and `spawn_no_auth(inv, extra: &[&str]) -> Server`
- `struct PostResult { code, body, session_id, www_authenticate }`
- `http_post(port, bearer: Option<&str>, session_id: Option<&str>, body: Value) -> PostResult` (the unified superset signature)
- `parse_first_sse_data(&str) -> Option<Value>`
- `init_body() -> Value`, `initialize(port, bearer) -> String`, `post_init_with_host(port, host) -> u16`
- `write_inv(json) -> NamedTempFile`, `write_tokens(json) -> NamedTempFile`

Refactor the three test files to `mod common;` + `use common::*;`, deleting their local copies:
- **http_smoke.rs** — drops its copies; tests unchanged.
- **http_reload.rs** — drops its copies; its `http_post(port, bearer, body)` call sites become `http_post(port, bearer, None, body)` (the unified signature adds `session_id`).
- **http_tls.rs** — uses `common` for `binary_path`/`ensure_built`/`pick_port`/`Server`/`parse_first_sse_data`. Its **TLS-specific** helpers (`wait_for_port`, `write_self_signed`, `build_tls_agent`, `spawn_tls`) have a single consumer and **stay in http_tls.rs**.

Non-HTTP junos test files (stdio_smoke, batch_smoke, pfe_smoke, etc.) are **out of scope** — #100 is the HTTP smoke harness specifically.

## Part B — #101: srx `tests/common/mod.rs` + `tests/http_smoke.rs`

Create `rust-srxmcp/tests/common/mod.rs` mirroring Part A for the srx binary. srx CLI differences: bind flags `--host`/`--port` (default `0.0.0.0:30032`), `--tokens-file`, `--allow-no-auth`, `--allowed-host`/`--disable-host-check` (added in #97), `--device-mapping` (optional). The readiness substring is the same for both crates — srx logs `"rust-srxmcp streamable-http listening"`, of which `"streamable-http listening"` is a substring, so the harness waits on `"streamable-http listening"`.

Create `rust-srxmcp/tests/http_smoke.rs` — all tests CI-runnable without a device (they exercise the transport/auth layers; device tools are never called), using a placeholder unreachable inventory:
- `missing_authorization_returns_401` — 401 + `WWW-Authenticate: Bearer` (RFC 6750 §3) + JSON body `{error:"invalid_request", error_description:…}`.
- `wrong_bearer_returns_401` — 401 + challenge `error="invalid_token"` + JSON body `{error:"invalid_token",…}`.
- `disallowed_host_is_rejected_403` — spawn `--allow-no-auth`; `Host: evil.example.com` → **403** (rmcp built-in Host check).
- `allowed_host_flag_permits_custom_host` — `--allow-no-auth --allowed-host friendly.example.com`; `Host: friendly.example.com` → **200**.
- `disable_host_check_allows_any_host` — `--allow-no-auth --disable-host-check`; any Host → **200**.
- `lists_nine_tools` — `tools/list` → exactly **9** tools (srx surface tripwire; mirrors junos's tool-count test).

Refactor `rust-srxmcp/tests/live_smoke.rs` to `use common::parse_first_sse_data` (dedup its copy). live_smoke is `#[ignore]`/env-based and does NOT spawn the binary, so it borrows only `parse_first_sse_data` (transport-agnostic) — it does not use the spawn helpers.

## Testing / acceptance

- `cargo test --workspace` — 0 failures. Part A is a behavior-preserving refactor (same tests pass); Part B adds new passing tests. Existing junos HTTP tests must still pass unchanged.
- `cargo fmt -- --check` clean; `cargo clippy --workspace --all-targets` clean (the `#![allow(dead_code)]` in each `common` avoids per-file unused-helper warnings).
- **No source (non-test) changes** — this is test-only. The srx tool count (9) must match reality; if it ever changes, this test is the intended tripwire.

## Risks

1. `http_post` signature reconciliation — http_reload's call sites must all gain the `None` session-id arg (compile error catches misses).
2. srx readiness-log substring — the harness waits on `"streamable-http listening"`; verified present in `rust-srxmcp/src/http_transport.rs:66`.
3. `tests/common/mod.rs` must be the submodule form so cargo doesn't compile it as a standalone test binary; `#![allow(dead_code)]` prevents unused-helper warnings in files that use only part of the module.

## Out of scope

- Non-HTTP test files in either crate.
- A shared cross-crate `test-support` crate (chosen against).
- Any change to non-test source, tool behavior, or the tool surface.
