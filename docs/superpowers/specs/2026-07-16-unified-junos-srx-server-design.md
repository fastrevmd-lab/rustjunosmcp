# Unified Junos and SRX MCP Server — Design

- **Issue:** [#163](https://github.com/fastrevmd-lab/rustjunosmcp/issues/163) — Merge `rust-srxmcp` into `rust-junosmcp` behind an `srx` feature
- **Date:** 2026-07-16
- **Release:** `0.8.0`
- **Status:** Approved design; written specification awaiting final review

## Problem

The workspace currently runs two MCP server processes against the same Juniper
inventory and bearer-token store:

- `rust-junosmcp` exposes 17 generic Junos tools on the packaged HTTP listener
  at `127.0.0.1:30030`;
- `rust-srxmcp` exposes 9 SRX workflow tools on a second listener at
  `127.0.0.1:30032`.

The split duplicates HTTP, TLS, CLI, inventory, token reload, session, resource
limit, metrics, service, packaging, and test infrastructure. It also divides
process-wide capacity limits and device state between two processes. Operators
must register, configure, monitor, and upgrade two servers even when they want
one Juniper automation surface.

Issue #163 replaces that deployment with one `rust-junosmcp` binary, process,
MCP endpoint, and systemd service. SRX workflows remain a separable compile-time
domain behind an `srx` Cargo feature, enabled by default.

## Goals

1. Expose the exact union of the existing 17 Junos and 9 SRX tools from one
   `rust-junosmcp` MCP server when built with default features.
2. Preserve every existing tool name, input/output schema, annotation, auth
   scope, audit contract, confirmation-token guardrail, error code, timeout,
   and device-safety behavior unless this merge strictly requires a documented
   deployment change.
3. Keep SRX workflow code optional at compile time and prove a Junos-only build
   contains no SRX tool surface.
4. Rename `rust-srxmcp-core` to `rust-junosmcp-srx-core`, delete the
   `rust-srxmcp` binary crate, and fold `rust-junosmcp-limits` into
   `rust-junosmcp-core`.
5. Retain `rust-junosmcp-auth` and `rust-junosmcp-audit` as independent
   security and review boundaries.
6. Reconcile CLI and environment configuration around canonical `JMCP_*`
   names while providing one release of explicit `JMCP_SRX_*` compatibility.
7. Ship one container binary and one LXC/systemd service, including a safe,
   testable upgrade from the current two-service package.
8. Migrate SRX unit, HTTP, TLS, scope, audit, limits, status, and ignored live
   tests to the unified harness.
9. Move all surviving workspace packages to release version `0.8.0` and
   document the breaking deployment change and single MCP registration.

## Non-Goals

- Adding, removing, renaming, or redesigning Junos or SRX tools.
- Changing inventory, bearer-token, MCP wire, audit-event, or workflow response
  schemas beyond metadata that necessarily reports version `0.8.0`.
- Merging the auth or audit crates into core.
- Changing `rustpanosmcp` or any non-Juniper repository.
- Moving or deleting existing support-bundle state during package upgrade.
- Running real-device or destructive integration tests without the existing
  explicit lab confirmation.
- Preserving a second listener, a `rust-srxmcp` executable alias, or a legacy
  systemd service after the `0.8.0` upgrade.

## Locked Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Server topology | One `rust-junosmcp` process and MCP endpoint | This is the central issue requirement and removes duplicated runtime state. |
| SRX feature default | Enabled | Existing packaged users receive the complete Juniper tool surface without special build flags. |
| Junos-only build | `--no-default-features`; add `--features tls` when TLS is wanted | Keeps SRX compile-time optional while retaining independent TLS control. |
| Handler composition | Separate named Junos/SRX generated routers on one handler | Preserves macro-generated schemas and keeps domain code reviewable without manual dispatch. |
| Resource limits | One shared HTTP/session/rate/concurrency stack | The single process must enforce one capacity budget across every tool. |
| Core crates | Rename SRX core; fold limits into Junos core | Matches the issue while keeping SRX workflows separable and auth/audit independent. |
| Environment compatibility | Canonical `JMCP_*` wins; legacy fallback for `0.8.0` warns | Gives operators a bounded migration window without silent behavior. |
| Legacy SRX port | Warn and ignore `JMCP_SRX_HTTP_PORT` | That variable selected a listener that no longer exists; treating it as the unified port could unexpectedly move the Junos endpoint. |
| Version | `0.8.0` for every surviving workspace package | The issue resolution moves the renamed SRX core to `0.8.0` with the rest of the workspace, and the server merge is a breaking deployment change. |
| Upgrade cleanup | Stop/disable and remove the old service and binary; preserve state | Merely omitting files leaves upgraded hosts running stale code on port 30032. |
| Default packaged endpoint | `127.0.0.1:30030/mcp` | Preserves the existing primary service endpoint and package contract. |

## Considered Architectures

### 1. One handler with separate generated routers — selected

Keep Junos and SRX tool methods in separate source modules, but implement both
sets on the same `JmcpHandler`. Give each `#[tool_router]` expansion a distinct
router name, combine those routers when constructing the handler, and let one
`#[tool_handler]` implementation serve the combined router.

This uses rmcp's supported multiple-router composition, preserves generated
schemas and dispatch, and keeps SRX code fully gated with `#[cfg(feature =
"srx")]`.

### 2. Two internal handlers behind a manual dispatcher — rejected

The binary could retain `JmcpHandler` and `JmcpSrxHandler`, then manually merge
their `list_tools` and `call_tool` behavior. That retains more source unchanged,
but creates a second source of truth for schema listing and dispatch. A new tool
could compile while being absent from the composite dispatcher, and handler
state would remain unnecessarily divided.

### 3. One monolithic tool module — rejected

Moving all 26 methods into the current `server.rs` would be mechanically simple,
but would produce an oversized mixed-domain module and make feature gating,
review, and test ownership harder. It provides no runtime advantage over named
router composition.

## Workspace and Feature Layout

The resulting workspace members are:

```text
rust-junosmcp/              # only server binary
rust-junosmcp-core/         # device primitives plus HTTP limits
rust-junosmcp-srx-core/     # feature-gated SRX workflows
rust-junosmcp-auth/         # independent auth boundary
rust-junosmcp-audit/        # independent audit boundary
```

`rust-srxmcp/`, `rust-srxmcp-core/`, and `rust-junosmcp-limits/` cease to exist
under those names. Historical design documents and changelog history remain
historical records; current documentation and build/deployment references are
updated.

All surviving package manifests (`rust-junosmcp`, core, renamed SRX core, auth,
and audit) move to `0.8.0`. Keeping auth and audit as security/review boundaries
does not require them to use independent release numbers.

`rust-junosmcp/Cargo.toml` uses independent features:

```toml
[features]
default = ["tls", "srx"]
tls = ["dep:rustls", "dep:rustls-pki-types", "dep:axum-server"]
srx = ["dep:rust-junosmcp-srx-core"]
```

The renamed SRX core dependency is optional. Every import, handler field,
router module, and integration test that requires it is gated by `srx`. The
workspace still tests `rust-junosmcp-srx-core` directly, while package-level
tests prove both the default and Junos-only binary feature sets.

`rust-junosmcp-core` gains a public `limits` module containing the existing
configuration, concurrency, overload, Prometheus, rate-limit, router, and
session modules. Their implementation and stable HTTP response contracts move
without behavioral redesign. Dependencies formerly owned by the limits crate
move to the core manifest. The auth crate remains a dependency rather than
being copied or merged.

## Unified Handler and Tool Routing

`JmcpHandler` remains the sole rmcp `ServerHandler`. Its common state continues
to include the shared `DeviceManager`, blocklist policy, transfer configuration,
and upgrade configuration. With `srx` enabled it also holds:

- the process start instant used by `srxmcp_status`;
- whether authenticated caller context is required;
- the same `Arc<DeviceLeaseManager>` used by Junos upgrade operations;
- the existing clone-safe SRX `ConfirmationStore`;
- a typed support-bundle staging configuration resolved once during bootstrap.

The handler stores its combined `ToolRouter<JmcpHandler>`. Construction starts
with the named Junos router and, under `srx`, adds the named SRX router. The
single `#[tool_handler]` delegates to that stored router. Junos and SRX
source-order constants remain separate and continue to assert exact equality
with `JUNOS_TOOLS` and `SRX_TOOLS`; a new aggregate test proves the default
server exposes exactly their 26-name union with no duplicates.

The SRX methods move with minimal changes into a gated module under
`rust-junosmcp/src/server/`. Their authorization checks, audit kinds,
device-identity binding, confirmation issuance/validation, workflow error
mapping, and response serialization remain intact. `srxmcp_status` keeps its
tool name and response shape, including `endpoint: "srxmcp"`; only its reported
package version changes to `0.8.0`.

The unified server info identifies `rust-junosmcp` and describes both Junos and
SRX capabilities when the feature is enabled. This metadata change does not
alter the MCP protocol or any tool schema.

## Bootstrap and Runtime Behavior

The existing `rust-junosmcp` bootstrap remains authoritative:

1. Resolve CLI and compatible environment configuration.
2. Initialize audit/tracing.
3. Handle token-management subcommands without starting a server.
4. Validate transport and TLS policy.
5. Load inventory, compile policy, and create one `DeviceManager`.
6. Load one token store and install one SIGHUP reload loop.
7. Create one device-lease manager and share it with Junos and SRX destructive
   workflows.
8. Resolve support-bundle staging directory and capacity into typed state.
9. Construct one handler and run either stdio or streamable HTTP.

Default-feature stdio and HTTP transports both expose all 26 tools. The
Junos-only build exposes the existing 17 tools. SIGHUP reload continues to
reload inventory before token validation and rebuilds the blocklist policy;
SRX calls observe the same refreshed `DeviceManager`.

The current fail-closed SRX behavior is retained: when bearer authentication is
configured, an SRX method refuses a request whose rmcp extensions unexpectedly
lack `CallerCtx`. Explicit loopback `--allow-no-auth` and stdio retain the
existing no-context behavior. Junos tool scope and router scope behavior does
not change.

## HTTP, TLS, Limits, and Metrics

Only `rust-junosmcp/src/http_transport.rs` remains. It imports the moved APIs
from `rust_junosmcp_core::limits` and keeps the current request order:

```text
body-size limit
  -> bearer authentication
    -> per-token rate limit
      -> concurrency and router limits
        -> rmcp streamable service and limited session manager
```

There is one `LocalSessionManager`, one global/session tracker, and one set of
per-token and per-router state for the combined endpoint. Existing 413, 429,
503, `Retry-After`, and JSON response contracts remain unchanged. The single
Prometheus runtime uses the `junos` server label; the old `srx` process label is
retired with the second process. `/metrics` remains outside bearer auth as
currently documented.

TLS continues to be controlled by the independent `tls` feature. The existing
Junos TLS loader and handshake path serve all tools; the duplicate SRX loader
and transport are removed.

## CLI and Environment Compatibility

Command-line flag names and precedence remain conventional: an explicit CLI
value wins over canonical environment configuration, which wins over a legacy
fallback, which wins over the existing default.

The unified CLI adds canonical environment bindings where the old SRX binary
had environment-only deployment controls:

| Purpose | Canonical | `0.8.0` legacy fallback |
|---|---|---|
| HTTP host | `JMCP_HTTP_HOST` | `JMCP_SRX_HTTP_HOST` |
| HTTP port | `JMCP_HTTP_PORT` | none; `JMCP_SRX_HTTP_PORT` is ignored |
| TLS certificate | `JMCP_TLS_CERT` | `JMCP_SRX_TLS_CERT` |
| TLS key | `JMCP_TLS_KEY` | `JMCP_SRX_TLS_KEY` |
| Metrics | `JMCP_ENABLE_METRICS` | `JMCP_SRX_ENABLE_METRICS` |
| Body limit | `JMCP_MAX_REQUEST_BODY_BYTES` | `JMCP_SRX_MAX_REQUEST_BODY_BYTES` |
| Global concurrency | `JMCP_MAX_INFLIGHT_REQUESTS` | `JMCP_SRX_MAX_INFLIGHT_REQUESTS` |
| Per-token concurrency | `JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN` | `JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_TOKEN` |
| Per-token rate | `JMCP_MAX_REQUESTS_PER_SECOND_PER_TOKEN` | `JMCP_SRX_MAX_REQUESTS_PER_SECOND_PER_TOKEN` |
| Per-token burst | `JMCP_MAX_REQUEST_BURST_PER_TOKEN` | `JMCP_SRX_MAX_REQUEST_BURST_PER_TOKEN` |
| Per-router concurrency | `JMCP_MAX_INFLIGHT_REQUESTS_PER_ROUTER` | `JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_ROUTER` |
| Global sessions | `JMCP_MAX_SESSIONS` | `JMCP_SRX_MAX_SESSIONS` |
| Per-token sessions | `JMCP_MAX_SESSIONS_PER_TOKEN` | `JMCP_SRX_MAX_SESSIONS_PER_TOKEN` |
| Idle timeout | `JMCP_SESSION_IDLE_TIMEOUT_SECS` | `JMCP_SRX_SESSION_IDLE_TIMEOUT_SECS` |
| Max session lifetime | `JMCP_SESSION_MAX_LIFETIME_SECS` | `JMCP_SRX_SESSION_MAX_LIFETIME_SECS` |
| Audit format | `JMCP_AUDIT_FORMAT` | `JMCP_SRX_AUDIT_FORMAT` |
| Audit file | `JMCP_AUDIT_LOG_FILE` | `JMCP_SRX_AUDIT_LOG_FILE` |
| Journald | `JMCP_AUDIT_JOURNALD` | `JMCP_SRX_AUDIT_JOURNALD` |
| Audit redaction | `JMCP_AUDIT_REDACT` | `JMCP_SRX_AUDIT_REDACT` |
| Audit HMAC key file | `JMCP_AUDIT_HMAC_KEY_FILE` | `JMCP_SRX_AUDIT_HMAC_KEY_FILE` |
| Support-bundle directory | `JMCP_SUPPORT_BUNDLE_STAGING_DIR` | `JMCP_SRX_STAGING_DIR` |
| Support-bundle cap | `JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES` | `JMCP_SRX_STAGING_MAX_BYTES` |

`JMCP_TOKENS_PATH`, `JMCP_DEVICES_PATH`, and `JMCP_DEVICE_LEASE_DIR` were
already shared rather than SRX-prefixed; the unified CLI accepts them as the
canonical bindings for their existing flags.

CLI parsing retains clap's `ArgMatches` value-source information so fallback
logic can distinguish a command-line or canonical-environment value from a
default. Legacy values are parsed with the same type/error semantics as their
canonical equivalents. Compatibility resolution records warnings before
tracing is initialized, then emits each warning once after initialization.
When both names are set, the canonical value is used and the obsolete name is
reported as ignored. `JMCP_SRX_HTTP_PORT` is always ignored and warns because
silently applying it to the unified endpoint could relocate the primary Junos
listener.

These aliases are promised only for `0.8.0`; documentation marks them for
removal in `0.9.0`.

The support-bundle variables bind to new
`--support-bundle-staging-dir` and
`--support-bundle-staging-max-bytes` options. Bootstrap resolves them into a
`SupportBundleStagingConfig` stored on the unified handler and passes it to the
support-bundle workflow. The workflow no longer consults process environment
variables during a tool call. This gives support-bundle configuration the same
CLI/canonical/legacy/default precedence as the rest of the server, makes an
invalid value a startup error, and avoids process-global environment races in
tests.

## Packaging and Upgrade Migration

The release archive, Docker image, and LXC package contain only:

- `/usr/local/bin/rust-junosmcp`;
- `/etc/systemd/system/rust-junosmcp.service`;
- the existing example configuration and installer assets.

The unified service listens on `127.0.0.1:30030`, loads the shared inventory and
token files, uses the existing device-lease and transfer staging paths, and
sets the canonical support-bundle staging path to the preserved
`/var/lib/jmcp/srx-staging/bundles` directory. Keeping that directory avoids a
risky state migration and preserves already-collected bundles.

The issue motivation mentions port 30031, but the authoritative checked-in
CLI default, systemd unit, Docker/package tests, and current deployment assets
all use 30030. This merge preserves that actual primary endpoint rather than
introducing an unrelated port migration.

The installer validates the complete new payload before changing target state.
For both live and staged installs it removes stale
`/usr/local/bin/rust-srxmcp` and
`/etc/systemd/system/rust-srxmcp.service` files if present. On a live root
upgrade it first asks systemd to stop and disable the legacy service, tolerating
the clean-install case where it is absent, then performs one daemon reload
after unit installation/removal. It never deletes `/etc/jmcp`, token or device
files, known hosts, lease state, transfer staging, or SRX support-bundle state.

Package smoke tests construct a simulated old installation with the legacy
binary, unit, and preserved data; run the new installer twice; and prove:

- the obsolete binary and unit are absent;
- configuration and known-host hashes are unchanged;
- support-bundle data remains;
- the new installer is idempotent;
- the one unit passes `systemd-analyze verify`;
- the installed binary serves an authenticated MCP initialization;
- its tool listing includes both a Junos and an SRX tool.

Distribution smokes make the equivalent layout and preservation assertions on
the supported Debian and Ubuntu bases. The Docker runtime creates or owns both
transfer and support-bundle staging directories and continues to run as the
non-root `jmcp` user.

## Test Migration and Verification Strategy

Implementation is test-driven. Each behavior is first represented by a failing
test or an intentionally failing existing test moved to its destination.

### Compile-time and registry tests

- default features compile the renamed SRX core and expose exactly 26 unique
  tool names;
- `cargo build -p rust-junosmcp --no-default-features` succeeds and exposes
  exactly the 17 Junos tools;
- `cargo build -p rust-junosmcp --no-default-features --features tls` succeeds;
- auth registries remain the exact union of the Junos and SRX tool constants;
- workspace manifests and lockfile contain no old package names.

### Unified server tests

Move SRX integration tests under `rust-junosmcp/tests/` with unambiguous names
and reuse the existing Junos process harness. Tests start only
`rust-junosmcp`, always selecting streamable HTTP explicitly where the removed
SRX binary previously implied it. Coverage includes:

- authenticated initialize, tools/list, and every SRX tool-scope denial;
- router-scope denial before device lookup or disclosure;
- fail-closed missing authorization context;
- SRX status shape and version;
- confirmation-token binding and destructive prechecks;
- HTTP body, session, rate, concurrency, and metrics behavior;
- TLS handshake plus independent bearer-auth and Host checks;
- existing Junos stdio, HTTP, reload, TLS, audit, and tool smokes;
- a combined endpoint test that lists and calls representative Junos/SRX tools
  through the same MCP session.

Duplicate SRX transport tests that assert behavior already proven by the same
unified stack may be consolidated, but no unique contract coverage is dropped.
Ignored live SRX tests move to the unified package and use a unified URL/token
name in their instructions. They remain ignored and are not run against a real
device during ordinary development or CI.

### Environment tests

Subprocess-level tests isolate process-global environment state and prove:

- CLI beats canonical and legacy environment values;
- canonical environment values beat legacy aliases;
- a legacy-only value is applied and warns once;
- invalid legacy values fail startup rather than silently defaulting;
- `JMCP_SRX_HTTP_PORT` is ignored, warns, and does not change the bind port;
- canonical and legacy support-bundle settings resolve to the expected paths
  and limits.

### Required project and CI gates

Before handoff, run the repository-required offline checks (`just fmt`,
`just lint`, `just test`, `just guard`, and `just e2e`) plus `just security` and
`just release-check`. If `just` is unavailable, run and report the exact recipe
commands directly. Also run feature-matrix builds, package/distribution smokes,
shellcheck, and any CI-specific commands touched by the change. Real-device
tests remain skipped unless `CONFIRM_LAB_INTEGRATION=yes` is separately and
deliberately authorized.

## Documentation and Release Notes

Update current `README.md`, `CHANGELOG.md`, `AGENTS.md`, `docs/AUDIT.md`,
`docs/METRICS.md`, crate readmes, CLI help, MCP registration examples, systemd
instructions, container examples, and live-test comments to describe one
server. The release notes call out:

- the single endpoint and retirement of port 30032;
- removal of the `rust-srxmcp` executable and service;
- the default-on `srx` feature and Junos-only build commands;
- the SRX core crate rename;
- canonical environment variables and the one-release alias window;
- active legacy-service cleanup with preserved support-bundle state;
- version `0.8.0` as a breaking deployment release.

Historical specifications, plans, and old changelog entries are not rewritten
to pretend the previous architecture never existed. Current-facing summaries
may link to this design as the superseding decision.

## Compatibility Contract

| Surface | `0.8.0` result |
|---|---|
| Junos MCP tool names and schemas | Unchanged |
| SRX MCP tool names and schemas | Unchanged; served from unified endpoint |
| Bearer token file and tool/router scopes | Unchanged |
| Confirmation store behavior | Preserved in one handler process |
| Audit schema and safety classification | Unchanged |
| HTTP rejection bodies/status/headers | Unchanged |
| TLS and Host validation | Unchanged on the unified listener |
| Inventory and token SIGHUP reload | One authoritative reload path |
| Junos endpoint `127.0.0.1:30030` | Preserved |
| SRX endpoint `127.0.0.1:30032` | Removed |
| `rust-srxmcp` binary/service | Removed during install/upgrade |
| `JMCP_SRX_*` deployment variables | Deprecated fallback for one release, except port |
| Support-bundle files | Preserved at existing packaged path |

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Generated router composition changes a tool schema or omits a tool | Use rmcp's supported named-router addition and assert the exact 26-tool runtime list and auth registries. |
| `srx` leaks into a disabled build | Gate dependency, modules, fields, constructors, and tests; build and inspect both feature sets. |
| Legacy environment precedence is ambiguous | Use clap value-source evidence, explicit mapping tests, one warning per obsolete variable, and documented precedence. |
| Upgrade leaves port 30032 active | Stop/disable the service and delete both stale artifacts; simulate the old layout in package tests. |
| Upgrade destroys operational data | Treat config and state preservation as hash/content assertions; never delete the SRX staging directory. |
| One endpoint increases aggregate load | Apply one existing global/session/per-token/per-router budget to the full surface; defaults do not double. |
| Shared handler accidentally weakens SRX authorization | Retain the explicit `authorization_required` check and migrate its fail-closed tests before deleting the old crate. |
| Large mechanical moves hide behavior changes | Use `git mv` where possible, separate structural commits from behavioral compatibility work, and review schema/test diffs. |
| Core dependency surface grows when limits move | Move the current dependencies without introducing new ones; review license/security output and keep auth/audit separate. |

## Success Criteria

The issue is complete only when all of the following are proven in the merged
repository:

1. Exactly one server binary, service, listener, HTTP stack, and MCP
   registration remain.
2. Default `rust-junosmcp` exposes all 26 existing tools with compatible
   schemas, scopes, audits, confirmation behavior, and stable errors.
3. A Junos-only build succeeds without compiling or exposing SRX code.
4. The renamed SRX core and folded limits module are the only current crate
   locations; old workspace packages and imports are absent.
5. Canonical and legacy environment behavior matches the table and warnings.
6. A simulated upgrade removes legacy runtime artifacts while preserving all
   operator configuration and support-bundle state.
7. Current documentation and release notes consistently describe version
   `0.8.0` and the one-server deployment.
8. All required local, security, release, feature-matrix, packaging, and CI
   checks pass; deliberately skipped live-device checks are reported.
9. The pull request is reviewed, CI is green, the change is squash-merged, the
   issue is closed, and the issue worktree and branch are cleaned up.
