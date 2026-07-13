# Caller-Attributed Audit Coverage — Design

- **Issue:** [#132](https://github.com/fastrevmd-lab/rustjunosmcp/issues/132) — [Medium] Complete caller-attributed audit coverage
- **Date:** 2026-07-12
- **Status:** Approved (first pass)
- **Scope note:** First pass — **core uniform coverage + redaction**. Pluggable
  syslog/journald sinks, rotation/retention tooling, and per-field encryption are
  deferred (see [Out of Scope](#out-of-scope)).

## Problem

Audit logging today is **ad-hoc inline `tracing::info!("audit")`** with inconsistent
fields (`token` vs `caller`, `status`/`outcome` vs `result`; `correlation_id` only on
`upgrade_junos`). Only **4 of 17** `rust-junosmcp` tools and **2 of 9** `rust-srxmcp`
tools emit any audit event, and the **four authorization-denial points log nothing**.
Operators cannot reliably answer who ran a command, changed configuration/inventory,
what device was targeted, whether authorization denied it, or how it ended.

Reference points:
- Richer existing pattern: `rust-junosmcp/src/server.rs` `transfer_file` (601–618),
  `upgrade_junos` (731–751) + `UpgradeAuditGuard` (77–118).
- SRX per-phase pattern: `rust-srxmcp-core/src/workflows/idp_package.rs`
  `audit_phase_with_action` (1466–1515).
- Caller extraction: `caller_ctx(&extensions)` (`server.rs:40–46`, srx `22–28`).
- Correlation id: `mint_request_id()` (`server.rs:48–54`).
- Denials (unlogged): `check_tool_scope`, `check_router_scope`, srx `authorize_call`
  (`MissingCallerContext`), inventory-readonly (`add_device.rs:25`, `reload_devices.rs:16`).
- Tracing init: `rust-junosmcp-core/src/bootstrap.rs:18–25` (stderr, human-readable,
  `RUST_LOG`; sink/format not configurable).
- Test harness: `CapturingWriter` + `run_with_capture` (`server.rs:1052–1156`).

## Goals (this pass)

1. **One shared audit schema** used by both binaries, with uniform field names.
2. Cover **every tool** on both binaries, emitting on success / failure /
   cancel-or-disconnect (unsettled).
3. Audit **all four denial points** with `result=denied`.
4. Include correlation id, caller, tool, router(s), action, authorization result,
   status/result, duration, and **safe** change metadata.
5. **Redact** secrets/config/command-output by construction; prove it with tests.
6. Modest **configurable sink**: JSON format flag + optional dedicated audit file.
7. **Captured-tracing tests** for field presence and redaction.
8. **Document the schema** for SIEM/log consumers.

## Non-Goals / Out of Scope

Deferred (track as comments/issues on #132):
- Pluggable **syslog/journald** sink targets.
- Log **rotation / retention** tooling (left to journald / logrotate, documented).
- Per-field **encryption** or tamper-evidence.
- Refactoring the SRX multi-phase workflow audit beyond field-name alignment.

## Design Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Emission | **RAII `AuditScope` guard** per handler | Generalizes the existing `UpgradeAuditGuard`; uniform fields, duration, drop-safe on cancel; ~4 lines/handler. No central rmcp hook exists (tool name lives in the JSON-RPC body). |
| Code home | **New crate `rust-junosmcp-audit`** | Consistent with `-auth`/`-limits`; keeps the cross-cutting concern out of `-core`. |
| Sink/format | **JSON format flag + optional audit file** | Satisfies "configurable sink" modestly, no new deps (`Mutex<File>` writer). |
| Redaction | **By construction (allowlist metadata)** | Secrets never enter the event; tests assert absence. |
| Command strings | **Logged** for operational tools; **output never logged** | The command *is* the audit-relevant action; its output may contain sensitive data. |

## Architecture

### New crate: `rust-junosmcp-audit`

**Dependencies:** `rust-junosmcp-auth` (for `CallerCtx`), `tracing`,
`tracing-subscriber`, `serde`/`serde_json` (JSON metadata + file lines), `sha2`
(content hashes are computed in handlers, but a helper may live here). No cycle:
`-auth` is standalone; `-core` may depend on `-audit`.

Modules:

#### `schema.rs`
```rust
/// Terminal outcome of an audited call.
pub enum AuditOutcome {
    /// Handler completed successfully.
    Succeeded,
    /// Handler returned an error (`error_kind` = a stable category).
    Failed { error_kind: &'static str, error: String },
    /// Authorization denied the call before work began.
    Denied { reason: &'static str },
    /// Guard dropped without an outcome (client cancel / disconnect).
    Unsettled,
}

/// A safe, non-secret metadata value attached to an audit event.
pub enum AuditValue { Str(String), U64(u64), Bool(bool) }
```
Field-name constants live here so both binaries and the schema doc stay in sync.

#### `scope.rs` — the guard
```rust
pub struct AuditScope { /* correlation_id, caller, tool, routers, action,
                          started: Instant, outcome, metadata: Vec<(&'static str, AuditValue)> */ }

impl AuditScope {
    /// Build at the top of a handler. `caller` is derived from CallerCtx
    /// (token_name) or "stdio" when absent.
    pub fn new(ctx: Option<&CallerCtx>, tool: &'static str, action: &'static str,
               routers: Vec<String>) -> Self;

    /// Attach a safe metadata field (never secrets).
    pub fn meta(&mut self, key: &'static str, val: impl Into<AuditValue>);

    /// Mark success (optionally after attaching metadata).
    pub fn succeed(&mut self);
    /// Mark failure with a stable kind + bounded message.
    pub fn fail(&mut self, error_kind: &'static str, error: impl Display);
    /// Mark an authorization denial with a reason.
    pub fn deny(&mut self, reason: &'static str);
}

impl Drop for AuditScope {
    // Emits exactly one `tracing::info!(target: "audit", correlation_id, caller,
    // tool, routers, router_count, action, authorization, result, duration_ms,
    // [error_kind, error], <metadata...>, "audit")`.
}
```
`authorization` is derived: `Denied → "denied"`; caller `"stdio"` → `"no_auth"`;
otherwise `"allowed"`. `result`: `Succeeded→"ok"`, `Failed→"error"`,
`Denied→"denied"`, `Unsettled→"unsettled"`.

#### `init.rs` — configurable output
```rust
pub enum AuditFormat { Text, Json }
pub struct AuditConfig { pub format: AuditFormat, pub audit_log_file: Option<PathBuf> }

/// Replaces the binaries' current `init_tracing`. Builds the stderr fmt layer
/// (human-readable or `.json()` per `format`) plus, when `audit_log_file` is set,
/// a second layer filtered to `target == "audit"` that appends JSON lines to the
/// file via a `Mutex<File>` writer. `RUST_LOG` still drives the env filter.
pub fn init_tracing(cfg: &AuditConfig);
```

#### `testutil.rs` (cfg(test) or a `test-util` feature)
Promotes `CapturingWriter` + `run_with_capture` so both the crate's own tests and
the binaries' tests can assert on captured `audit`-target output.

### Handler integration pattern (both binaries)

Every `#[tool]` handler adopts:
```rust
let ctx = caller_ctx(&extensions);
let mut audit = AuditScope::new(ctx, "load_and_commit_config", "commit", vec![router.clone()]);

if let Err(e) = self.check_tool_scope(ctx, "load_and_commit_config") {
    audit.deny("tool_scope");
    return Self::scope_to_call_result(e);
}
// ... router scope / inventory-readonly checks similarly set audit.deny(...) ...

match self.core.load_and_commit_config(/* ... */).await {
    Ok(v)  => { audit.meta("config_bytes", cfg_len as u64);
                audit.meta("config_sha256", sha); audit.succeed(); Ok(ok_result(v)) }
    Err(e) => { audit.fail(e.kind_str(), &e); Ok(err_result(e)) }
}
// audit drops here → single event emitted
```
- The **six existing inline `"audit"` calls are removed** and replaced by the guard
  (their operation-specific fields become `metadata`).
- Denials that previously returned early now set `audit.deny(reason)` first, so the
  guard emits a `denied` event.
- Unsettled (client cancel / disconnect) is emitted automatically by `Drop` because
  the outcome was never set.

### Per-tool safe metadata (redaction allowlist)

| Tool(s) | action | metadata (safe only) |
|---------|--------|----------------------|
| `load_and_commit_config`, `commit_check_config` | commit / commit-check | `config_bytes`, `config_sha256`, `commit_confirmed`, `comment_present` |
| `render_and_apply_j2_template` | apply | `template_name`, `var_count`, `rendered_bytes`, `rendered_sha256`, `committed` |
| `discard_candidate` | discard | (none beyond routers) |
| `execute_junos_command`, `execute_junos_pfe_command` | execute | `command` (string), `output_bytes` (size only) |
| `execute_junos_command_batch` | execute-batch | `command_count`, `router_count` |
| `add_device` | add-device | `name`, `host`, `auth_kind` (`password`\|`key`) — **never** secret material |
| `reload_devices` | reload-inventory | `device_count` |
| `transfer_file`, `fetch_file` | transfer / fetch | `basename`, `sha256` |
| `upgrade_junos` | upgrade | `basename`, `target_version` |
| read-only tools (`get_*`, `gather_device_facts`, `*_status`, `*_report`, `check_*`, `validate_*`, `collect_jtac_support_bundle`) | read | `output_bytes` (size only) |

**Never** logged as metadata: config bodies, rendered templates, template vars,
command output, credentials/keys/passwords. Error strings are logged (bounded length)
as diagnostics; `JmcpError`/`ScopeError` Display values are structured and do not echo
secrets.

## Configuration

Both binaries gain (SRX uses `JMCP_SRX_*` env prefixes):

| Flag | Env | Default | Effect |
|------|-----|---------|--------|
| `--audit-format text\|json` | `JMCP_AUDIT_FORMAT` | `text` | stderr audit/log format |
| `--audit-log-file <path>` | `JMCP_AUDIT_LOG_FILE` | unset | append JSON audit lines to a dedicated file |

`main.rs` builds `AuditConfig` from these and calls
`rust_junosmcp_audit::init_tracing(&cfg)` in place of `bootstrap::init_tracing`.

## Event Schema (documented in `docs/AUDIT.md`)

One line per audited call, `target=audit`, level INFO. JSON example:
```json
{"timestamp":"…","level":"INFO","target":"audit","fields":{
  "correlation_id":"…","caller":"ci-bot","tool":"load_and_commit_config",
  "routers":"vsrx-test10","router_count":1,"action":"commit",
  "authorization":"allowed","result":"ok","duration_ms":842,
  "config_bytes":1234,"config_sha256":"…","commit_confirmed":false,
  "comment_present":true}}
```
Denial example: `authorization=denied`, `result=denied`, `reason=router_scope`.

## Testing Strategy

Crate-level (`rust-junosmcp-audit`) using the promoted capture harness:
- `AuditScope` emits `result=ok` with `duration_ms` and metadata on success.
- Emits `result=unsettled` when dropped without an outcome.
- Emits `result=denied` + `authorization=denied` on `deny(...)`.
- `caller` = `"stdio"` (→ `authorization=no_auth`) when ctx is `None`.
- JSON `init_tracing` produces parseable JSON; audit-file layer writes only
  `target=audit` lines.

Binary-level (both `rust-junosmcp` and `rust-srxmcp`), captured-tracing:
- Representative tools emit the expected fields (commit, template, command,
  add_device, transfer).
- **Redaction:** a commit with a config body containing `pre-shared-key SECRET123`
  and an `add_device` with `password: "hunter2"` → captured audit output contains
  **neither** secret (only sizes/hashes/`auth_kind`).
- All **four** denial types emit `result=denied` with the correct `reason`.

## Acceptance-Criteria Mapping (#132)

| Criterion | This pass |
|-----------|-----------|
| Structured schema shared by Junos + SRX | ✅ `rust-junosmcp-audit` |
| correlation id, caller, tool, router(s), action, authz result, status, duration, safe change metadata | ✅ uniform event |
| Audit denied / failed / cancelled / timed-out / successful | ✅ (cancel/timeout that unwind → `error`; hard cancel/disconnect → `unsettled`) |
| Cover config, templates, discard, commands, file ops, upgrades, SRX lifecycle, inventory | ✅ all tools |
| Redact tokens/keys/creds/sensitive config/output | ✅ by construction + tests |
| Configurable sink; document retention/forwarding | ◑ JSON format + audit file; syslog/rotation deferred (documented) |
| Captured-tracing tests for fields + redaction | ✅ |
| Document schema for SIEM | ✅ `docs/AUDIT.md` |

## Risks / Open Questions

- **Hard cancel vs timeout indistinguishable from `Drop`.** Both surface as
  `unsettled`. Timeouts that return an error are captured as `result=error`,
  `error_kind="timeout"`. Documented; acceptable for first pass.
- **`error` strings could theoretically echo input.** Mitigation: bounded length and
  reliance on the structured `JmcpError`/`ScopeError` Display, which do not include
  secret material. Not a config/output dump.
- **Breadth:** ~26 handlers across two binaries change. Mechanical but wide — the plan
  batches junos and srx separately with tests per batch.
