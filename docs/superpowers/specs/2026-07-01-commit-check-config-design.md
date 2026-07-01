# commit_check_config — non-destructive Junos config validation

**Issue:** #95 — Add commit-check (validate-only) support
**Date:** 2026-07-01
**Status:** Approved design

## Problem

The only write verb in the server is `load_and_commit_config`, which always
commits. Validating a change therefore forces a bad tradeoff:

- A **valid** config gets **applied live** even when the caller only wanted to
  validate it.
- The closest workaround — `load_and_commit_config` with `confirm_timeout_mins`
  (confirmed commit + auto-rollback) — still **activates** the config on the box
  for the rollback window. It is not a true non-destructive check.

On a production firewall we want to validate syntax, semantics, and unresolved
references (e.g. an AAMW `inspection-profile` that may not exist) **before**
anything touches the running config. Junos supports this via
`<commit><test-only/>` / `<validate><source><candidate/></source></validate>`
(CLI `commit check`).

## Requested behavior (from #95)

- Load config into a private candidate, run commit-check, return
  `{success, diff, errors}` **without** committing.
- Never activate config; roll back / clear the candidate on completion.
- Surface commit-check errors (unresolved references, constraint failures) in
  the response.

## Design decision

Expose a **dedicated `commit_check_config` tool** (not a `check_only` flag on
`load_and_commit_config`). Rationale: the server is built around **per-tool
least-privilege token scopes** (`SERVER_TOOLS` ⇔ `KNOWN_TOOLS`, enforced by the
`server_tools_matches_known_tools_as_set` tripwire). A dedicated tool gets its
own scope, so an operator can grant validate-only rights to a token **without**
also granting commit rights. A flag on the existing tool would force any
validate-only caller to hold `load_and_commit_config` scope, which also permits
committing.

Upstream already provides the primitive: rustez 0.12.0 exposes
`Config::commit_check()` → `validate(Datastore::Candidate)`. No upstream change
needed.

## Architecture

### New handler: `rust-junosmcp-core/src/tools/commit_check.rs`

Modeled directly on `load_commit::handle`. Signature:

```rust
pub async fn handle(
    args: CommitCheckArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError>
```

Flow:

1. `validate_input_length("config_text", &args.config_text)?`
2. `dm.inventory().get(&args.router_name)?` — confirm router exists.
3. **Blocklist policy check** — same `policy.check_config(...)` gate as
   `load_and_commit_config`, emitting the same `tracing::warn!` + `JmcpError::Denied`
   on a match. Decision: keep the policy even though we never commit
   (defense-in-depth; a denied pattern stays denied regardless of intent, and it
   keeps the two write-path tools behaviorally consistent).
4. `build_config_payload(args.config_text, Some(&args.config_format))?`
5. Inside `tokio::time::timeout(Duration::from_secs(args.timeout), ...)`:
   - `let mut dev = dm.open(&args.router_name).await?;`
   - `let mut cfg = dev.config()?;`
   - `cfg.lock().await?;`
   - `cfg.load(payload).await` — on error, `unlock` and return the error.
   - `let diff = cfg.diff().await?.unwrap_or_default();`
   - `let check = cfg.commit_check().await;`
   - **`let _ = cfg.rollback(0).await;`** — always discard the loaded candidate
     so nothing persists in the private DB, on both pass and fail paths.
   - `let _ = cfg.unlock().await;`
   - Build result:
     - `Ok(_)`  → `{ "success": true,  "diff": diff, "checked_only": true }`
     - `Err(e)` → `{ "success": false, "diff": diff, "error": e.to_string() }`
6. Map elapsed timeout to `JmcpError::Timeout(timeout_dur)`.

**Response shape:** `{success, diff, error?}` (+ `checked_only: true` on success)
— a single `error` string, matching `load_and_commit_config` rather than the
`errors[]` array sketched in the issue, for codebase consistency. The rustez
error string already carries the device's validation failure text (unresolved
references, constraint failures).

**`checked_only: true`** is an explicit marker in the success payload so a caller
(or an LLM) can never mistake a passing check for an applied commit.

### New args: `rust-junosmcp-core/src/tools/mod.rs`

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommitCheckArgs {
    pub router_name: String,
    /// The configuration text to validate.
    pub config_text: String,
    /// Format: set, text, or xml.
    #[serde(default = "default_set_format")]
    pub config_format: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}
```

No `commit_comment` and no `confirm_timeout_mins` — the tool never commits.

Register `pub mod commit_check;` in `mod.rs`.

### New tool adapter: `rust-junosmcp/src/server.rs`

```rust
#[tool(
    name = "commit_check_config",
    description = "Validate a candidate configuration on a Junos router without committing (commit check). Loads into a private candidate, runs commit-check, returns {success, diff, error?}, then discards the candidate. Never activates config."
)]
async fn commit_check_config(
    &self,
    Parameters(args): Parameters<CommitCheckArgs>,
    extensions: Extensions,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let ctx = caller_ctx(&extensions);
    if let Err(e) = self.check_tool_scope(ctx, "commit_check_config") {
        return Self::scope_to_call_result(e);
    }
    if let Err(e) = self.check_router_scope(ctx, "commit_check_config", &args.router_name) {
        return Self::scope_to_call_result(e);
    }
    Self::to_call_result(
        commit_check::handle(args, self.dm.clone(), self.policy.load_full()).await,
    )
}
```

Add `commit_check` to the `use` import list and `CommitCheckArgs` to the args import.

### Scope registration (RJMCP-SEC-001)

- Add `"commit_check_config"` to `SERVER_TOOLS` in `server.rs`.
- Add `"commit_check_config"` to `KNOWN_TOOLS` in `rust-junosmcp-auth/src/file.rs`.
- Bump the tripwire test: `server_tools_len_is_15` → `server_tools_len_is_16`
  (rename + assert 16).

## Testing (TDD)

Unit tests in `commit_check.rs`, mirroring `load_commit.rs` (all short-circuit
before any network I/O, so no live device needed):

- `unknown_router_propagates_error` — `JmcpError::UnknownRouter`.
- `invalid_format_rejected_before_connect` — `config_format:"yaml"` →
  `JmcpError::BadFormat`.
- `non_set_format_with_rules_present_returns_format_error` — xml + blocklist rules
  present → `ConfigFormatNotAllowedWithRules`.
- `denied_payload_short_circuits_before_connect` — `delete *` pattern →
  `JmcpError::Denied { tool: "commit_check_config", .. }`.

Args tests in `mod.rs`:

- `commit_check_defaults_format_and_timeout` — defaults `set` / `360`.
- `commit_check_rejects_missing_required` — missing `config_text`.

Existing tripwire tests (`server_tools_len_is_16`,
`server_tools_matches_known_tools_as_set`, auth-crate KNOWN_TOOLS tests) cover
scope wiring.

**Live smoke (post-deploy, LXC 601):** run `commit_check_config` against a vSRX
with (a) a valid change → `success:true` + non-empty diff, `show configuration`
unchanged; (b) a change referencing a non-existent object → `success:false` with
the reference error in `error`.

## Out of scope

- No `errors[]` structured array — single `error` string for consistency.
- No change to `load_and_commit_config` or the template `dry_run` path.
- No new policy semantics — reuses the existing blocklist gate.

## Files touched

- `rust-junosmcp-core/src/tools/commit_check.rs` (new)
- `rust-junosmcp-core/src/tools/mod.rs` (CommitCheckArgs + mod decl + arg tests)
- `rust-junosmcp/src/server.rs` (tool adapter + SERVER_TOOLS + tripwire bump)
- `rust-junosmcp-auth/src/file.rs` (KNOWN_TOOLS)
- `README.md` / `CHANGELOG.md` — document the 16th tool.
