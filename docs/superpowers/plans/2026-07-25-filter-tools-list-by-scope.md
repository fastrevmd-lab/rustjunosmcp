# Filter `tools/list` by Token Tool Scope — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `tools/list` advertise only the tools the caller's token can actually invoke, closing [#199](https://github.com/fastrevmd-lab/rustjunosmcp/issues/199).

**Architecture:** A pure helper filters a `Vec<Tool>` through the same `ScopeSet::allows_tool(name, WRITE_TOOLS)` predicate that `check_tool_scope` already uses for `tools/call`. A hand-written `list_tools` in the `ServerHandler` impl calls that helper with the caller context pulled from `RequestContext.extensions`. Defining `list_tools` by hand suppresses the one `rmcp-macros` would otherwise generate.

**Tech Stack:** Rust (edition 2024), rmcp 2.0.0, mecmcp-auth 0.1.4, tokio, serde_json. Tests are `cargo test`; end-to-end tests spawn the real binary over HTTP.

**Spec:** `docs/superpowers/specs/2026-07-25-filter-tools-list-by-scope-design.md`

## Global Constraints

- Workspace is edition 2024, `rust-version = 1.88`. Do not change either.
- Lints: `unsafe_code = "deny"`, `clippy::all = "warn"`, `dbg_macro = "deny"`, `todo = "deny"`. `cargo clippy --workspace --all-targets --all-features -- -D warnings` must stay clean.
- `missing_docs` and `clippy::unwrap_used` are `allow` workspace-wide (tracked in #193). Do not enable them here, but do put doc comments on new public items — the codebase convention is that public functions carry them.
- Formatting: `cargo fmt --all` before every commit. rustfmt's style edition follows the crate edition (2024).
- The single source of truth for which tools are write tools is `rust_junosmcp_auth::WRITE_TOOLS`. Never re-list those ten names anywhere in shipping code.
- Scope checks are a no-op when there is no caller context (stdio, `--allow-no-auth`). Preserve that in every code path you touch.
- Tool counts: 27 total with the default `srx` feature, 18 with `--no-default-features`. `WRITE_TOOLS` has 10 entries, all present in both feature configurations except the two SRX ones.

## Deviation From The Spec (read before Task 1)

The spec sketched the filter inline inside `list_tools`. This plan extracts it into a pure `filter_tools_for_scope` helper instead, because `list_tools` takes a `RequestContext<RoleServer>` which owns a `Peer<RoleServer>` — there is no practical way to construct one in a unit test. The pure helper is trivially unit-testable, and the thin `list_tools` adapter is covered by the end-to-end test in Task 2. Same behaviour, same single predicate, better test seams. This matches how the rest of the codebase separates pure core logic from thin rmcp adapters.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `rust-junosmcp/src/server.rs` | rmcp `ServerHandler`; thin adapters over core tools | Add `filter_tools_for_scope` (pure, module-level, next to `caller_ctx` at line 47). Add `list_tools` to the `impl ServerHandler for JmcpHandler` block (line 1071). Add tests to the existing `scope_tests` module (line 1091). |
| `rust-junosmcp/tests/http_smoke.rs` | End-to-end streamable-http behaviour | Add one test asserting a wildcard token's `tools/list` response over real HTTP. |
| `README.md` | Operator documentation | Note the filtering in "Tool scopes and write tools"; add the stale-cache caveat. |
| `CHANGELOG.md` | Release notes | `Changed` entry under `[Unreleased]`. |

No new files. No new dependencies.

---

### Task 1: Pure scope filter + unit tests

**Files:**
- Modify: `rust-junosmcp/src/server.rs` (add helper after `caller_ctx`, ends line 51)
- Test: `rust-junosmcp/src/server.rs` — `scope_tests` module, starts line 1091

**Interfaces:**
- Consumes: `rust_junosmcp_auth::{CallerCtx, ScopeSet, WRITE_TOOLS, KNOWN_TOOLS}`, `rmcp::model::Tool`. `CallerCtx` has fields `token_name: String`, `devices: ScopeSet`, `tools: ScopeSet`. `ScopeSet` is an enum with variants `Wildcard` and `Allowlist(Vec<String>)`, and method `allows_tool(&self, name: &str, write_tools: &[&str]) -> bool`.
- Produces: `pub(super) fn filter_tools_for_scope(tools: Vec<rmcp::model::Tool>, ctx: Option<&rust_junosmcp_auth::CallerCtx>) -> Vec<rmcp::model::Tool>` — used by Task 2's `list_tools`.

- [ ] **Step 1: Write the failing tests**

Add to the `scope_tests` module in `rust-junosmcp/src/server.rs`, at the end (before the closing brace). Note `scope_tests` already has `use super::*;` and `use rust_junosmcp_auth::{CallerCtx, ScopeSet};` at its top, and a `make_handler()` helper.

```rust
    fn ctx_with_tools(tools: ScopeSet) -> CallerCtx {
        CallerCtx {
            token_name: "t".into(),
            devices: ScopeSet::Wildcard,
            tools,
        }
    }

    fn names_of(tools: Vec<rmcp::model::Tool>) -> std::collections::BTreeSet<String> {
        tools.into_iter().map(|t| t.name.to_string()).collect()
    }

    #[test]
    fn no_caller_context_lists_every_tool() {
        let all = make_handler().tool_router.list_all();
        let expected = names_of(all.clone());
        assert_eq!(names_of(filter_tools_for_scope(all, None)), expected);
    }

    #[test]
    fn wildcard_scope_hides_exactly_the_write_tools() {
        let ctx = ctx_with_tools(ScopeSet::Wildcard);
        let all = make_handler().tool_router.list_all();
        let all_names = names_of(all.clone());
        let listed = names_of(filter_tools_for_scope(all, Some(&ctx)));

        let compiled_write_tools: std::collections::BTreeSet<String> =
            rust_junosmcp_auth::WRITE_TOOLS
                .iter()
                .map(|n| (*n).to_string())
                .filter(|n| all_names.contains(n))
                .collect();

        for name in &compiled_write_tools {
            assert!(!listed.contains(name), "wildcard must hide write tool {name}");
        }
        assert_eq!(
            listed,
            all_names
                .difference(&compiled_write_tools)
                .cloned()
                .collect::<std::collections::BTreeSet<String>>(),
            "wildcard must keep every non-write tool"
        );
    }

    #[test]
    fn explicit_allowlist_naming_a_write_tool_still_lists_it() {
        let ctx = ctx_with_tools(ScopeSet::Allowlist(vec![
            "gather_device_facts".into(),
            "load_and_commit_config".into(),
        ]));
        let listed = names_of(filter_tools_for_scope(
            make_handler().tool_router.list_all(),
            Some(&ctx),
        ));
        assert_eq!(
            listed,
            ["gather_device_facts", "load_and_commit_config"]
                .iter()
                .map(|n| (*n).to_string())
                .collect::<std::collections::BTreeSet<String>>()
        );
    }

    #[test]
    fn empty_scope_lists_nothing() {
        let ctx = ctx_with_tools(ScopeSet::Allowlist(vec![]));
        assert!(
            filter_tools_for_scope(make_handler().tool_router.list_all(), Some(&ctx)).is_empty()
        );
    }

    /// The invariant #199 is about: everything advertised must be callable.
    #[test]
    fn every_listed_tool_passes_check_tool_scope() {
        let handler = make_handler();
        let scopes = [
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec![
                "gather_device_facts".into(),
                "load_and_commit_config".into(),
            ]),
            ScopeSet::Allowlist(vec![]),
        ];

        let compiled = names_of(handler.tool_router.list_all());

        for scope in scopes {
            let ctx = ctx_with_tools(scope);
            let listed = filter_tools_for_scope(handler.tool_router.list_all(), Some(&ctx));

            for tool in &listed {
                // check_tool_scope takes &'static str; find the matching
                // registry entry so the lifetime is satisfied.
                let name: &'static str = rust_junosmcp_auth::KNOWN_TOOLS
                    .iter()
                    .find(|known| **known == tool.name.as_ref())
                    .copied()
                    .unwrap_or_else(|| panic!("listed tool {} not in KNOWN_TOOLS", tool.name));
                assert!(
                    handler.check_tool_scope(Some(&ctx), name).is_ok(),
                    "listed tool {name} must be callable under scope {:?}",
                    ctx.tools
                );
            }

            // And the converse: nothing callable was wrongly hidden.
            let listed_names = names_of(listed);
            for known in rust_junosmcp_auth::KNOWN_TOOLS {
                // `*known` — iterating a &[&str] yields &&str, and
                // check_tool_scope takes &'static str.
                if compiled.contains(*known)
                    && handler.check_tool_scope(Some(&ctx), *known).is_ok()
                {
                    assert!(
                        listed_names.contains(*known),
                        "callable tool {known} must be advertised under scope {:?}",
                        ctx.tools
                    );
                }
            }
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-junosmcp --all-features scope_tests 2>&1 | tail -20`

Expected: compile error, `cannot find function 'filter_tools_for_scope' in this scope`. A compile failure is the correct "red" here — the function does not exist yet.

- [ ] **Step 3: Write the implementation**

Insert immediately after `caller_ctx` (which ends at line 51) in `rust-junosmcp/src/server.rs`:

```rust
/// Filter an advertised tool list down to what `ctx` is actually allowed to
/// call.
///
/// Uses the same `allows_tool(name, WRITE_TOOLS)` predicate as
/// [`JmcpHandler::check_tool_scope`], so `tools/list` cannot drift from the
/// authorization `tools/call` enforces. `None` — the stdio and
/// `--allow-no-auth` paths, which carry no caller context — returns the list
/// unchanged, matching every other scope check.
pub(super) fn filter_tools_for_scope(
    tools: Vec<rmcp::model::Tool>,
    ctx: Option<&rust_junosmcp_auth::CallerCtx>,
) -> Vec<rmcp::model::Tool> {
    let Some(ctx) = ctx else {
        return tools;
    };
    tools
        .into_iter()
        .filter(|tool| {
            ctx.tools
                .allows_tool(tool.name.as_ref(), rust_junosmcp_auth::WRITE_TOOLS)
        })
        .collect()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-junosmcp --all-features scope_tests 2>&1 | tail -20`

Expected: PASS, all `scope_tests` green including the pre-existing ones.

- [ ] **Step 5: Verify the Junos-only build too**

Run: `cargo test -p rust-junosmcp --no-default-features scope_tests 2>&1 | tail -20`

Expected: PASS. This proves the tests do not assume the two SRX write tools are compiled in — that is what the `.filter(|n| all_names.contains(n))` and `in_this_build` guards are for.

- [ ] **Step 6: Lint and format**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -20`

Expected: no output from fmt, clippy clean.

- [ ] **Step 7: Commit**

```bash
git add rust-junosmcp/src/server.rs
git commit -m "feat(#199): add pure tool-scope filter for the advertised tool list

filter_tools_for_scope applies the same allows_tool(name, WRITE_TOOLS)
predicate check_tool_scope uses, so the advertised list cannot drift from
the enforced authorization. Not yet wired into list_tools.

Includes the invariant test the issue is about: for a given scope, the set
of advertised tools and the set check_tool_scope accepts are equal."
```

---

### Task 2: Wire `list_tools` and prove it end to end

**Files:**
- Modify: `rust-junosmcp/src/server.rs` — imports at lines 9-12, and the `impl ServerHandler for JmcpHandler` block at line 1071
- Test: `rust-junosmcp/tests/http_smoke.rs` (append)

**Interfaces:**
- Consumes: `filter_tools_for_scope` from Task 1; `caller_ctx(&Extensions) -> Option<&CallerCtx>` (existing, `server.rs:47`).
- Produces: a `list_tools` override on `JmcpHandler`. Nothing later depends on it directly.

Background the implementer needs: `rmcp-macros` generates `list_tools` **only if the impl block does not already define one** (`rmcp-macros-2.0.0/src/tool_handler.rs:64`). Adding the method by hand is the supported way to override it — do not remove or alter the `#[tool_handler(router = self.tool_router)]` attribute, which still generates `call_tool` and `get_tool`.

`ListToolsResult` derives `Default` and provides `with_all_items(items)`; use that rather than a struct literal.

- [ ] **Step 1: Write the failing end-to-end test**

Append to `rust-junosmcp/tests/http_smoke.rs`. The file already has `mod common; use common::*;`, `use serde_json::json;`, and `use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};` at the top.

```rust
/// #199: a wildcard tool scope excludes write tools, so tools/list must not
/// advertise them. What you can see is what you can call.
#[test]
fn tools_list_hides_write_tools_from_a_wildcard_token() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "wildcard-ops",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    assert_eq!(response.code, 200, "body: {}", response.body);

    let listed: Vec<String> = response
        .body
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("missing tools array: {}", response.body))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();

    assert!(!listed.is_empty(), "wildcard token must still see read tools");
    for write_tool in rust_junosmcp_auth::WRITE_TOOLS {
        assert!(
            !listed.contains(&(*write_tool).to_string()),
            "tools/list must not advertise write tool {write_tool} to a wildcard token: {listed:?}"
        );
    }
    assert!(
        listed.contains(&"gather_device_facts".to_string()),
        "read-only tools must still be advertised: {listed:?}"
    );
}

/// The other half of #199: an explicit allowlist naming a write tool must
/// still advertise it, so narrowing a scope does not silently remove
/// capability the operator deliberately granted.
#[test]
fn tools_list_advertises_write_tools_named_in_an_explicit_allowlist() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "explicit-ops",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec![
            "gather_device_facts".into(),
            "load_and_commit_config".into(),
        ]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    assert_eq!(response.code, 200, "body: {}", response.body);

    let mut listed: Vec<String> = response
        .body
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("missing tools array: {}", response.body))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();
    listed.sort();

    assert_eq!(
        listed,
        vec![
            "gather_device_facts".to_string(),
            "load_and_commit_config".to_string()
        ]
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rust-junosmcp --all-features --test http_smoke tools_list_ 2>&1 | tail -25`

Expected: FAIL. `tools_list_hides_write_tools_from_a_wildcard_token` fails on the first write tool it finds in the list (currently all 27 are advertised); `tools_list_advertises_write_tools_named_in_an_explicit_allowlist` fails on the length assertion (gets 27, expects 2).

If instead you get a build error about `tempfile`, confirm it is in `[dev-dependencies]` of `rust-junosmcp/Cargo.toml` — `http_smoke.rs` already uses `tempfile::tempdir()`, so it should be.

- [ ] **Step 3: Add the imports**

In `rust-junosmcp/src/server.rs`, extend the existing `rmcp::model` import (line 9-11) and the `rmcp` import (line 12):

```rust
use rmcp::model::{
    CallToolResult, ContentBlock, Extensions, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
```

- [ ] **Step 4: Add the `list_tools` override**

In the `impl ServerHandler for JmcpHandler` block (line 1071), add this method alongside the existing `get_info`:

```rust
    /// Advertise only the tools this caller may invoke.
    ///
    /// Defining this by hand suppresses the one `#[tool_handler]` would
    /// generate; the attribute still generates `call_tool` and `get_tool`.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let tools = filter_tools_for_scope(
            self.tool_router.list_all(),
            caller_ctx(&context.extensions),
        );
        Ok(ListToolsResult::with_all_items(tools))
    }
```

- [ ] **Step 5: Run the end-to-end tests to verify they pass**

Run: `cargo test -p rust-junosmcp --all-features --test http_smoke tools_list_ 2>&1 | tail -25`

Expected: PASS, 2 tests.

If you get "method `list_tools` is not a member of trait `ServerHandler`", check the signature against `rmcp-2.0.0/src/handler/server.rs:316` — the parameter and return types must match the trait exactly.

- [ ] **Step 6: Run the whole suite in both feature configurations**

Run: `cargo test --workspace --all-features 2>&1 | grep -E "^test result|FAILED|^error"`

Expected: every line `ok`, zero failures. Baseline before this change is 943 passing; you should now see 950 (5 unit tests from Task 1 + 2 end-to-end tests here).

Run: `cargo test -p rust-junosmcp --no-default-features 2>&1 | grep -E "^test result|FAILED|^error"`

Expected: every line `ok`. The two new end-to-end tests are feature-agnostic — `gather_device_facts` and `load_and_commit_config` are both Junos tools present in either build.

- [ ] **Step 7: Lint and format**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -20`

Expected: clippy clean.

- [ ] **Step 8: Commit**

```bash
git add rust-junosmcp/src/server.rs rust-junosmcp/tests/http_smoke.rs
git commit -m "fix(#199): filter tools/list by the caller's token tool scope

tools/list advertised the full 27-tool surface regardless of scope, so a
wildcard token was shown the ten write tools it would be refused when it
called them. Agents plan against the advertised list, so this cost a turn
per denial and could strand a multi-step plan partway through.

list_tools now filters through filter_tools_for_scope. rmcp-macros skips
generating list_tools when the impl defines one, so the #[tool_handler]
attribute still supplies call_tool and get_tool unchanged.

stdio and --allow-no-auth carry no caller context and still see every tool."
```

---

### Task 3: Documentation

**Files:**
- Modify: `README.md` — "Tool scopes and write tools" section
- Modify: `CHANGELOG.md` — `[Unreleased]` section (line 7)

**Interfaces:** None. Documentation only.

- [ ] **Step 1: Update the README**

In `README.md`, find the "Tool scopes and write tools" section. After the paragraph beginning "Granting write authority is always an explicit, named decision", and before the paragraph beginning "Scope checks apply only to authenticated HTTP callers", insert:

```markdown
`tools/list` advertises only what the caller's token can invoke, so the list an
agent sees matches what it can actually call. A wildcard token is shown the
read-only tools and not the ten write tools; a token scoped to nothing is shown
an empty list.

> **Cached lists go stale.** A client that fetched `tools/list` before you
> re-scoped its token with `token set-scope` keeps the old view until it
> reconnects — the server does not currently emit
> `notifications/tools/list_changed` on SIGHUP reload. Authorization is
> unaffected: a call to a tool the token no longer has is refused regardless of
> what the client believes it can see.
```

- [ ] **Step 2: Update the CHANGELOG**

In `CHANGELOG.md`, replace the bare `## [Unreleased]` line (line 7) with:

```markdown
## [Unreleased]

### Changed

- **#199 — `tools/list` is filtered to the caller's tool scope.** The tool list
  advertised to an authenticated caller now contains only the tools that
  caller's token can invoke, using the same check that gates `tools/call`. A
  wildcard token sees the read-only tools and not the ten write tools; a token
  scoped to nothing sees an empty list. Previously the full surface was
  advertised to everyone, so an agent would plan around a tool, call it, and
  burn a turn on the denial. Authorization behaviour is unchanged — this makes
  the advertisement agree with the enforcement that already existed. Local
  stdio and `--allow-no-auth` loopback carry no caller context and still see
  every tool.

  A client that cached `tools/list` before a `token set-scope` keeps the stale
  view until it reconnects; the server does not emit
  `notifications/tools/list_changed`.
```

- [ ] **Step 3: Verify the docs build and links resolve**

Run: `grep -n "Tool scopes and write tools" README.md && grep -n "#199" CHANGELOG.md`

Expected: both match. Confirm by eye that the new README text sits inside the "Tool scopes and write tools" section and not in a neighbouring one.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs(#199): document tools/list scope filtering

README gains the filtering behaviour and the stale-cached-list caveat in
'Tool scopes and write tools'; CHANGELOG gets an Unreleased entry."
```

---

## Final Verification

- [ ] `cargo test --workspace --all-features` — expect 950 passing, 0 failed
- [ ] `cargo test -p rust-junosmcp --no-default-features` — expect 0 failed
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean
- [ ] `cargo fmt --all --check` — clean
- [ ] `cargo deny check` — advisories, bans, licenses, sources all ok

## Release Framing

Left open deliberately, to settle when the PR is raised. The lean is **0.10.1**: the advertised list moving into agreement with authorization that already existed reads as a fix rather than a new restriction, and no caller gains or loses any actual capability. The counter-argument is that a client hard-coded to expect 27 tools will see fewer, which is observable. Do not bump the version as part of these three tasks — raise it as a question on the PR.
