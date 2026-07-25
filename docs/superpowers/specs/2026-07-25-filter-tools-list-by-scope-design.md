# Filter `tools/list` by the caller's token tool scope

**Issue:** [#199](https://github.com/fastrevmd-lab/rustjunosmcp/issues/199)
**Date:** 2026-07-25
**Status:** approved, ready for implementation plan

## Problem

`tools/list` returns the full 27-tool surface regardless of the caller's tool
scope. Since v0.10.0 a wildcard tool scope (`"tools": ["*"]`) no longer confers
the ten write tools, so a wildcard token is advertised tools it will be refused
when it calls them:

```
tools/list count: 27
  write tools listed: ['add_device', 'load_and_commit_config', ...]

WRITE add_device -> token 'ops' is not authorized for tool 'add_device'
```

The authorization is correct. The advertisement disagrees with it.

The consumers are LLM agents, which choose actions from the advertised list.
Advertising a guaranteed-to-fail tool means the model plans around it, calls it,
and burns a turn on the denial — and in a multi-step plan a mid-sequence denial
can strand the agent partway through an operation. There is a secondary
disclosure argument: the list currently tells any authenticated caller the
complete tool surface, including capabilities its credential was deliberately
not granted.

## Approach

Override `list_tools` in the existing `impl ServerHandler for JmcpHandler`
block and filter the router's output through the same predicate that already
gates `tools/call`.

`rmcp-macros` generates `list_tools` only when the impl does not already define
one (`rmcp-macros-2.0.0/src/tool_handler.rs:64`,
`if !has_method("list_tools", &item_impl)`). Defining it by hand suppresses the
generated version — this is a supported extension point, not a workaround.

`RequestContext.extensions` is the same `Extensions` value the `#[tool]` methods
already receive, so the existing `caller_ctx()` helper (`server.rs:47`) works
unchanged at list time. No new plumbing.

### Rejected alternatives

**Filter in the tower middleware.** Intercept and rewrite the JSON-RPC response
body. Rejected: requires parsing and re-emitting responses, breaks under SSE
framing, and puts authorization logic in the transport layer where none of the
rest of it lives.

**Per-token cached `ToolRouter`.** Build a filtered router per token at auth
time. Rejected as premature — `list_all()` over 27 tools is trivial, and it adds
cache invalidation on SIGHUP for no measurable gain.

## Design

### Change surface

One method added to `rust-junosmcp/src/server.rs` (impl block at line 1071):

```rust
async fn list_tools(
    &self,
    _request: Option<PaginatedRequestParams>,
    context: RequestContext<RoleServer>,
) -> Result<ListToolsResult, rmcp::ErrorData> {
    let all = self.tool_router.list_all();
    let tools = match caller_ctx(&context.extensions) {
        Some(ctx) => all
            .into_iter()
            .filter(|t| ctx.tools.allows_tool(t.name.as_ref(), WRITE_TOOLS))
            .collect(),
        None => all,
    };
    Ok(ListToolsResult { tools, ..Default::default() })
}
```

`ToolRouter::list_all()` returns `Vec<Tool>`; `Tool.name` is a
`Cow<'static, str>`, hence `as_ref()`. `ListToolsResult` implements `Default`
(`handler/server.rs:317`), so spreading it sets `meta` and `next_cursor` to the
same `None` the generated version uses while surviving any future field
additions.

### Why this cannot drift

`tools/list` and `tools/call` call the identical predicate —
`ScopeSet::allows_tool(name, WRITE_TOOLS)` — on the identical `ScopeSet`. There
is one rule, evaluated in two places. If `WRITE_TOOLS` changes, both move
together. This is the same pattern `filter_device_names` already establishes for
the device list.

### Behaviour by caller

| Caller | Result |
|---|---|
| stdio | full 27 tools — no `CallerCtx`, matches every existing scope check |
| loopback `--allow-no-auth` | full list — same reason |
| token, explicit allowlist | exactly the listed tools |
| token, `tools: ["*"]` | 17 read-only tools; the 10 write tools hidden |
| token, empty allowlist | empty array |

An empty tool scope yielding an empty `tools` array is correct and MCP-legal;
clients initialize fine on an empty list.

### Data flow

Unchanged from `tools/call`. `StreamableHttpService` inserts
`http::request::Parts` into `RequestContext.extensions`; the auth middleware has
already placed `CallerCtx` into `parts.extensions`; `caller_ctx()` walks the two.

### Error handling

None to add. Filtering cannot fail. An absent caller context is the
unauthenticated path, which returns the full list rather than erroring.

### Not affected

- The drift tests at `server.rs:1145-1182` call `list_all()` on the router
  directly, not through `list_tools`.
- `get_tool()` is used by rmcp only for taskSupport validation, not
  authorization, so it does not need filtering.
- `tools/call` behaviour is unchanged. An out-of-scope call still returns
  `token '<name>' is not authorized for tool '<tool>'`.

## Testing

Three layers, matching patterns already in the repo:

1. **Unit tests** in the `scope_tests` module (`server.rs:1091`), which already
   constructs `CallerCtx` values directly:
   - wildcard scope hides exactly the 10 write tools and keeps the other 17
   - an explicit allowlist naming a write tool still lists it
   - an empty scope lists nothing
   - `None` context lists all 27
2. **End-to-end HTTP test** asserting the JSON-RPC `tools/list` response over a
   real authenticated request, so the extensions plumbing is exercised rather
   than assumed. That walk is the part most likely to break silently.
3. **Consistency test**: for a given scope, every tool `list_tools` returns is
   one `check_tool_scope` accepts. This is the invariant the issue is about.

## Out of scope

No `notifications/tools/list_changed`. A client that cached the list before a
`token set-scope` + SIGHUP keeps the stale view until it reconnects. This is
documented in the README rather than left implicit. Revisit if it causes real
operational trouble.

## Documentation

- README "Tool scopes and write tools": note that the advertised list is
  filtered to what the token can call, plus the stale-cache caveat.
- CHANGELOG: a `Changed` entry.

## Release framing

Open, to settle at PR time. This changes what existing clients see from
`tools/list`, so it is arguably breaking for anything assuming the full surface.
The lean is 0.10.1 — the advertised list moving into agreement with
authorization that already existed reads as a fix, not a new restriction.
