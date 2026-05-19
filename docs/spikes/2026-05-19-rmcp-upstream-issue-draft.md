# Upstream rmcp issue draft

**Target repo:** `modelcontextprotocol/rust-sdk`
**Target version:** rmcp 0.8.5 (verify against `main` before filing)
**Status:** draft — pre-filing, hold until minimal-repro confirmed

---

## Title

`streamable-http-server: client TCP disconnect does not cancel in-flight tool futures (RequestContext::ct never fires)`

## Body

### Summary

When a client connected over `transport-streamable-http-server` closes
its TCP connection while a `#[tool]` handler is awaiting, the server-side
future is **not cancelled**. It detaches from the response lifecycle and
runs to natural completion. `RequestContext::ct` (the per-request
`CancellationToken` exposed to handlers) never fires.

Explicit `notifications/cancelled` from the client *does* fire the
token — that path works correctly. Only the raw TCP-disconnect case is
affected.

This effectively makes the streamable-HTTP transport unable to support
cooperative cancellation for any long-running tool whose client may go
away (Ctrl-C, network drop, client-side read timeout).

### Versions

- `rmcp = "0.8.5"` with default features + `transport-streamable-http-server`
- axum 0.8.x
- tokio 1.x

(I have not yet confirmed against `main`. Will do before filing — included
here for completeness once verified.)

### Reproduction

Minimal example using the `counter` server pattern from
`examples/servers/src/counter_streamhttp.rs`, with one long-sleep tool
added:

```rust
use rmcp::{ServerHandler, model::*, tool, tool_router};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Repro { tool_router: rmcp::handler::server::router::tool::ToolRouter<Self> }

#[tool_router]
impl Repro {
    pub fn new() -> Self { Self { tool_router: Self::tool_router() } }

    /// Sleeps for 60s, polling the request token every 100ms.
    /// Emits a log line on every poll so the journal shows whether
    /// the future is still alive after the client disconnects.
    #[tool(description = "Sleep 60s, log every 100ms, observe cancel token")]
    pub async fn long_sleep(&self, ct: CancellationToken) -> Result<CallToolResult, ErrorData> {
        for i in 0..600 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            tracing::info!(i, cancelled = ct.is_cancelled(), "poll");
            if ct.is_cancelled() {
                return Ok(CallToolResult::success(vec![Content::text("cancelled")]));
            }
        }
        Ok(CallToolResult::success(vec![Content::text("ran to completion")]))
    }
}

impl ServerHandler for Repro { /* default */ }
```

Mount under axum as per the existing `counter_streamhttp` example, then:

```
# Terminal 1 — server with `RUST_LOG=info`
$ cargo run --example counter_streamhttp

# Terminal 2 — invoke the tool, then disconnect after 2s
$ timeout 2 curl -sN \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
         "params":{"name":"long_sleep","arguments":{}}}' \
    http://127.0.0.1:8000/mcp
```

**Observed:** Terminal 1 emits `poll i=N cancelled=false` for the full
60 seconds. The future runs to completion ~58 seconds after curl
disconnected.

**Expected:** `RequestContext::ct` fires when axum/hyper observes the
client gone (at the latest on the next SSE keep-alive write), and the
handler exits within one tick.

### Why this matters

Tools that mutate external state (file uploads, device upgrades, long
shell-outs, anything destructive) cannot rely on the request token to
bound their lifetime. A client that Ctrl-Cs or hits its own read timeout
silently triggers the full server-side effect with no way to abort.

For comparison, the stdio transport does behave correctly here: when the
peer closes stdin, in-flight futures are dropped.

### Conjecture on root cause

In `crates/rmcp/src/transport/streamable_http_server/`, the streamable-
HTTP service splits the incoming `http::Request` into `(Parts, Body)`,
inserts `Parts` into rmcp's per-request extensions, and spawns the tool
future via the session manager. The SSE response body holds the writer
half of the channel that the spawned future sends results on, but the
spawn handle itself is not joined against the response body's drop.
When axum drops the response body on client disconnect, the spawn
handle keeps running; nothing fires `RequestContext::ct`.

(I have not yet read the code end-to-end; happy to do so if useful and
attach a more specific pointer.)

### Possible directions

I am not requesting a specific implementation — just flagging two
shapes that look plausible from the outside:

1. **Bind `RequestContext::ct` to the SSE response body's `Drop`.**
   Wrap the response body in a guard whose `Drop` impl calls
   `token.cancel()`. SSE keep-alive (`sse_keep_alive`, default 15s)
   becomes the disconnect-detection probe — disconnect latency is
   bounded by that interval. Handlers that already `select!` against
   `RequestContext::ct` need no changes. For stateless / single-JSON
   mode without SSE, a periodic zero-byte chunk could serve as the probe.

2. **Explicit `SessionManager::cancel_in_flight(session_id)` hook**,
   called from the existing session-close path. More explicit but
   doesn't solve TCP-disconnect-without-DELETE on its own; needs (1)
   or similar to detect.

Happy to PR (1) if maintainers prefer that direction.

### Workarounds shipped downstream

In our project ([RustJunosMCP / fastrevmd-lab](https://github.com/fastrevmd-lab/RustJunosMCP),
PR #54 / issue #44) we plumb `RequestContext::ct` through every
long-running tool and `select!` at every await point, so the two paths
rmcp 0.8.5 *does* honor today work end to end:

- explicit `notifications/cancelled`
- per-request server timeout

The TCP-disconnect case is the remaining gap; we surface it via an
audit `outcome="unsettled"` line emitted from a Drop guard, but the
guard fires too late to actually abort the work.

### Environment

- OS: Linux (Debian-based LXC, kernel 6.x)
- rust 1.x stable
- axum 0.8.x, hyper 1.x, tokio 1.x

### Related

- Issue/PR in our repo with full trace + design notes:
  [fastrevmd-lab/RustJunosMCP#44](https://github.com/fastrevmd-lab/RustJunosMCP/issues/44)
  (the design doc at `docs/spikes/2026-05-19-rmcp-streamable-http-disconnect-half-b.md`
  has the live-trace evidence).

---

## Filing checklist

Hold filing until all of the following are checked:

- [ ] Minimal repro above actually built and run against rmcp 0.8.5;
      paste exact log lines into the issue body
- [ ] Behavior verified against rmcp `main` (may already be fixed)
- [ ] Read `streamable_http_server/tower.rs` + `session/local.rs` end
      to end; attach a more specific code pointer to the "Conjecture
      on root cause" section
- [ ] Cross-check stdio transport behavior to confirm the "stdio works
      correctly" claim
- [ ] Confirm whether `sse_keep_alive` is observable from
      `StreamableHttpServerConfig` in a way that a contributor PR could
      hook into without breaking changes
- [ ] Strip our company-specific framing if filing as a personal issue;
      or keep the RustJunosMCP cross-link if filing on behalf of the
      project
