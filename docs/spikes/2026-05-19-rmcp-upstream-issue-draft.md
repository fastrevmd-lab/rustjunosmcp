# Upstream rmcp issue — filed

**Target repo:** `modelcontextprotocol/rust-sdk`
**Filed as:** `fastrevmd-lab` (no project affiliation in body)
**Filed issue:** [modelcontextprotocol/rust-sdk#857](https://github.com/modelcontextprotocol/rust-sdk/issues/857) (2026-05-19 20:29 UTC)
**Status:** filed, awaiting triage

The block below is the verbatim issue content. Everything before the
`==== ISSUE BODY ====` separator is internal-only and must not be
copied into the GitHub issue.

==== ISSUE BODY ====

**Title (for the GitHub title field):**

`streamable-http-server: client TCP disconnect does not cancel in-flight tool futures (RequestContext::ct never fires)`

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

Exact pins are in the `Cargo.toml` of the reproduction below
(`rmcp = "=0.8.5"`, axum 0.8, tokio 1, hyper 1).

A code walk of `main` (`rmcp-v1.7.0`, commit `cd2f5f1`) shows the same
`local_ct_pool` shape and the same two-fire-site pattern. The
`StreamableHttpServerConfig::cancellation_token` field added since
0.8.5 is a server-wide graceful-shutdown signal, not a per-request HTTP
body hook. Runtime verification against `main` not done; code walk
evidence in "Root cause" below.

### Reproduction

`Cargo.toml`:

```toml
[dependencies]
rmcp = { version = "=0.8.5", features = ["server", "transport-streamable-http-server", "macros"] }
tokio = { version = "1", features = ["full"] }
tokio-util = "0.7"
axum = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["fmt", "env-filter"] }
schemars = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

`src/main.rs`:

```rust
use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::{
        streamable_http_server::{
            session::local::LocalSessionManager, tower::StreamableHttpService,
        },
        StreamableHttpServerConfig,
    },
    ServerHandler,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Repro {
    tool_router: ToolRouter<Self>,
}

impl Repro {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl Repro {
    #[tool(description = "Sleep 60s, log every 100ms, observe cancel token")]
    async fn long_sleep(&self, ct: CancellationToken) -> String {
        let started = std::time::Instant::now();
        for i in 0..600 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            tracing::info!(
                i,
                elapsed_ms = started.elapsed().as_millis() as u64,
                cancelled = ct.is_cancelled(),
                "poll"
            );
            if ct.is_cancelled() {
                return "cancelled".into();
            }
        }
        "ran_to_completion".into()
    }
}

#[tool_handler(router = Self::tool_router())]
impl ServerHandler for Repro {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("rmcp disconnect repro".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let svc = StreamableHttpService::new(
        || Ok(Repro::new()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig {
            // Stateless mode keeps the repro one-curl-friendly: no
            // `mcp-session-id` handshake required.
            stateful_mode: false,
            sse_keep_alive: Some(std::time::Duration::from_secs(15)),
        },
    );
    let app = axum::Router::new().nest_service("/mcp", svc);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8765").await?;
    tracing::info!(addr = "127.0.0.1:8765", "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
```

Invocation:

```
# Terminal 1
$ RUST_LOG=info cargo run

# Terminal 2 — invoke the tool, then disconnect after 2s
$ timeout 2 curl -sN \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
         "params":{"name":"long_sleep","arguments":{}}}' \
    http://127.0.0.1:8765/mcp
# curl exits with 124 (timeout); leave the server running and watch the log
```

**Observed (live run 2026-05-19, rmcp 0.8.5, stateless mode):**

```text
2026-05-19T17:22:49.115Z  INFO  rmcp-disconnect-repro listening addr="127.0.0.1:8765"
2026-05-19T17:22:57.657Z  INFO  poll i=0   elapsed_ms=101    cancelled=false   ← tool started
2026-05-19T17:22:58.669Z  INFO  poll i=10  elapsed_ms=1112   cancelled=false
                                                                                ← curl exited at ~17:22:59.553 (timeout 2s, exit 124)
2026-05-19T17:23:02.722Z  INFO  poll i=50  elapsed_ms=5166   cancelled=false   ← +3 s post-disconnect
2026-05-19T17:23:07.787Z  INFO  poll i=100 elapsed_ms=10231  cancelled=false   ← +8 s post-disconnect
2026-05-19T17:23:10.829Z  INFO  poll i=130 elapsed_ms=13273  cancelled=false   ← +11 s post-disconnect
2026-05-19T17:23:26.037Z  INFO  poll i=280 elapsed_ms=28480  cancelled=false   ← +27 s post-disconnect
```

281 polls executed after curl's TCP close, `cancelled=false` on every
one. `sse_keep_alive` is set to its 15 s default — even one full
keep-alive interval is not enough for the transport to learn about the
disconnect and fire `RequestContext::ct`.

**Expected:** `RequestContext::ct` fires when axum/hyper observes the
client gone (at the latest on the next SSE keep-alive write), and the
handler exits within one tick.

### Why this matters

Tools that mutate external state (file uploads, device upgrades, long
shell-outs — anything destructive) cannot rely on the request token to
bound their lifetime. A client that Ctrl-Cs or hits its own read
timeout silently triggers the full server-side effect with no way to
abort.

The stdio transport doesn't surface this gap as visibly because
operators typically drop `RunningService` on stdin EOF, which fires the
`DropGuard` cascade at `service.rs:852`. The streamable-HTTP transport
keeps the service alive across many HTTP connections, so a single
client TCP-disconnect cannot achieve the same effect.

### Root cause (verified from code walk against 0.8.5)

The per-request `CancellationToken` exposed to handlers as
`RequestContext::ct` is created inside `crates/rmcp/src/service.rs` in
the shared serve loop:

```text
service.rs:746   let request_ct = serve_loop_ct.child_token();
service.rs:747   let context_ct = request_ct.child_token();
service.rs:748   local_ct_pool.insert(id.clone(), request_ct);
service.rs:763   tokio::spawn(async move {
service.rs:765       let result = service.handle_request(request, context).await;
service.rs:777       let _send_result = sink.send(response).await;  // unbounded channel
service.rs:778   });
```

`request_ct` is fired in exactly two places (`service.rs` in 0.8.5,
same in `main`):

```text
service.rs:687-688   on outbound response (natural completion)
                       if let Some(ct) = local_ct_pool.remove(id) { ct.cancel(); }

service.rs:789-791   on inbound notifications/cancelled
                       if let Some(ct) = local_ct_pool.remove(&cancelled.params.request_id) { ct.cancel(); }
```

For the **streamable-HTTP transport** specifically
(`streamable_http_server/tower.rs:269-310`), each tool-call POST builds
a session-scoped `Stream` and returns it as the SSE response body. The
spawned tool future from `service.rs:763` reaches its `sink.send(response)`
via an unbounded mpsc — which never errors. When the client TCP-closes
the SSE response, axum/hyper drop the response body, but:

- The mpsc channel keeps accepting the eventual `response` write.
- The serve loop has no signal that the response can no longer be
  delivered to the client.
- Neither of the two `local_ct_pool.remove(id)` branches above is
  reached on TCP close.

The result is a zombie tool future that runs to natural completion.

### Possible directions

Two shapes look plausible from the code walk above:

1. **Drive a synthetic `notifications/cancelled` into the serve loop
   when the SSE response body is dropped.** The existing serve-loop
   path at `service.rs:781-817` already handles inbound cancellation
   notifications and fires `local_ct_pool.remove(id).cancel()`. If the
   SSE response body in `streamable_http_server` is wrapped in a guard
   whose `Drop` impl pushes a synthetic `CancelledNotification` for the
   in-flight `request_id` back through the session's input side, the
   existing cancellation path activates with no new public surface.
   SSE keep-alive (`sse_keep_alive`, default 15 s) is the disconnect-
   detection probe, so disconnect latency is bounded by that interval.
   Handlers that already `select!` against `RequestContext::ct` need no
   changes. For stateless / `json_response` mode (the latter only in
   `main`), a periodic zero-byte chunk or an internal `oneshot::Sender`
   watcher on the response body could serve as the probe.

2. **Bind `request_ct` to the SSE response body's `Drop` directly.**
   Same idea but reaching into the serve-loop internals: expose a
   `cancel_request(request_id)` hook on `SessionManager`, called from
   the response body's Drop. More explicit, but adds a new public method
   to every `SessionManager` implementor.

I'd be happy to PR option 1 if maintainers prefer that direction.

### Workarounds available today

Cooperative cancellation via `RequestContext::ct` works today for
explicit `notifications/cancelled` and per-request server timeouts;
TCP disconnect is the remaining gap. A Drop guard around the tool
future can detect zombie completion after the fact for audit, but
cannot abort the work in-flight.

### Environment

- OS: Linux (Debian-based LXC, kernel 6.x)
- rust 1.x stable
- axum 0.8.x, hyper 1.x, tokio 1.x

### Related

No direct duplicate found in the issue tracker. Adjacent work:

- **#493 / PR #494** (merged 2025-12-02) "Gracefully shutdown is hang
  while a SSE connection is established" — added the server-wide
  `StreamableHttpServerConfig::cancellation_token` for graceful
  shutdown by cutting off the SSE body. Same code area as this issue
  but the opposite direction: server-initiated shutdown, not
  client-initiated TCP disconnect. PR #494's body cutoff does **not**
  propagate into the per-request `local_ct_pool`, so it does not fire
  `RequestContext::ct` either.
- **#528 / SEP-1686 Tasks** (completed 2025-12-22) — explicit
  long-running-task capability with disconnection/reconnection semantics.
  Architecturally adjacent: a tool migrated to the Tasks API would have
  a different lifecycle; this issue is about the existing tool-call API.
- **#529 / SEP-1699** (completed 2026-01-09) — server-side disconnect
  mid-stream. Different direction.

Other partially-overlapping but distinct issues: #266 (connection-handle
leak), #347 / #572 / #220 (client-side or stdio shutdown), #754 (client
hang in stateless+json_response).

==== END ISSUE BODY ====

## Filing notes (internal — not part of the issue body)

Outstanding before filing:

1. (Optional but cheap) re-run the same repro against rmcp `main` with
   a git dep to confirm the same behavior. Recommended but not strictly
   required given the code walk evidence.
2. Final read-through pass for tone.

Repro artifacts (paths are local to this workspace):

- Cargo manifest + source: `/tmp/rmcp-disconnect-repro/`
- Captured live-run log: `docs/spikes/2026-05-19-rmcp-disconnect-repro-server.log`
- Companion design doc: `docs/spikes/2026-05-19-rmcp-streamable-http-disconnect-half-b.md`
