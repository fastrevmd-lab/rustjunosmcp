# rmcp 0.8 streamable-http spike

**Date:** 2026-05-05
**rmcp version:** 0.8.5
**Outcome:** success (path A, with one signature tweak vs the design doc)

## Findings

- **Feature flag:** `transport-streamable-http-server`
  (NOT `transport-streamable-http-axum` as the design doc assumed; that name does not exist in 0.8.5.
  The full set of streamable-http feature flags in `rmcp-0.8.5/Cargo.toml`:
  `transport-streamable-http-server`, `transport-streamable-http-server-session`,
  `transport-streamable-http-client`, `transport-streamable-http-client-reqwest`.)

- **Mount API:** `rmcp::transport::streamable_http_server::StreamableHttpService` is a
  `tower_service::Service<http::Request<B>>` and mounts directly under axum 0.8 via
  `Router::nest_service("/mcp", svc)`. Construction:

  ```rust
  let svc = StreamableHttpService::new(
      || Ok(Spike::new()),                       // Fn() -> Result<S, io::Error>
      Arc::new(LocalSessionManager::default()),  // session manager
      StreamableHttpServerConfig::default(),     // sse_keep_alive=15s, stateful_mode=true
  );
  let app = Router::new()
      .nest_service("/mcp", svc)
      .layer(middleware::from_fn(auth_layer));
  ```

  The service handles POST (JSON-RPC), GET (SSE resume), DELETE (session close); enforces
  `Accept: application/json, text/event-stream` and `Content-Type: application/json`; manages
  sessions via the `mcp-session-id` header.

- **Extension access from `#[tool]`:** **YES**, with one indirection.
  rmcp does NOT auto-propagate arbitrary outer-axum request extensions into the rmcp request
  context. What it DOES do (see `streamable_http_server/tower.rs` lines 291-301, 333-334, 399):
  it splits the incoming `Request` into `(Parts, Body)` and inserts the **whole `http::request::Parts`**
  into the per-rmcp-request extensions. Because `Parts` itself carries `extensions: http::Extensions`,
  any extension the outer middleware put on the axum request rides along inside `parts.extensions`.

  The `#[tool]` extractor is `rmcp::handler::server::tool::Extension<T>` where `T: Send+Sync+'static+Clone`.
  Working signature observed in the spike:

  ```rust
  use rmcp::handler::server::tool::Extension;
  use http::request::Parts;

  #[tool(description = "...")]
  async fn echo(
      &self,
      Parameters(args): Parameters<EchoArgs>,
      Extension(parts): Extension<Parts>,
  ) -> Result<CallToolResult, McpError> {
      let ctx = parts.extensions.get::<CallerCtx>()
          .ok_or_else(|| McpError::internal_error("missing CallerCtx", None))?;
      // ...
  }
  ```

  End-to-end probe result: outer middleware reads header `x-spike-user: alice`, inserts
  `CallerCtx { user }` into axum request extensions; the `#[tool]` body retrieves it via
  `Extension<Parts>` -> `parts.extensions.get::<CallerCtx>()` and the response body is
  `user=alice msg=hello`. Confirmed.

  Ergonomics note: the design-doc shorthand of `Extension<CallerCtx>` directly does NOT work
  out of the box — it returned `"missing extension rmcp_spike::CallerCtx"`. Either (a) accept
  the one-line `parts.extensions.get::<CallerCtx>()` indirection in each tool body (recommended,
  trivial), or (b) write a small helper trait/extractor wrapper that goes `&RequestContext -> CallerCtx`.

## Other notes worth recording

- The rmcp doc-comment on `StreamableHttpService` explicitly endorses this pattern and shows
  the exact `Extension<Parts>` signature (rmcp-0.8.5/src/transport/streamable_http_server/tower.rs:47-59).
- `StreamableHttpServerConfig::default()` is `stateful_mode = true`, which requires session
  management. For our use case (Claude Desktop / mcpcli) stateful is correct.
- The sample crate features needed for the implementation crate are:
  `["server", "macros", "schemars", "transport-streamable-http-server"]` — `tower` and `axum`
  do NOT need to be in rmcp's feature list because rmcp pulls them transitively under
  `transport-streamable-http-server`.
- T11 will need direct deps on `axum = "0.8"` and `tower = "0.5"` for the middleware and router.
- Body type used by rmcp service: it returns `Response<BoxBody<Bytes, Infallible>>`, which axum
  0.8 handles directly via `nest_service`.

## Decision

Implementation Tasks T11 (HTTP transport + AuthLayer) and T12 (smoke tests) use **path A** from
the design doc, with the corrected signature `Extension<http::request::Parts>` plus a
`parts.extensions.get::<CallerCtx>()` lookup inside each tool. The design-doc fallback `DashMap<RequestId, CallerCtx>`
(path B) is NOT required.

Update needed in the design doc / T11 spec:
- Replace assumed feature `transport-streamable-http-axum` with `transport-streamable-http-server`.
- Replace `Extension<CallerCtx>` with `Extension<http::request::Parts>` + small helper (`fn caller_ctx(parts: &Parts) -> Result<&CallerCtx, ScopeError>`).
