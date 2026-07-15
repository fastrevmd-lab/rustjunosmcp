//! Load-shedding concurrency middleware for global, per-token, and per-router
//! limits. Permits are attached to the response body (`GuardedBody`) so they
//! release at end-of-stream — rmcp runs the tool lazily while the SSE body is
//! polled, so a permit held only across the response future would release too
//! early.

use crate::config::LimitsConfig;
use crate::overload::overload_response;
use crate::router::{extract_router_targets, RouterLimiter};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::LengthLimitError;
use rust_junosmcp_auth::caller::CallerCtx;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::limit::RequestBodyLimitLayer;

/// Shared concurrency state, cheaply cloneable.
#[derive(Clone)]
pub struct ConcurrencyState {
    global: Arc<Semaphore>,
    max_global: usize,
    /// Map grows unbounded with the number of distinct token names ever seen.
    /// In typical deployments, it is bounded by the token store's stable size
    /// (hot-reloads replace tokens atomically, not additively). If high-churn
    /// dynamic token provisioning becomes a use case, add LRU eviction or
    /// periodic cleanup of semaphores with zero permits in use.
    per_token: Arc<DashMap<String, Arc<Semaphore>>>,
    max_per_token: usize,
    per_router: RouterLimiter,
    max_per_router: usize,
    sessions: Option<Arc<crate::session::SessionTracker>>,
}

impl ConcurrencyState {
    /// Build from config. `sessions` enables the `session_cap` early-shed.
    pub fn new(cfg: &LimitsConfig, sessions: Option<Arc<crate::session::SessionTracker>>) -> Self {
        let global_permits = if cfg.max_inflight_requests > 0 {
            cfg.max_inflight_requests
        } else {
            1
        };
        Self {
            global: Arc::new(Semaphore::new(global_permits)),
            max_global: cfg.max_inflight_requests,
            per_token: Arc::new(DashMap::new()),
            max_per_token: cfg.max_inflight_requests_per_token,
            per_router: RouterLimiter::new(cfg.max_inflight_requests_per_router),
            max_per_router: cfg.max_inflight_requests_per_router,
            sessions,
        }
    }

    fn token_sem(&self, token: &str) -> Arc<Semaphore> {
        self.per_token
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_token.max(1))))
            .clone()
    }
}

/// Axum middleware enforcing global + per-token + per-router concurrency with load-shed.
pub async fn concurrency_middleware(
    State(state): State<ConcurrencyState>,
    mut req: Request,
    next: Next,
) -> Response {
    let mut permits: Vec<OwnedSemaphorePermit> = Vec::new();

    if state.max_global > 0 {
        match state.global.clone().try_acquire_owned() {
            Ok(p) => permits.push(p),
            Err(_) => {
                tracing::warn!(
                    limit = "global_concurrency",
                    max = state.max_global,
                    "request shed"
                );
                return overload_response("global_concurrency");
            }
        }
    }

    if state.max_per_token > 0 {
        if let Some(ctx) = req.extensions().get::<CallerCtx>() {
            let token = ctx.token_name.clone();
            let sem = state.token_sem(&token);
            match sem.try_acquire_owned() {
                Ok(p) => permits.push(p),
                Err(_) => {
                    tracing::warn!(limit = "token_concurrency", token = %token, max = state.max_per_token, "request shed");
                    return overload_response("token_concurrency"); // global permit drops here
                }
            }
        }
    }

    if let Some(tracker) = &state.sessions {
        if is_session_creating(&req) && tracker.at_capacity() {
            tracing::warn!(limit = "session_cap", "request shed");
            return overload_response("session_cap");
        }
    }

    if state.max_per_router > 0 {
        let (rebuilt, routers) = match inspect_router_targets(req).await {
            Ok(result) => result,
            Err(response) => return response,
        };
        req = rebuilt;

        match state.per_router.try_acquire(&routers) {
            Ok(mut router_permits) => permits.append(&mut router_permits),
            Err(router) => {
                tracing::warn!(
                    limit = "router_concurrency",
                    router = %router,
                    max = state.max_per_router,
                    "request shed"
                );
                let mut response = overload_response("router_concurrency");
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                return response;
            }
        }
    }

    let resp = next.run(req).await;
    attach_permits(resp, permits)
}

async fn inspect_router_targets(req: Request) -> Result<(Request, Vec<String>), Response> {
    if req.method() != Method::POST {
        return Ok((req, Vec::new()));
    }

    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let status = if is_length_limit_error(&error) {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            tracing::warn!(error = %error, %status, "request body rejected while extracting router targets");
            return Err(status.into_response());
        }
    };
    let targets = extract_router_targets(&bytes);
    Ok((Request::from_parts(parts, Body::from(bytes)), targets))
}

fn is_length_limit_error(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error.is::<LengthLimitError>() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

/// A session-creating request = POST without an `Mcp-Session-Id` header.
fn is_session_creating(req: &Request) -> bool {
    req.method() == axum::http::Method::POST && !req.headers().contains_key("mcp-session-id")
}

/// Apply the request-body size limit as the outermost concern. `0` disables.
pub fn apply_body_limit(router: axum::Router, cfg: &LimitsConfig) -> axum::Router {
    if cfg.max_request_body_bytes > 0 {
        router.layer(RequestBodyLimitLayer::new(cfg.max_request_body_bytes))
    } else {
        router
    }
}

/// Move the held permits into the response body so they release at end-of-stream.
fn attach_permits(resp: Response, permits: Vec<OwnedSemaphorePermit>) -> Response {
    if permits.is_empty() {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    Response::from_parts(
        parts,
        Body::new(GuardedBody {
            inner: body,
            _permits: permits,
        }),
    )
}

/// Response body wrapper that owns concurrency permits until the body ends.
struct GuardedBody {
    inner: Body,
    _permits: Vec<OwnedSemaphorePermit>,
}

impl HttpBody for GuardedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // axum::body::Body is Unpin, so GuardedBody is Unpin.
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::body::Bytes;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use rust_junosmcp_auth::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;
    use rust_junosmcp_core::DeviceLeaseManager;
    use serde_json::{json, Value};
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;
    use tokio::time::timeout;
    use tower::ServiceExt as _; // oneshot

    const TEST_TIMEOUT: Duration = Duration::from_secs(1);

    fn ctx(name: &str) -> CallerCtx {
        CallerCtx {
            token_name: name.to_string(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
        }
    }

    fn tool_request(arguments: Value) -> Request<Body> {
        Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("mcp-session-id", "test-session")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "test", "arguments": arguments}
                })
                .to_string(),
            ))
            .unwrap()
    }

    fn blocking_post_router(release: Arc<Notify>, entered: Arc<Notify>) -> Router {
        Router::new().route(
            "/mcp",
            post(move || {
                let release = release.clone();
                let entered = entered.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    "ok"
                }
            }),
        )
    }

    fn router_state(max_per_router: usize) -> ConcurrencyState {
        ConcurrencyState::new(
            &LimitsConfig {
                max_inflight_requests: 0,
                max_inflight_requests_per_token: 0,
                max_inflight_requests_per_router: max_per_router,
                max_sessions: 0,
                ..Default::default()
            },
            None,
        )
    }

    // A handler that blocks until `release` is notified, so we can pin permits.
    fn blocking_router(release: Arc<Notify>) -> Router {
        Router::new().route(
            "/mcp",
            get(move || {
                let release = release.clone();
                async move {
                    release.notified().await;
                    "ok"
                }
            }),
        )
    }

    #[tokio::test]
    async fn per_router_sheds_same_router_and_isolates_different_router() {
        let release = Arc::new(Notify::new());
        let entered = Arc::new(Notify::new());
        let app = blocking_post_router(release.clone(), entered.clone()).layer(
            axum::middleware::from_fn_with_state(router_state(1), concurrency_middleware),
        );

        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(tool_request(json!({"router": "r1"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("first request did not enter the handler");

        let same = timeout(
            Duration::from_millis(200),
            app.clone()
                .oneshot(tool_request(json!({"router_name": "r1"}))),
        )
        .await
        .expect("same-router request queued instead of being shed")
        .unwrap();
        assert_eq!(same.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(same.headers().get("retry-after").unwrap(), "1");
        assert_eq!(
            same.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(same.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "overloaded", "limit": "router_concurrency"})
        );

        let other_app = app.clone();
        let other = tokio::spawn(async move {
            other_app
                .oneshot(tool_request(json!({"router": "r2"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("different-router request did not enter the handler");

        release.notify_waiters();
        let first = timeout(TEST_TIMEOUT, first)
            .await
            .expect("first request did not finish")
            .unwrap();
        let other = timeout(TEST_TIMEOUT, other)
            .await
            .expect("different-router request did not finish")
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(other.status(), StatusCode::OK);
        drop(first);
        drop(other);
    }

    #[tokio::test]
    async fn router_permit_lives_until_response_body_is_dropped() {
        let app = Router::new().route("/mcp", post(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(router_state(1), concurrency_middleware),
        );

        let first = app
            .clone()
            .oneshot(tool_request(json!({"router": "r1"})))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let shed = app
            .clone()
            .oneshot(tool_request(json!({"router": "r1"})))
            .await
            .unwrap();
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(first);
        let admitted = app
            .oneshot(tool_request(json!({"router": "r1"})))
            .await
            .unwrap();
        assert_eq!(admitted.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn aborted_request_releases_router_permit() {
        let release = Arc::new(Notify::new());
        let entered = Arc::new(Notify::new());
        let app = blocking_post_router(release.clone(), entered.clone()).layer(
            axum::middleware::from_fn_with_state(router_state(1), concurrency_middleware),
        );

        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(tool_request(json!({"router": "r1"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("first request did not enter the handler");

        first.abort();
        let cancelled = timeout(TEST_TIMEOUT, first)
            .await
            .expect("aborted request task did not finish")
            .expect_err("aborted request unexpectedly completed");
        assert!(cancelled.is_cancelled());

        let second_app = app.clone();
        let second = tokio::spawn(async move {
            second_app
                .oneshot(tool_request(json!({"router": "r1"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("router permit was not released after request cancellation");

        release.notify_waiters();
        let response = timeout(TEST_TIMEOUT, second)
            .await
            .expect("replacement request did not finish")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn malformed_json_is_replayed_unchanged() {
        let app = Router::new()
            .route("/mcp", post(|body: Bytes| async move { body }))
            .layer(axum::middleware::from_fn_with_state(
                router_state(1),
                concurrency_middleware,
            ));
        let original = Bytes::from_static(b"not-json");
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::from(original.clone()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let replayed = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(replayed, original);
    }

    #[tokio::test]
    async fn streamed_body_over_outer_limit_stays_413() {
        let cfg = LimitsConfig {
            max_request_body_bytes: 8,
            max_inflight_requests: 0,
            max_inflight_requests_per_token: 0,
            max_inflight_requests_per_router: 1,
            max_sessions: 0,
            ..Default::default()
        };
        let app = Router::new().route("/mcp", post(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(
                ConcurrencyState::new(&cfg, None),
                concurrency_middleware,
            ),
        );
        let app = apply_body_limit(app, &cfg);
        let stream = futures::stream::iter([Ok::<_, Infallible>(Bytes::from_static(
            b"more-than-eight-bytes",
        ))]);
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::from_stream(stream))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn fallible_body_stream_is_bad_request_not_payload_too_large() {
        let app = Router::new().route("/mcp", post(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(router_state(1), concurrency_middleware),
        );
        let stream = futures::stream::iter([Err::<Bytes, _>(std::io::Error::other(
            "request body stream failed",
        ))]);
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::from_stream(stream))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn router_limit_composes_with_real_destructive_lease() {
        let directory = tempfile::tempdir().unwrap();
        let leases = Arc::new(
            DeviceLeaseManager::with_timing(
                directory.path(),
                Duration::from_secs(2),
                Duration::from_millis(10),
            )
            .unwrap(),
        );
        let external = leases
            .acquire("r1", "external", "external-1")
            .await
            .unwrap();
        let entered = Arc::new(Notify::new());

        let app = Router::new()
            .route(
                "/mcp",
                post({
                    let leases = leases.clone();
                    let entered = entered.clone();
                    move || {
                        let leases = leases.clone();
                        let entered = entered.clone();
                        async move {
                            entered.notify_one();
                            let _lease = leases
                                .acquire("r1", "http-destructive", "http-1")
                                .await
                                .unwrap();
                            "ok"
                        }
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                router_state(1),
                concurrency_middleware,
            ));

        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(tool_request(json!({"router": "r1"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("destructive request did not enter the handler");

        let shed = timeout(
            Duration::from_millis(200),
            app.clone().oneshot(tool_request(json!({"router": "r1"}))),
        )
        .await
        .expect("second request entered the lease wait instead of being shed")
        .unwrap();
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(external);
        let first = timeout(TEST_TIMEOUT, first)
            .await
            .expect("first request deadlocked after lease release")
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let _ = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();

        let admitted = timeout(
            TEST_TIMEOUT,
            app.oneshot(tool_request(json!({"router": "r1"}))),
        )
        .await
        .expect("request was not admitted after lease release")
        .unwrap();
        assert_eq!(admitted.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn global_concurrency_sheds_over_limit() {
        let state = ConcurrencyState::new(
            &LimitsConfig {
                max_inflight_requests: 1,
                max_inflight_requests_per_token: 0,
                ..Default::default()
            },
            None,
        );
        let release = Arc::new(Notify::new());
        let app = blocking_router(release.clone()).layer(axum::middleware::from_fn_with_state(
            state,
            concurrency_middleware,
        ));

        // First request occupies the only permit (held on the blocked handler).
        let app2 = app.clone();
        let inflight = tokio::spawn(async move {
            app2.oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second concurrent request must be shed with 503.
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "1");

        // Release the first; its permit frees.
        release.notify_waiters();
        let first = timeout(TEST_TIMEOUT, inflight)
            .await
            .expect("global-limited request did not finish")
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // A new request now succeeds (permit freed at end-of-body).
        // Drain the first response body first to release its GuardedBody permit.
        let _ = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn per_token_isolated() {
        let state = ConcurrencyState::new(
            &LimitsConfig {
                max_inflight_requests: 0,
                max_inflight_requests_per_token: 1,
                ..Default::default()
            },
            None,
        );
        let release = Arc::new(Notify::new());
        let app = blocking_router(release.clone()).layer(axum::middleware::from_fn_with_state(
            state,
            concurrency_middleware,
        ));

        // token "a" occupies its single per-token permit.
        let app_a = app.clone();
        let inflight = tokio::spawn(async move {
            let mut req = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
            req.extensions_mut().insert(ctx("a"));
            app_a.oneshot(req).await.unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // second "a" request is shed...
        let mut req_a2 = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
        req_a2.extensions_mut().insert(ctx("a"));
        let resp_a2 = app.clone().oneshot(req_a2).await.unwrap();
        assert_eq!(resp_a2.status(), StatusCode::SERVICE_UNAVAILABLE);

        // ...but token "b" still has its own permit (isolated from "a").
        // Start token "b" request before releasing token "a" to prove isolation.
        let app_b = app.clone();
        let req_b_task = tokio::spawn(async move {
            let mut req_b = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
            req_b.extensions_mut().insert(ctx("b"));
            app_b.oneshot(req_b).await.unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Release both and verify "b" succeeded.
        release.notify_waiters();
        let _ = timeout(TEST_TIMEOUT, inflight)
            .await
            .expect("token a request did not finish")
            .unwrap();
        let resp_b = timeout(TEST_TIMEOUT, req_b_task)
            .await
            .expect("token b request did not finish")
            .unwrap();
        assert_eq!(resp_b.status(), StatusCode::OK);
    }
}
