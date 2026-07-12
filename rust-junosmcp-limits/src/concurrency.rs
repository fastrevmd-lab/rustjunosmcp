//! Load-shedding concurrency middleware. Permits are attached to the response
//! body (`GuardedBody`) so they release at end-of-stream — rmcp runs the tool
//! lazily while the SSE body is polled, so a permit held only across the
//! response future would release too early.

use crate::config::LimitsConfig;
use crate::overload::overload_response;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use dashmap::DashMap;
use http_body::{Body as HttpBody, Frame, SizeHint};
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

/// Axum middleware enforcing global + per-token concurrency with load-shed.
pub async fn concurrency_middleware(
    State(state): State<ConcurrencyState>,
    req: Request,
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

    let resp = next.run(req).await;
    attach_permits(resp, permits)
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
    use axum::http::{Request, StatusCode};
    use axum::{routing::get, Router};
    use rust_junosmcp_auth::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;
    use std::sync::Arc;
    use tokio::sync::Notify;
    use tower::ServiceExt as _; // oneshot

    fn ctx(name: &str) -> CallerCtx {
        CallerCtx {
            token_name: name.to_string(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
        }
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
        let first = inflight.await.unwrap();
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
        let _ = inflight.await.unwrap();
        let resp_b = req_b_task.await.unwrap();
        assert_eq!(resp_b.status(), StatusCode::OK);
    }
}
