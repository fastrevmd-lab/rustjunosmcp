//! Per-authenticated-token request-rate limiting.

use crate::limits::config::LimitsConfig;
use crate::limits::overload::rate_limited_response;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use dashmap::DashMap;
use rust_junosmcp_auth::caller::CallerCtx;
use std::sync::Arc;
use std::time::{Duration, Instant};

const TOKEN_SCALE: u128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateDecision {
    Allowed,
    Limited { retry_after_secs: u64 },
}

#[derive(Debug)]
struct Bucket {
    available_units: u128,
    last_refill: Instant,
}

impl Bucket {
    fn full(burst: u64, now: Instant) -> Self {
        Self {
            available_units: capacity_units(burst),
            last_refill: now,
        }
    }

    fn check(&mut self, now: Instant, rate: u64, burst: u64) -> RateDecision {
        if let Some(elapsed) = now.checked_duration_since(self.last_refill) {
            self.available_units = self
                .available_units
                .saturating_add(refill_units(elapsed, rate))
                .min(capacity_units(burst));
            self.last_refill = now;
        }

        if self.available_units >= TOKEN_SCALE {
            self.available_units -= TOKEN_SCALE;
            return RateDecision::Allowed;
        }

        let deficit_units = TOKEN_SCALE - self.available_units;
        let wait_ns = deficit_units.div_ceil(u128::from(rate));
        let retry_secs = wait_ns.div_ceil(TOKEN_SCALE).max(1);
        RateDecision::Limited {
            retry_after_secs: u64::try_from(retry_secs).unwrap_or(u64::MAX),
        }
    }
}

#[derive(Clone)]
struct TokenRateLimitState {
    buckets: Arc<DashMap<String, Bucket>>,
    rate_per_second: u64,
    burst: u64,
}

impl TokenRateLimitState {
    fn new(config: &LimitsConfig) -> Self {
        debug_assert!(config.token_rate_limit_enabled());
        Self {
            buckets: Arc::new(DashMap::new()),
            rate_per_second: config.max_requests_per_second_per_token,
            burst: config.max_request_burst_per_token,
        }
    }

    fn check_at(&self, token: &str, now: Instant) -> RateDecision {
        let mut bucket = self
            .buckets
            .entry(token.to_owned())
            .or_insert_with(|| Bucket::full(self.burst, now));
        bucket.check(now, self.rate_per_second, self.burst)
    }
}

async fn token_rate_limit_middleware(
    State(state): State<TokenRateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(caller) = request.extensions().get::<CallerCtx>() {
        let token = caller.token_name.clone();
        if let RateDecision::Limited { retry_after_secs } = state.check_at(&token, Instant::now()) {
            tracing::warn!(
                limit = "token_rate",
                token = %token,
                rate = state.rate_per_second,
                burst = state.burst,
                retry_after_secs,
                "request rate limited"
            );
            return rate_limited_response(retry_after_secs);
        }
    }
    next.run(request).await
}

pub fn apply_token_rate_limit(router: Router, config: &LimitsConfig) -> Router {
    if !config.token_rate_limit_enabled() {
        return router;
    }
    router.layer(axum::middleware::from_fn_with_state(
        TokenRateLimitState::new(config),
        token_rate_limit_middleware,
    ))
}

fn capacity_units(burst: u64) -> u128 {
    u128::from(burst).saturating_mul(TOKEN_SCALE)
}

fn refill_units(elapsed: Duration, rate: u64) -> u128 {
    elapsed.as_nanos().saturating_mul(u128::from(rate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use rust_junosmcp_auth::caller::CallerCtx;
    use rust_junosmcp_auth::ScopeSet;
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    fn caller(name: &str) -> CallerCtx {
        CallerCtx {
            token_name: name.to_owned(),
            routers: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
        }
    }

    fn request(token: Option<&str>) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        if let Some(token) = token {
            request.extensions_mut().insert(caller(token));
        }
        request
    }

    fn state(rate: u64, burst: u64) -> TokenRateLimitState {
        TokenRateLimitState::new(&LimitsConfig {
            max_requests_per_second_per_token: rate,
            max_request_burst_per_token: burst,
            ..Default::default()
        })
    }

    #[test]
    fn fresh_bucket_admits_exact_burst_then_limits() {
        let state = state(2, 3);
        let now = Instant::now();
        assert_eq!(state.check_at("alice", now), RateDecision::Allowed);
        assert_eq!(state.check_at("alice", now), RateDecision::Allowed);
        assert_eq!(state.check_at("alice", now), RateDecision::Allowed);
        assert_eq!(
            state.check_at("alice", now),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn partial_refill_reaches_exact_token_boundary() {
        let state = state(2, 1);
        let start = Instant::now();
        assert_eq!(state.check_at("alice", start), RateDecision::Allowed);
        assert_eq!(
            state.check_at("alice", start + Duration::from_millis(250)),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
        assert_eq!(
            state.check_at("alice", start + Duration::from_millis(500)),
            RateDecision::Allowed
        );
    }

    #[test]
    fn long_idle_refill_is_capped_at_burst() {
        let state = state(4, 2);
        let start = Instant::now();
        assert_eq!(state.check_at("alice", start), RateDecision::Allowed);
        assert_eq!(state.check_at("alice", start), RateDecision::Allowed);
        let later = start + Duration::from_secs(60);
        assert_eq!(state.check_at("alice", later), RateDecision::Allowed);
        assert_eq!(state.check_at("alice", later), RateDecision::Allowed);
        assert_eq!(
            state.check_at("alice", later),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn token_names_are_isolated() {
        let state = state(1, 1);
        let now = Instant::now();
        assert_eq!(state.check_at("alice", now), RateDecision::Allowed);
        assert!(matches!(
            state.check_at("alice", now),
            RateDecision::Limited { .. }
        ));
        assert_eq!(state.check_at("bob", now), RateDecision::Allowed);
    }

    #[test]
    fn concurrent_checks_admit_exactly_the_burst() {
        const BURST: usize = 8;
        let state = Arc::new(state(1, BURST as u64));
        let barrier = Arc::new(std::sync::Barrier::new(BURST * 2));
        let now = Instant::now();
        let admitted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..BURST * 2)
                .map(|_| {
                    let state = state.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        state.check_at("alice", now) == RateDecision::Allowed
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|admitted| *admitted)
                .count()
        });
        assert_eq!(admitted, BURST);
    }

    #[test]
    fn refill_arithmetic_saturates() {
        assert_eq!(refill_units(Duration::MAX, u64::MAX), u128::MAX);
    }

    #[test]
    fn earlier_instant_does_not_move_refill_clock_backward() {
        let state = state(2, 1);
        let start = Instant::now();
        assert_eq!(state.check_at("alice", start), RateDecision::Allowed);
        assert!(matches!(
            state.check_at("alice", start + Duration::from_millis(250)),
            RateDecision::Limited { .. }
        ));
        assert!(matches!(
            state.check_at("alice", start),
            RateDecision::Limited { .. }
        ));
        assert_eq!(
            state.check_at("alice", start + Duration::from_millis(500)),
            RateDecision::Allowed
        );
    }

    #[tokio::test]
    async fn middleware_returns_exact_429_and_isolates_tokens() {
        let config = LimitsConfig {
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let app = apply_token_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let limited = app.clone().oneshot(request(Some("alice"))).await.unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers().get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(
            limited.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(limited.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"rate_limited","limit":"token_rate"}"#
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("bob")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(request(None)).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(request(None)).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn rate_limit_precedes_global_concurrency_but_preserves_503() {
        let config = LimitsConfig {
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            max_inflight_requests: 1,
            max_inflight_requests_per_token: 0,
            max_inflight_requests_per_router: 0,
            ..Default::default()
        };
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let handler = {
            let entered = entered.clone();
            let release = release.clone();
            move || {
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    StatusCode::OK
                }
            }
        };
        let concurrency = crate::limits::ConcurrencyState::new(&config, None);
        let app =
            Router::new()
                .route("/", post(handler))
                .layer(axum::middleware::from_fn_with_state(
                    concurrency,
                    crate::limits::concurrency_middleware,
                ));
        let app = apply_token_rate_limit(app, &config);

        let first_app = app.clone();
        let first =
            tokio::spawn(async move { first_app.oneshot(request(Some("alice"))).await.unwrap() });
        entered.notified().await;

        let alice = app.clone().oneshot(request(Some("alice"))).await.unwrap();
        assert_eq!(alice.status(), StatusCode::TOO_MANY_REQUESTS);

        let bob = app.clone().oneshot(request(Some("bob"))).await.unwrap();
        assert_eq!(bob.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(bob.headers().get(header::RETRY_AFTER).unwrap(), "1");
        let body = to_bytes(bob.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"overloaded","limit":"global_concurrency"}"#
        );

        release.notify_one();
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cancellation_does_not_refund_consumed_rate_token() {
        let config = LimitsConfig {
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let entered = Arc::new(Notify::new());
        let never_release = Arc::new(Notify::new());
        let handler = {
            let entered = entered.clone();
            let never_release = never_release.clone();
            move || {
                let entered = entered.clone();
                let never_release = never_release.clone();
                async move {
                    entered.notify_one();
                    never_release.notified().await;
                    StatusCode::OK
                }
            }
        };
        let app = apply_token_rate_limit(Router::new().route("/", post(handler)), &config);
        let first_app = app.clone();
        let first =
            tokio::spawn(async move { first_app.oneshot(request(Some("alice"))).await.unwrap() });
        entered.notified().await;
        first.abort();
        let _ = first.await;

        let second = app.oneshot(request(Some("alice"))).await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn downstream_error_does_not_refund_consumed_rate_token() {
        let config = LimitsConfig {
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let app = apply_token_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::INTERNAL_SERVER_ERROR })),
            &config,
        );

        let first = app.clone().oneshot(request(Some("alice"))).await.unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let second = app.oneshot(request(Some("alice"))).await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
