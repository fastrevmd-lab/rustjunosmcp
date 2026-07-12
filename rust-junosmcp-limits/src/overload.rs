//! Stable overload responses: HTTP 503 + `Retry-After`, load-shed semantics.

use axum::http::{header::RETRY_AFTER, StatusCode};
use axum::response::{IntoResponse, Response};

/// Seconds advertised in `Retry-After` on every shed response.
const RETRY_AFTER_SECS: u64 = 1;

/// Build a stable overload response for the given limit kind
/// (e.g. `"global_concurrency"`, `"token_concurrency"`, `"session_cap"`).
pub fn overload_response(limit_kind: &'static str) -> Response {
    let body = format!(r#"{{"error":"overloaded","limit":"{limit_kind}"}}"#);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, RETRY_AFTER_SECS.to_string())],
        body,
    )
        .into_response()
}
