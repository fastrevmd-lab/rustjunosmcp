//! Stable overload responses: HTTP 503 + `Retry-After`, load-shed semantics.

use axum::http::{header::RETRY_AFTER, StatusCode};
use axum::response::{IntoResponse, Response};

/// Seconds advertised in `Retry-After` on every shed response.
const RETRY_AFTER_SECS: u64 = 1;

/// Build a stable overload response for the given limit kind
/// (e.g. `"global_concurrency"`, `"token_concurrency"`, `"session_cap"`).
pub fn overload_response(limit_kind: &'static str) -> Response {
    if matches!(
        limit_kind,
        "global_concurrency"
            | "token_concurrency"
            | "router_concurrency"
            | "session_cap"
            | "token_session_cap"
    ) {
        crate::prometheus::record_limit_hit(limit_kind, "request_rejected");
    }
    let body = format!(r#"{{"error":"overloaded","limit":"{limit_kind}"}}"#);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, RETRY_AFTER_SECS.to_string())],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn overload_response_counts_each_fixed_limit_kind() {
        let (recorder, handle) = crate::prometheus::test_recorder("junos");
        metrics::with_local_recorder(&recorder, || {
            for limit in [
                "global_concurrency",
                "token_concurrency",
                "router_concurrency",
                "session_cap",
                "token_session_cap",
            ] {
                let _ = overload_response(limit);
            }
        });
        handle.run_upkeep();
        let text = handle.render();
        for limit in [
            "global_concurrency",
            "token_concurrency",
            "router_concurrency",
            "session_cap",
            "token_session_cap",
        ] {
            assert!(
                text.lines().any(|line| {
                    line.starts_with("junosmcp_limit_hits_total{")
                        && line.contains(&format!("limit=\"{limit}\""))
                        && line.contains("event=\"request_rejected\"")
                        && line.ends_with(" 1")
                }),
                "missing {limit} in:\n{text}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_limit_preserves_response_without_metric_series() {
        let (recorder, handle) = crate::prometheus::test_recorder("junos");
        let response =
            metrics::with_local_recorder(&recorder, || overload_response("future_limit_kind"));

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"overloaded","limit":"future_limit_kind"}"#
        );

        handle.run_upkeep();
        let text = handle.render();
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("junosmcp_limit_hits_total{")),
            "unexpected limit series in:\n{text}"
        );
    }
}
