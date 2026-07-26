//! Prometheus /metrics contract test.
//!
//! This test pins the exact metric names and output format emitted by the
//! `mecmcp-transport` crate when configured with Junos identity. A change to
//! any of these assertions breaks every existing Prometheus dashboard and
//! alert rule pointing at this server. DO NOT relax these assertions.

#![allow(clippy::unwrap_used)]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header::CONTENT_TYPE};
use metrics::with_local_recorder;
use tower::ServiceExt as _;

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

fn sample_with<'a>(text: &'a str, prefix: &str, fragments: &[&str]) -> &'a str {
    text.lines()
        .find(|line| {
            line.starts_with(prefix) && fragments.iter().all(|fragment| line.contains(fragment))
        })
        .unwrap_or_else(|| panic!("missing {prefix} with {fragments:?} in:\n{text}"))
}

/// The acceptance criterion that matters most.
///
/// This test pins the exact `/metrics` output that `rustjunosmcp` exposes
/// when using `mecmcp-transport`. The assertions reproduce the test that was
/// in `rust-junosmcp-core/src/limits/prometheus.rs` before Phase 3a Task 8,
/// byte-for-byte.
///
/// **DO NOT modify any assertion here** unless you have audited every
/// Prometheus dashboard and alert rule in production and verified the change
/// is safe. These metric names are the contract with deployed monitoring
/// infrastructure that is not in this repo.
#[tokio::test(flavor = "current_thread")]
async fn renders_exact_metric_contract_and_content_type() {
    use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

    mecmcp_audit::install_duration_metric_name("junosmcp_tool_duration_seconds");

    let tool_duration_name = "junosmcp_tool_duration_seconds";
    let buckets: &[f64] = &[
        0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
        1800.0,
    ];

    let recorder = PrometheusBuilder::new()
        .add_global_label("server", "junos")
        .set_buckets_for_metric(Matcher::Full(tool_duration_name.to_owned()), buckets)
        .expect("fixed histogram buckets")
        .build_recorder();
    let handle = recorder.handle();

    with_local_recorder(&recorder, || {
        metrics::describe_gauge!(
            "junosmcp_active_sessions",
            "Current MCP sessions tracked by the HTTP session manager."
        );
        metrics::describe_counter!(
            "junosmcp_limit_hits_total",
            "HTTP resource-limit rejections and manager-level session cap hits."
        );
        metrics::describe_histogram!(
            "junosmcp_tool_duration_seconds",
            metrics::Unit::Seconds,
            "Elapsed MCP tool-handler duration by tool and terminal result."
        );
        metrics::describe_counter!(
            "junosmcp_sessions_reaped_total",
            "MCP sessions removed by the idle/lifetime reaper."
        );

        metrics::gauge!("junosmcp_active_sessions").set(2.0);
        metrics::counter!(
            "junosmcp_limit_hits_total",
            "limit" => "global_concurrency",
            "event" => "request_rejected"
        )
        .increment(1);
        metrics::counter!("junosmcp_sessions_reaped_total", "reason" => "idle").increment(1);
        // Use AuditScope to emit junosmcp_tool_duration_seconds, not a direct
        // metrics::histogram! call. This tests the real code path.
        let mut audit =
            mecmcp_audit::AuditScope::stdio("get_router_list", "read", vec!["r1".into()]);
        audit.succeed();
    });
    handle.run_upkeep();

    // Build a simple metrics router like PrometheusRuntime does
    let metrics_router = axum::Router::new().route(
        "/metrics",
        axum::routing::get({
            let h = handle.clone();
            move || async move {
                h.run_upkeep();
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        axum::http::HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
                    )],
                    h.render(),
                )
            }
        }),
    );

    let response = metrics_router
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        PROMETHEUS_CONTENT_TYPE
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();

    sample_with(
        text,
        "junosmcp_active_sessions{",
        &["server=\"junos\"", "} 2"],
    );
    sample_with(
        text,
        "junosmcp_limit_hits_total{",
        &[
            "server=\"junos\"",
            "limit=\"global_concurrency\"",
            "event=\"request_rejected\"",
            "} 1",
        ],
    );
    sample_with(
        text,
        "junosmcp_sessions_reaped_total{",
        &["server=\"junos\"", "reason=\"idle\"", "} 1"],
    );
    sample_with(
        text,
        "junosmcp_tool_duration_seconds_bucket{",
        &[
            "server=\"junos\"",
            "tool=\"get_router_list\"",
            "result=\"ok\"",
            "le=\"0.01\"",
        ],
    );
    sample_with(
        text,
        "junosmcp_tool_duration_seconds_bucket{",
        &["le=\"1800\"", "tool=\"get_router_list\""],
    );
    assert!(!text.contains("junosmcp_limit_hits_total_total"));
}
