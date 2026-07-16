use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::Duration;
use tokio::time::MissedTickBehavior;
use tokio_util::task::AbortOnDropHandle;

pub(crate) const ACTIVE_SESSIONS: &str = "junosmcp_active_sessions";
pub(crate) const LIMIT_HITS_TOTAL: &str = "junosmcp_limit_hits_total";
pub(crate) const TOOL_DURATION_SECONDS: &str = "junosmcp_tool_duration_seconds";
pub(crate) const SESSIONS_REAPED_TOTAL: &str = "junosmcp_sessions_reaped_total";
pub(crate) const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const TOOL_DURATION_BUCKETS: &[f64] = &[
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0,
];

pub struct PrometheusRuntime {
    handle: PrometheusHandle,
    _upkeep: AbortOnDropHandle<()>,
}

impl PrometheusRuntime {
    pub fn install(server: &str) -> Result<Self, BuildError> {
        let handle = prometheus_builder(server)?.install_recorder()?;
        describe_metrics();
        metrics::gauge!(ACTIVE_SESSIONS).set(0.0);

        let upkeep_handle = handle.clone();
        let upkeep = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPKEEP_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                upkeep_handle.run_upkeep();
            }
        }));

        Ok(Self {
            handle,
            _upkeep: upkeep,
        })
    }

    pub fn router(&self) -> Router {
        metrics_router(self.handle.clone())
    }
}

fn prometheus_builder(server: &str) -> Result<PrometheusBuilder, BuildError> {
    PrometheusBuilder::new()
        .with_recommended_naming(false)
        .add_global_label("server", server)
        .set_buckets_for_metric(
            Matcher::Full(TOOL_DURATION_SECONDS.to_owned()),
            TOOL_DURATION_BUCKETS,
        )
}

fn describe_metrics() {
    metrics::describe_gauge!(
        ACTIVE_SESSIONS,
        "Current MCP sessions tracked by the HTTP session manager."
    );
    metrics::describe_counter!(
        LIMIT_HITS_TOTAL,
        "HTTP resource-limit rejections and manager-level session cap hits."
    );
    metrics::describe_histogram!(
        TOOL_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "Elapsed MCP tool-handler duration by tool and terminal result."
    );
    metrics::describe_counter!(
        SESSIONS_REAPED_TOTAL,
        "MCP sessions removed by the idle/lifetime reaper."
    );
}

fn metrics_router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(handle)
}

async fn render_metrics(State(handle): State<PrometheusHandle>) -> Response {
    handle.run_upkeep();
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
        )],
        handle.render(),
    )
        .into_response()
}

// Wired into limit and session paths in Task 2.
#[allow(dead_code)]
pub(crate) fn record_limit_hit(limit: &'static str, event: &'static str) {
    metrics::counter!(
        LIMIT_HITS_TOTAL,
        "limit" => limit,
        "event" => event
    )
    .increment(1);
}

#[allow(dead_code)]
pub(crate) fn increment_active_sessions() {
    metrics::gauge!(ACTIVE_SESSIONS).increment(1.0);
}

#[allow(dead_code)]
pub(crate) fn decrement_active_sessions() {
    metrics::gauge!(ACTIVE_SESSIONS).decrement(1.0);
}

#[allow(dead_code)]
pub(crate) fn record_session_reaped(reason: &'static str) {
    metrics::counter!(SESSIONS_REAPED_TOTAL, "reason" => reason).increment(1);
}

#[cfg(test)]
pub(crate) fn test_recorder(
    server: &str,
) -> (
    metrics_exporter_prometheus::PrometheusRecorder,
    PrometheusHandle,
) {
    let recorder = prometheus_builder(server)
        .expect("fixed non-empty histogram buckets")
        .build_recorder();
    let handle = recorder.handle();
    (recorder, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{header::CONTENT_TYPE, Request, StatusCode};
    use metrics::with_local_recorder;
    use tower::ServiceExt as _;

    fn sample_with<'a>(text: &'a str, prefix: &str, fragments: &[&str]) -> &'a str {
        text.lines()
            .find(|line| {
                line.starts_with(prefix) && fragments.iter().all(|fragment| line.contains(fragment))
            })
            .unwrap_or_else(|| panic!("missing {prefix} with {fragments:?} in:\n{text}"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn renders_exact_metric_contract_and_content_type() {
        let (recorder, handle) = test_recorder("junos");
        with_local_recorder(&recorder, || {
            describe_metrics();
            metrics::gauge!(ACTIVE_SESSIONS).set(2.0);
            record_limit_hit("global_concurrency", "request_rejected");
            record_session_reaped("idle");
            metrics::histogram!(
                TOOL_DURATION_SECONDS,
                "tool" => "get_router_list",
                "result" => "ok"
            )
            .record(0.25);
        });
        handle.run_upkeep();

        let response = metrics_router(handle)
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
}
