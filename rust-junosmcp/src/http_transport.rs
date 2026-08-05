//! axum router: AuthLayer + rmcp streamable-http handler.
//!
//! Mount API per Task 0 spike memo: `StreamableHttpService` is a
//! `tower::Service<http::Request<B>>`, mounted under axum 0.8 via
//! `Router::nest_service("/mcp", svc)`. The service splits requests into
//! `(Parts, Body)` and inserts the whole `http::request::Parts` into rmcp's
//! per-request `Extensions`, so `CallerCtx` (which our outer middleware put
//! on the axum request extensions) is reachable from `#[tool]` handlers via
//! `parts.extensions.get::<CallerCtx>()` (see `server::caller_ctx`).

use crate::server::JmcpHandler;
use anyhow::{Context, Result};
use axum::Router;
use mecmcp_transport::{
    ConcurrencyState, LimitedSessionManager, LimitsConfig, OptionalPreflight, PrometheusRuntime,
    ScopePreflight, TransportIdentity, apply_body_limit, apply_rate_limit, concurrency_middleware,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rust_junosmcp_auth::CallerCtx as SharedCallerCtx;
use rust_junosmcp_auth::tower::{AuthState, auth_layer};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

/// Junos scope preflight implementation.
///
/// Parses JSON-RPC `tools/call` requests (both single and batched), checking:
/// - Tool name against `caller.tools` using the write-tool registry
/// - Target devices from all four Junos argument spellings (`router`, `router_name`,
///   `routers`, `router_names`) against `caller.devices`
///
/// Rejects before dispatch if either check fails. Handler-level checks remain the
/// final authority and run for all transport paths (stdio, HTTP with preflight
/// bypassed).
struct JunosPreflight;

impl ScopePreflight for JunosPreflight {
    fn check(&self, body: &[u8], caller: &SharedCallerCtx) -> Result<(), String> {
        if request_exceeds_scope(body, caller) {
            Err("insufficient_scope".to_owned())
        } else {
            Ok(())
        }
    }
}

fn request_exceeds_scope(bytes: &[u8], caller: &SharedCallerCtx) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| tool_call_exceeds_scope(value, caller)),
        value => tool_call_exceeds_scope(&value, caller),
    }
}

fn tool_call_exceeds_scope(value: &Value, caller: &SharedCallerCtx) -> bool {
    if value.get("method").and_then(Value::as_str) != Some("tools/call") {
        return false;
    }
    let Some(params) = value.get("params") else {
        return false;
    };
    let Some(tool) = params.get("name").and_then(Value::as_str) else {
        return false;
    };
    if !caller
        .tools
        .allows_tool(tool, rust_junosmcp_auth::WRITE_TOOLS)
    {
        return true;
    }
    // Check device scope for all four Junos argument spellings.
    // If arguments exists but is not an object, deny — unrecognised shapes must fail closed.
    let Some(arguments) = params.get("arguments").and_then(Value::as_object) else {
        // No arguments field at all is fine (some tools don't take arguments).
        // But if it exists and is not an object, that's malformed and we deny.
        if params.get("arguments").is_some() {
            return true;
        }
        return false;
    };
    for key in ["router", "router_name", "routers", "router_names"] {
        if let Some(value) = arguments.get(key)
            && !device_value_in_scope(value, caller)
        {
            return true;
        }
    }
    false
}

fn device_value_in_scope(value: &Value, caller: &SharedCallerCtx) -> bool {
    match value {
        Value::String(device) => caller.devices.allows(device),
        Value::Array(devices) => {
            // Empty array is denied: .all() on empty iterator returns true, which
            // would incorrectly pass the check.
            if devices.is_empty() {
                return false;
            }
            devices
                .iter()
                .all(|d| d.as_str().is_some_and(|s| caller.devices.allows(s)))
        }
        // Unrecognised shapes (number, object, boolean, null) must deny.
        // This is fail-closed: if we can't recognize it, we refuse it.
        _ => false,
    }
}

/// Build the streamable-http server config, applying the Host allowlist policy.
/// Default = rmcp's loopback-only allowlist (localhost/127.0.0.1/::1); each
/// `--allowed-host` value extends it.
///
/// There is deliberately no way to turn the gate off. The allowlist is the
/// DNS-rebinding guard (RUSTSEC-2026-0189), and rebinding targets loopback-bound
/// services specifically — a browser resolves an attacker domain to 127.0.0.1 and
/// reaches the server with a foreign `Host`. So "off" would be most dangerous
/// exactly where it looked safest. Name the authority clients actually send with
/// `--allowed-host` instead; it is repeatable and precise.
///
/// Built from `mecmcp_transport::streamable_http_server_config` rather than
/// `StreamableHttpServerConfig::default()`. rmcp 3 added its own
/// `max_request_body_bytes` defaulting to 4 MiB, enforced *inside* rmcp after
/// our `apply_body_limit` layer has already accepted the request — so on
/// `default()` every request between 4 MiB and `--max-request-body-bytes`
/// (10 MiB here) would 413 from a limit that appears nowhere in our config.
/// `load_and_commit_config` carries whole device configurations, which is
/// exactly the payload that gets large.
fn build_http_config(
    allowed_hosts: Vec<String>,
    limits: &LimitsConfig,
) -> StreamableHttpServerConfig {
    let mut cfg = mecmcp_transport::streamable_http_server_config(limits);
    cfg.allowed_hosts.extend(allowed_hosts);
    cfg
}

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    handler: JmcpHandler,
    addr: SocketAddr,
    token_store: Option<Arc<rust_junosmcp_auth::TokenStoreFile>>,
    allowed_hosts: Vec<String>,
    enable_metrics: bool,
    limits: LimitsConfig,
    #[cfg(feature = "tls")] tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    // Factory closure: rmcp wants a fresh handler per session. JmcpHandler
    // is cheap to clone (Arc fields) so we just clone it.
    let handler_factory = move || Ok::<_, std::io::Error>(handler.clone());

    limits
        .validate()
        .context("validating HTTP resource limits")?;
    limits.log_effective();

    // Junos transport identity: metric prefix, server label, bearer realm, target keys.
    let identity = TransportIdentity::new(
        "junosmcp",
        "junos",
        "rust-junosmcp",
        ["router", "router_name", "routers", "router_names"],
    );

    let metrics_runtime = if enable_metrics {
        Some(
            PrometheusRuntime::install(&identity.metric_prefix, &identity.server_label)
                .context("initializing Prometheus metrics")?,
        )
    } else {
        None
    };

    let session_mgr = LimitedSessionManager::new(LocalSessionManager::default(), &limits);
    let conc = ConcurrencyState::new(
        &limits,
        identity.target_keys.clone(),
        Some(session_mgr.tracker()),
    );

    let http_cfg = build_http_config(allowed_hosts, &limits);
    let svc = StreamableHttpService::new(handler_factory, session_mgr, http_cfg);
    let rmcp_router = Router::new().nest_service("/mcp", svc);

    // Innermost added layer: concurrency (auth and rate run first in request order).
    let app = rmcp_router.layer(axum::middleware::from_fn_with_state(
        conc,
        concurrency_middleware,
    ));

    // Rate limiting wraps concurrency but remains inside auth, so CallerCtx exists
    // and an over-rate request acquires no concurrency/session capacity.
    let app = apply_rate_limit(app, &limits);

    // Auth runs before rate limiting and concurrency so CallerCtx is present.
    // Preflight is integrated into auth: it runs after bearer authentication
    // succeeds but before the request reaches the handler.
    let app = if let Some(store) = token_store {
        let preflight: OptionalPreflight = Some(Arc::new(JunosPreflight));
        app.layer(axum::middleware::from_fn_with_state(
            AuthState {
                store,
                preflight,
                body_limit: limits.max_request_body_bytes,
            },
            auth_layer,
        ))
    } else {
        app
    };

    // Body limit outermost: reject oversized bodies before buffering.
    let app = apply_body_limit(app, &limits);
    let app = if let Some(runtime) = metrics_runtime.as_ref() {
        app.merge(runtime.router())
    } else {
        app
    };

    #[cfg(feature = "tls")]
    if let Some(cfg) = tls {
        let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(cfg);
        tracing::info!(addr = %addr, "streamable-http listening (TLS)");
        return axum_server::bind_rustls(addr, rustls_cfg)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .context("axum_server::bind_rustls");
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(addr = %addr, "streamable-http listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("axum::serve")?;
    Ok(())
}
