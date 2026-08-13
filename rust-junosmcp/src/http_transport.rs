//! Junos MCP Streamable HTTP transport using mecmcp-transport 0.7.0.
//!
//! Uses `HttpTransportConfig` / `build_streamable_http_router` / `serve_router`
//! from mecmcp-transport 0.7.0, which replaces the hand-rolled router assembly
//! this crate used in 0.6.1 and adds graceful shutdown with request draining.

use crate::server::JmcpHandler;
use anyhow::{Context, Result};
use mecmcp_auth::BearerSyntax;
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpTransportConfig, LimitsConfig, NoAuthAcknowledgement, ServePlan, TransportIdentity,
    build_streamable_http_router, serve_router,
};
use rust_junosmcp_auth::{CallerCtx, TokenStoreFile};
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

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

impl mecmcp_transport::ScopePreflight for JunosPreflight {
    fn check(&self, body: &[u8], caller: mecmcp_transport::CallerScopes<'_>) -> Result<(), String> {
        if request_exceeds_scope(body, caller) {
            Err("insufficient_scope".to_owned())
        } else {
            Ok(())
        }
    }
}

fn request_exceeds_scope(bytes: &[u8], caller: mecmcp_transport::CallerScopes<'_>) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| tool_call_exceeds_scope(value, &caller)),
        value => tool_call_exceeds_scope(&value, &caller),
    }
}

fn tool_call_exceeds_scope(value: &Value, caller: &mecmcp_transport::CallerScopes<'_>) -> bool {
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

fn device_value_in_scope(value: &Value, caller: &mecmcp_transport::CallerScopes<'_>) -> bool {
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

/// Build the complete Junos HTTP router using mecmcp-transport 0.7.0.
///
/// Returns `(Router, HttpShutdown)`, and that value **must** be passed to
/// `serve_router`. It carries the listener's token and rmcp's, which are
/// cancelled at different times: sharing one ended every session the instant
/// shutdown began, so no in-flight call could deliver its response.
pub fn build_http_router(
    handler: JmcpHandler,
    token_store: Option<Arc<TokenStoreFile>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    shutdown: CancellationToken,
) -> Result<ServePlan> {
    // Junos transport identity: metric prefix, server label, bearer realm, target keys.
    let identity = TransportIdentity::new(
        "junosmcp",
        "junos",
        "rust-junosmcp",
        ["router", "router_name", "routers", "router_names"],
    );

    let config = if let Some(store_file) = token_store {
        // Authenticated mode with token store
        let auth_store = store_file.clone();
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            let snapshot = auth_store.store();
            snapshot.authenticate(candidate).map(CallerCtx::from)
        });
        let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("jmcp"))
            .with_preflight(JunosPreflight);
        HttpTransportConfig::authenticated(
            identity.clone(),
            limits.clone(),
            HostOriginPolicy::enforced(allowed_hosts, allowed_origins),
            shutdown,
            boundary,
        )
    } else {
        // Unauthenticated mode
        HttpTransportConfig::unauthenticated(
            identity.clone(),
            limits.clone(),
            HostOriginPolicy::enforced(allowed_hosts, allowed_origins),
            shutdown,
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        )
    }
    .with_metrics(enable_metrics);

    // Factory closure: rmcp wants a fresh handler per session. JmcpHandler
    // is cheap to clone (Arc fields) so we just clone it.
    build_streamable_http_router(move || Ok::<_, std::io::Error>(handler.clone()), config)
        .context("building Junos Streamable HTTP router")
}

/// Serve the Junos HTTP router over plain HTTP or supplied TLS with graceful shutdown.
///
/// **Graceful shutdown**: When `shutdown` is triggered, the listener stops accepting
/// new connections and waits up to `shutdown_timeout` for in-flight requests to complete.
/// rmcp terminates SSE sessions on the same token, so streams end immediately. The
/// timeout bounds stuck connections well under systemd's `TimeoutStopSec`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_http(
    handler: JmcpHandler,
    address: SocketAddr,
    token_store: Option<Arc<TokenStoreFile>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: CancellationToken,
    shutdown_timeout: std::time::Duration,
) -> Result<()> {
    let plan = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
        shutdown,
    )?;
    // Readiness marker. Three test harnesses block on this exact string, and
    // `--tls-cert` callers on the "(TLS)" suffix, so it is a contract rather
    // than a log line. mecmcp emits its own "Streamable HTTP listening" from
    // inside serve_router; that is a different string, and relying on it once
    // cost an afternoon to a suite that hung rather than failed.
    if tls.is_some() {
        tracing::info!(%address, "streamable-http listening (TLS)");
    } else {
        tracing::info!(%address, "streamable-http listening");
    }
    serve_router(plan, address, tls, shutdown_timeout)
        .await
        .context("serving Junos Streamable HTTP")
}
