//! axum router for rust-srxmcp: AuthLayer + rmcp streamable-http handler.
//! Mirror of rust-junosmcp/src/http_transport.rs, bound to JmcpSrxHandler.
//! No TLS in 0.0.1.

use crate::server::JmcpSrxHandler;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
    middleware::Next,
    Router,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rust_junosmcp_auth::tower::{auth_layer, AuthState};
use rust_junosmcp_auth::TokenStore;
use std::net::SocketAddr;
use std::sync::Arc;

/// Build the streamable-http server config, applying the Host allowlist policy.
/// Default = rmcp's loopback-only allowlist (localhost/127.0.0.1/::1); each
/// `--allowed-host` value extends it. `--disable-host-check` turns the gate off.
fn build_http_config(
    allowed_hosts: Vec<String>,
    disable_host_check: bool,
) -> StreamableHttpServerConfig {
    if disable_host_check {
        tracing::warn!(
            "--disable-host-check: streamable-http Host allowlist DISABLED; accepting any Host header. \
             This reintroduces RUSTSEC-2026-0189 (DNS rebinding); bearer auth still applies."
        );
        return StreamableHttpServerConfig::default().disable_allowed_hosts();
    }
    let mut cfg = StreamableHttpServerConfig::default(); // loopback defaults
    cfg.allowed_hosts.extend(allowed_hosts);
    cfg
}

#[derive(Clone)]
struct HostGateState {
    allowed_hosts: Arc<Vec<String>>,
}

/// Reject requests whose `Host` header isn't in `allowed_hosts` before they
/// reach auth or the rmcp handler.
///
/// rmcp's own Host allowlist (`StreamableHttpServerConfig.allowed_hosts`, set
/// up in `build_http_config` above) only runs inside
/// `StreamableHttpService::handle`, which sits *behind* the auth middleware in
/// this router — axum's outer `.layer()` always runs before the service it
/// wraps, including a nested one. That means an anonymous DNS-rebinding probe
/// never reaches rmcp's Host check: it gets rejected with 401 (missing
/// bearer) before the Host header is ever inspected. RUSTSEC-2026-0189 wants
/// a disallowed Host rejected with 403 regardless of auth state, so this gate
/// duplicates rmcp's matching rule (a portless allowlist entry matches that
/// host on any port; an empty list means the check is disabled) and runs as
/// the outermost layer, ahead of auth.
async fn host_gate(
    axum::extract::State(state): axum::extract::State<HostGateState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    if state.allowed_hosts.is_empty() {
        // Empty allowlist == disabled, mirroring rmcp's own `host_is_allowed`.
        return next.run(req).await;
    }
    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let Some(host_header) = host_header else {
        return forbidden_response("Bad Request: missing Host header");
    };
    if host_authority_allowed(&host_header, &state.allowed_hosts) {
        next.run(req).await
    } else {
        tracing::warn!(
            host = %host_header,
            "rejected request with disallowed Host header (possible DNS rebinding attempt)"
        );
        forbidden_response("Forbidden: Host header is not allowed")
    }
}

fn forbidden_response(message: &'static str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(message))
        // OK: builder only fails on invalid header values; there are none here.
        .unwrap()
}

/// Parse `raw` as an authority (`host` or `host:port`), lower-cased and with
/// IPv6 brackets stripped. Mirrors rmcp 2.0.0's `parse_allowed_authority` /
/// `normalize_host` so this gate agrees with the inner
/// `StreamableHttpServerConfig` check built by `build_http_config`.
fn normalize_authority(raw: &str) -> Option<(String, Option<u16>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(authority) = raw.parse::<axum::http::uri::Authority>() {
        let host = authority
            .host()
            .trim_matches('[')
            .trim_matches(']')
            .to_ascii_lowercase();
        return Some((host, authority.port_u16()));
    }
    Some((
        raw.trim_matches('[').trim_matches(']').to_ascii_lowercase(),
        None,
    ))
}

fn host_authority_allowed(host_header: &str, allowed_hosts: &[String]) -> bool {
    let Some((host, port)) = normalize_authority(host_header) else {
        return false;
    };
    allowed_hosts
        .iter()
        .filter_map(|a| normalize_authority(a))
        .any(|(a_host, a_port)| a_host == host && (a_port.is_none() || a_port == port))
}

pub async fn serve(
    handler: JmcpSrxHandler,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
    allowed_hosts: Vec<String>,
    disable_host_check: bool,
) -> Result<()> {
    let handler_factory = move || Ok::<_, std::io::Error>(handler.clone());

    let http_cfg = build_http_config(allowed_hosts, disable_host_check);
    let effective_allowed_hosts = http_cfg.allowed_hosts.clone();
    let svc = StreamableHttpService::new(
        handler_factory,
        Arc::new(LocalSessionManager::default()),
        http_cfg,
    );

    let rmcp_router = Router::new().nest_service("/mcp", svc);

    let app = if let Some(store) = token_store {
        rmcp_router.layer(axum::middleware::from_fn_with_state(
            AuthState { store },
            auth_layer,
        ))
    } else {
        rmcp_router
    };

    // Outermost: the Host gate, so a disallowed Host is rejected before auth
    // even runs (see `host_gate` doc comment for why this can't just rely on
    // rmcp's own inner check).
    let app = app.layer(axum::middleware::from_fn_with_state(
        HostGateState {
            allowed_hosts: Arc::new(effective_allowed_hosts),
        },
        host_gate,
    ));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(addr = %addr, "rust-srxmcp streamable-http listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("axum::serve")?;
    Ok(())
}
