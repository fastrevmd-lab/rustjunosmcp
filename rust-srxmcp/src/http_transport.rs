//! axum router for rust-srxmcp: AuthLayer + rmcp streamable-http handler.
//! Mirror of rust-junosmcp/src/http_transport.rs, bound to JmcpSrxHandler.

use crate::server::JmcpSrxHandler;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::Router;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rust_junosmcp_auth::tower::{auth_layer, AuthState};
use rust_junosmcp_auth::TokenStore;
use rust_junosmcp_limits::{
    apply_body_limit, concurrency_middleware, ConcurrencyState, LimitedSessionManager, LimitsConfig,
};
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

pub async fn serve(
    handler: JmcpSrxHandler,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
    allowed_hosts: Vec<String>,
    disable_host_check: bool,
    limits: LimitsConfig,
) -> Result<()> {
    serve_inner(
        handler,
        addr,
        token_store,
        allowed_hosts,
        disable_host_check,
        limits,
        #[cfg(feature = "tls")]
        None,
    )
    .await
}

#[cfg(feature = "tls")]
pub async fn serve_with_tls(
    handler: JmcpSrxHandler,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
    allowed_hosts: Vec<String>,
    disable_host_check: bool,
    limits: LimitsConfig,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    serve_inner(
        handler,
        addr,
        token_store,
        allowed_hosts,
        disable_host_check,
        limits,
        tls,
    )
    .await
}

async fn serve_inner(
    handler: JmcpSrxHandler,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
    allowed_hosts: Vec<String>,
    disable_host_check: bool,
    limits: LimitsConfig,
    #[cfg(feature = "tls")] tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let handler_factory = move || Ok::<_, std::io::Error>(handler.clone());

    limits.log_effective();

    let session_mgr = LimitedSessionManager::new(LocalSessionManager::default(), &limits);
    let conc = ConcurrencyState::new(&limits, Some(session_mgr.tracker()));

    let http_cfg = build_http_config(allowed_hosts, disable_host_check);
    let svc = StreamableHttpService::new(handler_factory, session_mgr, http_cfg);
    let rmcp_router = Router::new().nest_service("/mcp", svc);

    // Innermost added layer: concurrency (needs CallerCtx from auth, which runs first).
    let app = rmcp_router.layer(axum::middleware::from_fn_with_state(
        conc,
        concurrency_middleware,
    ));

    // Auth runs before concurrency so CallerCtx is present.
    let app = if let Some(store) = token_store {
        app.layer(axum::middleware::from_fn_with_state(
            AuthState { store },
            auth_layer,
        ))
    } else {
        app
    };

    // Body limit outermost: reject oversized bodies before buffering.
    let app = apply_body_limit(app, &limits);

    #[cfg(feature = "tls")]
    if let Some(config) = tls {
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(config);
        tracing::info!(addr = %addr, "rust-srxmcp streamable-http listening (TLS)");
        return axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .context("axum_server::bind_rustls");
    }

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
