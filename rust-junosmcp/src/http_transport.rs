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
use arc_swap::ArcSwap;
use axum::Router;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rust_junosmcp_auth::tower::{auth_layer, AuthState};
use rust_junosmcp_auth::TokenStore;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn serve(
    handler: JmcpHandler,
    addr: SocketAddr,
    token_store: Option<Arc<ArcSwap<TokenStore>>>,
    #[cfg(feature = "tls")] tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    // Factory closure: rmcp wants a fresh handler per session. JmcpHandler
    // is cheap to clone (Arc fields) so we just clone it.
    let handler_factory = move || Ok::<_, std::io::Error>(handler.clone());

    let svc = StreamableHttpService::new(
        handler_factory,
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let rmcp_router = Router::new().nest_service("/mcp", svc);

    let app = if let Some(store) = token_store {
        rmcp_router.layer(axum::middleware::from_fn_with_state(
            AuthState { store },
            auth_layer,
        ))
    } else {
        // --allow-no-auth path: no middleware, no token check.
        rmcp_router
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
