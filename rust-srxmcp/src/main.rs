//! `rust-srxmcp` — Phase 1A scaffolding entry point.
//!
//! Boots an opt-in second MCP endpoint on `:30032` (override
//! `JMCP_SRX_HTTP_PORT`). Wires bearer auth against the shared
//! `/etc/jmcp/tokens.json` store and registers exactly one tool:
//! `srxmcp_status`.

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use rust_junosmcp_auth::file::TokenStoreFile;
use rust_srxmcp::{http_transport, server::JmcpSrxHandler};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Debug, Parser)]
#[command(
    name = "rust-srxmcp",
    version,
    about = "Juniper SRX-specific MCP server (Phase 1A scaffolding)."
)]
struct Cli {
    /// HTTP bind host.
    #[arg(long, default_value = "0.0.0.0", env = "JMCP_SRX_HTTP_HOST")]
    host: String,

    /// HTTP bind port.
    #[arg(long, default_value_t = 30032, env = "JMCP_SRX_HTTP_PORT")]
    port: u16,

    /// Bearer-token file (shared with rust-junosmcp).
    #[arg(long, env = "JMCP_TOKENS_PATH")]
    tokens_file: Option<PathBuf>,

    /// Devices file — read for token-scope validation; not used by `srxmcp_status` itself.
    #[arg(long, env = "JMCP_DEVICES_PATH")]
    device_mapping: Option<PathBuf>,

    /// Allow unauthenticated requests (lab only).
    #[arg(long, default_value_t = false)]
    allow_no_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    rust_junosmcp_core::bootstrap::init_tracing();

    let args = Cli::parse();

    let token_store = match (&args.tokens_file, args.allow_no_auth, &args.device_mapping) {
        (Some(path), _, devices) => {
            let names: Vec<String> = match devices {
                Some(dpath) => {
                    let (inv, _) = rust_junosmcp_core::bootstrap::load_inventory(dpath)
                        .map_err(anyhow::Error::from)
                        .with_context(|| format!("loading {}", dpath.display()))?;
                    inv.names()
                }
                None => Vec::new(),
            };
            let known: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            let store = TokenStoreFile::load(path, &known)
                .with_context(|| format!("loading {}", path.display()))?;
            tracing::info!(tokens = store.len(), "token store loaded");
            Some(Arc::new(ArcSwap::from_pointee(store)))
        }
        (None, true, _) => {
            tracing::warn!("--allow-no-auth: streamable-http will accept unauthenticated requests");
            None
        }
        (None, false, _) => {
            anyhow::bail!(
                "--tokens-file required for streamable-http (or pass --allow-no-auth for lab use)"
            );
        }
    };

    let started = Arc::new(Instant::now());
    let handler = JmcpSrxHandler::new(started);

    // SIGHUP: mirrors rust-junosmcp's shape. 0.0.1 only reloads the token
    // store (no policy/inventory state to reload here — the only tool is
    // diagnostic). The inventory file is re-read on each HUP so the token
    // scope validation sees the current router set.
    #[cfg(unix)]
    if let (Some(store_arc), Some(token_path), Some(dev_path)) = (
        token_store.clone(),
        args.tokens_file.clone(),
        args.device_mapping.clone(),
    ) {
        tokio::spawn(async move {
            let mut hup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGHUP handler; reload disabled");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                tracing::info!("SIGHUP: reloading token store");
                let names = match rust_junosmcp_core::bootstrap::load_inventory(&dev_path) {
                    Ok((inv, _)) => inv.names(),
                    Err(e) => {
                        tracing::error!(error = %e, "SIGHUP inventory reload failed; reusing previous router list");
                        Vec::new()
                    }
                };
                let known: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                match TokenStoreFile::load(&token_path, &known) {
                    Ok(new_store) => {
                        store_arc.store(Arc::new(new_store));
                        tracing::info!(path = %token_path.display(), "token store reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "SIGHUP token reload failed; keeping previous store");
                    }
                }
            }
        });
    }

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .with_context(|| format!("parsing {}:{}", args.host, args.port))?;

    http_transport::serve(handler, addr, token_store).await
}
