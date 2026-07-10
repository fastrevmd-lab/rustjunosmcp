//! `rust-srxmcp` — Phase 1B entry point.
//!
//! Boots an opt-in second MCP endpoint on `:30032` (override
//! `JMCP_SRX_HTTP_PORT`). Wires bearer auth against the shared
//! `/etc/jmcp/tokens.json` store and registers Phase 1B tools.

mod cli;
mod cli_validate;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use cli::Cli;
use rust_junosmcp_auth::file::TokenStoreFile;
use rust_junosmcp_core::DeviceManager;
use rust_srxmcp::{http_transport, server::JmcpSrxHandler};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    rust_junosmcp_core::bootstrap::init_tracing();

    let args = Cli::parse();
    cli_validate::validate(&args).map_err(|error| anyhow::anyhow!(error))?;

    // ── Inventory + DeviceManager ────────────────────────────────────────────

    let inv_path = match &args.device_mapping {
        Some(p) => p.clone(),
        None => {
            // Without a device mapping, tools that open devices will fail at
            // call-time. We construct an empty inventory so the binary still
            // starts and srxmcp_status works.
            tracing::warn!("--device-mapping not set: NETCONF tools will fail at call-time");
            PathBuf::from("/etc/jmcp/devices.json")
        }
    };

    let (inventory, inv_hash) = rust_junosmcp_core::bootstrap::load_inventory(&inv_path)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("loading {}", inv_path.display()))?;
    tracing::info!(
        devices = inventory.names().len(),
        path = %inv_path.display(),
        "loaded inventory"
    );

    let host_key_policy = rust_junosmcp_core::bootstrap::build_host_key_policy(
        args.ssh_accept_new_host_keys,
        args.known_hosts_file.clone(),
    );

    let dev_manager = Arc::new(
        DeviceManager::with_path(
            inventory.clone(),
            inv_path.clone(),
            inv_hash,
            true,  // inventory_readonly — srxmcp never mutates the device list
            false, // allow_password_auth_add — not needed
        )
        .with_host_key_policy(host_key_policy),
    );

    // ── Token store ──────────────────────────────────────────────────────────

    let token_store = match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), _) => {
            let names: Vec<String> = inventory.names();
            let known: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            let store = TokenStoreFile::load(path, &known)
                .with_context(|| format!("loading {}", path.display()))?;
            tracing::info!(tokens = store.len(), "token store loaded");
            Some(Arc::new(ArcSwap::from_pointee(store)))
        }
        (None, true) => {
            tracing::warn!("--allow-no-auth: streamable-http will accept unauthenticated requests");
            None
        }
        (None, false) => {
            anyhow::bail!(
                "--tokens-file required for streamable-http (or pass --allow-no-auth for lab use)"
            );
        }
    };

    // ── Handler ──────────────────────────────────────────────────────────────

    let started = Arc::new(Instant::now());
    // Shared per-router lock map. Destructive sig-package workflows acquire
    // a permit before pre-flight re-runs (design D4 lock-first ordering).
    let transfer_locks =
        Arc::new(rust_junosmcp_core::tools::transfer_file::TransferLocks::default());
    let handler = JmcpSrxHandler::new(started, dev_manager.clone(), transfer_locks);

    // ── SIGHUP: reload token store ───────────────────────────────────────────
    #[cfg(unix)]
    if token_store.is_some() && args.device_mapping.is_none() {
        tracing::warn!(
            "--device-mapping not set: SIGHUP reload disabled (token store will not refresh on signal)"
        );
    }
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

    // ── Bind and serve ───────────────────────────────────────────────────────

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .with_context(|| format!("parsing {}:{}", args.host, args.port))?;

    #[cfg(feature = "tls")]
    let tls_config = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            Some(rust_srxmcp::tls::load(cert, key).context("loading TLS cert/key")?)
        }
        _ => None,
    };

    #[cfg(not(feature = "tls"))]
    if args.tls_cert.is_some() || args.tls_key.is_some() {
        anyhow::bail!(
            "rust-srxmcp built without the 'tls' feature; cannot honor --tls-cert/--tls-key"
        );
    }

    #[cfg(feature = "tls")]
    {
        http_transport::serve_with_tls(
            handler,
            addr,
            token_store,
            args.allowed_host.clone(),
            args.disable_host_check,
            tls_config,
        )
        .await
    }

    #[cfg(not(feature = "tls"))]
    {
        http_transport::serve(
            handler,
            addr,
            token_store,
            args.allowed_host.clone(),
            args.disable_host_check,
        )
        .await
    }
}
