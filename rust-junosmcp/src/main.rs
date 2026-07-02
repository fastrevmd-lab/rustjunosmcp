mod cli;
mod cli_validate;
mod http_transport;
mod server;
#[cfg(feature = "tls")]
mod tls;
mod token_cmd;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command, Transport};
use rmcp::ServiceExt;
use rust_junosmcp_auth::file::TokenStoreFile;
use rust_junosmcp_core::{DeviceManager, OpenSshScpRunner, Policy, TransferConfig};
use server::JmcpHandler;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    rust_junosmcp_core::bootstrap::init_tracing();

    let args = Cli::parse();

    if let Some(Command::Token { action }) = args.command {
        return token_cmd::run(action);
    }

    cli_validate::validate(&args).map_err(|e| anyhow::anyhow!("{}", e))?;

    let inv_path = args.device_mapping.clone();
    let (inventory, inv_hash) = rust_junosmcp_core::bootstrap::load_inventory(&inv_path)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("loading {}", inv_path.display()))?;
    tracing::info!(
        devices = inventory.names().len(),
        path = %inv_path.display(),
        "loaded inventory"
    );

    let policy = Arc::new(Policy::build(&inventory).context("compiling blocklist policy")?);
    let counts = policy.rule_counts();
    tracing::info!(
        default_command_rules = counts.default_commands,
        default_config_rules = counts.default_config,
        devices_with_rules = counts.devices_with_rules,
        total_devices = inventory.names().len(),
        "blocklist policy loaded"
    );
    // Mirror the scp host-key posture for NETCONF SSH:
    //   default → strict KnownHosts lookup against --known-hosts-file
    //   --ssh-accept-new-host-keys → lab/TOFU mode (AcceptAll)
    // Without this opt-in the rustez/rustnetconf 0.11+ default is RejectAll
    // (fail-closed) and every op command would error `Unknown server key`.
    let host_key_policy = rust_junosmcp_core::bootstrap::build_host_key_policy(
        args.ssh_accept_new_host_keys,
        args.known_hosts_file.clone(),
    );
    let dev_manager = Arc::new(
        DeviceManager::with_path(
            inventory.clone(),
            inv_path,
            inv_hash,
            args.inventory_readonly,
            args.allow_password_auth_add,
        )
        .with_host_key_policy(host_key_policy),
    );

    // Build the token store (or None for --allow-no-auth / stdio).
    let token_store = match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), _) => {
            let names = inventory.names();
            let known: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            let store = TokenStoreFile::load(path, &known)
                .with_context(|| format!("loading {}", path.display()))?;
            tracing::info!(tokens = store.len(), "token store loaded");
            Some(Arc::new(arc_swap::ArcSwap::from_pointee(store)))
        }
        (None, true) => {
            tracing::warn!("--allow-no-auth: streamable-http will accept unauthenticated requests");
            None
        }
        (None, false) if matches!(args.transport, Transport::StreamableHttp) => {
            unreachable!("cli_validate::validate should have refused this combination");
        }
        _ => None,
    };

    if args.ssh_accept_new_host_keys {
        tracing::warn!(
            "--ssh-accept-new-host-keys: scp pins unknown host keys on first contact (TOFU); NETCONF SSH uses HostKeyVerification::AcceptAll. Use only in lab environments."
        );
    } else {
        tracing::info!(
            known_hosts = %args.known_hosts_file.display(),
            "ssh host-key policy: scp StrictHostKeyChecking=yes + NETCONF HostKeyVerification::KnownHosts (strict, default)"
        );
    }
    let transfer_cfg = TransferConfig {
        staging_dir: args.staging_dir.clone(),
        known_hosts_file: args.known_hosts_file.clone(),
        scp_runner: std::sync::Arc::new(OpenSshScpRunner),
        // Process-wide per-router serialization (issue #26, L4).
        transfer_locks: std::sync::Arc::new(
            rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
        ),
        accept_new_host_keys: args.ssh_accept_new_host_keys,
    };
    let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
    };
    let handler = JmcpHandler::new(dev_manager.clone(), policy, transfer_cfg, upgrade_cfg);

    // SIGHUP hot reload of the token store (unix only). On HUP, re-read the
    // tokens file and atomically swap the ArcSwap so subsequent requests see
    // the new state. Stdio mode and --allow-no-auth produce a None token_store
    // and skip this entirely.
    #[cfg(unix)]
    if let (Some(store_arc), Some(path)) = (token_store.clone(), args.tokens_file.clone()) {
        // Inventory is now mutable at runtime (add_device / reload_devices).
        // We must refresh `known` from dev_manager.inventory().names() each iteration
        // so token-scope validation sees the post-reload router set.
        let dm = dev_manager.clone();
        let hup_handler = handler.clone();
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
                tracing::info!("SIGHUP: reloading token store and inventory");
                // Reload inventory FIRST so the token store sees current routers.
                match rust_junosmcp_core::tools::reload_devices::handle(
                    rust_junosmcp_core::tools::ReloadDevicesArgs::default(),
                    dm.clone(),
                )
                .await
                {
                    Ok(result) => {
                        hup_handler.rebuild_policy();
                        tracing::info!(?result, "inventory reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "inventory reload failed; keeping previous inventory");
                    }
                }
                // Refresh known router names from the (possibly updated) inventory.
                let known: Vec<String> = dm.inventory().names();
                let known_refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
                match TokenStoreFile::load(&path, &known_refs) {
                    Ok(new_store) => {
                        store_arc.store(Arc::new(new_store));
                        tracing::info!(path = %path.display(), "token store reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "SIGHUP reload failed; keeping previous store");
                    }
                }
            }
        });
    }

    match args.transport {
        Transport::Stdio => {
            let service = handler
                .serve((tokio::io::stdin(), tokio::io::stdout()))
                .await
                .context("starting MCP stdio service")?;
            service
                .waiting()
                .await
                .context("MCP service exited with error")?;
        }
        Transport::StreamableHttp => {
            let addr: std::net::SocketAddr = format!("{}:{}", args.host, args.port)
                .parse()
                .with_context(|| format!("parsing {}:{}", args.host, args.port))?;

            #[cfg(feature = "tls")]
            let tls_cfg = match (&args.tls_cert, &args.tls_key) {
                (Some(cert), Some(key)) => {
                    Some(tls::load(cert, key).context("loading TLS cert/key")?)
                }
                _ => None,
            };

            #[cfg(not(feature = "tls"))]
            if args.tls_cert.is_some() || args.tls_key.is_some() {
                anyhow::bail!(
                    "rust-junosmcp built without the 'tls' feature; cannot honor --tls-cert/--tls-key"
                );
            }

            http_transport::serve(
                handler,
                addr,
                token_store,
                args.allowed_host.clone(),
                args.disable_host_check,
                #[cfg(feature = "tls")]
                tls_cfg,
            )
            .await?;
        }
    }
    Ok(())
}
