mod cli;
mod cli_validate;
mod env_compat;
mod http_transport;
mod server;
#[cfg(feature = "tls")]
mod tls;
mod token_cmd;

use anyhow::{Context, Result};
use cli::{Command, Transport};
use rmcp::ServiceExt;
use rust_junosmcp_auth::file::TokenStoreFile;
use rust_junosmcp_core::{DeviceManager, OpenSshScpRunner, Policy, TransferConfig};
use server::JmcpHandler;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let env_compat::ParsedCli {
        cli: args,
        warnings,
    } = env_compat::parse();

    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            rust_junosmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("invalid --audit-redact: {e}"))?,
        )
    };
    let audit_cfg = rust_junosmcp_audit::AuditConfig {
        format: rust_junosmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
    };
    rust_junosmcp_audit::init_tracing(&audit_cfg).context("initializing audit tracing")?;
    env_compat::emit_warnings(&warnings);

    if let Some(Command::Token { action }) = args.command {
        return token_cmd::run(action);
    }

    cli_validate::validate(&args).map_err(|e| anyhow::anyhow!("{}", e))?;

    rust_junosmcp_core::tools::transfer_file::validate_scp_runtime(std::path::Path::new("scp"))
        .map_err(anyhow::Error::from)
        .context("checking file-transfer runtime dependency")?;

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
    let device_leases = std::sync::Arc::new(
        rust_junosmcp_core::DeviceLeaseManager::for_directory(&args.device_lease_dir)
            .with_context(|| {
                format!(
                    "initializing device leases in {}",
                    args.device_lease_dir.display()
                )
            })?,
    );
    let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
        device_leases,
    };
    let handler = JmcpHandler::new(dev_manager.clone(), policy, transfer_cfg, upgrade_cfg);
    #[cfg(feature = "srx")]
    let handler = handler.with_srx_runtime(
        token_store.is_some() && matches!(args.transport, Transport::StreamableHttp),
        rust_junosmcp_srx_core::workflows::support_bundle::SupportBundleStagingConfig::new(
            args.support_bundle_staging_dir.clone(),
            args.support_bundle_staging_max_bytes,
        ),
    );

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

            let limits = rust_junosmcp_core::limits::LimitsConfig {
                max_request_body_bytes: args.max_request_body_bytes,
                max_inflight_requests: args.max_inflight_requests,
                max_inflight_requests_per_token: args.max_inflight_requests_per_token,
                max_requests_per_second_per_token: args.max_requests_per_second_per_token,
                max_request_burst_per_token: args.max_request_burst_per_token,
                max_inflight_requests_per_router: args.max_inflight_requests_per_router,
                max_sessions: args.max_sessions,
                max_sessions_per_token: args.max_sessions_per_token,
                session_idle_timeout_secs: args.session_idle_timeout_secs,
                session_max_lifetime_secs: args.session_max_lifetime_secs,
            };

            http_transport::serve(
                handler,
                addr,
                token_store,
                args.allowed_host.clone(),
                args.disable_host_check,
                args.enable_metrics,
                limits,
                #[cfg(feature = "tls")]
                tls_cfg,
            )
            .await?;
        }
    }
    Ok(())
}
