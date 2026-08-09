//! Junos and SRX MCP server.
//!
//! Provides MCP tools for Junos device management (generic operations across all
//! Junos platforms) and SRX-specific operational workflows. Authenticates remote
//! callers via HTTP Bearer tokens with per-token tool and device scopes, and
//! supports unauthenticated stdio transport for local-only operation.
//!
//! See [`server::JmcpHandler`] for the tool surface and
//! `rust-junosmcp-auth::tower` for the authentication boundary.

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod cli;
mod env_compat;
#[cfg(feature = "tls")]
mod tls;
mod token_cmd;

use anyhow::{Context, Result};
use cli::{Command, Transport};
use rmcp::ServiceExt;
use rust_junosmcp::server::JmcpHandler;
use rust_junosmcp_auth::TokenStoreFile;
use rust_junosmcp_core::{DeviceManager, MecmcpScpRunner, Policy, TransferConfig};
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
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("invalid --audit-redact: {e}"))?,
        )
    };
    let audit_cfg = mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
    };
    mecmcp_audit::init_tracing(&audit_cfg).context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("junosmcp_tool_duration_seconds");
    env_compat::emit_warnings(&warnings);

    if let Some(Command::Token { action }) = args.command {
        return token_cmd::run(action);
    }

    // Convert to shared CLI for validation
    let shared_cli = mecmcp_runtime::cli::Cli {
        command: None, // Not checked by validate
        device_mapping: args.device_mapping.clone(),
        transport: args.transport,
        host: args.host.clone(),
        port: args.port,
        tokens_file: args.tokens_file.clone(),
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        allow_no_auth: args.allow_no_auth,
        allow_insecure_bind: args.allow_insecure_bind,
        allowed_host: args.allowed_host.clone(),
        allowed_origin: args.allowed_origin.clone(),
        audit_format: args.audit_format.clone(),
        audit_log_file: args.audit_log_file.clone(),
        audit_journald: args.audit_journald,
        audit_redact: args.audit_redact.clone(),
        audit_hmac_key_file: args.audit_hmac_key_file.clone(),
    };
    mecmcp_runtime::cli_validate::validate(&shared_cli).map_err(|e| anyhow::anyhow!("{}", e))?;

    // Vendor-specific validation.
    //
    // These two rules cannot live in mecmcp-runtime: --inventory-readonly,
    // --allow-password-auth-add, and --enable-metrics are junos flags, and the
    // shared Cli struct has no fields for them. The Phase 3b migration moved
    // cli_validate.rs upstream and dropped the inventory rule on the way — the
    // doc comment on --allow-password-auth-add still promised "Mutually
    // exclusive with --inventory-readonly" while the binary happily accepted
    // both, which is the same class of defect as #217 with the polarity
    // reversed: documentation asserting a constraint nothing enforces.
    if args.inventory_readonly && args.allow_password_auth_add {
        anyhow::bail!(
            "--inventory-readonly and --allow-password-auth-add are mutually exclusive: \
             the first rejects add_device outright, the second widens what it accepts"
        );
    }
    if args.enable_metrics && args.transport != Transport::StreamableHttp {
        anyhow::bail!("--enable-metrics requires --transport streamable-http");
    }

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
            let store_file = TokenStoreFile::load(path)
                .with_context(|| format!("loading {}", path.display()))?;
            tracing::info!(tokens = store_file.store().len(), "token store loaded");
            Some(Arc::new(store_file))
        }
        (None, true) => {
            tracing::warn!("--allow-no-auth: streamable-http will accept unauthenticated requests");
            None
        }
        (None, false) if matches!(args.transport, Transport::StreamableHttp) => {
            unreachable!(
                "mecmcp_runtime::cli_validate::validate should have refused this combination"
            );
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
        scp_runner: std::sync::Arc::new(MecmcpScpRunner),
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
    rust_junosmcp_core::tools::set_cleanup_timeout_secs(args.cleanup_timeout_secs);
    // State the aggregate at startup rather than leaving an operator to derive
    // it. The mismatch between this and a client's idle timeout is what turns a
    // stalled device into "sent no response" with no other explanation (#257).
    tracing::info!(
        cleanup_timeout_secs = args.cleanup_timeout_secs,
        worst_case_secs =
            rust_junosmcp_core::tools::worst_case_duration(std::time::Duration::from_secs(360))
                .as_secs(),
        "device operation budget: a stalled 360s call can run to the worst case \
         before returning; a client idle timeout below that will abandon it"
    );

    // Lab mode removes two-person control, so say so where an operator will
    // actually see it. Reading it off flags typed weeks ago is not visibility.
    if args.lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets are approved on creation with no second \
             principal. Records carry approval_waiver=lab-mode. Do not run this against \
             production devices."
        );
    }

    let coordinator = std::sync::Arc::new(
        mecmcp_changeset::ChangesetCoordinator::load(
            Some(&args.changeset_state_file),
            mecmcp_changeset::OperationLimits::default(),
            std::time::Duration::from_secs(args.changeset_approval_timeout_secs),
            args.lab_mode,
        )
        .with_context(|| {
            format!(
                "initializing changeset coordinator at {}",
                args.changeset_state_file.display()
            )
        })?,
    );
    let handler = JmcpHandler::new(
        dev_manager.clone(),
        policy,
        transfer_cfg,
        upgrade_cfg,
        coordinator,
    );
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
    if let (Some(store_file), Some(_path)) = (token_store.clone(), args.tokens_file.clone()) {
        // Inventory is now mutable at runtime (add_device / reload_devices).
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
                match rust_junosmcp_core::tools::reload_devices::reload_current_from_disk(
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
                // Reload the token store. The shared TokenStoreFile's reload()
                // method swaps the internal store atomically.
                match store_file.reload() {
                    Ok(()) => {
                        tracing::info!(path = %store_file.path().display(), "token store reloaded");
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

            let limits = mecmcp_transport::LimitsConfig {
                max_request_body_bytes: args.max_request_body_bytes,
                max_inflight_requests: args.max_inflight_requests,
                max_inflight_requests_per_token: args.max_inflight_requests_per_token,
                max_requests_per_second_per_ip: args.max_requests_per_second_per_ip,
                max_request_burst_per_ip: args.max_request_burst_per_ip,
                max_requests_per_second_per_token: args.max_requests_per_second_per_token,
                max_request_burst_per_token: args.max_request_burst_per_token,
                max_inflight_requests_per_device: args.max_inflight_requests_per_router,
                max_sessions: args.max_sessions,
                max_sessions_per_token: args.max_sessions_per_token,
                session_idle_timeout_secs: args.session_idle_timeout_secs,
                session_max_lifetime_secs: args.session_max_lifetime_secs,
            };

            // Install graceful shutdown handler for SIGINT/SIGTERM.
            // mecmcp-runtime 0.7.0: GracefulShutdown::new() returns Result.
            let shutdown_coordinator = mecmcp_runtime::shutdown::GracefulShutdown::new()
                .context("installing shutdown signal handlers")?;

            // The shutdown token is passed to both the router builder (which gives it to
            // rmcp for SSE session termination) and serve_router (which uses it to drain
            // in-flight HTTP connections). Using separate tokens would leave SSE streams
            // live past the drain timeout.
            let shutdown_token = tokio_util::sync::CancellationToken::new();

            // Wire the shutdown coordinator to the token so SIGTERM/SIGINT trigger it.
            let shutdown_signal = shutdown_coordinator.subscribe();
            let shutdown_token_clone = shutdown_token.clone();
            tokio::spawn(async move {
                shutdown_signal.await;
                shutdown_token_clone.cancel();
            });

            // Shutdown timeout: give in-flight requests 10s to complete.
            // rmcp terminates SSE sessions immediately on the same token, so this
            // timeout only bounds stuck connections (e.g., slow clients, network issues).
            let shutdown_timeout = std::time::Duration::from_secs(10);

            rust_junosmcp::http_transport::serve_http(
                handler,
                addr,
                token_store,
                args.allowed_host.clone(),
                Vec::new(), // allowed_origins: empty by default (no browser CORS)
                limits,
                args.enable_metrics,
                #[cfg(feature = "tls")]
                tls_cfg,
                #[cfg(not(feature = "tls"))]
                None,
                shutdown_token,
                shutdown_timeout,
            )
            .await?;
        }
    }
    Ok(())
}
