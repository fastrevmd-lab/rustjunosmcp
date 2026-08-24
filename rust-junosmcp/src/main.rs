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
mod state_cmd;
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

/// The (primary, legacy) pair handed to [`mecmcp_auth::resolve_token_path`].
///
/// The configured path is ALWAYS the primary. `/etc/jmcp/tokens.json` is the
/// legacy fallback that keeps an un-migrated upgrade starting.
///
/// Kept as a named function so the wiring is testable. The defect this guards
/// against is not in the resolution logic but in which arguments reach it:
/// hardcoding `/var/lib/jmcp/tokens.json` as the primary and passing the CLI
/// value as the fallback collapses both to one path, because the shipped unit
/// passes exactly that. There is then no fallback at all, and an upgraded guest
/// whose tokens are still in /etc fails to start.
fn token_path_pair(configured: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    const LEGACY_TOKENS: &str = "/etc/jmcp/tokens.json";
    (
        configured.to_path_buf(),
        std::path::PathBuf::from(LEGACY_TOKENS),
    )
}

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

    match args.command {
        Some(Command::Token { action }) => return token_cmd::run(action),
        Some(Command::State { action }) => return state_cmd::run(action),
        None => {}
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
        evidence: args.evidence.clone(),
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
        (Some(configured_path), _) => {
            // The CONFIGURED path is the primary; the legacy /etc/jmcp location is
            // the fallback, so an upgrade whose tokens have not been moved yet still
            // starts.
            //
            // Do NOT hardcode /var/lib as the primary and pass the CLI value as the
            // fallback. The shipped unit passes
            // `--tokens-file /var/lib/jmcp/tokens.json`, so both arguments would
            // collapse to the same path and there would be no fallback at all — an
            // upgraded guest with tokens still in /etc/jmcp fails to start, which is
            // the client lockout #333 exists to prevent.
            let (primary, legacy) = token_path_pair(configured_path);
            let resolved = mecmcp_auth::resolve_token_path(&primary, &legacy)
                .context("resolving token file path")?;

            if resolved.used_fallback {
                tracing::warn!(
                    primary = %primary.display(),
                    fallback = %legacy.display(),
                    "tokens.json found in the legacy /etc location; migrate it to {} and remove \
                     the stale copy. It is NOT copied automatically, and /etc is read-only to \
                     the service under ProtectSystem=strict.",
                    primary.display()
                );
            }

            let store_file = TokenStoreFile::load(&resolved.path)
                .with_context(|| format!("loading {}", resolved.path.display()))?;
            tracing::info!(
                tokens = store_file.store().len(),
                path = %resolved.path.display(),
                "token store loaded"
            );
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

    // Plane-owned writes flag defeats the durability check #292 was created to
    // provide. Log its state at startup so it's visible, not just a flag typed once.
    //
    // Deliberately NOT on `target: "audit"`. That stream carries one record per
    // tool call with a fixed schema — request_id, caller, tool, action, result —
    // and downstream SIEM queries parse it on that basis. A startup banner has
    // none of those fields, so emitting it there pollutes the audit stream with
    // something no consumer can interpret as an action record.
    if args.allow_plane_owned_writes {
        tracing::warn!(
            "allow-plane-owned-writes enabled: destructive operations on devices owned by \
             management planes (Mist, Security Director) will proceed with a warning instead \
             of refusal. Changes to plane-owned devices may be overwritten at the next push. \
             This flag is for break-glass scenarios only."
        );
    } else {
        tracing::info!(
            "plane-owned device protection active: load_and_commit_config, rollback_config, \
             and upgrade_junos refuse operations on devices whose config_authority is not \
             'local' or 'unknown' (default). Use --allow-plane-owned-writes for break-glass."
        );
    }

    // The SSDF evidence pipeline, when configured. Built before the coordinator
    // because the coordinator takes its recorder, and started here rather than
    // lazily so a misconfiguration -- an unwritable spool, a credential with
    // the wrong mode, an unreachable ClickHouse -- fails the server at startup
    // instead of at the first change, which is the worst moment to discover it.
    let evidence = match args.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let transport = std::sync::Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.evidence.ca_file(),
                    provider,
                )
                .context("building the SSDF evidence transport")?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(config, transport)
                    .context("starting the SSDF evidence pipeline")?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };

    let mut changeset_coordinator = mecmcp_changeset::ChangesetCoordinator::load(
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
    })?;
    if let Some(service) = &evidence {
        changeset_coordinator = changeset_coordinator.with_evidence(service.recorder());
    }
    let coordinator = std::sync::Arc::new(changeset_coordinator);
    let handler = JmcpHandler::new(
        dev_manager.clone(),
        policy,
        transfer_cfg,
        upgrade_cfg,
        coordinator,
        args.allow_plane_owned_writes,
        args.web_approver.web_enabled_approver,
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

    // Bound rather than propagated with `?`, so the evidence flush below runs
    // whichever way serving ended. Returning the error directly would skip it,
    // and `EvidenceService::Drop` deliberately does not spool -- a Drop that
    // performs network I/O turns teardown into an unpredictable stall -- so
    // every proposal and approval the recorder still held would be lost on a
    // controlled transport failure. That is the case the trail exists for.
    let served: anyhow::Result<()> = async {
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
                // Was Vec::new() with a comment claiming "empty by default (no
                // browser CORS)". The CLI has always accepted --allowed-origin,
                // and LXC 950's unit passes it — so the flag was parsed, shown in
                // --help, and silently discarded here. Same defect class as
                // mecmcp#273: present but ignored.
                args.allowed_origin.clone(),
                limits,
                args.enable_metrics,
                #[cfg(feature = "tls")]
                tls_cfg,
                #[cfg(not(feature = "tls"))]
                None,
                args.allow_insecure_bind,
                shutdown_token,
                shutdown_timeout,
            )
            .await?;
        }
        }
        Ok(())
    }
    .await;

    // Deliver what is still spooled before the process leaves. The drain ships
    // on an interval, so without this every record written since the last tick
    // waits for the next start -- and a segment still open has never been
    // spooled at all. A failure here is reported rather than swallowed: the
    // records stay in the outbox and the next start replays them, but an
    // operator stopping a server has no other signal that its trail is behind.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

#[cfg(test)]
mod token_path_tests {
    use super::token_path_pair;
    use std::path::Path;

    /// The shipped unit passes `--tokens-file /var/lib/jmcp/tokens.json`. If the
    /// primary is hardcoded to that value the two arguments become identical and
    /// the /etc fallback silently disappears.
    #[test]
    fn shipped_unit_path_still_leaves_a_distinct_fallback() {
        let (primary, legacy) = token_path_pair(Path::new("/var/lib/jmcp/tokens.json"));
        assert_ne!(
            primary, legacy,
            "primary and fallback collapsed to one path - the /etc fallback is gone"
        );
        assert_eq!(primary, Path::new("/var/lib/jmcp/tokens.json"));
        assert_eq!(legacy, Path::new("/etc/jmcp/tokens.json"));
    }

    /// An operator-supplied path must be honoured as the primary, not discarded.
    #[test]
    fn an_explicit_path_is_used_as_the_primary() {
        let (primary, legacy) = token_path_pair(Path::new("/srv/custom/tokens.json"));
        assert_eq!(primary, Path::new("/srv/custom/tokens.json"));
        assert_ne!(primary, legacy);
    }
}
