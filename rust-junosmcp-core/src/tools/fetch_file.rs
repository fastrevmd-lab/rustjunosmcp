//! `fetch_file` MCP tool. SCP a file from a Junos device's /var/tmp/ back
//! to the host's staging directory, with per-router serialization and
//! sha256 verification. Mirror image of `transfer_file`.

use std::sync::Arc;

use crate::cancel::{select_cancel, select_cancel_raw};
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::transfer_file::{
    hex32, parse_checksum_output, scrub_scp_stderr, sha256_file_cancellable,
    validate_source_basename, ScpFetchJob, TransferConfig,
};
use crate::tools::FetchFileArgs;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

fn skipped_response(
    local_path: &std::path::Path,
    remote_basename: &str,
    sha: &[u8; 32],
    size: u64,
) -> Value {
    json!({
        "status": "skipped",
        "local_path": local_path.display().to_string(),
        "remote_path": format!("/var/tmp/{}", remote_basename),
        "size_bytes": size,
        "sha256": hex32(sha),
        "verified": true,
        "message": "local file already present with matching sha256; no fetch performed",
    })
}

pub async fn handle(
    args: FetchFileArgs,
    dm: Arc<DeviceManager>,
    cfg: TransferConfig,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        // Issue #44 Half A: short-circuit if the request was cancelled
        // before we even entered the body.
        if ct.is_cancelled() {
            return Err(JmcpError::Cancelled);
        }
        validate_source_basename(&args.remote_path)?;
        let local_basename = args
            .local_name
            .clone()
            .unwrap_or_else(|| args.remote_path.clone());
        validate_source_basename(&local_basename)?;

        // RJMCP-SEC-004: known_hosts is mandatory unless the operator opted
        // into TOFU (`--ssh-accept-new-host-keys`).
        match std::fs::metadata(&cfg.known_hosts_file) {
            Ok(m) if m.is_file() => {}
            _ if cfg.accept_new_host_keys => {
                tracing::info!(
                    known_hosts = %cfg.known_hosts_file.display(),
                    "fetch_file: known_hosts missing; running in accept-new (TOFU) mode"
                );
            }
            _ => {
                return Err(JmcpError::KnownHostsMissing(cfg.known_hosts_file.clone()));
            }
        }

        // Per-router serialization (shared with transfer_file). Acquired AFTER
        // basename validation so an obviously-bogus path never queues behind a
        // live transfer.
        let _permit =
            select_cancel_raw(&ct, cfg.transfer_locks.acquire(&args.router_name)).await?;

        // Resolve device + check auth type. Snapshot the fields we need before
        // dropping the borrow so we can hand `dm` to `dm.open(...)` below.
        let inv = dm.inventory();
        let entry = inv.get(&args.router_name)?;
        let private_key_path = match &entry.auth {
            AuthConfig::Password { .. } => {
                return Err(JmcpError::UnsupportedAuth(args.router_name.clone()));
            }
            AuthConfig::SshKey { private_key_path } => private_key_path.clone(),
        };
        let host = entry.ip.clone();
        let port = entry.port;
        let username = entry.username.clone();
        drop(inv);

        let remote_basename = args.remote_path.clone();
        let remote_path = format!("/var/tmp/{}", remote_basename);
        let local_path = cfg.staging_dir.join(&local_basename);

        // Open pooled NETCONF session for the remote checksum probe.
        let mut dev = select_cancel(&ct, dm.open(&args.router_name)).await?;

        // Probe remote checksum. If absent, fail fast.
        let probe_cmd = format!("file checksum sha-256 {}", remote_path);
        let probe_out = select_cancel_raw(&ct, dev.cli(&probe_cmd))
            .await?
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "remote_checksum".into(),
                message: e.to_string(),
            })?;
        let remote_sha = match parse_checksum_output(&probe_out)? {
            Some(s) => s,
            None => {
                return Err(JmcpError::RemoteFileMissing {
                    router: args.router_name.clone(),
                    remote_path: remote_path.clone(),
                });
            }
        };

        // Idempotent skip / local-conflict check.
        if let Ok(meta) = std::fs::symlink_metadata(&local_path) {
            if meta.file_type().is_symlink() {
                return Err(JmcpError::BadSourcePath(format!(
                    "local destination is a symlink, refusing to overwrite: {}",
                    local_path.display()
                )));
            }
            if meta.is_file() {
                let (local_sha, local_size) =
                    sha256_file_cancellable(&local_path, &ct).await?;
                if local_sha == remote_sha {
                    return Ok(skipped_response(
                        &local_path,
                        &remote_basename,
                        &local_sha,
                        local_size,
                    ));
                }
                if !args.force {
                    return Err(JmcpError::LocalDestExistsDiffers {
                        dest: local_path.display().to_string(),
                        local_sha: hex32(&local_sha),
                        remote_sha: hex32(&remote_sha),
                    });
                }
                // force=true: fall through and overwrite.
            }
        }

        // SCP the file down.
        let job = ScpFetchJob {
            private_key_path,
            known_hosts_file: cfg.known_hosts_file.clone(),
            username,
            host,
            port,
            remote_path: remote_path.clone(),
            local_path: local_path.clone(),
            accept_new_host_keys: cfg.accept_new_host_keys,
        };
        let outcome = cfg
            .scp_runner
            .fetch(&job, &ct)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::Interrupted => JmcpError::Cancelled,
                _ => JmcpError::Io(e),
            })?;
        if outcome.exit_code != 0 {
            if outcome.exit_code == 255
                && (outcome.stderr.contains("Connection timed out")
                    || outcome.stderr.contains("No route to host"))
            {
                return Err(JmcpError::ConnectTimeout(args.router_name.clone()));
            }
            return Err(JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: scrub_scp_stderr(&outcome.stderr),
            });
        }

        // Post-fetch local hash + verify.
        let (post_sha, post_size) = sha256_file_cancellable(&local_path, &ct).await?;
        let verified = post_sha == remote_sha;
        if args.verify && !verified {
            // Best-effort cleanup of the corrupted local file.
            let _ = std::fs::remove_file(&local_path);
            return Err(JmcpError::FetchVerifyMismatch {
                dest: local_path.display().to_string(),
                local_sha: hex32(&post_sha),
                remote_sha: hex32(&remote_sha),
            });
        }

        Ok(json!({
            "status": "fetched",
            "local_path": local_path.display().to_string(),
            "remote_path": remote_path,
            "size_bytes": post_size,
            "sha256": hex32(&post_sha),
            "verified": verified,
        }))
    })
    .await
    .map_err(|_| JmcpError::TransferOuterTimeout(timeout))?
}

#[cfg(test)]
mod handle_tests {
    #[tokio::test]
    #[ignore = "needs fake-device helper from Task 6"]
    async fn fetches_emits_skipped_when_local_matches_remote() {
        // placeholder
    }
}
