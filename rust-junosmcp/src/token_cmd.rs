//! `rust-junosmcp token …` subcommand.

use crate::cli::TokenAction;
use anyhow::{Context, Result};
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};

pub fn run(action: TokenAction) -> Result<()> {
    match action {
        TokenAction::Add {
            tokens_file,
            name,
            devices,
            tools,
            server_pid,
        } => {
            // Convert to mecmcp-runtime's TokenAction format
            let runtime_action = mecmcp_runtime::cli::TokenAction::Add {
                tokens_file,
                name,
                devices,
                tools,
                server_pid,
            };
            mecmcp_runtime::token_cmd::run(
                runtime_action,
                &[], // No inventory loaded; validation is lenient
                rust_junosmcp_auth::KNOWN_TOOLS,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))
        }
        TokenAction::List { tokens_file } => {
            let runtime_action = mecmcp_runtime::cli::TokenAction::List { tokens_file };
            mecmcp_runtime::token_cmd::run(runtime_action, &[], rust_junosmcp_auth::KNOWN_TOOLS)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let runtime_action = mecmcp_runtime::cli::TokenAction::Revoke {
                tokens_file,
                name,
                server_pid,
            };
            mecmcp_runtime::token_cmd::run(runtime_action, &[], rust_junosmcp_auth::KNOWN_TOOLS)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            let runtime_action = mecmcp_runtime::cli::TokenAction::Rotate {
                tokens_file,
                name,
                server_pid,
            };
            mecmcp_runtime::token_cmd::run(runtime_action, &[], rust_junosmcp_auth::KNOWN_TOOLS)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        TokenAction::SetScope {
            tokens_file,
            name,
            devices,
            tools,
            server_pid,
        } => {
            // SetScope stays junos-only (plan D7)
            if devices.is_none() && tools.is_none() {
                anyhow::bail!("at least one of --devices or --tools must be provided");
            }
            let devices_scope = devices.map(parse_scope).transpose()?;
            let tools_scope = tools.map(parse_scope).transpose()?;
            let known = build_known_names();
            TokenStoreFile::set_scopes(&tokens_file, &name, devices_scope, tools_scope, &known)
                .with_context(|| format!("setting scopes for '{name}'"))?;

            // Read back and display the resulting scopes
            let store_file = TokenStoreFile::load(&tokens_file)
                .with_context(|| format!("reloading {}", tokens_file.display()))?;
            let store = store_file.store();
            if let Some(entry) = store.entries().iter().find(|e| e.name == name) {
                let devices_str = match &entry.devices {
                    ScopeSet::Wildcard => "*".to_string(),
                    ScopeSet::Allowlist(v) => v.join(","),
                };
                let tools_str = match &entry.tools {
                    ScopeSet::Wildcard => "*".to_string(),
                    ScopeSet::Allowlist(v) => v.join(","),
                };
                eprintln!("updated '{name}': devices=[{devices_str}], tools=[{tools_str}]");
            }
            sighup_if_requested(server_pid);
            Ok(())
        }
    }
}

fn parse_scope(parts: Vec<String>) -> Result<ScopeSet> {
    if parts.iter().any(|p| p == "*") && parts.len() > 1 {
        anyhow::bail!("scope cannot mix '*' with other names: {parts:?}");
    }
    if parts.len() == 1 && parts[0] == "*" {
        Ok(ScopeSet::Wildcard)
    } else {
        Ok(ScopeSet::Allowlist(parts))
    }
}

fn build_known_names() -> KnownNames<'static> {
    // Device names: token operations happen before inventory is loaded.
    // Use None to skip device-name validation (lenient, warns on unknown).
    // Tool validation is always enforced (fatal on unknown).
    KnownNames {
        devices: None,
        tools: rust_junosmcp_auth::KNOWN_TOOLS,
    }
}

#[cfg(unix)]
fn sighup_if_requested(pid: Option<i32>) {
    if let Some(raw) = pid {
        if let Some(pid) = rustix::process::Pid::from_raw(raw) {
            if let Err(e) = rustix::process::kill_process(pid, rustix::process::Signal::Hup) {
                tracing::warn!(pid = raw, errno = e.raw_os_error(), "kill(SIGHUP) failed");
            }
        } else {
            tracing::warn!(pid = raw, "invalid server PID (must be positive)");
        }
    }
}

#[cfg(not(unix))]
fn sighup_if_requested(_pid: Option<i32>) {
    // SIGHUP is unix-only; on non-unix we silently skip.
}
