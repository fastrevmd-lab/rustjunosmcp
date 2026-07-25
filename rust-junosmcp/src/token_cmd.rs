//! `rust-junosmcp token …` subcommand.

use crate::cli::TokenAction;
use anyhow::{Context, Result};
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use std::io::Write;
use std::path::Path;

pub fn run(action: TokenAction) -> Result<()> {
    match action {
        TokenAction::Add {
            tokens_file,
            name,
            routers,
            tools,
            server_pid,
        } => {
            let routers_scope = parse_scope(routers)?;
            let tools_scope = parse_scope(tools)?;
            // For `add`, we don't have inventory loaded. Pass empty slices
            // to KnownNames — validation will happen in the shared code.
            let known = build_known_names();
            let secret =
                TokenStoreFile::add(&tokens_file, &name, routers_scope, tools_scope, &known)
                    .with_context(|| format!("adding token '{name}'"))?;
            // Print only the secret to stdout; nothing else, so it can be
            // piped/captured.
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            sighup_if_requested(server_pid);
            Ok(())
        }
        TokenAction::List { tokens_file } => list(&tokens_file),
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let known = build_known_names();
            let removed = TokenStoreFile::revoke(&tokens_file, &name, &known)
                .with_context(|| format!("revoking '{name}'"))?;
            if removed {
                eprintln!("revoked '{name}'");
            } else {
                eprintln!("no such token '{name}' (no-op)");
            }
            sighup_if_requested(server_pid);
            Ok(())
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            let known = build_known_names();
            let secret = TokenStoreFile::rotate(&tokens_file, &name, &known)
                .with_context(|| format!("rotating '{name}'"))?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            sighup_if_requested(server_pid);
            Ok(())
        }
        TokenAction::SetScope {
            tokens_file,
            name,
            routers,
            tools,
            server_pid,
        } => {
            if routers.is_none() && tools.is_none() {
                anyhow::bail!("at least one of --routers or --tools must be provided");
            }
            let routers_scope = routers.map(parse_scope).transpose()?;
            let tools_scope = tools.map(parse_scope).transpose()?;
            let known = build_known_names();
            TokenStoreFile::set_scopes(&tokens_file, &name, routers_scope, tools_scope, &known)
                .with_context(|| format!("setting scopes for '{name}'"))?;

            // Read back and display the resulting scopes
            let store_file = TokenStoreFile::load(&tokens_file)
                .with_context(|| format!("reloading {}", tokens_file.display()))?;
            let store = store_file.store();
            if let Some(entry) = store.entries().iter().find(|e| e.name == name) {
                let routers_str = match &entry.devices {
                    ScopeSet::Wildcard => "*".to_string(),
                    ScopeSet::Allowlist(v) => v.join(","),
                };
                let tools_str = match &entry.tools {
                    ScopeSet::Wildcard => "*".to_string(),
                    ScopeSet::Allowlist(v) => v.join(","),
                };
                eprintln!("updated '{name}': routers=[{routers_str}], tools=[{tools_str}]");
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

fn list(path: &Path) -> Result<()> {
    let store_file =
        TokenStoreFile::load(path).with_context(|| format!("loading {}", path.display()))?;
    let store = store_file.store();
    if store.is_empty() {
        eprintln!("(no tokens)");
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<32} {:<24} {:<24} CREATED_AT",
        "NAME", "ROUTERS", "TOOLS"
    )?;
    for e in store.entries() {
        let routers = match &e.devices {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        let tools = match &e.tools {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        writeln!(
            out,
            "{:<32} {:<24} {:<24} {}",
            e.name,
            routers,
            tools,
            e.created_at.to_rfc3339()
        )?;
    }
    Ok(())
}

#[cfg(unix)]
// The last `unsafe` outside rust-junosmcp-auth, which is why `unsafe_code` is
// `deny` rather than `forbid`. This module moves to `mecmcp-runtime` in
// mecmcp Phase 3, where the signal is sent safely through `rustix`.
#[allow(unsafe_code)]
fn sighup_if_requested(pid: Option<i32>) {
    if let Some(pid) = pid {
        // SAFETY: libc::kill is an FFI call with no preconditions on `pid`; invalid pids
        // return ESRCH/EPERM via errno, which we capture below.
        let r = unsafe { libc::kill(pid, libc::SIGHUP) };
        if r != 0 {
            tracing::warn!(
                pid,
                errno = std::io::Error::last_os_error().raw_os_error(),
                "kill(SIGHUP) failed"
            );
        }
    }
}

#[cfg(not(unix))]
fn sighup_if_requested(_pid: Option<i32>) {
    // SIGHUP is unix-only; on non-unix we silently skip.
}
