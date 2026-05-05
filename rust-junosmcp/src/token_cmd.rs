//! `rust-junosmcp token …` subcommand.

use crate::cli::TokenAction;
use anyhow::{Context, Result};
use rust_junosmcp_auth::{ScopeSet, TokenStoreFile};
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
            let routers = parse_scope(routers)?;
            let tools = parse_scope(tools)?;
            let secret = TokenStoreFile::add(&tokens_file, &name, routers, tools)
                .with_context(|| format!("adding token '{name}'"))?;
            // Print only the secret to stdout; nothing else, so it can be
            // piped/captured.
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose())?;
            sighup_if_requested(server_pid);
            Ok(())
        }
        TokenAction::List { tokens_file } => list(&tokens_file),
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let removed = TokenStoreFile::revoke(&tokens_file, &name)
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
            let secret = TokenStoreFile::rotate(&tokens_file, &name)
                .with_context(|| format!("rotating '{name}'"))?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose())?;
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

fn list(path: &Path) -> Result<()> {
    let store =
        TokenStoreFile::load(path, &[]).with_context(|| format!("loading {}", path.display()))?;
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
        let routers = match &e.routers {
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
