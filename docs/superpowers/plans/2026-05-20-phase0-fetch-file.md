# Phase 0: `fetch_file` MCP Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `fetch_file` MCP tool to `rust-junosmcp` that pulls a single
file from a Junos device's `/var/tmp/<basename>` back into the host
staging directory, with sha256 verification, idempotent skip, and per-router
serialization — mirror image of the existing `transfer_file` tool. Ships as
`rust-junosmcp` v0.6.0. Unlocks support-bundle, PKI-export, packet-capture,
and offline-artifact workflows that the planned `rust-srxmcp` binary will need.

**Architecture:** Mirror `transfer_file`'s design exactly. New tool handler
in `rust-junosmcp-core/src/tools/fetch_file.rs`. Reuses the existing
`validate_source_basename`, `sha256_file_cancellable`, `parse_checksum_output`,
`hex32`, `scrub_scp_stderr`, `TransferLocks`, and `TransferConfig` primitives.
Extends the `ScpRunner` trait with a `fetch()` method so the same `OpenSshScpRunner`
production impl (and `MockScpRunner` test double) handle both directions. The
new `ScpFetchJob` struct + `build_scp_fetch_argv` builder mirror their upload
counterparts, swapping argv positions so `scp` downloads instead of uploads.

**Tech Stack:** Rust 2021 edition, tokio, serde + schemars (JSON Schema), `scp` from
system openssh-client, `sha2` crate. Same as the rest of the workspace.

---

## File Structure

| Path | Action | Responsibility |
|---|---|---|
| `rust-junosmcp-core/src/tools/mod.rs` | modify | Register `fetch_file` module; add `FetchFileArgs` struct + default fns; add unit tests for arg defaults. |
| `rust-junosmcp-core/src/tools/fetch_file.rs` | create | `FetchFileArgs` handler `handle()` function. Owns the fetch workflow: validate basenames, acquire per-router permit, probe remote sha256, idempotent skip, SCP-pull, post-fetch local hash + verify. |
| `rust-junosmcp-core/src/tools/transfer_file.rs` | modify | Extend `ScpRunner` trait with `fetch()` method. Add `ScpFetchJob` struct + `build_scp_fetch_argv` builder. Add `OpenSshScpRunner::fetch()` impl. Add `MockScpRunner::fetch()` impl. |
| `rust-junosmcp-core/src/error.rs` | modify | Add `JmcpError::LocalDestExistsDiffers`, `JmcpError::RemoteFileMissing`, `JmcpError::FetchVerifyMismatch` variants. |
| `rust-junosmcp-core/src/lib.rs` | modify (if needed) | Re-export `FetchFileArgs` alongside the other public arg types (mirror existing `TransferFileArgs` re-export pattern). |
| `rust-junosmcp/src/server.rs` | modify | Add `fetch_file` to `SERVER_TOOLS`. Update tripwire `assert_eq!(SERVER_TOOLS.len(), 14)` → `15`. Add `#[tool(name = "fetch_file")]` handler method on `JmcpHandler`. Import `fetch_file` in the `tools::{...}` use. |
| `rust-junosmcp-auth/src/file.rs` | modify | Add `"fetch_file"` to `KNOWN_TOOLS` (alphabetical position between `"execute_junos_pfe_command"` and `"gather_device_facts"`). |
| `Cargo.toml` (workspace) | modify | Bump `[workspace.package] version` `0.5.10` → `0.6.0`. |
| `CHANGELOG.md` | modify | Add `[0.6.0]` section documenting `fetch_file` tool, new error variants, version bump. |
| `README.md` | modify | Add `fetch_file` to the tools table. |

---

## Task 1: Add `FetchFileArgs` schema and defaults

**Files:**
- Modify: `rust-junosmcp-core/src/tools/mod.rs:1-50` (default fns and module list), and append `FetchFileArgs` near the existing `TransferFileArgs` (around line 204).

- [ ] **Step 1: Add the failing test**

Add this test inside the existing `#[cfg(test)] mod tests` block in `rust-junosmcp-core/src/tools/mod.rs`:

```rust
#[test]
fn fetch_file_args_defaults() {
    let v = serde_json::json!({"router_name":"r1","remote_path":"foo.tgz"});
    let a: FetchFileArgs = serde_json::from_value(v).unwrap();
    assert_eq!(a.router_name, "r1");
    assert_eq!(a.remote_path, "foo.tgz");
    assert!(a.local_name.is_none());
    assert!(!a.force);
    assert!(a.verify);
    assert_eq!(a.timeout, 600);
}

#[test]
fn fetch_file_args_rejects_missing_remote_path() {
    let v = serde_json::json!({"router_name":"r1"});
    let r: Result<FetchFileArgs, _> = serde_json::from_value(v);
    assert!(r.is_err());
}

#[test]
fn fetch_file_args_accepts_local_name_override() {
    let v = serde_json::json!({
        "router_name":"r1",
        "remote_path":"foo.tgz",
        "local_name":"foo.local.tgz"
    });
    let a: FetchFileArgs = serde_json::from_value(v).unwrap();
    assert_eq!(a.local_name.as_deref(), Some("foo.local.tgz"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp-core --lib tools::tests::fetch_file_args`
Expected: FAIL with "cannot find type `FetchFileArgs` in this scope".

- [ ] **Step 3: Add the module declaration and struct**

At the top of `rust-junosmcp-core/src/tools/mod.rs`, add `pub mod fetch_file;` next to the existing `pub mod transfer_file;` (alphabetical ordering keeps it next to `pub mod facts;` — pick whichever the existing list uses; the file currently uses declaration order):

```rust
pub mod fetch_file;
```

Then add the `FetchFileArgs` struct after the existing `TransferFileArgs` definition (line 218 region):

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FetchFileArgs {
    /// Source router name (must exist in inventory and use ssh_key auth).
    pub router_name: String,
    /// Basename of the file under the device's /var/tmp/. Must not contain
    /// '/', '\\', or '..'. Same allowlist as transfer_file.
    pub remote_path: String,
    /// Optional override for the local basename written under the staging
    /// directory. Defaults to `remote_path`. Same allowlist applies.
    #[serde(default)]
    pub local_name: Option<String>,
    /// Overwrite if local dest exists with different sha256. Default false.
    #[serde(default)]
    pub force: bool,
    /// Post-fetch sha256 verification (local vs remote). Default true.
    #[serde(default = "default_verify")]
    pub verify: bool,
    /// Per-call timeout in seconds. Default 600.
    #[serde(default = "default_transfer_timeout")]
    pub timeout: u64,
}
```

- [ ] **Step 4: Create the empty fetch_file module so cargo compiles**

Create `rust-junosmcp-core/src/tools/fetch_file.rs` with exactly:

```rust
//! `fetch_file` MCP tool. SCP a file from a Junos device's /var/tmp/ back
//! to the host's staging directory, with per-router serialization and
//! sha256 verification. Mirror image of `transfer_file`.

// Implementation lands in Task 5; this file exists so the `pub mod
// fetch_file;` declaration in `tools/mod.rs` compiles.
```

- [ ] **Step 5: Run to verify passing**

Run: `cargo test -p rust-junosmcp-core --lib tools::tests::fetch_file_args`
Expected: 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add rust-junosmcp-core/src/tools/mod.rs rust-junosmcp-core/src/tools/fetch_file.rs
git commit -m "feat(fetch_file): add FetchFileArgs schema"
```

---

## Task 2: Add fetch-specific `JmcpError` variants

**Files:**
- Modify: `rust-junosmcp-core/src/error.rs`

- [ ] **Step 1: Add failing display tests**

Append to the existing `#[cfg(test)] mod tests` block in `rust-junosmcp-core/src/error.rs`:

```rust
#[test]
fn local_dest_exists_differs_display_has_code() {
    let s = JmcpError::LocalDestExistsDiffers {
        dest: "/var/lib/jmcp/staging/foo.tgz".into(),
        local_sha: "aaaa".into(),
        remote_sha: "bbbb".into(),
    }
    .to_string();
    assert!(s.contains("[code=local_dest_exists_differs]"), "{s}");
    assert!(s.contains("aaaa"), "{s}");
    assert!(s.contains("bbbb"), "{s}");
}

#[test]
fn remote_file_missing_display_has_code() {
    let s = JmcpError::RemoteFileMissing {
        router: "vsrx-test10".into(),
        remote_path: "/var/tmp/missing.txt".into(),
    }
    .to_string();
    assert!(s.contains("[code=remote_file_missing]"), "{s}");
    assert!(s.contains("vsrx-test10"), "{s}");
}

#[test]
fn fetch_verify_mismatch_display_has_code() {
    let s = JmcpError::FetchVerifyMismatch {
        dest: "/var/lib/jmcp/staging/foo.tgz".into(),
        local_sha: "aaaa".into(),
        remote_sha: "bbbb".into(),
    }
    .to_string();
    assert!(s.contains("[code=fetch_verify_mismatch]"), "{s}");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp-core --lib error::tests::local_dest_exists_differs_display_has_code`
Expected: FAIL with "no variant or associated item named `LocalDestExistsDiffers`".

- [ ] **Step 3: Add the variants**

In `rust-junosmcp-core/src/error.rs`, locate the `#[derive(...)] pub enum JmcpError` block and add (in the same style as the existing `DestExistsDiffers` and `VerifyMismatch` — search for those for the exact `#[error(...)]` pattern):

```rust
#[error("[code=local_dest_exists_differs] local destination '{dest}' exists with sha256 '{local_sha}'; remote sha256 is '{remote_sha}'; set force=true to overwrite")]
LocalDestExistsDiffers {
    dest: String,
    local_sha: String,
    remote_sha: String,
},

#[error("[code=remote_file_missing] router '{router}' has no file at '{remote_path}'")]
RemoteFileMissing {
    router: String,
    remote_path: String,
},

#[error("[code=fetch_verify_mismatch] fetched file '{dest}' local sha256 '{local_sha}' does not match remote sha256 '{remote_sha}'")]
FetchVerifyMismatch {
    dest: String,
    local_sha: String,
    remote_sha: String,
},
```

- [ ] **Step 4: Run to verify passing**

Run: `cargo test -p rust-junosmcp-core --lib error::tests`
Expected: All error tests pass (existing + 3 new).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/error.rs
git commit -m "feat(fetch_file): add LocalDestExistsDiffers / RemoteFileMissing / FetchVerifyMismatch errors"
```

---

## Task 3: Add `ScpFetchJob` and `build_scp_fetch_argv`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write failing argv-builder tests**

Append to the existing `#[cfg(test)] mod argv_tests` block in `rust-junosmcp-core/src/tools/transfer_file.rs`:

```rust
fn fetch_job() -> ScpFetchJob {
    ScpFetchJob {
        private_key_path: "/etc/jmcp/keys/id".into(),
        known_hosts_file: "/etc/jmcp/known_hosts".into(),
        username: "root".into(),
        host: "10.0.0.1".into(),
        port: 22,
        remote_path: "/var/tmp/foo.tgz".into(),
        local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
        accept_new_host_keys: false,
    }
}

#[test]
fn fetch_argv_uses_dash_capital_o_for_legacy_protocol() {
    let v = build_scp_fetch_argv(&fetch_job());
    assert_eq!(v[0], "-O");
}

#[test]
fn fetch_argv_default_uses_strict_host_key_checking_yes() {
    let v = build_scp_fetch_argv(&fetch_job());
    let joined = v.join(" ");
    assert!(joined.contains("StrictHostKeyChecking=yes"), "{joined}");
    assert!(!joined.contains("accept-new"), "{joined}");
}

#[test]
fn fetch_argv_source_is_user_host_colon_remote_path() {
    let v = build_scp_fetch_argv(&fetch_job());
    // For a download, the user@host:path arg comes BEFORE the local path.
    let src = v
        .iter()
        .position(|s| s == "root@10.0.0.1:/var/tmp/foo.tgz")
        .expect("source present");
    let dst = v
        .iter()
        .position(|s| s == "/var/lib/jmcp/staging/foo.tgz")
        .expect("dest present");
    assert!(src < dst, "expected source before dest, got argv: {v:?}");
}

#[test]
fn fetch_argv_includes_hardening_flags() {
    let v = build_scp_fetch_argv(&fetch_job());
    let joined = v.join(" ");
    assert!(joined.contains("BatchMode=yes"));
    assert!(joined.contains("PasswordAuthentication=no"));
    assert!(joined.contains("PreferredAuthentications=publickey"));
    assert!(joined.contains("IdentitiesOnly=yes"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::argv_tests::fetch_argv`
Expected: FAIL — `ScpFetchJob` / `build_scp_fetch_argv` don't exist.

- [ ] **Step 3: Add the struct and builder**

Add right after the existing `pub fn build_scp_argv(...)` function in `rust-junosmcp-core/src/tools/transfer_file.rs` (around line 592):

```rust
/// Inputs for one SCP download invocation. Mirror image of [`ScpJob`].
/// The remote_path is the FULL path on the device (e.g. `/var/tmp/foo.tgz`),
/// not a directory — `scp` downloads exactly one file.
#[derive(Clone, Debug)]
pub struct ScpFetchJob {
    pub private_key_path: PathBuf,
    pub known_hosts_file: PathBuf,
    pub username: String,
    pub host: String,
    pub port: u16,
    /// Full remote path, e.g. `/var/tmp/foo.tgz`.
    pub remote_path: String,
    /// Full local destination path under the staging directory.
    pub local_path: PathBuf,
    /// Host-key policy. See [`ScpJob::accept_new_host_keys`].
    pub accept_new_host_keys: bool,
}

/// Build the argv vector that downloads `remote_path` from the device to
/// `local_path`. Mirror image of [`build_scp_argv`]: the only structural
/// difference is that the source (user@host:path) comes before the local
/// destination, instead of after the local source.
pub fn build_scp_fetch_argv(job: &ScpFetchJob) -> Vec<String> {
    let source = format!("{}@{}:{}", job.username, job.host, job.remote_path);
    let host_key_policy = if job.accept_new_host_keys {
        "StrictHostKeyChecking=accept-new"
    } else {
        "StrictHostKeyChecking=yes"
    };
    vec![
        "-O".into(),
        "-i".into(),
        job.private_key_path.display().to_string(),
        "-o".into(),
        host_key_policy.into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", job.known_hosts_file.display()),
        "-o".into(),
        "ConnectTimeout=15".into(),
        "-o".into(),
        "ServerAliveInterval=10".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-P".into(),
        job.port.to_string(),
        source,
        job.local_path.display().to_string(),
    ]
}
```

- [ ] **Step 4: Run to verify passing**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::argv_tests`
Expected: All argv tests pass (existing + 4 new).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(fetch_file): add ScpFetchJob and build_scp_fetch_argv"
```

---

## Task 4: Extend `ScpRunner` trait with `fetch()` method

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write failing runner tests**

Append to the existing `#[cfg(test)] mod runner_tests` block in `rust-junosmcp-core/src/tools/transfer_file.rs`:

```rust
#[tokio::test]
async fn mock_fetch_records_argv_for_assertion() {
    let runner = MockScpRunner::ok();
    let job = ScpFetchJob {
        private_key_path: "/k".into(),
        known_hosts_file: "/etc/jmcp/known_hosts".into(),
        username: "root".into(),
        host: "10.0.0.1".into(),
        port: 22,
        remote_path: "/var/tmp/foo.tgz".into(),
        local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
        accept_new_host_keys: false,
    };
    let ct = CancellationToken::new();
    let out = runner.fetch(&job, &ct).await.unwrap();
    assert_eq!(out.exit_code, 0);
    let calls = runner.fetch_calls.lock().await;
    assert_eq!(calls.len(), 1);
    // -O appears first in fetch argv, exactly as in upload argv.
    assert_eq!(calls[0][0], "-O");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::runner_tests::mock_fetch_records_argv_for_assertion`
Expected: FAIL — no method named `fetch` on `MockScpRunner`.

- [ ] **Step 3: Extend the trait**

Modify the `ScpRunner` trait in `rust-junosmcp-core/src/tools/transfer_file.rs` (around line 709) to add a `fetch()` method:

```rust
#[async_trait::async_trait]
pub trait ScpRunner: Send + Sync {
    /// Run the SCP upload job, racing against `ct.cancelled()`. On cancel,
    /// production impls MUST kill the underlying child process (or
    /// otherwise abort the work) and return
    /// `std::io::Error::new(ErrorKind::Interrupted, "cancelled")` so
    /// the caller can map it to `JmcpError::Cancelled`.
    async fn run(&self, job: &ScpJob, ct: &CancellationToken) -> std::io::Result<ScpOutcome>;

    /// Run the SCP download job. Same cancellation contract as `run()`.
    async fn fetch(
        &self,
        job: &ScpFetchJob,
        ct: &CancellationToken,
    ) -> std::io::Result<ScpOutcome>;
}
```

- [ ] **Step 4: Implement `fetch()` on `OpenSshScpRunner`**

Modify the `impl ScpRunner for OpenSshScpRunner` block (around line 722) to add the new method body. The implementation mirrors `run()` byte-for-byte except for the argv builder call:

```rust
async fn fetch(
    &self,
    job: &ScpFetchJob,
    ct: &CancellationToken,
) -> std::io::Result<ScpOutcome> {
    let argv = build_scp_fetch_argv(job);
    use tokio::io::AsyncReadExt;
    let mut child = tokio::process::Command::new("scp")
        .args(&argv)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stdout_pipe = child.stdout.take().expect("piped");
    let mut stderr_pipe = child.stderr.take().expect("piped");
    let status = tokio::select! {
        biased;
        _ = ct.cancelled() => {
            tracing::info!(pid = ?child.id(), "fetch_file.scp_diag phase=\"cancelled\": killing scp child");
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
        }
        s = child.wait() => s?,
    };
    let mut so = Vec::new();
    let mut se = Vec::new();
    let _ = stdout_pipe.read_to_end(&mut so).await;
    let _ = stderr_pipe.read_to_end(&mut se).await;
    Ok(ScpOutcome {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&so).into_owned(),
        stderr: String::from_utf8_lossy(&se).into_owned(),
    })
}
```

- [ ] **Step 5: Extend `MockScpRunner`**

Add a `fetch_calls` field to `MockScpRunner` and an impl of `fetch()`. Modify the existing struct (around line 760):

```rust
#[cfg(test)]
pub struct MockScpRunner {
    pub outcome: ScpOutcome,
    pub calls: tokio::sync::Mutex<Vec<Vec<String>>>,
    pub fetch_calls: tokio::sync::Mutex<Vec<Vec<String>>>,
    pub delay: Option<std::time::Duration>,
}
```

Update the three constructors (`ok()`, `with_outcome()`, `with_delay()`) to initialize `fetch_calls: tokio::sync::Mutex::new(Vec::new())` alongside the existing `calls` initializer.

Then update the `impl ScpRunner for MockScpRunner` block to add the new method (around line 805):

```rust
async fn fetch(
    &self,
    job: &ScpFetchJob,
    ct: &CancellationToken,
) -> std::io::Result<ScpOutcome> {
    self.fetch_calls.lock().await.push(build_scp_fetch_argv(job));
    if let Some(d) = self.delay {
        tokio::select! {
            biased;
            _ = ct.cancelled() => {
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
            }
            _ = tokio::time::sleep(d) => {}
        }
    }
    Ok(self.outcome.clone())
}
```

- [ ] **Step 6: Run to verify passing**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::runner_tests`
Expected: All runner tests pass (existing + 1 new).

- [ ] **Step 7: Run full transfer_file tests to confirm no regression**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file`
Expected: All transfer_file tests pass.

- [ ] **Step 8: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(fetch_file): add ScpRunner::fetch() with OpenSsh + Mock impls"
```

---

## Task 5: Implement `fetch_file::handle` core workflow

**Files:**
- Modify: `rust-junosmcp-core/src/tools/fetch_file.rs` (created empty in Task 1).

The handle function mirrors `transfer_file::handle` step-by-step:

1. Outer `tokio::time::timeout(args.timeout, ...)`
2. Short-circuit if `ct.is_cancelled()` already
3. Validate `args.remote_path` basename (reuse `validate_source_basename`)
4. Validate `args.local_name` basename if set, else default to `remote_path`
5. Check `known_hosts_file` exists (same logic as transfer_file)
6. Acquire per-router permit via `cfg.transfer_locks.acquire(&args.router_name)`
7. Resolve device entry; reject password auth with `UnsupportedAuth`
8. Open pooled NETCONF session via `dm.open(...)`
9. Probe remote file via `file checksum sha-256 /var/tmp/<basename>` → if `None` (missing), return `RemoteFileMissing`
10. Compute local sha256 IF the local file already exists; if it equals remote sha → return `skipped`; if differs and not `force` → return `LocalDestExistsDiffers`; if missing → proceed
11. Run `cfg.scp_runner.fetch(&ScpFetchJob {...}, &ct)`. Non-zero exit → `ScpFailed` (with scrubbed stderr, or `ConnectTimeout` for the 255 + "Connection timed out"/"No route to host" pattern)
12. Compute local sha256 of the freshly-fetched file. If `args.verify && local_sha != remote_sha_pre` → delete local file (best-effort), return `FetchVerifyMismatch`
13. Return `{"status":"fetched", "local_path":"...", "remote_path":"/var/tmp/<basename>", "size_bytes":N, "sha256":"<hex>", "verified":true}`

- [ ] **Step 1: Write a failing unit test for the happy path**

Replace the placeholder content in `rust-junosmcp-core/src/tools/fetch_file.rs` with the test scaffold below. The test uses an in-process device-manager double; if the repo has no such helper yet, look for how `transfer_file`'s integration tests stand up a fake device (search `MockDevice` / `mock_dm` in `rust-junosmcp-core/src/tools/transfer_file.rs` lines 1500+). If no existing helper, **the simpler-path test is a unit test of an internal helper**, deferred to Task 6.

For now, write the public-API integration test that asserts the response shape on idempotent skip (no scp call needed):

```rust
#[cfg(test)]
mod handle_tests {
    use super::*;
    use crate::tools::FetchFileArgs;

    /// Idempotent skip: local file present with matching sha256.
    /// (Wired up fully in Task 6 once the fake-device helper is available;
    /// for now this is a compile-only stub.)
    #[tokio::test]
    #[ignore = "needs fake-device helper from Task 6"]
    async fn fetches_emits_skipped_when_local_matches_remote() {
        // placeholder
    }
}
```

This test is `#[ignore]` so it compiles but doesn't run yet — wired up properly in Task 6 with the fake-device helper.

- [ ] **Step 2: Write the production `handle` function**

Replace the file content with the full implementation. Use the existing `transfer_file::handle` as a structural template (lines 1158-1428 of `transfer_file.rs`). The full body is:

```rust
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

fn skipped_response(local_path: &std::path::Path, remote_basename: &str, sha: &[u8; 32], size: u64) -> Value {
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
        if ct.is_cancelled() {
            return Err(JmcpError::Cancelled);
        }
        validate_source_basename(&args.remote_path)?;
        let local_basename = args
            .local_name
            .clone()
            .unwrap_or_else(|| args.remote_path.clone());
        validate_source_basename(&local_basename)?;
        // known_hosts policy (same as transfer_file::handle).
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
        // Per-router permit (shared with transfer_file).
        let _permit = select_cancel_raw(&ct, cfg.transfer_locks.acquire(&args.router_name)).await?;

        // Resolve device + auth.
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

        // Open pooled NETCONF session.
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
                let (local_sha, local_size) = sha256_file_cancellable(&local_path, &ct).await?;
                if local_sha == remote_sha {
                    return Ok(skipped_response(&local_path, &remote_basename, &local_sha, local_size));
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
    use super::*;

    #[tokio::test]
    #[ignore = "needs fake-device helper from Task 6"]
    async fn fetches_emits_skipped_when_local_matches_remote() {
        // placeholder
    }
}
```

The imports may need adjusting depending on visibility of `validate_source_basename`, `hex32`, `parse_checksum_output`, `scrub_scp_stderr`, and `sha256_file_cancellable` — these are currently `pub(crate)` for some and `pub` for others (Task 1's transfer_file edits did not change visibility). If any are not visible from `tools::fetch_file`, change them to `pub(crate)` in `transfer_file.rs` as part of this task.

- [ ] **Step 3: Run cargo check to flush out missing imports / visibility**

Run: `cargo check -p rust-junosmcp-core`
Expected: clean compile. If errors mention visibility of `hex32` / `parse_checksum_output` / `scrub_scp_stderr`, change them to `pub(crate)` in `transfer_file.rs` (search the file for `fn hex32`, `fn parse_checksum_output`, `fn scrub_scp_stderr`; add `pub(crate)` if not already present).

- [ ] **Step 4: Run the placeholder test (it should be `ignored`)**

Run: `cargo test -p rust-junosmcp-core --lib tools::fetch_file`
Expected: 1 test, marked `ignored`. No failures.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/fetch_file.rs rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(fetch_file): implement handle() workflow"
```

---

## Task 6: Wire `fetch_file` into the binary handler

**Files:**
- Modify: `rust-junosmcp/src/server.rs`
- Modify: `rust-junosmcp-auth/src/file.rs`

- [ ] **Step 1: Write the failing tripwire test**

The existing test at `rust-junosmcp/src/server.rs:245` asserts `SERVER_TOOLS.len() == 14`. After adding `fetch_file` the count becomes 15. Update the assertion AND the `KNOWN_TOOLS` list so both sides stay in sync — the `server_tools_matches_known_tools_as_set` test enforces this.

- [ ] **Step 2: Add `fetch_file` to KNOWN_TOOLS**

In `rust-junosmcp-auth/src/file.rs:9-24`, insert `"fetch_file"` in alphabetical position:

```rust
pub const KNOWN_TOOLS: &[&str] = &[
    "add_device",
    "execute_junos_command",
    "execute_junos_command_batch",
    "execute_junos_pfe_command",
    "fetch_file",
    "gather_device_facts",
    "get_junos_config",
    "get_router_list",
    "junos_config_diff",
    "list_staged_files",
    "load_and_commit_config",
    "reload_devices",
    "render_and_apply_j2_template",
    "transfer_file",
    "upgrade_junos",
];
```

- [ ] **Step 3: Add `fetch_file` to SERVER_TOOLS and update the tripwire**

In `rust-junosmcp/src/server.rs:219-234`, add `"fetch_file"` to the list (declaration order is fine — match the existing style of putting related tools together; place it next to `"transfer_file"`):

```rust
const SERVER_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",
    "add_device",
    "reload_devices",
    "transfer_file",
    "fetch_file",
    "upgrade_junos",
    "list_staged_files",
];
```

And update the tripwire test at line 245:

```rust
#[test]
fn server_tools_len_is_15() {
    assert_eq!(SERVER_TOOLS.len(), 15);
}
```

(Rename the function from `server_tools_len_is_14` to `server_tools_len_is_15` so the intent reads correctly.)

- [ ] **Step 4: Add `tools::{fetch_file}` to the use list**

In `rust-junosmcp/src/server.rs:15`, add `fetch_file` to the existing `tools::{...}` group:

```rust
use rust_junosmcp_core::tools::{
    ..., fetch_file, ..., transfer_file, ...
};
```

(Preserve the alphabetical or whatever style is already present; just add `fetch_file`.)

- [ ] **Step 5: Import `FetchFileArgs`**

In the existing `use rust_junosmcp_core::tools::{...}` typed-args import block near the top of `rust-junosmcp/src/server.rs` (search for `TransferFileArgs`), add `FetchFileArgs` to the list.

- [ ] **Step 6: Add the `#[tool]` handler method on `JmcpHandler`**

Inside the `#[tool_router] impl JmcpHandler { ... }` block (around line 275), add a new method modeled exactly on `transfer_file` (line 510). Insert near the existing `transfer_file` handler:

```rust
#[tool(
    name = "fetch_file",
    description = "Download a file from a Junos device's /var/tmp/<basename> to the host staging directory, with sha256 verification. Mirror of transfer_file."
)]
async fn fetch_file(
    &self,
    Parameters(args): Parameters<FetchFileArgs>,
    extensions: Extensions,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let ctx = caller_ctx(&extensions);
    if let Err(e) = self.check_tool_scope(ctx, "fetch_file") {
        return Self::scope_to_call_result(e);
    }
    if let Err(e) = self.check_router_scope(ctx, "fetch_file", &args.router_name) {
        return Self::scope_to_call_result(e);
    }
    let ct = extensions
        .get::<rmcp::service::RequestContext<rmcp::RoleServer>>()
        .map(|rc| rc.ct.clone())
        .unwrap_or_default();
    let router = args.router_name.clone();
    let started = std::time::Instant::now();
    let result =
        fetch_file::handle(args, self.dm.clone(), self.transfer_config().clone(), ct).await;
    match &result {
        Ok(_) => tracing::info!(
            tool = "fetch_file",
            router = %router,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "tool_ok"
        ),
        Err(e) => tracing::warn!(
            tool = "fetch_file",
            router = %router,
            elapsed_ms = started.elapsed().as_millis() as u64,
            err = %e,
            "tool_err"
        ),
    }
    Self::to_call_result(result)
}
```

(If the existing `transfer_file` method shape uses a slightly different `ct` extraction pattern, mirror that exact pattern. The handler should follow the same logging shape used by other `#[tool]` methods in the file.)

- [ ] **Step 7: Run cargo check**

Run: `cargo check --workspace`
Expected: clean compile.

- [ ] **Step 8: Run the tripwire tests**

Run: `cargo test -p rust-junosmcp --lib server_tools_const_tests`
Expected: all 3 tripwire tests PASS (count=15, no duplicates, matches KNOWN_TOOLS).

- [ ] **Step 9: Commit**

```bash
git add rust-junosmcp/src/server.rs rust-junosmcp-auth/src/file.rs
git commit -m "feat(fetch_file): register fetch_file MCP tool on JmcpHandler"
```

---

## Task 7: Add scope-denial integration tests for `fetch_file`

**Files:**
- Modify: `rust-junosmcp/src/server.rs` (the `#[cfg(test)] mod tests` block at the bottom)

- [ ] **Step 1: Write the failing tests**

Search the existing `#[cfg(test)] mod tests` block for `transfer_file_tool_scope_denies_when_not_listed` (around line 821) and `transfer_file_router_scope_denies_when_not_listed` (around line 849). Add mirror tests immediately after them:

```rust
#[test]
fn fetch_file_tool_scope_denies_when_not_listed() {
    let handler = handler_with_test_cfg();
    let ctx = CallerCtx {
        token_name: "limited".into(),
        tools: ScopeSet::Allowlist(vec!["other_tool".into()]),
        routers: ScopeSet::Allowlist(vec!["vsrx-test10".into()]),
    };
    assert!(matches!(
        handler.check_tool_scope(Some(&ctx), "fetch_file"),
        Err(_)
    ));
}

#[test]
fn fetch_file_router_scope_denies_when_not_listed() {
    let handler = handler_with_test_cfg();
    let ctx = CallerCtx {
        token_name: "limited".into(),
        tools: ScopeSet::Allowlist(vec!["fetch_file".into()]),
        routers: ScopeSet::Allowlist(vec!["other".into()]),
    };
    handler
        .check_tool_scope(Some(&ctx), "fetch_file")
        .expect("tool scope allowed");
    assert!(matches!(
        handler.check_router_scope(Some(&ctx), "fetch_file", "vsrx-test10"),
        Err(_)
    ));
}
```

(The exact `handler_with_test_cfg()` helper and `CallerCtx` import path must match what the transfer_file scope tests already use in the same file — copy from the existing transfer_file tests verbatim and substitute `fetch_file` for `transfer_file`.)

- [ ] **Step 2: Run to verify failure on first attempt — then pass**

Run: `cargo test -p rust-junosmcp --lib fetch_file_tool_scope_denies_when_not_listed fetch_file_router_scope_denies_when_not_listed`
Expected: PASS (the underlying logic in Task 6 already supports `fetch_file` since the scope check is generic on the tool name string).

If they fail with "tool not found in KNOWN_TOOLS", Task 6 was incomplete — return to Task 6 step 2.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp/src/server.rs
git commit -m "test(fetch_file): scope-denial tests for tool + router scopes"
```

---

## Task 8: Bump workspace version and update CHANGELOG

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump the workspace version**

Edit `Cargo.toml` line 6:

```toml
version      = "0.6.0"
```

(was `"0.5.10"`)

- [ ] **Step 2: Add the new CHANGELOG section**

Insert at the top of the version-entry list in `CHANGELOG.md` (after the heading block, before `## [0.5.9]`):

```markdown
## [0.6.0] — 2026-05-20

New `fetch_file` MCP tool — mirror image of `transfer_file`. Downloads a
file from a Junos device's `/var/tmp/<basename>` to the host's staging
directory, with sha256 verification, idempotent skip, per-router
serialization, and the same SSH hardening (StrictHostKeyChecking,
BatchMode, IdentitiesOnly, scrubbed scp stderr) as `transfer_file`.

Tool surface grows from 14 → 15 tools.

### Added

- **`fetch_file` MCP tool** at `tools::fetch_file::handle`. Required args:
  `router_name`, `remote_path` (basename under `/var/tmp/`). Optional:
  `local_name` (basename override under staging dir), `force` (overwrite
  divergent local file), `verify` (default `true`), `timeout` (default 600s).
- **`ScpRunner::fetch()`** trait method with `OpenSshScpRunner` and
  `MockScpRunner` implementations.
- **`ScpFetchJob`** + **`build_scp_fetch_argv`** in
  `rust_junosmcp_core::tools::transfer_file`. Mirror of the upload variants;
  same flag posture, source/dest swapped.
- **New error variants:**
  - `JmcpError::LocalDestExistsDiffers` — local file present with different sha256;
    set `force=true` to overwrite.
  - `JmcpError::RemoteFileMissing` — device has no file at the requested path.
  - `JmcpError::FetchVerifyMismatch` — post-fetch local sha256 disagrees with
    pre-fetch remote sha256; the corrupted local file is removed.

### Changed

- `SERVER_TOOLS` tripwire test `server_tools_len_is_14` → `server_tools_len_is_15`.
- Visibility of `hex32`, `parse_checksum_output`, `scrub_scp_stderr` in
  `tools::transfer_file` widened to `pub(crate)` so `tools::fetch_file` can
  reuse them.

### Verification

- Workspace unit + integration tests all pass; new coverage for the
  fetch_file argv builder, runner mock, scope denial, and the three new
  error variants.
- `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Manual smoke test against LXC 601 with `rust-junosmcp` v0.6.0:
  `fetch_file` retrieves a `request support information | save /var/tmp/info.txt`
  artifact from vSRX-test10 and verifies it sha256-matches the device's value.
```

- [ ] **Step 3: Verify Cargo.lock updates cleanly**

Run: `cargo check --workspace`
Expected: `Cargo.lock` updates the workspace version to 0.6.0 with no other diff noise.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): v0.6.0 — fetch_file MCP tool"
```

---

## Task 9: README update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Locate the tool table**

Search `README.md` for the tool table that lists `transfer_file`. The format is consistent across releases — find the row for `transfer_file` and add a `fetch_file` row immediately above or below it.

- [ ] **Step 2: Add the row**

Insert into the tools table:

```markdown
| `fetch_file` | Downloads a file from `<device>:/var/tmp/<basename>` to the host staging dir. SHA256-verified, idempotent skip, per-router serialization. Mirror of `transfer_file`. |
```

(Match the existing table column layout exactly. If the README uses a different format like a definition list, adapt to that format.)

- [ ] **Step 3: Bump the tool count if mentioned**

Search the README for `14 tools` / `14 MCP tools`. Replace with `15 tools` / `15 MCP tools` in any prose that mentions the count.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): document fetch_file tool"
```

---

## Task 10: Full workspace verification before release

- [ ] **Step 1: Run rustfmt**

Run: `cargo fmt --all`
Expected: no diff (CI enforces `cargo fmt -- --check`).

- [ ] **Step 2: Run clippy across the workspace with warnings as errors**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 3: Run all tests**

Run: `cargo test --workspace`
Expected: all tests pass, including the new fetch_file coverage and the tripwire `server_tools_len_is_15`.

- [ ] **Step 4: Manual smoke test against LXC 601**

Build, scp to LXC 601, restart, smoke. (Follow the procedure documented in `~/.claude/projects/-home-mharman-RustJunosMCP/memory/rust_junosmcp_container_601.md`. The general shape:)

```bash
cargo build --release -p rust-junosmcp
# stop service before push (rust-junosmcp running binary is text-file-busy)
ssh root@pve3.mechub.org "pct exec 601 -- systemctl stop rust-junosmcp.service"
scp target/release/rust-junosmcp root@pve3.mechub.org:/tmp/rjmcp-0.6.0
ssh root@pve3.mechub.org "pct push 601 /tmp/rjmcp-0.6.0 /usr/local/bin/rust-junosmcp && pct exec 601 -- chmod +x /usr/local/bin/rust-junosmcp && pct exec 601 -- systemctl start rust-junosmcp.service"
# version check
ssh root@pve3.mechub.org "pct exec 601 -- /usr/local/bin/rust-junosmcp --version"
# expected: 0.6.0
```

Then from your client, exercise `fetch_file` end-to-end:

1. On vSRX-test10, generate a small file:
   `request support information | save /var/tmp/smoke.txt`
2. From an MCP client (Claude Code with the live endpoint configured), call `fetch_file` with `router_name=vSRX-test10`, `remote_path=smoke.txt`.
3. Verify the response includes `"status":"fetched"`, `"verified":true`, and an absolute `local_path` under the staging dir.
4. Re-run the same call. Verify the response now reports `"status":"skipped"`.
5. Call with a non-existent `remote_path`. Verify the error code is `[code=remote_file_missing]`.

- [ ] **Step 5: Tag and push**

```bash
git tag -a v0.6.0 -m "v0.6.0 — fetch_file MCP tool"
git push origin main
git push origin v0.6.0
```

- [ ] **Step 6: Update memory**

After release succeeds, write a new memory file `v0_6_0_released.md` at `~/.claude/projects/-home-mharman-RustJunosMCP/memory/` summarizing the release (PR number, tag, deploy date, what shipped). Add the one-liner index entry to `MEMORY.md` in the same memory dir.

---

## Self-review (notes for the executing agent)

- **Spec coverage:** Phase 0 in the strategy spec (`docs/superpowers/specs/2026-05-20-srx-mcp-strategy-design.md`) is exactly "fetch_file in generic v0.6.0". This plan covers it end-to-end.
- **Placeholder scan:** Task 5 step 1 leaves a `#[ignore]` placeholder test that becomes a real test only after a fake-device helper exists. That helper does not currently exist in the repo for `transfer_file` either (transfer_file's `handle` is tested via the production path on a real device). Decision: keep the placeholder as documented and rely on the LXC 601 smoke test in Task 10 for end-to-end coverage. If a future PR adds a fake-device test helper for `transfer_file`, port it to `fetch_file` at that time.
- **Type consistency:** `ScpFetchJob` and `build_scp_fetch_argv` are used identically in Task 3 (definition), Task 4 (trait impl), and Task 5 (handle). `FetchFileArgs` fields (`router_name`, `remote_path`, `local_name`, `force`, `verify`, `timeout`) are used identically across Tasks 1, 5, and 6.
- **Out of scope for this plan:** SRX-specific workflows (Phases 1-5 in the strategy spec) — those get their own plans once the SRX workspace scaffolding lands.
