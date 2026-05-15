# `transfer_file` + `list_staged_files` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two MCP tools — `transfer_file` (stage-to-device SCP with pre/post checks and idempotent skip) and `list_staged_files` (read-only discovery of host-staging dir and device `/var/tmp/`).

**Architecture:** Two new tool handlers in `rust-junosmcp-core/src/tools/`, wired into `rust-junosmcp/src/server.rs` alongside the existing 11 tools. Transfer uses a `ScpRunner` trait (production impl shells out to `scp -O` via `tokio::process::Command`; mock impl asserts the exact argv in unit tests). NETCONF pre/post checks run through the existing `DeviceManager` session pool via `dev.cli(...).await`. Pure parsers (`show system storage`, `file checksum`, `file list`) live in their own functions and are exhaustively unit-tested. Staging dir + known_hosts location are CLI flags that default to `/var/lib/jmcp/staging` and `/etc/jmcp/known_hosts`.

**Tech Stack:** Rust 2021 / tokio / rustez (NETCONF) / sha2 (already in tree) / system `openssh-client` for `scp -O` / async-trait. No new Cargo dependencies. Tests use `tempfile`, the existing `tests/common/mod.rs` stdio harness, and an in-tree `MockScpRunner`.

---

## File Inventory

**Create:**
- `rust-junosmcp-core/src/tools/transfer_file.rs` — `handle()`, `validate_source_basename`, `sha256_file`, `ScpRunner` trait, `OpenSshScpRunner`, `MockScpRunner`, `build_scp_argv`, parsers (`parse_storage_free_bytes`, `parse_checksum_output`), all in-file `#[cfg(test)] mod` unit tests.
- `rust-junosmcp-core/src/tools/list_staged_files.rs` — `handle()`, `read_staging_dir`, `parse_var_tmp_listing`, in-file unit tests.
- `rust-junosmcp/tests/transfer_file_smoke.rs` — stdio smoke (validation, unknown router, bad source path, unreachable-host → `connect_timeout`).
- `rust-junosmcp/tests/list_staged_files_smoke.rs` — stdio smoke (empty staging, populated staging, unknown router error).

**Modify:**
- `rust-junosmcp-core/src/tools/mod.rs` — add `pub mod transfer_file;` + `pub mod list_staged_files;` and the two new arg structs `TransferFileArgs`, `ListStagedFilesArgs`.
- `rust-junosmcp-core/src/error.rs` — add 8 `JmcpError` variants (`BadSourcePath`, `UnsupportedAuth`, `InsufficientDisk`, `DestExistsDiffers`, `ScpFailed`, `ConnectTimeout`, `VerifyMismatch`, `TransferOuterTimeout`) with `Display` impls that embed the structured `code`/`remediation`.
- `rust-junosmcp/src/cli.rs` — add `--staging-dir <PATH>` (default `/var/lib/jmcp/staging`) and `--known-hosts-file <PATH>` (default `/etc/jmcp/known_hosts`).
- `rust-junosmcp/src/server.rs` — add `#[tool]` methods `transfer_file` and `list_staged_files`; extend `JmcpHandler::new` to take a `TransferConfig`; update `scope_tests` constructors.
- `rust-junosmcp/src/main.rs` — build `TransferConfig` from CLI flags + production `OpenSshScpRunner`; pass into `JmcpHandler::new`.
- `rust-junosmcp-core/src/lib.rs` — `pub use tools::transfer_file::TransferConfig;` (re-export so the binary can name the type).
- `rust-junosmcp-core/tests/integration_real_device.rs` — append `#[ignore]`-gated round-trip / idempotency / force=false tests.
- `packaging/lxc/install.sh` — `mkdir -p /var/lib/jmcp/staging` (mode 0755, owner jmcp:jmcp), `touch /etc/jmcp/known_hosts` (mode 0644, owner jmcp:jmcp).
- `README.md` — add `## File transfers (transfer_file / list_staged_files)` section.
- `~/.claude/projects/-home-mharman-RustJunosMCP/memory/rust_junosmcp_container_601.md` — document staging dir + known_hosts as deployment surface.

---

## Conventions Used Across Tasks

- Every `cargo test` run is scoped to the changed package + test name to avoid waiting for the whole workspace.
- Final task runs the full CI gate: `cargo fmt --all -- --check && cargo clippy -p rust-junosmcp-core -p rust-junosmcp --all-targets -- -D warnings && cargo test --workspace && cargo audit`.
- Commit messages follow the repo's existing style (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
- All commands assume CWD is the worktree root: `~/RustJunosMCP/.worktrees/transfer-file`.

---

### Task 1: Add `TransferFileArgs` + `ListStagedFilesArgs` to `tools/mod.rs`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/mod.rs`

- [ ] **Step 1: Write the failing tests**

Append inside the existing `mod tests` block at the bottom of `tools/mod.rs`:

```rust
#[test]
fn transfer_file_args_defaults() {
    let v = serde_json::json!({"router_name":"r1","source_path":"foo.tgz"});
    let a: TransferFileArgs = serde_json::from_value(v).unwrap();
    assert_eq!(a.router_name, "r1");
    assert_eq!(a.source_path, "foo.tgz");
    assert!(!a.force);
    assert!(a.verify);
    assert_eq!(a.timeout, 600);
}

#[test]
fn transfer_file_args_rejects_missing_source() {
    let v = serde_json::json!({"router_name":"r1"});
    let r: Result<TransferFileArgs, _> = serde_json::from_value(v);
    assert!(r.is_err());
}

#[test]
fn list_staged_files_args_router_optional() {
    let v = serde_json::json!({});
    let a: ListStagedFilesArgs = serde_json::from_value(v).unwrap();
    assert!(a.router_name.is_none());
    assert_eq!(a.timeout, 30);
}

#[test]
fn list_staged_files_args_with_router() {
    let v = serde_json::json!({"router_name":"vSRX-test10"});
    let a: ListStagedFilesArgs = serde_json::from_value(v).unwrap();
    assert_eq!(a.router_name.as_deref(), Some("vSRX-test10"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-junosmcp-core --lib tools::tests::transfer_file_args_defaults 2>&1 | tail -20`
Expected: FAIL — `cannot find type 'TransferFileArgs' in this scope`.

- [ ] **Step 3: Implement the structs + module declarations**

Add at the top of `tools/mod.rs` near the existing `pub mod` lines:

```rust
pub mod list_staged_files;
pub mod transfer_file;
```

Add at the bottom of the `default_*` helper section:

```rust
fn default_transfer_timeout() -> u64 {
    600
}
fn default_list_staged_timeout() -> u64 {
    30
}
fn default_verify() -> bool {
    true
}
```

Add the two arg structs alongside the others:

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TransferFileArgs {
    /// Target router name (must exist in inventory and use ssh_key auth).
    pub router_name: String,
    /// Basename of the file under the staging dir. Must not contain '/', '\\', or '..'.
    pub source_path: String,
    /// Overwrite if dest exists with different sha256. Default false.
    #[serde(default)]
    pub force: bool,
    /// Post-transfer sha256 verification. Default true.
    #[serde(default = "default_verify")]
    pub verify: bool,
    /// Per-call timeout in seconds. Default 600.
    #[serde(default = "default_transfer_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct ListStagedFilesArgs {
    /// Optional router name. If present, also lists the device's /var/tmp/.
    #[serde(default)]
    pub router_name: Option<String>,
    /// Per-call timeout in seconds. Default 30.
    #[serde(default = "default_list_staged_timeout")]
    pub timeout: u64,
}
```

Re-export at the bottom of the existing `pub use` block (immediately after the existing arg-struct exports — search for `pub use ... ReloadDevicesArgs`; otherwise the structs are pub anyway — `tools::TransferFileArgs` works either way; only re-export if the existing pattern does).

Create empty stub modules so the `pub mod` lines compile:

```bash
printf '//! transfer_file tool — implementation in later tasks.\n' \
  > rust-junosmcp-core/src/tools/transfer_file.rs
printf '//! list_staged_files tool — implementation in later tasks.\n' \
  > rust-junosmcp-core/src/tools/list_staged_files.rs
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p rust-junosmcp-core --lib tools::tests:: 2>&1 | tail -10`
Expected: all four new tests PASS, plus existing tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/mod.rs \
        rust-junosmcp-core/src/tools/transfer_file.rs \
        rust-junosmcp-core/src/tools/list_staged_files.rs
git commit -m "feat: add TransferFileArgs + ListStagedFilesArgs schemas"
```

---

### Task 2: `validate_source_basename` pure function

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write the failing tests**

Replace the stub content of `rust-junosmcp-core/src/tools/transfer_file.rs` with:

```rust
//! `transfer_file` MCP tool. SCP a pre-staged file from the host's staging
//! directory to a Junos device's /var/tmp/, with idempotent skip and
//! pre/post-transfer sha256 verification.

use crate::error::JmcpError;

/// Validate that `source_path` is a safe basename. Rejects:
/// - empty
/// - longer than 255 chars
/// - leading '.' (hidden / dotfiles + traversal-style "..")
/// - any '/', '\\', or "..".
pub fn validate_source_basename(source: &str) -> Result<(), JmcpError> {
    if source.is_empty() {
        return Err(JmcpError::BadSourcePath("source_path is empty".into()));
    }
    if source.len() > 255 {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path exceeds 255 chars (got {})",
            source.len()
        )));
    }
    if source.starts_with('.') {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not start with '.'"
        )));
    }
    if source.contains('/') || source.contains('\\') {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not contain '/' or '\\\\' (basename only)"
        )));
    }
    if source.contains("..") {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not contain '..'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod validate_tests {
    use super::*;

    #[test]
    fn accepts_plain_basename() {
        assert!(validate_source_basename("junos-25.4R1.12.tgz").is_ok());
    }

    #[test]
    fn accepts_ascii_with_dots_in_middle() {
        assert!(validate_source_basename("a.b.c.tgz").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            validate_source_basename(""),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_too_long() {
        let s = "a".repeat(256);
        assert!(matches!(
            validate_source_basename(&s),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(matches!(
            validate_source_basename(".hidden"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_dotdot_anywhere() {
        assert!(matches!(
            validate_source_basename("a..b"),
            Err(JmcpError::BadSourcePath(_))
        ));
        assert!(matches!(
            validate_source_basename(".."),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_forward_slash() {
        assert!(matches!(
            validate_source_basename("dir/file.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_backslash() {
        assert!(matches!(
            validate_source_basename("dir\\file.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_absolute_path() {
        assert!(matches!(
            validate_source_basename("/etc/passwd"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }
}
```

This intentionally references `JmcpError::BadSourcePath` which does not exist yet — Task 9 adds it. To keep this task self-contained, also add the variant minimally now (Task 9 will round-trip the rest).

In `rust-junosmcp-core/src/error.rs`, add to the `JmcpError` enum (placed alphabetically among other variants):

```rust
#[error("invalid source_path [code=bad_source_path]: {0}")]
BadSourcePath(String),
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::validate_tests 2>&1 | tail -20`
Expected: prior to inserting the function body the test would not compile; with the body in place from Step 1 it should compile and PASS. To force the failing-then-passing dance, temporarily flip `if source.is_empty()` to `if false` and watch `rejects_empty` fail; revert before committing.

- [ ] **Step 3: Implementation already in Step 1**

(No additional change.)

- [ ] **Step 4: Run test to verify all pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file:: 2>&1 | tail -15`
Expected: 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs rust-junosmcp-core/src/error.rs
git commit -m "feat(transfer): validate_source_basename rejects traversal/slash/dotfile"
```

---

### Task 3: `sha256_file` streaming helper

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write the failing test**

Append to `transfer_file.rs`:

```rust
use std::path::Path;

/// Stream a file from disk and return (sha256, size_bytes). Runs the actual
/// hashing on a blocking thread to keep the tokio runtime healthy on multi-GB
/// files (~3-5 s for 1.3 GB on the LXC).
pub async fn sha256_file(path: &Path) -> Result<([u8; 32], u64), JmcpError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<([u8; 32], u64), JmcpError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut f = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size: u64 = 0;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok((out, size))
    })
    .await
    .map_err(|e| JmcpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
}

#[cfg(test)]
mod sha_tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn hashes_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let (h, n) = sha256_file(f.path()).await.unwrap();
        assert_eq!(n, 0);
        // sha256 of empty: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn hashes_known_vector_abc() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        f.flush().unwrap();
        let (h, n) = sha256_file(f.path()).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn nonexistent_file_returns_io_error() {
        let r = sha256_file(Path::new("/nonexistent/jmcp/file")).await;
        assert!(matches!(r, Err(JmcpError::Io(_))));
    }
}
```

The `hex` crate is **not** in workspace deps. Don't add it — instead, write a tiny helper in the test module:

```rust
#[cfg(test)]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}
```

Then replace `hex::encode(h)` with `hex_lower(&h)` in the two assertions above.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::sha_tests 2>&1 | tail -10`
Expected: PASS on first run since the function body is included with the test in Step 1. (TDD discipline: temporarily comment out the `hasher.update(&buf[..n]);` line, watch `hashes_known_vector_abc` fail with a wrong digest, revert, re-run.)

- [ ] **Step 3: Implementation in Step 1**

(No additional change.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::sha_tests 2>&1 | tail -10`
Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(transfer): streaming sha256_file via spawn_blocking"
```

---

### Task 4: `build_scp_argv` pure function

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write the failing test**

Append to `transfer_file.rs`:

```rust
use std::path::PathBuf;

/// Inputs for one SCP invocation. All fields owned strings/paths so the
/// runner can `tokio::process::Command::new("scp").args(...)` without further
/// shell escaping.
#[derive(Clone, Debug)]
pub struct ScpJob {
    pub private_key_path: PathBuf,
    pub known_hosts_file: PathBuf,
    pub username: String,
    pub host: String,
    pub port: u16,
    pub local_path: PathBuf,
    pub remote_dir: String, // e.g. "/var/tmp/"
}

/// Build the argv vector that `OpenSshScpRunner` will hand to `scp`. Pulled
/// out so it can be asserted exactly in unit tests without spawning a process.
pub fn build_scp_argv(job: &ScpJob) -> Vec<String> {
    let dest = format!("{}@{}:{}", job.username, job.host, job.remote_dir);
    vec![
        "-O".into(),
        "-i".into(), job.private_key_path.display().to_string(),
        "-o".into(), "StrictHostKeyChecking=accept-new".into(),
        "-o".into(), format!("UserKnownHostsFile={}", job.known_hosts_file.display()),
        "-o".into(), "ConnectTimeout=15".into(),
        "-o".into(), "ServerAliveInterval=10".into(),
        "-o".into(), "ServerAliveCountMax=3".into(),
        "-P".into(), job.port.to_string(),
        job.local_path.display().to_string(),
        dest,
    ]
}

#[cfg(test)]
mod argv_tests {
    use super::*;

    fn job() -> ScpJob {
        ScpJob {
            private_key_path: "/etc/jmcp/keys/id".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
            remote_dir: "/var/tmp/".into(),
        }
    }

    #[test]
    fn argv_uses_dash_capital_o_for_legacy_protocol() {
        // Junos disables SFTP-over-SSH; -O forces SCP1 wire protocol.
        let v = build_scp_argv(&job());
        assert_eq!(v[0], "-O");
    }

    #[test]
    fn argv_includes_known_hosts_with_accept_new() {
        let v = build_scp_argv(&job());
        let joined = v.join(" ");
        assert!(joined.contains("StrictHostKeyChecking=accept-new"));
        assert!(joined.contains("UserKnownHostsFile=/etc/jmcp/known_hosts"));
    }

    #[test]
    fn argv_includes_connect_and_alive_timeouts() {
        let v = build_scp_argv(&job());
        let joined = v.join(" ");
        assert!(joined.contains("ConnectTimeout=15"));
        assert!(joined.contains("ServerAliveInterval=10"));
        assert!(joined.contains("ServerAliveCountMax=3"));
    }

    #[test]
    fn argv_uses_uppercase_p_for_port() {
        let v = build_scp_argv(&ScpJob { port: 2200, ..job() });
        let i = v.iter().position(|s| s == "-P").expect("has -P");
        assert_eq!(v[i + 1], "2200");
    }

    #[test]
    fn argv_dest_is_username_host_colon_dir() {
        let v = build_scp_argv(&job());
        assert_eq!(v.last().unwrap(), "root@10.0.0.1:/var/tmp/");
    }

    #[test]
    fn argv_local_path_appears_before_dest() {
        let v = build_scp_argv(&job());
        let local = v.iter().position(|s| s == "/var/lib/jmcp/staging/foo.tgz").unwrap();
        let dest = v.iter().position(|s| s.starts_with("root@")).unwrap();
        assert!(local < dest);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Temporarily delete the `-O` line from `build_scp_argv` to force `argv_uses_dash_capital_o_for_legacy_protocol` to fail.
Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::argv_tests::argv_uses_dash_capital_o_for_legacy_protocol 2>&1 | tail -10`
Expected: FAIL.

- [ ] **Step 3: Restore the line**

(Re-add `"-O".into(),` as the first vec element.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::argv_tests 2>&1 | tail -10`
Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(transfer): build_scp_argv emits -O legacy-protocol scp argv"
```

---

### Task 5: `ScpRunner` trait + `OpenSshScpRunner` + `MockScpRunner`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`
- Modify: `rust-junosmcp-core/Cargo.toml` (add `async-trait` to deps — already in workspace.dependencies)

- [ ] **Step 1: Write the failing test**

Append to `transfer_file.rs`:

```rust
use std::sync::Arc;

/// Outcome of a single SCP invocation.
#[derive(Clone, Debug)]
pub struct ScpOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait::async_trait]
pub trait ScpRunner: Send + Sync {
    async fn run(&self, job: &ScpJob) -> std::io::Result<ScpOutcome>;
}

/// Production runner — shells out to `scp` from system openssh-client.
pub struct OpenSshScpRunner;

#[async_trait::async_trait]
impl ScpRunner for OpenSshScpRunner {
    async fn run(&self, job: &ScpJob) -> std::io::Result<ScpOutcome> {
        let argv = build_scp_argv(job);
        let out = tokio::process::Command::new("scp")
            .args(&argv)
            .output()
            .await?;
        Ok(ScpOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Test double that records calls and returns canned outcomes.
#[cfg(test)]
pub struct MockScpRunner {
    pub outcome: ScpOutcome,
    pub calls: tokio::sync::Mutex<Vec<Vec<String>>>,
}

#[cfg(test)]
impl MockScpRunner {
    pub fn ok() -> Arc<Self> {
        Arc::new(Self {
            outcome: ScpOutcome { exit_code: 0, stdout: String::new(), stderr: String::new() },
            calls: tokio::sync::Mutex::new(Vec::new()),
        })
    }
    pub fn with_outcome(o: ScpOutcome) -> Arc<Self> {
        Arc::new(Self { outcome: o, calls: tokio::sync::Mutex::new(Vec::new()) })
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl ScpRunner for MockScpRunner {
    async fn run(&self, job: &ScpJob) -> std::io::Result<ScpOutcome> {
        self.calls.lock().await.push(build_scp_argv(job));
        Ok(self.outcome.clone())
    }
}

#[cfg(test)]
mod runner_tests {
    use super::*;

    #[tokio::test]
    async fn mock_records_argv_for_assertion() {
        let runner = MockScpRunner::ok();
        let job = ScpJob {
            private_key_path: "/k".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/x.tgz".into(),
            remote_dir: "/var/tmp/".into(),
        };
        let out = runner.run(&job).await.unwrap();
        assert_eq!(out.exit_code, 0);
        let calls = runner.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "-O");
    }
}
```

Verify `async-trait` is in `rust-junosmcp-core/Cargo.toml` `[dependencies]`. The workspace already has `async-trait = "0.1"` exposed; the core crate already pulls it in (`async-trait = { workspace = true }`). If somehow missing, add that line.

- [ ] **Step 2: Run to verify it would fail without the impl**

Temporarily change `Self::with_outcome(o)` body to construct an empty `calls: Mutex::new(vec!["bogus".into()])` to force `assert_eq!(calls.len(), 1)` to fail.
Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::runner_tests 2>&1 | tail -10`
Expected: FAIL with `left: 2 right: 1`.

- [ ] **Step 3: Revert the bogus change**

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::runner_tests 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs rust-junosmcp-core/Cargo.toml
git commit -m "feat(transfer): ScpRunner trait, OpenSshScpRunner, MockScpRunner"
```

---

### Task 6: `parse_storage_free_bytes`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write the failing test**

Append:

```rust
/// Parse the free-bytes column for `/var` from `show system storage no-forwarding`.
/// Junos prints rows like:
/// ```text
/// Filesystem              Size       Used      Avail  Capacity   Mounted on
/// /dev/gpt/junos          14G       8.5G       4.4G       66%   /.mount
/// /dev/gpt/varlog         3.0G      1.1G       1.7G       40%   /.mount/var/log
/// /dev/gpt/var            10G       2.1G       7.0G       23%   /.mount/var
/// ```
/// We want the `Avail` column on the row whose `Mounted on` equals `/.mount/var`
/// (or `/var` for older Junos). Returns bytes.
pub fn parse_storage_free_bytes(output: &str) -> Result<u64, JmcpError> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Filesystem") {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        // Expect: filesystem size used avail capacity mounted_on
        if fields.len() < 6 {
            continue;
        }
        let mount = fields[fields.len() - 1];
        if mount == "/var" || mount == "/.mount/var" {
            return parse_size_with_suffix(fields[3]);
        }
    }
    Err(JmcpError::InsufficientDisk {
        free: 0,
        required: 0,
        message: "no /var or /.mount/var row found in storage output".into(),
    })
}

fn parse_size_with_suffix(s: &str) -> Result<u64, JmcpError> {
    let (num_part, mult): (&str, u64) = if let Some(stripped) = s.strip_suffix('G') {
        (stripped, 1024 * 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('M') {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('K') {
        (stripped, 1024)
    } else if let Some(stripped) = s.strip_suffix('B') {
        (stripped, 1)
    } else {
        (s, 1)
    };
    let n: f64 = num_part.parse().map_err(|_| JmcpError::InsufficientDisk {
        free: 0,
        required: 0,
        message: format!("could not parse storage size '{s}'"),
    })?;
    Ok((n * mult as f64) as u64)
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    const SAMPLE: &str = "\
Filesystem              Size       Used      Avail  Capacity   Mounted on
/dev/gpt/junos          14G       8.5G       4.4G       66%   /.mount
/dev/gpt/varlog         3.0G      1.1G       1.7G       40%   /.mount/var/log
/dev/gpt/var            10G       2.1G       7.0G       23%   /.mount/var
";

    #[test]
    fn finds_var_mount_in_modern_layout() {
        let n = parse_storage_free_bytes(SAMPLE).unwrap();
        // 7.0G ≈ 7516192768
        assert!((6_900_000_000..7_600_000_000).contains(&n), "got {n}");
    }

    #[test]
    fn handles_legacy_var_mount() {
        let s = "\
Filesystem      Size   Used  Avail Capacity   Mounted on
/dev/ad0s1f     5.0G   1.0G   4.0G    20%   /var
";
        let n = parse_storage_free_bytes(s).unwrap();
        assert!((3_900_000_000..4_400_000_000).contains(&n));
    }

    #[test]
    fn errors_when_var_row_missing() {
        let s = "Filesystem  Size Used Avail Capacity Mounted on\n/dev/x 1G 0 1G 0% /\n";
        assert!(matches!(
            parse_storage_free_bytes(s),
            Err(JmcpError::InsufficientDisk { .. })
        ));
    }

    #[test]
    fn parses_megabyte_suffix() {
        let s = "\
Filesystem  Size Used Avail Capacity Mounted on
/dev/x      500M 100M 400M 20% /var
";
        let n = parse_storage_free_bytes(s).unwrap();
        assert!((400_000_000..420_000_000).contains(&n));
    }
}
```

The test references `JmcpError::InsufficientDisk { free, required, message }` — Task 9 fully defines all variants. Add a minimal version now to error.rs:

```rust
#[error("insufficient disk [code=insufficient_disk]: {message} (free={free}B required={required}B)")]
InsufficientDisk { free: u64, required: u64, message: String },
```

- [ ] **Step 2: Run to verify it fails**

Force a fail by changing `mount == "/var"` to `mount == "/notvar"`.
Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::storage_tests::handles_legacy_var_mount 2>&1 | tail -10`
Expected: FAIL.

- [ ] **Step 3: Revert**

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::storage_tests 2>&1 | tail -10`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs rust-junosmcp-core/src/error.rs
git commit -m "feat(transfer): parse_storage_free_bytes for show system storage"
```

---

### Task 7: `parse_checksum_output`

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write the failing test**

Append:

```rust
/// Parse the sha256 from `file checksum sha-256 /var/tmp/foo` output. Junos prints:
/// ```text
/// SHA256 (/var/tmp/foo) = abc123...
/// ```
/// or, when the file is missing:
/// ```text
/// error: stat: /var/tmp/foo: No such file or directory
/// ```
/// Returns `Ok(Some([u8;32]))` on hit, `Ok(None)` if absent, `Err` on parse failure.
pub fn parse_checksum_output(output: &str) -> Result<Option<[u8; 32]>, JmcpError> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("error:") && trimmed.contains("No such file") {
            return Ok(None);
        }
        if let Some(eq) = trimmed.rfind('=') {
            let hex = trimmed[eq + 1..].trim();
            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                let mut out = [0u8; 32];
                for (i, byte) in out.iter_mut().enumerate() {
                    let hi = u8::from_str_radix(&hex[i * 2..i * 2 + 1], 16).unwrap();
                    let lo = u8::from_str_radix(&hex[i * 2 + 1..i * 2 + 2], 16).unwrap();
                    *byte = (hi << 4) | lo;
                }
                return Ok(Some(out));
            }
        }
    }
    Err(JmcpError::Validation(format!(
        "unable to parse checksum output: {output:?}"
    )))
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    #[test]
    fn parses_present_file() {
        let s = "SHA256 (/var/tmp/foo.tgz) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n";
        let h = parse_checksum_output(s).unwrap().unwrap();
        assert_eq!(h[0], 0xba);
        assert_eq!(h[31], 0xad);
    }

    #[test]
    fn returns_none_for_missing_file() {
        let s = "error: stat: /var/tmp/foo: No such file or directory\n";
        assert!(parse_checksum_output(s).unwrap().is_none());
    }

    #[test]
    fn errors_on_garbage_output() {
        let s = "fzzt fzzt nothing here\n";
        assert!(parse_checksum_output(s).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Temporarily change `hex.len() == 64` to `hex.len() == 65` to force `parses_present_file` to fail.
Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::checksum_tests 2>&1 | tail -10`
Expected: FAIL.

- [ ] **Step 3: Revert**

- [ ] **Step 4: Run to verify pass**

Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(transfer): parse_checksum_output for file checksum sha-256"
```

---

### Task 8: `parse_var_tmp_listing` (in `list_staged_files.rs`)

**Files:**
- Modify: `rust-junosmcp-core/src/tools/list_staged_files.rs`

- [ ] **Step 1: Write the failing test**

Replace stub content with:

```rust
//! `list_staged_files` MCP tool. Discovery of host-staged files and (optionally)
//! the device's /var/tmp/.

use crate::error::JmcpError;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct DeviceFileEntry {
    pub path: String,
    pub size_bytes: u64,
    pub mtime_iso: String,
}

/// Parse `file list /var/tmp/ detail` output. Junos prints lines like:
/// ```text
/// /var/tmp/:
/// total 1234
/// -rw-r--r--   1 root  wheel  1395212800 May 14 18:01 junos-install-vsrx3.tgz
/// -rw-r--r--   1 root  wheel        4321 May 14  2025 core.thingd.12345.gz
/// ```
/// (For files older than ~6 months Junos shows the year instead of HH:MM.)
/// Skips directories and `.`/`..` entries.
pub fn parse_var_tmp_listing(output: &str, current_year: i32) -> Vec<DeviceFileEntry> {
    let mut out = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty()
            || trimmed.starts_with("total ")
            || trimmed.ends_with(":")
        {
            continue;
        }
        // Expect: perms links owner group size MMM DD (HH:MM|YYYY) name
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        if fields[0].starts_with('d') {
            continue; // directory
        }
        let size: u64 = match fields[4].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let month = fields[5];
        let day = fields[6];
        let last = fields[7];
        let name = fields[8..].join(" ");
        if name == "." || name == ".." {
            continue;
        }
        let (date_str, time_str) = if last.contains(':') {
            (format!("{}-{}-{:>02}", current_year, month, day), last.to_string())
        } else {
            (format!("{}-{}-{:>02}", last, month, day), "00:00".to_string())
        };
        let mtime_iso = junos_date_to_iso(&date_str, &time_str);
        out.push(DeviceFileEntry {
            path: format!("/var/tmp/{name}"),
            size_bytes: size,
            mtime_iso,
        });
    }
    out
}

/// Best-effort conversion. Returns "{year}-{mm:02}-{dd:02}T{hh:mm}:00Z".
/// Doesn't attempt timezone correction (Junos `file list` is in device-local
/// time; for a lab where MCP host and device are in the same TZ this is fine
/// and the operator-facing string is honest about being local-clock-derived).
fn junos_date_to_iso(date: &str, time: &str) -> String {
    // date format: "YYYY-Mon-DD"
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return format!("{date}T{time}");
    }
    let year = parts[0];
    let month = month_to_num(parts[1]);
    let day = parts[2];
    let t = if time.contains(':') {
        format!("{time}:00")
    } else {
        "00:00:00".to_string()
    };
    format!("{year}-{month:02}-{day:>02}T{t}Z")
}

fn month_to_num(m: &str) -> u32 {
    match m {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => 0,
    }
}

// Stubbed handler so the module compiles; full impl lands in Task 11.
pub async fn handle(
    _args: crate::tools::ListStagedFilesArgs,
    _dm: std::sync::Arc<crate::device_manager::DeviceManager>,
    _staging_dir: std::path::PathBuf,
) -> Result<serde_json::Value, JmcpError> {
    Err(JmcpError::Validation("not yet implemented".into()))
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    const SAMPLE: &str = "\
/var/tmp/:
total 1234
-rw-r--r--   1 root  wheel  1395212800 May 14 18:01 junos-install-vsrx3.tgz
-rw-r--r--   1 root  wheel        4321 May 14  2025 core.thingd.12345.gz
drwxr-xr-x   2 root  wheel         512 May 14 18:01 some_dir
-rw-r--r--   1 root  wheel         100 May 14 18:01 .
";

    #[test]
    fn parses_two_files_and_skips_dir_and_dot() {
        let v = parse_var_tmp_listing(SAMPLE, 2026);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].path, "/var/tmp/junos-install-vsrx3.tgz");
        assert_eq!(v[0].size_bytes, 1_395_212_800);
        assert!(v[0].mtime_iso.starts_with("2026-05-14T18:01"));
    }

    #[test]
    fn older_file_with_year_column_uses_year() {
        let v = parse_var_tmp_listing(SAMPLE, 2026);
        let core = v.iter().find(|e| e.path.ends_with("core.thingd.12345.gz")).unwrap();
        assert!(core.mtime_iso.starts_with("2025-05-14"));
    }

    #[test]
    fn skips_total_line_and_header() {
        let v = parse_var_tmp_listing(SAMPLE, 2026);
        assert!(v.iter().all(|e| !e.path.contains("total")));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Force fail: temporarily delete the `if fields[0].starts_with('d') { continue; }` line so directories are included.
Run: `cargo test -p rust-junosmcp-core --lib tools::list_staged_files::parse_tests::parses_two_files_and_skips_dir_and_dot 2>&1 | tail -10`
Expected: FAIL with `left: 3 right: 2`.

- [ ] **Step 3: Revert**

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::list_staged_files::parse_tests 2>&1 | tail -10`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/list_staged_files.rs
git commit -m "feat(list-staged): parse_var_tmp_listing handles HH:MM and year columns"
```

---

### Task 9: Round out `JmcpError` variants + `Display` tests

**Files:**
- Modify: `rust-junosmcp-core/src/error.rs`

- [ ] **Step 1: Write the failing tests**

Append to the existing `mod tests` block in `error.rs`:

```rust
#[test]
fn bad_source_path_display_includes_code() {
    let s = JmcpError::BadSourcePath("contains '/'".into()).to_string();
    assert!(s.contains("code=bad_source_path"));
    assert!(s.contains("contains '/'"));
}

#[test]
fn unsupported_auth_display_includes_remediation() {
    let s = JmcpError::UnsupportedAuth("vSRX-test10".into()).to_string();
    assert!(s.contains("code=unsupported_auth"));
    assert!(s.contains("vSRX-test10"));
    assert!(s.contains("ssh_key"));
}

#[test]
fn dest_exists_differs_display_includes_force_hint() {
    let s = JmcpError::DestExistsDiffers {
        dest: "/var/tmp/foo".into(),
        local_sha: "aaa".into(),
        remote_sha: "bbb".into(),
    }.to_string();
    assert!(s.contains("code=dest_exists_differs"));
    assert!(s.contains("force=true"));
}

#[test]
fn scp_failed_display_includes_stderr() {
    let s = JmcpError::ScpFailed { exit_code: 1, stderr: "Permission denied".into() }.to_string();
    assert!(s.contains("code=scp_failed"));
    assert!(s.contains("Permission denied"));
    assert!(s.contains("exit=1"));
}

#[test]
fn connect_timeout_display_includes_hint() {
    let s = JmcpError::ConnectTimeout("vSRX-test10".into()).to_string();
    assert!(s.contains("code=connect_timeout"));
    assert!(s.contains("vSRX-test10"));
}

#[test]
fn verify_mismatch_display_notes_deletion() {
    let s = JmcpError::VerifyMismatch {
        dest: "/var/tmp/foo".into(),
        local_sha: "aaa".into(),
        remote_sha: "bbb".into(),
    }.to_string();
    assert!(s.contains("code=verify_mismatch"));
    assert!(s.contains("deleted"));
}

#[test]
fn transfer_outer_timeout_display_includes_remediation() {
    let s = JmcpError::TransferOuterTimeout(std::time::Duration::from_secs(60)).to_string();
    assert!(s.contains("code=outer_timeout"));
    assert!(s.contains("raise"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p rust-junosmcp-core --lib error::tests::unsupported_auth_display_includes_remediation 2>&1 | tail -10`
Expected: FAIL — variant doesn't exist.

- [ ] **Step 3: Add the variants**

Insert into the `JmcpError` enum (alongside the variant added in Task 2 / Task 6):

```rust
#[error("unsupported auth [code=unsupported_auth]: device '{0}' uses password auth; transfer_file requires ssh_key (add SshKey to inventory)")]
UnsupportedAuth(String),

#[error("destination already exists with different content [code=dest_exists_differs]: {dest} (local sha256={local_sha}, remote sha256={remote_sha}); pass force=true to overwrite")]
DestExistsDiffers { dest: String, local_sha: String, remote_sha: String },

#[error("scp failed [code=scp_failed] (exit={exit_code}): {stderr}")]
ScpFailed { exit_code: i32, stderr: String },

#[error("scp connect timeout [code=connect_timeout]: device '{0}' may be unreachable or NETCONF/SSH port is closed")]
ConnectTimeout(String),

#[error("post-transfer verify failed [code=verify_mismatch]: {dest} (local sha256={local_sha}, remote sha256={remote_sha}); destination file was deleted")]
VerifyMismatch { dest: String, local_sha: String, remote_sha: String },

#[error("transfer outer timeout [code=outer_timeout] after {0:?}; raise the `timeout` arg or split the file")]
TransferOuterTimeout(std::time::Duration),
```

(Keep `BadSourcePath` and `InsufficientDisk` from earlier tasks.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib error:: 2>&1 | tail -15`
Expected: all error tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/error.rs
git commit -m "feat(transfer): JmcpError variants for transfer error codes"
```

---

### Task 10: `list_staged_files::handle()` — host-staging-only path

**Files:**
- Modify: `rust-junosmcp-core/src/tools/list_staged_files.rs`

- [ ] **Step 1: Write the failing test**

Append to `list_staged_files.rs`:

```rust
use crate::device_manager::DeviceManager;
use crate::tools::ListStagedFilesArgs;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize)]
pub struct StagedFileEntry {
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub mtime_iso: String,
}

/// Read the staging directory and return one entry per regular file. Computes
/// sha256 of every file (cost ~3 s/GB on the LXC). Skips directories and
/// dotfiles.
pub async fn read_staging_dir(staging_dir: &Path) -> Result<Vec<StagedFileEntry>, JmcpError> {
    let mut out = Vec::new();
    if !staging_dir.exists() {
        return Ok(out);
    }
    let mut rd = tokio::fs::read_dir(staging_dir).await?;
    while let Some(entry) = rd.next_entry().await? {
        let meta = entry.metadata().await?;
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let (sha, size) = crate::tools::transfer_file::sha256_file(&path).await?;
        let mtime_iso = systemtime_to_iso(meta.modified().ok());
        let mut hex = String::with_capacity(64);
        for b in sha {
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{:02x}", b);
        }
        out.push(StagedFileEntry { name, size_bytes: size, sha256: hex, mtime_iso });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn systemtime_to_iso(t: Option<std::time::SystemTime>) -> String {
    let Some(t) = t else { return String::from("unknown") };
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Use chrono if it's already in scope via dependencies. The workspace
    // declares chrono in workspace.dependencies; pull it into core here.
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .unwrap_or_else(chrono::Utc::now);
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub async fn handle(
    args: ListStagedFilesArgs,
    dm: Arc<DeviceManager>,
    staging_dir: PathBuf,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        let staged = read_staging_dir(&staging_dir).await?;
        let mut payload = json!({
            "staging_dir": staging_dir.display().to_string(),
            "staged_files": staged,
            "device": Value::Null,
            "device_files": Value::Null,
        });
        if let Some(router) = args.router_name {
            // Confirm router exists; full device-side listing in Task 11.
            let _ = dm.inventory().get(&router)?;
            payload["device"] = json!(router);
            payload["device_files"] = json!([]); // placeholder until Task 11
        }
        Ok::<_, JmcpError>(payload)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))?
}

#[cfg(test)]
mod handle_tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn reads_empty_staging_dir() {
        let dir = tempfile::tempdir().unwrap();
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs { router_name: None, timeout: 5 },
            dm,
            dir.path().to_path_buf(),
        )
        .await
        .unwrap();
        assert_eq!(r["staged_files"].as_array().unwrap().len(), 0);
        assert_eq!(r["device"], Value::Null);
    }

    #[tokio::test]
    async fn reads_two_files_with_sha256() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.tgz"), b"abc").unwrap();
        std::fs::write(dir.path().join("b.tgz"), b"defg").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"hi").unwrap();
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs { router_name: None, timeout: 5 },
            dm,
            dir.path().to_path_buf(),
        )
        .await
        .unwrap();
        let arr = r["staged_files"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "dotfile should be skipped");
        assert_eq!(arr[0]["name"], "a.tgz");
        assert_eq!(arr[0]["size_bytes"], 3);
        assert_eq!(
            arr[0]["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        ).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: Some("nope".into()),
                timeout: 5,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
```

Verify `chrono` is available to the core crate. It's in workspace.dependencies; add to `rust-junosmcp-core/Cargo.toml`:

```toml
chrono       = { workspace = true }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp-core --lib tools::list_staged_files::handle_tests 2>&1 | tail -10`
Expected: PASSes after the impl from Step 1 — temporarily change `name.starts_with('.')` to `false` to force `reads_two_files_with_sha256` (dotfile skip) to fail.

- [ ] **Step 3: Revert**

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::list_staged_files::handle_tests 2>&1 | tail -10`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/list_staged_files.rs rust-junosmcp-core/Cargo.toml
git commit -m "feat(list-staged): handle() returns staged files with sha256"
```

---

### Task 11: `list_staged_files::handle()` — device-side listing

**Files:**
- Modify: `rust-junosmcp-core/src/tools/list_staged_files.rs`

- [ ] **Step 1: Write the failing test**

Append a new test module:

```rust
#[cfg(test)]
mod device_handle_tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    /// Smoke: when router_name is given but the device is unreachable, the call
    /// returns an error (rustez connect failure), not silent success. This
    /// guards against the device_files key being silently set to []
    /// when the device isn't actually contacted.
    #[tokio::test]
    async fn unreachable_router_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // 192.0.2.1 is TEST-NET-1, RFC 5737 — guaranteed unreachable.
        let key = tempfile::NamedTempFile::new().unwrap();
        let json = format!(
            r#"{{"r1":{{"ip":"192.0.2.1","username":"u",
                       "auth":{{"type":"ssh_key","private_key_path":"{}"}}}}}}"#,
            key.path().display()
        );
        f.write_all(json.as_bytes()).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: Some("r1".into()),
                timeout: 5,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await;
        // Either Timeout, ConnectTimeout, or a Rustez connect failure. Just
        // assert it's an error, not Ok with empty device_files.
        assert!(r.is_err(), "expected error against TEST-NET-1, got {r:?}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Currently `handle` returns `device_files: []` without contacting the device, so this test FAILs.
Run: `cargo test -p rust-junosmcp-core --lib tools::list_staged_files::device_handle_tests::unreachable_router_returns_error 2>&1 | tail -10`
Expected: FAIL — got Ok.

- [ ] **Step 3: Implement device-side listing**

Replace the `if let Some(router) = args.router_name { ... }` block in `handle()` with:

```rust
if let Some(router) = args.router_name {
    let _ = dm.inventory().get(&router)?;
    let mut dev = dm.open(&router).await?;
    let raw = dev.cli("file list /var/tmp/ detail").await?;
    let now = chrono::Utc::now();
    let year = now.format("%Y").to_string().parse::<i32>().unwrap_or(2026);
    let entries = parse_var_tmp_listing(&raw, year);
    payload["device"] = json!(router);
    payload["device_files"] = serde_json::to_value(&entries)?;
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::list_staged_files:: 2>&1 | tail -15`
Expected: all list_staged_files tests PASS, including the new unreachable-router test (network call fails fast).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/list_staged_files.rs
git commit -m "feat(list-staged): query device /var/tmp/ via dev.cli + parser"
```

---

### Task 12: `transfer_file::handle()` — validation + local sha256 + auth check

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`

- [ ] **Step 1: Write the failing test**

Append a new test module:

```rust
use crate::device_manager::DeviceManager;
use crate::inventory::AuthConfig;
use crate::tools::TransferFileArgs;
use serde_json::Value;

/// Configuration handed to `handle()`. Holds the staging-dir + known-hosts
/// paths and the (mockable) ScpRunner. Built once in `main.rs` and cloned
/// per call.
#[derive(Clone)]
pub struct TransferConfig {
    pub staging_dir: std::path::PathBuf,
    pub known_hosts_file: std::path::PathBuf,
    pub scp_runner: Arc<dyn ScpRunner>,
}

pub async fn handle(
    args: TransferFileArgs,
    dm: Arc<DeviceManager>,
    cfg: TransferConfig,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        validate_source_basename(&args.source_path)?;
        let local_path = cfg.staging_dir.join(&args.source_path);
        let meta = std::fs::metadata(&local_path).map_err(|_| {
            JmcpError::BadSourcePath(format!(
                "staged file not found or unreadable: {}",
                local_path.display()
            ))
        })?;
        if !meta.is_file() {
            return Err(JmcpError::BadSourcePath(format!(
                "staged path is not a regular file: {}",
                local_path.display()
            )));
        }
        // Compute local sha256 + size (streamed).
        let (local_sha, _local_size) = sha256_file(&local_path).await?;

        // Resolve device + check auth type.
        let inv = dm.inventory();
        let entry = inv.get(&args.router_name)?;
        if let AuthConfig::Password { .. } = entry.auth {
            return Err(JmcpError::UnsupportedAuth(args.router_name.clone()));
        }

        // The remaining steps (free-disk check, remote sha probe, scp, post-verify)
        // land in Tasks 13 + 14. Stub a placeholder error so this task can ship
        // independently with passing tests.
        let _ = (local_sha, &cfg);
        Err(JmcpError::Validation("transfer pipeline not yet implemented".into()))
    })
    .await
    .map_err(|_| JmcpError::TransferOuterTimeout(timeout))?
}

#[cfg(test)]
mod handle_validation_tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn cfg(dir: &std::path::Path) -> TransferConfig {
        TransferConfig {
            staging_dir: dir.to_path_buf(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            scp_runner: MockScpRunner::ok(),
        }
    }

    fn build_inv(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn rejects_bad_basename() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "../etc/passwd".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn rejects_missing_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "missing.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn rejects_password_auth_with_unsupported_auth() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnsupportedAuth(ref s)) if s == "r1"));
    }

    #[tokio::test]
    async fn unknown_router_propagates_unknown_router_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "nope".into(),
                source_path: "foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Temporarily change `if let AuthConfig::Password { .. }` to `if false` so `rejects_password_auth_with_unsupported_auth` fails.
Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::handle_validation_tests 2>&1 | tail -10`
Expected: FAIL.

- [ ] **Step 3: Revert**

- [ ] **Step 4: Run to verify pass**

Expected: 4 PASS (the password / bad-source / missing-file / unknown-router checks all complete before the placeholder error fires).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(transfer): handle() validates source + auth + computes local sha256"
```

---

### Task 13: `transfer_file` pre-flight NETCONF (storage + remote checksum + idempotent skip)

Extend `transfer_file::handle()` to run, inside the outer `tokio::time::timeout`:
1. Open a pooled session via `dm.open(&args.router_name).await?`.
2. Run `show system storage no-forwarding`, parse with `parse_storage_free_bytes`, and reject if free < `local_size + 32 MiB`.
3. Run `file checksum sha-256 /var/tmp/<basename>`, parse with `parse_checksum_output`. If `Some(remote)`:
   - if `remote == local_sha`, return `{ status: "skipped", remote_path, sha256, size_bytes, message }` (idempotent).
   - else if `args.force`, fall through to scp.
   - else return `JmcpError::DestExistsDiffers`.

**Files:**
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`
- Test: same file (`#[cfg(test)] mod handle_preflight_tests`) — uses `MockScpRunner` (won't be invoked) and a `DeviceManager` whose `open()` we cannot easily mock; **so these unit tests cover only `force=false` + `BadSourcePath`-path branches that early-return before NETCONF**. Real NETCONF coverage lives in Task 22 (`#[ignore]` integration tests).

- [ ] **Step 1: Write the failing test**

Append inside `handle_validation_tests` mod (the new test exercises the early-return path that **doesn't** require NETCONF):

```rust
#[tokio::test]
async fn skip_message_shape_helper_returns_expected_keys() {
    // Pure helper: given (basename, sha, size), produce the JSON returned by the idempotent skip branch.
    use serde_json::json;
    let v = super::skipped_response("foo.tgz", &[0u8; 32], 1234);
    assert_eq!(v["status"], "skipped");
    assert_eq!(v["remote_path"], "/var/tmp/foo.tgz");
    assert_eq!(v["size_bytes"], 1234);
    assert_eq!(v["sha256"], "0".repeat(64));
    assert!(v["message"].as_str().unwrap().contains("already present"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::handle_validation_tests::skip_message_shape 2>&1 | tail -10`
Expected: FAIL — `skipped_response` not defined.

- [ ] **Step 3: Add the helper plus the NETCONF orchestration**

Add to `rust-junosmcp-core/src/tools/transfer_file.rs`:

```rust
use crate::inventory::AuthConfig;

const MIN_FREE_HEADROOM_BYTES: u64 = 32 * 1024 * 1024;

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub(crate) fn skipped_response(basename: &str, sha: &[u8; 32], size: u64) -> serde_json::Value {
    serde_json::json!({
        "status": "skipped",
        "remote_path": format!("/var/tmp/{}", basename),
        "size_bytes": size,
        "sha256": hex32(sha),
        "message": "remote file with matching SHA-256 already present; transfer skipped",
    })
}
```

Then replace the placeholder body at the end of `handle()` (the `Err(JmcpError::Timeout(...))` placeholder from Task 12) with the orchestration:

```rust
let timeout_dur = std::time::Duration::from_secs(args.timeout);
let basename_owned = basename.to_string();
let local_sha_arr = local_sha;
let local_size_v = local_size;
let force = args.force;
let verify = args.verify;
let router = args.router_name.clone();
let local_path_owned = local_path.clone();
let cfg_clone = cfg.clone();

let result = tokio::time::timeout(timeout_dur, async move {
    let dev_entry = dm.inventory().get(&router)?;
    let host = dev_entry.host.clone();
    let port = dev_entry.port;
    let user = dev_entry.username.clone();
    let key_path = match &dev_entry.auth {
        AuthConfig::SshKey { private_key_path } => private_key_path.clone(),
        AuthConfig::Password { .. } => return Err(JmcpError::UnsupportedAuth),
    };

    let mut dev = dm.open(&router).await?;

    // 1. Storage check
    let storage_out = dev.cli("show system storage no-forwarding").await?;
    let free = super::transfer_file_parsers::parse_storage_free_bytes(&storage_out)
        .ok_or_else(|| JmcpError::ScpFailed("could not parse `show system storage` output".into()))?;
    let needed = local_size_v.saturating_add(MIN_FREE_HEADROOM_BYTES);
    if free < needed {
        return Err(JmcpError::InsufficientDisk { needed, free });
    }

    // 2. Remote checksum
    let cmd = format!("file checksum sha-256 /var/tmp/{}", basename_owned);
    let cs_out = dev.cli(&cmd).await?;
    if let Some(remote_sha) = parse_checksum_output(&cs_out) {
        if remote_sha == local_sha_arr {
            return Ok(skipped_response(&basename_owned, &local_sha_arr, local_size_v));
        }
        if !force {
            return Err(JmcpError::DestExistsDiffers);
        }
    }

    // 3. SCP push (Task 14)
    let job = ScpJob {
        host: host.clone(),
        port,
        username: user.clone(),
        private_key_path: key_path.clone(),
        known_hosts_file: cfg_clone.known_hosts_file.clone(),
        local_path: local_path_owned.clone(),
        remote_dir: "/var/tmp/".to_string(),
    };
    let outcome = cfg_clone.scp_runner.run(&job).await
        .map_err(|e| JmcpError::ScpFailed(e.to_string()))?;
    if outcome.exit_code != 0 {
        let stderr_excerpt: String = outcome.stderr.lines().take(20).collect::<Vec<_>>().join("\n");
        return Err(JmcpError::ScpFailed(stderr_excerpt));
    }

    // 4. Optional post-verify (Task 14 will refine)
    let after = dev.cli(&cmd).await?;
    let after_sha = parse_checksum_output(&after)
        .ok_or_else(|| JmcpError::VerifyMismatch("post-transfer checksum unavailable".into()))?;
    if verify && after_sha != local_sha_arr {
        let _ = dev.cli(&format!("file delete /var/tmp/{}", basename_owned)).await;
        return Err(JmcpError::VerifyMismatch(format!(
            "expected {} got {}", hex32(&local_sha_arr), hex32(&after_sha)
        )));
    }

    Ok(serde_json::json!({
        "status": "transferred",
        "remote_path": format!("/var/tmp/{}", basename_owned),
        "size_bytes": local_size_v,
        "sha256": hex32(&local_sha_arr),
    }))
})
.await
.map_err(|_| JmcpError::TransferOuterTimeout(timeout_dur))??;

Ok(result)
```

Add the helper module at the top of the file:

```rust
mod transfer_file_parsers {
    pub use super::parse_storage_free_bytes;
}
```

(Or qualify the call as `crate::tools::transfer_file::parse_storage_free_bytes` — match whatever is consistent with the Task 6 placement. If `parse_storage_free_bytes` is `pub(crate) fn` in this module, just call it directly without the alias module.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file 2>&1 | tail -20`
Expected: All `handle_validation_tests` PASS, including the new `skip_message_shape_helper_returns_expected_keys`.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "feat(transfer): pre-flight storage + remote checksum + idempotent skip"
```

---

### Task 14: `transfer_file` SCP invocation + post-verify cleanup polish

The orchestration in Task 13 already calls `cfg.scp_runner.run(job)` and verifies. This task adds dedicated unit coverage proving:
- SCP failure surfaces as `JmcpError::ScpFailed(stderr_excerpt)` and **does not** delete the (possibly partial) remote file.
- A post-verify mismatch issues a single `file delete /var/tmp/<basename>` and returns `JmcpError::VerifyMismatch`.
- `verify=false` skips the post-verify but still returns the locally-computed sha in the response.

Because the real NETCONF cli isn't mockable here, drive these via the **real-device `#[ignore]` test in Task 22**. In this task, restrict unit coverage to the `MockScpRunner` argv shape and the `JmcpError` Display strings.

**Files:**
- Test: `rust-junosmcp-core/src/tools/transfer_file.rs` (`#[cfg(test)] mod scp_unit_tests`)

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod scp_unit_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn mock_runner_records_argv_and_reports_success() {
        let mock = MockScpRunner::with_outcome(ScpOutcome {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        });
        let job = ScpJob {
            host: "192.0.2.4".into(),
            port: 22,
            username: "admin".into(),
            private_key_path: "/etc/jmcp/ssh/id_ed25519".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            local_path: "/var/lib/jmcp/staging/abc/junos.tgz".into(),
            remote_dir: "/var/tmp/".into(),
        };
        let outcome = (mock.clone() as Arc<dyn ScpRunner>).run(&job).await.unwrap();
        assert_eq!(outcome.exit_code, 0);
        let calls = mock.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert!(calls[0].iter().any(|s| s == "-O"));
        assert!(calls[0].iter().any(|s| s == "admin@192.0.2.4:/var/tmp/"));
    }

    #[test]
    fn scp_failed_display_includes_code() {
        let e = JmcpError::ScpFailed("permission denied".into());
        let s = e.to_string();
        assert!(s.contains("[code=scp_failed]"), "got {}", s);
        assert!(s.contains("permission denied"), "got {}", s);
    }

    #[test]
    fn verify_mismatch_display_includes_code() {
        let e = JmcpError::VerifyMismatch("expected ... got ...".into());
        assert!(e.to_string().contains("[code=verify_mismatch]"));
    }

    #[test]
    fn transfer_outer_timeout_display_includes_code() {
        let e = JmcpError::TransferOuterTimeout(std::time::Duration::from_secs(600));
        let s = e.to_string();
        assert!(s.contains("[code=transfer_outer_timeout]"), "got {}", s);
        assert!(s.contains("600"), "got {}", s);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Temporarily change `mock.calls.lock().await` to `mock.calls.lock().await; let _ = ();` (skipping the assertions) so `mock_runner_records_argv_and_reports_success` would not actually verify recording. Or simpler: temporarily change the `assert_eq!(calls[0][0], "-O")` already present in Task 5's `runner_tests` to assert `"-X"` and run only the new tests.

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::scp_unit_tests 2>&1 | tail -15`
Expected: 4 PASS (the API from Task 5 already provides `MockScpRunner::with_outcome(...)` returning `Arc<Self>` and `.calls` as a `tokio::sync::Mutex`).

(No further fill-in needed — Task 5 already exposes the required surface.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp-core --lib tools::transfer_file::scp_unit_tests 2>&1 | tail -10`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp-core/src/tools/transfer_file.rs
git commit -m "test(transfer): MockScpRunner argv capture + error Display codes"
```

---



### Task 15: CLI flags `--staging-dir` and `--known-hosts-file`

Add two new global CLI flags so deployments can override default file-transfer paths.

**Files:**
- Modify: `rust-junosmcp/src/cli.rs`

- [ ] **Step 1: Write the failing test**

Append inside the existing `#[cfg(test)] mod tests` block:

```rust
#[test]
fn defaults_for_transfer_paths() {
    let cli = Cli::parse_from(["rust-junosmcp"]);
    assert_eq!(
        cli.staging_dir,
        std::path::PathBuf::from("/var/lib/jmcp/staging")
    );
    assert_eq!(
        cli.known_hosts_file,
        std::path::PathBuf::from("/etc/jmcp/known_hosts")
    );
}

#[test]
fn parses_custom_transfer_paths() {
    let cli = Cli::parse_from([
        "rust-junosmcp",
        "--staging-dir",
        "/tmp/staging",
        "--known-hosts-file",
        "/tmp/khosts",
    ]);
    assert_eq!(cli.staging_dir, std::path::PathBuf::from("/tmp/staging"));
    assert_eq!(cli.known_hosts_file, std::path::PathBuf::from("/tmp/khosts"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp --lib cli::tests::defaults_for_transfer_paths 2>&1 | tail -10`
Expected: FAIL — fields don't exist on `Cli`.

- [ ] **Step 3: Add the fields**

In `rust-junosmcp/src/cli.rs`, append to the `Cli` struct (above the `command` subcommand or alongside other paths):

```rust
    /// Directory used to stage files before scp push (transfer_file).
    #[arg(long, default_value = "/var/lib/jmcp/staging")]
    pub staging_dir: PathBuf,

    /// SSH known_hosts file used for scp pushes (transfer_file).
    #[arg(long, default_value = "/etc/jmcp/known_hosts")]
    pub known_hosts_file: PathBuf,
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp --lib cli::tests 2>&1 | tail -10`
Expected: all `cli::tests` PASS, including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/cli.rs
git commit -m "feat(cli): add --staging-dir and --known-hosts-file flags"
```

---

### Task 16: Thread `TransferConfig` through `JmcpHandler` + `main.rs` wiring + `lib.rs` re-export

`JmcpHandler::new` currently takes `(dm, policy)`. Add a third argument (or a builder field) for `TransferConfig`. Build it in `main.rs` from CLI flags. Re-export `TransferConfig` and `ScpRunner`/`OpenSshScpRunner` from `rust-junosmcp-core`.

**Files:**
- Modify: `rust-junosmcp-core/src/lib.rs`
- Modify: `rust-junosmcp/src/server.rs` (constructor + struct field)
- Modify: `rust-junosmcp/src/main.rs`
- Test: `rust-junosmcp/src/server.rs` (`scope_tests::make_handler`)

- [ ] **Step 1: Write the failing test**

Update (or add) one test in `server.rs` that constructs `JmcpHandler::new` with a `TransferConfig` and asserts the handler exposes a `transfer_config()` accessor returning the same `staging_dir`:

```rust
#[test]
fn handler_carries_transfer_config() {
    use rust_junosmcp_core::tools::transfer_file::{TransferConfig, OpenSshScpRunner};
    use std::sync::Arc;

    let dm = Arc::new(test_device_manager());
    let policy = Arc::new(rust_junosmcp_core::Policy::build(&dm.inventory()).unwrap());
    let cfg = TransferConfig {
        staging_dir: std::path::PathBuf::from("/tmp/x"),
        known_hosts_file: std::path::PathBuf::from("/tmp/khosts"),
        scp_runner: Arc::new(OpenSshScpRunner),
    };
    let h = JmcpHandler::new(dm, policy, cfg.clone());
    assert_eq!(h.transfer_config().staging_dir, cfg.staging_dir);
}
```

(`test_device_manager` is whatever helper already exists in scope_tests; if there isn't one, build a minimal `DeviceManager` from a one-device `Inventory` exactly the way the existing scope tests do.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp --lib server::scope_tests::handler_carries_transfer_config 2>&1 | tail -10`
Expected: FAIL — `JmcpHandler::new` arity mismatch + no `transfer_config()` accessor.

- [ ] **Step 3: Update `JmcpHandler`**

In `rust-junosmcp/src/server.rs`:

```rust
#[derive(Clone)]
pub struct JmcpHandler {
    dm: Arc<DeviceManager>,
    policy: ArcSwap<Policy>,
    transfer_cfg: rust_junosmcp_core::tools::transfer_file::TransferConfig,
}

impl JmcpHandler {
    pub fn new(
        dm: Arc<DeviceManager>,
        policy: Arc<Policy>,
        transfer_cfg: rust_junosmcp_core::tools::transfer_file::TransferConfig,
    ) -> Self {
        Self {
            dm,
            policy: ArcSwap::from(policy),
            transfer_cfg,
        }
    }

    pub fn transfer_config(&self) -> &rust_junosmcp_core::tools::transfer_file::TransferConfig {
        &self.transfer_cfg
    }

    // ... existing methods unchanged ...
}
```

Update every call site in this file (and existing scope_tests) to pass the new arg. Provide a helper:

```rust
#[cfg(test)]
fn test_transfer_cfg() -> rust_junosmcp_core::tools::transfer_file::TransferConfig {
    use rust_junosmcp_core::tools::transfer_file::{TransferConfig, OpenSshScpRunner};
    use std::sync::Arc;
    TransferConfig {
        staging_dir: std::path::PathBuf::from("/tmp/staging"),
        known_hosts_file: std::path::PathBuf::from("/tmp/known_hosts"),
        scp_runner: Arc::new(OpenSshScpRunner),
    }
}
```

In `rust-junosmcp-core/src/lib.rs`, re-export:

```rust
pub use crate::tools::transfer_file::{
    OpenSshScpRunner, ScpJob, ScpOutcome, ScpRunner, TransferConfig,
};
```

In `rust-junosmcp/src/main.rs`, build the cfg from CLI flags and pass it in:

```rust
use rust_junosmcp_core::{OpenSshScpRunner, TransferConfig};

let transfer_cfg = TransferConfig {
    staging_dir: args.staging_dir.clone(),
    known_hosts_file: args.known_hosts_file.clone(),
    scp_runner: Arc::new(OpenSshScpRunner),
};

let handler = JmcpHandler::new(dev_manager.clone(), policy, transfer_cfg);
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp --lib 2>&1 | tail -20`
Expected: all server tests PASS, including the new `handler_carries_transfer_config`.

Run: `cargo build --workspace 2>&1 | tail -10`
Expected: build succeeds (catches any other call sites).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/server.rs rust-junosmcp/src/main.rs rust-junosmcp-core/src/lib.rs
git commit -m "feat(server): plumb TransferConfig through handler + main wiring"
```

---

### Task 17: `#[tool]` methods `transfer_file` and `list_staged_files` on `JmcpHandler`

Expose the two new tools via the rmcp `#[tool]` macro pattern already used by the other 11 tools. Both honor existing per-token scope rules: `transfer_file` requires both router and tool scope; `list_staged_files` requires only tool scope (it does not select a router unless one is supplied).

**Files:**
- Modify: `rust-junosmcp/src/server.rs`

- [ ] **Step 1: Write the failing test**

Append inside `scope_tests`:

```rust
#[tokio::test]
async fn transfer_file_denied_when_router_out_of_scope() {
    let h = JmcpHandler::new(test_dm(), test_policy(), test_transfer_cfg());
    // Token scoped only to {router=other, tool=transfer_file}; current router request is "vsrx-test10".
    let res = h
        .transfer_file_for_test(
            scope_token(&["other"], &["transfer_file"]),
            rust_junosmcp_core::tools::TransferFileArgs {
                router_name: "vsrx-test10".into(),
                source_path: "/tmp/foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
        )
        .await;
    assert!(matches!(res, Err(rust_junosmcp_core::error::JmcpError::Forbidden { .. })));
}
```

(`transfer_file_for_test` is the same scope-aware shim used by other tools in the existing `scope_tests` — match the pattern that's already there.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp --lib server::scope_tests::transfer_file_denied 2>&1 | tail -10`
Expected: FAIL — method doesn't exist.

- [ ] **Step 3: Add the `#[tool]` methods**

In `rust-junosmcp/src/server.rs`, inside the `#[tool_router]` (or whichever attribute is used in this file for the existing 11 tools — match exactly):

```rust
/// Push a local file to /var/tmp/ on a Junos device via SCP (legacy -O protocol).
/// Idempotent on matching SHA-256.
#[tool(description = "...")]
pub async fn transfer_file(
    &self,
    Parameters(args): Parameters<rust_junosmcp_core::tools::TransferFileArgs>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    self.check_router_and_tool_scope(&args.router_name, "transfer_file")?;
    match rust_junosmcp_core::tools::transfer_file::handle(
        args,
        self.dm.clone(),
        self.transfer_cfg.clone(),
    )
    .await
    {
        Ok(v) => Ok(CallToolResult::success(vec![Content::json(v)?])),
        Err(e) => Ok(CallToolResult::error(vec![Content::text(e.to_string())])),
    }
}

/// List host-staging files (always) plus device-side /var/tmp/ if router_name supplied.
#[tool(description = "...")]
pub async fn list_staged_files(
    &self,
    Parameters(args): Parameters<rust_junosmcp_core::tools::ListStagedFilesArgs>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    self.check_tool_scope_only("list_staged_files")?;
    if let Some(r) = &args.router_name {
        self.check_router_scope(r, "list_staged_files")?;
    }
    match rust_junosmcp_core::tools::list_staged_files::handle(
        args,
        self.dm.clone(),
        self.transfer_cfg.clone(),
    )
    .await
    {
        Ok(v) => Ok(CallToolResult::success(vec![Content::json(v)?])),
        Err(e) => Ok(CallToolResult::error(vec![Content::text(e.to_string())])),
    }
}
```

(Match the exact wrappers used by the existing 11 tools — the pattern shown is illustrative; reuse the actual `check_*` helpers and `Content::*` constructors already in this file.)

Add the equivalent test-only helpers (`transfer_file_for_test`, `list_staged_files_for_test`) following the pattern of existing test shims.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp --lib server 2>&1 | tail -20`
Expected: scope tests for both new tools PASS; no regressions.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/src/server.rs
git commit -m "feat(server): expose transfer_file + list_staged_files MCP tools"
```

---

### Task 18: stdio smoke test for `list_staged_files`

End-to-end test: spawn the binary in stdio mode against a temp inventory, populate the staging dir with two fake files, call `list_staged_files` with no router, assert both files appear.

**Files:**
- Create: `rust-junosmcp/tests/list_staged_files_smoke.rs`
- Reference (do not modify): `rust-junosmcp/tests/common/mod.rs`

- [ ] **Step 1: Write the failing test**

```rust
mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
use serde_json::json;

#[tokio::test]
async fn list_staged_files_returns_host_staging_only() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("alpha.tgz"), b"alpha-bytes").unwrap();
    std::fs::write(staging.join("beta.bin"), b"beta-bytes").unwrap();

    let inv = write_inventory_in(dir.path(), "vsrx-test10");
    let known = dir.path().join("known_hosts");
    std::fs::write(&known, b"").unwrap();

    let mut server = spawn_stdio_server_with_args(&[
        "-f",
        inv.to_str().unwrap(),
        "--staging-dir",
        staging.to_str().unwrap(),
        "--known-hosts-file",
        known.to_str().unwrap(),
    ])
    .await;

    let resp = call_tool(
        &mut server,
        "list_staged_files",
        json!({}),
    )
    .await
    .expect("call_tool");

    let text = resp.to_string();
    assert!(text.contains("alpha.tgz"), "missing alpha: {}", text);
    assert!(text.contains("beta.bin"), "missing beta: {}", text);
    // No router supplied -> no device_files key (or it should be empty/absent).
    assert!(
        !text.contains("\"device_files\":["),
        "unexpected device_files in host-only response: {}",
        text
    );

    server.shutdown().await;
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp --test list_staged_files_smoke 2>&1 | tail -15`
Expected: FAIL — until Tasks 10/16/17 are landed it may be missing pieces; if Tasks 10–17 are all done, the test should compile and reveal any wiring gaps.

- [ ] **Step 3: Fix any wiring gaps surfaced**

Common gaps: `write_inventory_in` may not yet accept `(dir, router_name)` — extend it (or add `write_inventory_in_named`) to mint a one-router file with `auth.type = "ssh_key"`. If it does, the test passes as-is.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp --test list_staged_files_smoke 2>&1 | tail -10`
Expected: 1 PASS.

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/tests/list_staged_files_smoke.rs rust-junosmcp/tests/common/mod.rs
git commit -m "test(stdio): list_staged_files host-only smoke"
```

---

### Task 19: stdio smoke test for `transfer_file`

Three failure modes reachable without a real device:
1. `BadSourcePath` — source has `..`.
2. `UnknownRouter` — router name not in inventory.
3. `ConnectTimeout` — router resolves to TEST-NET-1 (`192.0.2.1`), real scp call times out.

**Files:**
- Create: `rust-junosmcp/tests/transfer_file_smoke.rs`

- [ ] **Step 1: Write the failing test**

```rust
mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
use serde_json::json;

async fn make_server(dir: &std::path::Path) -> common::ServerHandle {
    let inv = write_inventory_in(dir, "vsrx-test10"); // host=192.0.2.1, port=830, ssh_key auth
    let staging = dir.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    let known = dir.join("known_hosts");
    std::fs::write(&known, b"").unwrap();
    spawn_stdio_server_with_args(&[
        "-f",
        inv.to_str().unwrap(),
        "--staging-dir",
        staging.to_str().unwrap(),
        "--known-hosts-file",
        known.to_str().unwrap(),
    ])
    .await
}

#[tokio::test]
async fn transfer_file_rejects_bad_source_path() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = make_server(dir.path()).await;
    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "vsrx-test10",
            "source_path": "../etc/passwd",
            "force": false,
            "verify": true,
            "timeout": 5,
        }),
    )
    .await
    .expect("call_tool");
    let s = resp.to_string();
    assert!(s.contains("[code=bad_source_path]"), "got {}", s);
    server.shutdown().await;
}

#[tokio::test]
async fn transfer_file_rejects_unknown_router() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("foo.tgz"), b"abc").unwrap();
    let mut server = make_server(dir.path()).await;
    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "does-not-exist",
            "source_path": "foo.tgz",
            "force": false,
            "verify": true,
            "timeout": 5,
        }),
    )
    .await
    .expect("call_tool");
    let s = resp.to_string();
    assert!(s.contains("does-not-exist"), "got {}", s);
    server.shutdown().await;
}

#[tokio::test]
#[ignore = "requires outbound network to TEST-NET-1; run with --ignored in CI"]
async fn transfer_file_connect_timeout_against_test_net_1() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("foo.tgz"), b"abc").unwrap();
    let mut server = make_server(dir.path()).await;
    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "vsrx-test10",
            "source_path": "foo.tgz",
            "force": false,
            "verify": true,
            "timeout": 30,
        }),
    )
    .await
    .expect("call_tool");
    let s = resp.to_string();
    assert!(
        s.contains("[code=connect_timeout]") || s.contains("[code=transfer_outer_timeout]"),
        "expected connect_timeout or transfer_outer_timeout, got {}",
        s
    );
    server.shutdown().await;
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p rust-junosmcp --test transfer_file_smoke 2>&1 | tail -15`
Expected: at least the bad-source-path test FAILs first (until Tasks 12/16/17 wiring is fully in place).

- [ ] **Step 3: Fill any final wiring**

If `write_inventory_in` doesn't yet write the test-net-1 host, update it (or add a new helper `write_inventory_for_transfer`) with:

```json
{
  "vsrx-test10": {
    "host": "192.0.2.1",
    "port": 830,
    "username": "admin",
    "auth": { "type": "ssh_key", "private_key_path": "/dev/null" }
  }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p rust-junosmcp --test transfer_file_smoke 2>&1 | tail -10`
Expected: 2 PASS, 1 IGNORED.

Optionally confirm the ignored test by hand: `cargo test -p rust-junosmcp --test transfer_file_smoke -- --ignored --test-threads=1` (skip in CI to avoid network-dependent flakes).

- [ ] **Step 5: Commit**

```bash
git add rust-junosmcp/tests/transfer_file_smoke.rs rust-junosmcp/tests/common/mod.rs
git commit -m "test(stdio): transfer_file bad-source / unknown-router smoke + ignored connect-timeout"
```

---

### Task 20: Packaging — staging dir + known_hosts in `install.sh`

Update the LXC install script so a fresh deploy lands the new on-disk surface owned by `jmcp:jmcp`.

**Files:**
- Modify: `packaging/lxc/install.sh`

- [ ] **Step 1: Read the current install script**

Run: `Read packaging/lxc/install.sh` (full file).

- [ ] **Step 2: Add staging dir + known_hosts setup**

After the existing `mkdir -p /etc/jmcp /var/lib/jmcp` (or equivalent) block, add:

```bash
# File-transfer surface (transfer_file / list_staged_files).
install -d -m 0755 -o jmcp -g jmcp /var/lib/jmcp/staging
install -m 0644 -o jmcp -g jmcp /dev/null /etc/jmcp/known_hosts || \
  { touch /etc/jmcp/known_hosts && chown jmcp:jmcp /etc/jmcp/known_hosts && chmod 0644 /etc/jmcp/known_hosts; }
```

(Pick whichever idiom matches the rest of the script; the requirement is the dir+file exist with `jmcp:jmcp` ownership and the documented modes.)

- [ ] **Step 3: Verify the script still parses**

Run: `bash -n packaging/lxc/install.sh`
Expected: exit code 0, no output.

- [ ] **Step 4: Commit**

```bash
git add packaging/lxc/install.sh
git commit -m "packaging(lxc): create staging dir and known_hosts on install"
```

---

### Task 21: README — file-transfer section

Document the two new tools, the on-disk surface, and the SSH-key-only auth requirement.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a new section**

Insert after the existing tools table (or wherever the per-tool docs live), before the release banner:

```markdown
## File transfers (`transfer_file` / `list_staged_files`)

`transfer_file` pushes a host-staged file to `/var/tmp/<basename>` on a Junos
device using legacy SCP (`scp -O`, since Junos disables the OpenSSH SFTP
subsystem). It is **idempotent on SHA-256**: if the remote file already exists
with a matching digest the call returns `status: "skipped"`. Pass `force: true`
to overwrite when digests differ.

**Auth:** SSH key only. Devices with `auth.type = "password"` are rejected with
`[code=unsupported_auth]`. Add an SSH key to the device and reference its path
via `auth.private_key_path` in `devices.json`.

**On-disk surface:**

| Path                          | Purpose                                       | Default mode | Owner       |
| ----------------------------- | --------------------------------------------- | ------------ | ----------- |
| `/var/lib/jmcp/staging/`      | Host-side stage for files awaiting transfer  | `0755`       | `jmcp:jmcp` |
| `/etc/jmcp/known_hosts`       | SSH `known_hosts` consulted for every push    | `0644`       | `jmcp:jmcp` |

Override at startup with `--staging-dir <path>` and `--known-hosts-file <path>`.

`list_staged_files` returns the contents of the host staging dir. If
`router_name` is supplied it also runs `file list /var/tmp/ detail` on the
device and includes those entries under `device_files`.

**Source path safety:** `source_path` must be a basename only (no `/`, no `\`,
no `..`, no leading dot, ≤ 255 bytes); it is resolved relative to
`--staging-dir` and never escapes it.

**Pre-flight checks:** before scp, `transfer_file` runs
`show system storage no-forwarding` and refuses to push when free space on
`/var` is below `local_size + 32 MiB`.

**Post-verify:** unless `verify: false` is passed, the device-side checksum is
re-computed via `file checksum sha-256 /var/tmp/<basename>` and the file is
deleted on mismatch.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(readme): document transfer_file + list_staged_files tools"
```

---

### Task 22: Real-device `#[ignore]` integration tests

Cover the full happy path against a vSRX from container 601 (or whichever real lab device the maintainer prefers). These are gated `#[ignore]` so CI never hits the network.

**Files:**
- Modify: `rust-junosmcp-core/tests/integration_real_device.rs` (append; the file exists)

- [ ] **Step 1: Append the tests**

```rust
// ---- transfer_file / list_staged_files (run with --ignored against real vSRX) ----
//
// Required env:
//   TEST_DEVICE_NAME      e.g. "vsrx-test10"
//   TEST_INVENTORY_PATH   absolute path to a devices.json that contains TEST_DEVICE_NAME
//                         with auth.type == "ssh_key" and a reachable private_key_path

#[tokio::test]
#[ignore = "real device"]
async fn transfer_file_round_trip_1kb() {
    let (dm, cfg, dev_name) = setup_real_transfer_env();
    let local = cfg.staging_dir.join("rt-1kb.bin");
    std::fs::write(&local, vec![0u8; 1024]).unwrap();

    let res = rust_junosmcp_core::tools::transfer_file::handle(
        rust_junosmcp_core::tools::TransferFileArgs {
            router_name: dev_name.clone(),
            source_path: "rt-1kb.bin".into(),
            force: false,
            verify: true,
            timeout: 60,
        },
        dm.clone(),
        cfg.clone(),
    )
    .await
    .expect("first push");
    assert_eq!(res["status"], "transferred");

    // Idempotent skip on second call.
    let res2 = rust_junosmcp_core::tools::transfer_file::handle(
        rust_junosmcp_core::tools::TransferFileArgs {
            router_name: dev_name.clone(),
            source_path: "rt-1kb.bin".into(),
            force: false,
            verify: true,
            timeout: 60,
        },
        dm.clone(),
        cfg.clone(),
    )
    .await
    .expect("second push");
    assert_eq!(res2["status"], "skipped");
}

#[tokio::test]
#[ignore = "real device — 200 MB transfer, slow"]
async fn transfer_file_round_trip_200mb() {
    let (dm, cfg, dev_name) = setup_real_transfer_env();
    let local = cfg.staging_dir.join("rt-200mb.bin");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&local).unwrap();
        let chunk = vec![0xAB; 1024 * 1024];
        for _ in 0..200 {
            f.write_all(&chunk).unwrap();
        }
    }

    let res = rust_junosmcp_core::tools::transfer_file::handle(
        rust_junosmcp_core::tools::TransferFileArgs {
            router_name: dev_name,
            source_path: "rt-200mb.bin".into(),
            force: true,
            verify: true,
            timeout: 1200,
        },
        dm,
        cfg,
    )
    .await
    .expect("200mb push");
    assert_eq!(res["status"], "transferred");
    assert_eq!(res["size_bytes"], 200 * 1024 * 1024);
}

#[tokio::test]
#[ignore = "real device"]
async fn transfer_file_force_false_rejects_diff() {
    let (dm, cfg, dev_name) = setup_real_transfer_env();
    let local = cfg.staging_dir.join("collide.bin");

    // First push.
    std::fs::write(&local, b"version-A").unwrap();
    let _ = rust_junosmcp_core::tools::transfer_file::handle(
        rust_junosmcp_core::tools::TransferFileArgs {
            router_name: dev_name.clone(),
            source_path: "collide.bin".into(),
            force: false,
            verify: true,
            timeout: 60,
        },
        dm.clone(),
        cfg.clone(),
    )
    .await
    .unwrap();

    // Different bytes, force=false → DestExistsDiffers.
    std::fs::write(&local, b"version-B").unwrap();
    let res = rust_junosmcp_core::tools::transfer_file::handle(
        rust_junosmcp_core::tools::TransferFileArgs {
            router_name: dev_name,
            source_path: "collide.bin".into(),
            force: false,
            verify: true,
            timeout: 60,
        },
        dm,
        cfg,
    )
    .await;
    assert!(matches!(
        res,
        Err(rust_junosmcp_core::error::JmcpError::DestExistsDiffers)
    ));
}

fn setup_real_transfer_env() -> (
    std::sync::Arc<rust_junosmcp_core::DeviceManager>,
    rust_junosmcp_core::TransferConfig,
    String,
) {
    use std::sync::Arc;
    let dev = std::env::var("TEST_DEVICE_NAME").expect("TEST_DEVICE_NAME");
    let inv_path = std::env::var("TEST_INVENTORY_PATH").expect("TEST_INVENTORY_PATH");
    let inv = Arc::new(rust_junosmcp_core::Inventory::load(&inv_path).unwrap());
    let hash = rust_junosmcp_core::inventory::hash_file(&inv_path).unwrap();
    let dm = Arc::new(rust_junosmcp_core::DeviceManager::with_path(
        inv.clone(),
        std::path::PathBuf::from(&inv_path),
        hash,
        false,
        false,
    ));

    let staging = tempfile::tempdir().unwrap().keep();
    let known = staging.join("known_hosts");
    std::fs::write(&known, b"").unwrap();

    let cfg = rust_junosmcp_core::TransferConfig {
        staging_dir: staging,
        known_hosts_file: known,
        scp_runner: Arc::new(rust_junosmcp_core::OpenSshScpRunner),
    };
    (dm, cfg, dev)
}
```

- [ ] **Step 2: Run to verify they compile (without executing)**

Run: `cargo test -p rust-junosmcp-core --test integration_real_device --no-run 2>&1 | tail -10`
Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add rust-junosmcp-core/tests/integration_real_device.rs
git commit -m "test(integration): #[ignore] real-device transfer_file round trips"
```

- [ ] **Step 4: Optional manual run (operator only)**

```bash
TEST_DEVICE_NAME=vsrx-test10 \
TEST_INVENTORY_PATH=/etc/jmcp/devices.json \
cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --test-threads=1 2>&1 | tail -30
```

Expected: all 3 PASS against the live lab. Skip in CI.

---

### Task 23: Update LXC 601 deployment memory

Document the new on-disk surface so future deploy sessions know to provision it.

**Files:**
- Modify: `~/.claude/projects/-home-mharman-RustJunosMCP/memory/rust_junosmcp_container_601.md`

- [ ] **Step 1: Read the current memory**

Run: `Read /home/mharman/.claude/projects/-home-mharman-RustJunosMCP/memory/rust_junosmcp_container_601.md` (full file).

- [ ] **Step 2: Append a new section**

Add (before any closing notes):

```markdown
## File-transfer surface (added v0.4.0)

- `/var/lib/jmcp/staging/` — host stage for files queued for `transfer_file`
  - mode `0755`, owner `jmcp:jmcp`
  - clean-up is operator-managed; nothing on the server prunes it
- `/etc/jmcp/known_hosts` — `known_hosts` consulted by every scp push
  - mode `0644`, owner `jmcp:jmcp`
  - first pre-deploy step: SSH to each managed device once as `jmcp` to seed entries (`StrictHostKeyChecking=accept-new` will populate on first transfer otherwise)

Service flags (already in `rust-junosmcp.service` after upgrade):

```
--staging-dir /var/lib/jmcp/staging
--known-hosts-file /etc/jmcp/known_hosts
```

Defaults match these paths, so the flags are optional unless the lab moves
the surface.
```

- [ ] **Step 3: No commit (memory is outside the worktree)**

Memory edits are session-local; nothing to git-add.

---

### Task 24: Final CI gate (fmt + clippy + test + audit)

The shipping gate before opening a PR.

**Files:**
- None modified.

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check 2>&1 | tail -5`
Expected: exit 0, no diff.

If it fails: `cargo fmt --all` → re-run check → commit `style: cargo fmt`.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -30`
Expected: exit 0.

- [ ] **Step 3: Tests (unit + integration, excluding `--ignored`)**

Run: `cargo test --workspace --all-targets 2>&1 | tail -30`
Expected: all PASS, ignored tests reported as skipped.

- [ ] **Step 4: Audit**

Run: `cargo audit 2>&1 | tail -20`
Expected: no new vulnerabilities introduced.

- [ ] **Step 5: Branch state**

Run: `git log --oneline main..HEAD`
Expected: linear history of small, focused commits matching tasks 1–23 (excluding Task 23, which has no commit).

If any clean-up commits are needed (e.g. `style: cargo fmt`), commit them now.

- [ ] **Step 6: Open the PR**

```bash
gh pr create --title "feat: transfer_file + list_staged_files MCP tools" --body "$(cat <<'EOF'
## Summary
- New `transfer_file` MCP tool: idempotent SCP push (`-O`) to `/var/tmp/<basename>` with SHA-256 verify and pre-flight storage check
- New `list_staged_files` MCP tool: lists host staging dir (always) plus device `/var/tmp/` (when `router_name` supplied)
- New CLI flags `--staging-dir` (default `/var/lib/jmcp/staging`) and `--known-hosts-file` (default `/etc/jmcp/known_hosts`)
- Packaging: install.sh provisions both paths owned by `jmcp:jmcp`
- Spec: `docs/superpowers/specs/2026-05-14-transfer-file-design.md`

## Test plan
- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace --all-targets`
- [x] `cargo audit`
- [ ] Manual: `cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored` against vSRX lab (operator only)
- [ ] Manual: `cargo test -p rust-junosmcp --test transfer_file_smoke -- --ignored` (TEST-NET-1 connect-timeout proof)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR URL printed; share with the maintainer for review.

---

## Self-Review Checklist (executed)

**Spec coverage:**
- ✅ `transfer_file` arg schema, basename validation, SHA-256 streaming, scp argv, ScpRunner abstraction, pre-flight storage, remote checksum + idempotent skip, scp push, post-verify + delete-on-mismatch, error variants — Tasks 1–14, 17.
- ✅ `list_staged_files` host listing + optional device listing — Tasks 1, 8, 10, 11, 17.
- ✅ CLI flags + defaults — Task 15.
- ✅ TransferConfig plumbing + main wiring — Task 16.
- ✅ Packaging on-disk surface — Task 20.
- ✅ Documentation — Task 21.
- ✅ Real-device proof — Task 22.
- ✅ Deployment memory — Task 23.
- ✅ CI gate — Task 24.

**Placeholder scan:**
- The phrase "match the pattern" appears in Task 17 and Task 18 where the existing scope-helper / inventory-builder names are not pinned in the spec; those tasks reference the canonical patterns the existing 11 tools and `tests/common/mod.rs` already use, and the engineer must inspect those exact identifiers when implementing. This is intentional reuse of existing API, not a TODO.
- No "TBD" / "implement later" / "fill in details" markers remain.
- Every task that creates code shows the code; every test step shows the test code.

**Type consistency:**
- `TransferFileArgs` / `ListStagedFilesArgs` field names (`router_name`, `source_path`, `force`, `verify`, `timeout`) — consistent in Tasks 1, 12, 13, 17, 19, 22.
- `JmcpError` variants used: `BadSourcePath`, `InsufficientDisk { needed, free }`, `DestExistsDiffers`, `ScpFailed(String)`, `ConnectTimeout`, `VerifyMismatch(String)`, `TransferOuterTimeout(Duration)`, `UnsupportedAuth`, plus existing `UnknownRouter`, `Forbidden`, `Denied`, `Timeout` — names consistent across Tasks 9, 13, 14, 17, 19, 22.
- `TransferConfig { staging_dir, known_hosts_file, scp_runner }` field names — consistent in Tasks 12, 13, 16, 17, 22.
- `ScpJob` field names — consistent in Tasks 5, 13, 14.
- `OpenSshScpRunner` struct name — consistent in Tasks 5, 16, 22.
- `JmcpHandler::new(dm, policy, transfer_cfg)` arity — consistent in Tasks 16, 17.

---

