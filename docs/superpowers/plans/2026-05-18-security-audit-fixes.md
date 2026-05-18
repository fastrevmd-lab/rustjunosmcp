# Security Audit Fixes Implementation Plan (v0.5.2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remediate the 6 findings in `SECURITY_CODE_REVIEW_REPORT.md` (2026-05-18) and ship as a single PR / `v0.5.2` release. Findings span access-control hardening (RJMCP-SEC-001, -005), dependency / parser risk (-002, -006), input validation parity (-003), and SCP host-key policy (-004).

**Branch:** `fix/security-audit-v0.5.2` off `main`.

**Scope decisions (locked with operator 2026-05-18):**

1. **YAML in `vars_content`:** dropped entirely. `render_and_apply_j2_template.vars_content` becomes JSON-only.
2. **Strict host-key default:** `StrictHostKeyChecking=yes` becomes the default; opt-in flag `--ssh-accept-new-host-keys` preserves the old behavior for labs. A `scripts/scan-known-hosts.sh` helper ships in the same PR to pre-populate `known_hosts`.
3. **`reload_devices` path policy:** pure tightening. Only paths that canonicalize inside the current inventory directory are accepted. No new allowlist flag.

**Architecture:**

- **Tool name single source of truth:** introduce `pub const SERVER_TOOLS: &[&str]` in `rust-junosmcp/src/server.rs` enumerating the 14 `#[tool(name = ...)]` strings; a new integration test asserts `SERVER_TOOLS` and `rust_junosmcp_auth::file::KNOWN_TOOLS` agree as sets. This prevents future drift.
- **Template parser:** `parse_vars` collapses to a single JSON path; YAML branch and `serde_yml` dependency removed. Add 64 KiB caps on `template_content` and `vars_content` to bound parser/renderer cost.
- **Inventory validation:** promote `is_valid_device_name`, `is_valid_ip_or_hostname` from `add_device.rs` into a new `inventory::validation` module; add `is_valid_ssh_username` (regex `^[A-Za-z0-9._-]{1,64}$`, must not start with `-`) and `is_valid_auth_path` (non-empty, no NUL, no leading `-`). `Inventory::validate` + `add_device::handle` both call the same helpers.
- **SCP host-key policy:** `transfer_file::TransferJob` gains `accept_new_host_keys: bool`. CLI flag `--ssh-accept-new-host-keys` (default `false`) threads through `DeviceManager` / handler context. Default argv emits `StrictHostKeyChecking=yes`. `transfer_file` and `upgrade_junos` handlers now `pre-check` that `known_hosts_file` exists and is readable.
- **`reload_devices` lock-down:** canonicalize inventory directory and candidate path; reject if candidate is absolute or if canonical form escapes inventory directory. Existing `..` rejection remains as defense-in-depth.
- **TLS PEM parsing:** `tls.rs` switches from `rustls_pemfile` to `rustls_pki_types::{CertificateDer, PrivateKeyDer}` PEM APIs. `rustls-pemfile` dep removed.

**Tech Stack:** Rust 2021. New helper script in `bash`. No new runtime deps; `serde_yml` and `rustls-pemfile` removed. `regex` already in workspace.

**Spec:** `SECURITY_CODE_REVIEW_REPORT.md` (repo root, 2026-05-18).

**Prerequisites:** clean working tree on `fix/security-audit-v0.5.2` from `origin/main` (commit `c99dd7f`).

---

## File map

| Path | Action | Purpose |
|---|---|---|
| `rust-junosmcp-auth/src/file.rs` | Modify | Extend `KNOWN_TOOLS` (+`transfer_file`, `list_staged_files`, `upgrade_junos`); add unit tests for new scopes |
| `rust-junosmcp/src/server.rs` | Modify | Add `pub const SERVER_TOOLS: &[&str]` (14 entries); thread `accept_new_host_keys` into `transfer_file` / `upgrade_junos` handler context |
| `rust-junosmcp/tests/known_tools_drift.rs` | Create | Drift test: `SERVER_TOOLS` set == `KNOWN_TOOLS` set |
| `rust-junosmcp/tests/token_scope_enforcement.rs` | Create | Negative test: token scoped only to `transfer_file` is denied `upgrade_junos` |
| `rust-junosmcp-core/src/tools/template.rs` | Modify | `parse_vars` JSON-only; remove YAML branch; add size cap |
| `rust-junosmcp-core/src/tools/mod.rs` | Modify | Update `TemplateArgs.vars_content` docstring → JSON-only |
| `Cargo.toml` (workspace) | Modify | Remove `serde_yml`; remove `rustls-pemfile` |
| `Cargo.lock` | Modify | Regenerate after dep removal |
| `.cargo/audit.toml` | Modify | Remove `RUSTSEC-2025-0067` and `RUSTSEC-2025-0068` ignore entries |
| `rust-junosmcp-core/src/inventory.rs` | Modify | Promote / add validation helpers; extend `Inventory::validate` |
| `rust-junosmcp-core/src/tools/add_device.rs` | Modify | Use shared helpers; add username validation |
| `rust-junosmcp-core/src/tools/transfer_file.rs` | Modify | `accept_new_host_keys` field on `TransferJob`; argv emits `StrictHostKeyChecking=yes` by default; `known_hosts` pre-check |
| `rust-junosmcp-core/src/tools/upgrade_junos.rs` | Modify | Same host-key policy thread-through; `known_hosts` pre-check |
| `rust-junosmcp-core/src/tools/reload_devices.rs` | Modify | Canonicalize + escape check; reject absolute paths |
| `rust-junosmcp/src/cli.rs` | Modify | New `--ssh-accept-new-host-keys` flag (default false) |
| `rust-junosmcp/src/main.rs` | Modify | Thread flag into `DeviceManager` / handler context |
| `rust-junosmcp/src/tls.rs` | Modify | Swap to `rustls-pki-types` PEM APIs |
| `scripts/scan-known-hosts.sh` | Create | Operator helper: `ssh-keyscan` all inventory hosts → `known_hosts` |
| `README.md` | Modify | Document JSON-only `vars_content`, `--ssh-accept-new-host-keys`, `scripts/scan-known-hosts.sh`, strict `reload_devices` path policy |
| `CHANGELOG.md` | Modify | v0.5.2 entry summarizing all 6 fixes |
| `Cargo.toml` (workspace package) | Modify | Bump workspace version `0.5.1` → `0.5.2` |

---

## Task 1: RJMCP-SEC-001 — KNOWN_TOOLS drift fix + drift-prevention test

**Files:**
- Modify: `rust-junosmcp-auth/src/file.rs`
- Modify: `rust-junosmcp/src/server.rs`
- Create: `rust-junosmcp/tests/known_tools_drift.rs`
- Create: `rust-junosmcp/tests/token_scope_enforcement.rs`

- [ ] **Step 1.1:** Insert `"transfer_file"`, `"list_staged_files"`, `"upgrade_junos"` into `KNOWN_TOOLS` in `rust-junosmcp-auth/src/file.rs:7-19` **and alphabetize the full list** in the same edit (so future drift checks are easier to eyeball).
- [ ] **Step 1.2:** In `rust-junosmcp/src/server.rs`, add `pub const SERVER_TOOLS: &[&str] = &[ ... ];` above the `impl JmcpServer` block. Enumerate exactly the 14 `#[tool(name = "...")]` strings, in source order. Add a `#[cfg(test)] mod server_tools_const_tests` that asserts `SERVER_TOOLS.len() == 14` so removing a tool without updating the const breaks build.
- [ ] **Step 1.3:** Create `rust-junosmcp/tests/known_tools_drift.rs`:
  ```rust
  use rust_junosmcp::server::SERVER_TOOLS;
  use rust_junosmcp_auth::file::KNOWN_TOOLS;
  use std::collections::HashSet;

  #[test]
  fn known_tools_matches_server_tools() {
      let server: HashSet<&str> = SERVER_TOOLS.iter().copied().collect();
      let known: HashSet<&str> = KNOWN_TOOLS.iter().copied().collect();
      assert_eq!(server, known, "KNOWN_TOOLS drift vs SERVER_TOOLS");
  }
  ```
- [ ] **Step 1.4:** Add a `#[cfg(test)]` test in `rust-junosmcp-auth/src/file.rs` proving `TokenStoreFile::load` accepts a token scope of `["transfer_file"]`, `["list_staged_files"]`, `["upgrade_junos"]`, and rejects `["definitely_not_a_tool"]`.
- [ ] **Step 1.5:** Create `rust-junosmcp/tests/token_scope_enforcement.rs`: spin up `JmcpServer` with a token scoped only to `transfer_file`, attempt `upgrade_junos`, assert scope-denied error. Reuse harness pattern from existing `tests/stdio_smoke.rs`.
- [ ] **Step 1.6:** `cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`.
- [ ] **Step 1.7:** Commit `fix(auth): add transfer_file/list_staged_files/upgrade_junos to KNOWN_TOOLS + drift test (SEC-001)`.

---

## Task 2: RJMCP-SEC-002 — Drop YAML support from vars_content

**Files:**
- Modify: `rust-junosmcp-core/src/tools/template.rs`
- Modify: `rust-junosmcp-core/src/tools/mod.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `.cargo/audit.toml`
- Modify: `README.md`

- [ ] **Step 2.1:** Rewrite `parse_vars` in `rust-junosmcp-core/src/tools/template.rs:13-28` to:
  - Reject input where `input.len() > 65_536` with `JmcpError::TemplateVars("vars_content exceeds 64 KiB limit")`.
  - Parse exclusively as JSON via `serde_json::from_str::<Value>`.
  - Keep top-level-object check.
  - Remove `serde_yml::from_str` branch.
- [ ] **Step 2.2:** Add matching 64 KiB cap on `template_content` at the handler entry (introduce `const MAX_TEMPLATE_BYTES: usize = 65_536;`).
- [ ] **Step 2.3:** Update `TemplateArgs.vars_content` doc-comment in `rust-junosmcp-core/src/tools/mod.rs:144-150` to "JSON only; YAML is no longer accepted (v0.5.2)". Update the `#[tool(description = ...)]` string in `rust-junosmcp/src/server.rs` for `render_and_apply_j2_template`.
- [ ] **Step 2.4:** In `template.rs` tests:
  - Update / replace any test that fed YAML into `parse_vars` (search for `serde_yml` usage in tests + YAML-shaped string literals).
  - Add: YAML input rejected with `JmcpError::TemplateVars` containing "JSON".
  - Add: 64 KiB+1 input rejected.
  - Keep happy-path JSON object test.
- [ ] **Step 2.5:** Remove `serde_yml = "0.0.12"` from workspace `Cargo.toml:44`. Remove any per-crate `serde_yml` deps (`grep -nr serde_yml --include=Cargo.toml`).
- [ ] **Step 2.6:** Run `cargo build` to regenerate `Cargo.lock`. Verify `serde_yml` and `libyml` no longer appear in `Cargo.lock`.
- [ ] **Step 2.7:** Remove `"RUSTSEC-2025-0067"` and `"RUSTSEC-2025-0068"` lines (plus their justification comments) from `.cargo/audit.toml`.
- [ ] **Step 2.8:** Update README — find the `render_and_apply_j2_template` section, replace "JSON or YAML" wording with "JSON only".
- [ ] **Step 2.9:** `cargo audit && cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`. `cargo audit` must report zero unignored vulnerabilities AND no longer warn about the two removed advisories.
- [ ] **Step 2.10:** Commit `feat(template)!: vars_content is now JSON-only; drop serde_yml dep (SEC-002)`. Note the `!` — this is a breaking change.

---

## Task 3: RJMCP-SEC-003 — Centralize inventory validation

**Files:**
- Modify: `rust-junosmcp-core/src/inventory.rs`
- Modify: `rust-junosmcp-core/src/tools/add_device.rs`

- [ ] **Step 3.1:** In `rust-junosmcp-core/src/inventory.rs`, create a new module-level `pub(crate) mod validation { ... }` (or inline `pub(crate) fn`s if simpler). Helpers:
  - `is_valid_device_name(s: &str) -> bool` — move definition from `add_device.rs:78`; keep behavior identical so existing valid names (`admin`, `netconf`, `user.name`, `user-name`, `user_name`) still pass.
  - `is_valid_ip_or_hostname(s: &str) -> bool` — move from `add_device.rs:84`.
  - `is_valid_ssh_username(s: &str) -> bool` — new. Regex `^[A-Za-z0-9._-]{1,64}$` AND `!s.starts_with('-')`. Use a `once_cell::sync::Lazy<Regex>` to compile once.
  - `is_valid_auth_path(p: &std::path::Path) -> bool` — new. Non-empty, no NUL byte in `OsStr`, string form does not start with `-`.
- [ ] **Step 3.2:** Extend `Inventory::validate` (`inventory.rs:219-243`) to call all four helpers per entry. On failure return `JmcpError::InventoryInvalid("router '{name}': {field} invalid: {value-redacted}")`. For passwords path, do NOT log the secret.
- [ ] **Step 3.3:** Rewrite `add_device::handle` to call `inventory::validation::is_valid_*` instead of the local copies; delete the now-duplicate local fns. Add username validation before constructing `DeviceEntry`.
- [ ] **Step 3.4:** Tests in `inventory.rs::load_tests`:
  - Reject device key `"bad name"` (space).
  - Reject `ip = "10.0.0.1; rm -rf /"`.
  - Reject `username = "-oProxyCommand=foo"`.
  - Reject `username = "user with space"`.
  - Reject `private_key_path = "-evil"` (would need to create a file literally named `-evil` in a tempdir; assert validation rejects the leading dash even if the file exists).
  - Accept: `admin`, `netconf`, `user.name`, `user-name`, `user_name` (regression).
- [ ] **Step 3.5:** Tests in `add_device.rs`: confirm `add_device` rejects the same username patterns it now blocks.
- [ ] **Step 3.6:** `cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`.
- [ ] **Step 3.7:** Commit `fix(inventory): centralize validation; add username + key-path checks (SEC-003)`.

---

## Task 4: RJMCP-SEC-004 — SCP strict host-key default + scan helper

**Files:**
- Modify: `rust-junosmcp/src/cli.rs`
- Modify: `rust-junosmcp/src/main.rs`
- Modify: `rust-junosmcp-core/src/tools/transfer_file.rs`
- Modify: `rust-junosmcp-core/src/tools/upgrade_junos.rs`
- Modify: `rust-junosmcp-core/src/device_manager.rs` (carry policy flag if it lives there)
- Modify: `rust-junosmcp/src/server.rs`
- Create: `scripts/scan-known-hosts.sh`
- Modify: `README.md`

- [ ] **Step 4.1:** In `rust-junosmcp/src/cli.rs`, add:
  ```rust
  /// Accept and pin new device host keys on first contact (TOFU).
  /// Off by default for security; use only in lab environments.
  #[arg(long, default_value_t = false)]
  pub ssh_accept_new_host_keys: bool,
  ```
- [ ] **Step 4.2:** Thread the flag from `main.rs` into `DeviceManager` (add `accept_new_host_keys: bool` field) so handlers can read it via `dm.accept_new_host_keys()`.
- [ ] **Step 4.3:** In `rust-junosmcp-core/src/tools/transfer_file.rs`:
  - Add `accept_new_host_keys: bool` to `TransferJob`.
  - In argv builder (`:480-511`), emit `StrictHostKeyChecking=yes` when `false`, `accept-new` when `true`.
  - Before kicking off the SCP command, verify `job.known_hosts_file` exists and `metadata()?.is_file()`. Return clear error `JmcpError::KnownHostsMissing(PathBuf)` (new variant) otherwise.
  - Add a one-line audit log at INFO level: `"transfer_file: host_key_policy={strict|accept-new}"`.
- [ ] **Step 4.4:** Same `known_hosts` pre-check + flag in `upgrade_junos` (it calls into `transfer_file`; if the policy now flows through `TransferJob`, no separate change needed — verify).
- [ ] **Step 4.5:** Update `transfer_file::argv_tests` (search for "StrictHostKeyChecking"):
  - Strict-default case asserts `yes` appears.
  - Accept-new case (flag flipped) asserts `accept-new` appears.
  - `known_hosts_file` missing → handler returns `KnownHostsMissing`.
- [ ] **Step 4.6:** Create `scripts/scan-known-hosts.sh`:
  - `#!/usr/bin/env bash` with `set -euo pipefail`.
  - Args: `--inventory PATH` (default `/etc/jmcp/devices.json`), `--known-hosts PATH` (default `/etc/jmcp/known_hosts`).
  - Read inventory JSON via `jq`, extract `(ip, port)` pairs.
  - For each: `ssh-keyscan -p $port -T 5 $ip >> $TMPFILE`.
  - Atomic move `$TMPFILE` → `$known_hosts`; print a summary of hosts added.
  - Refuse to run if `$known_hosts` exists unless `--append` or `--replace` flag set.
  - `chmod +x` the script.
- [ ] **Step 4.7:** README: new subsection "Host-key policy" documenting default-strict, `--ssh-accept-new-host-keys` opt-in, and pointing at `scripts/scan-known-hosts.sh`.
- [ ] **Step 4.8:** `cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`. Manually run `bash -n scripts/scan-known-hosts.sh` for syntax check.
- [ ] **Step 4.9:** Commit `fix(transfer): default StrictHostKeyChecking=yes + scan-known-hosts helper (SEC-004)`.

---

## Task 5: RJMCP-SEC-005 — Restrict reload_devices to inventory directory

**Files:**
- Modify: `rust-junosmcp-core/src/tools/reload_devices.rs`
- Modify: `README.md`

- [ ] **Step 5.1:** In `reload_devices.rs:22-46` path-resolution block, after the existing `..` rejection:
  - Reject any absolute `candidate` with `JmcpError::InventoryInvalid("file_name must be a relative path within the inventory directory")`.
  - Resolve to `parent.join(candidate)` (existing logic).
  - `let inv_dir = dm.inventory_path().parent().ok_or(...)?.canonicalize()?;`
  - `let resolved = path.canonicalize()?;` (after file existence check).
  - If `!resolved.starts_with(&inv_dir)` → `JmcpError::InventoryInvalid("file_name resolves outside inventory directory")`.
- [ ] **Step 5.2:** Tests (extend existing `mod tests`):
  - `reload_rejects_absolute_path`: pass `/etc/passwd` → `InventoryInvalid` containing "relative".
  - `reload_rejects_symlink_escape`: in a `tempdir`, create `inventory.json` and a sibling symlink `escape.json` → `/etc/passwd`; pass `file_name="escape.json"`; expect rejection.
  - Update `reload_with_file_name_swaps_inventory` so `f2` lives in the same tempdir as `f1` (currently uses two separate `NamedTempFile`s; refactor to a `TempDir` + two files inside).
- [ ] **Step 5.3:** Log `tracing::info!(prev = ?prev_path, new = ?resolved, "reload_devices: inventory swapped")` on success.
- [ ] **Step 5.4:** README: update `reload_devices` section to state "`file_name` must be a relative path resolving inside the current inventory directory (v0.5.2)".
- [ ] **Step 5.5:** `cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`.
- [ ] **Step 5.6:** Commit `fix(reload): restrict file_name to inventory directory (SEC-005)`.

---

## Task 6: RJMCP-SEC-006 — Migrate off rustls-pemfile

**Files:**
- Modify: `Cargo.toml`
- Modify: `rust-junosmcp/src/tls.rs`
- Modify: `Cargo.lock`

- [ ] **Step 6.1:** Read `rust-junosmcp/src/tls.rs` current implementation (`:33-40`) and surrounding context.
- [ ] **Step 6.2:** Replace:
  ```rust
  let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_bytes[..])
      .collect::<std::result::Result<_, _>>()?;
  let private_key = rustls_pemfile::private_key(&mut &key_bytes[..])?.ok_or(...)?;
  ```
  with the `rustls_pki_types` PEM APIs:
  ```rust
  use rustls_pki_types::{CertificateDer, PrivateKeyDer};
  use rustls_pki_types::pem::PemObject;

  let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
      .collect::<std::result::Result<_, _>>()?;
  let private_key = PrivateKeyDer::from_pem_slice(&key_bytes)?;
  ```
  (Adjust to whatever the current `rustls-pki-types` version in `Cargo.lock` actually exposes — verify with `cargo doc` or crates.io docs before settling on the exact call.)
- [ ] **Step 6.3:** Remove `rustls-pemfile = ...` from `Cargo.toml`. Run `cargo build` and verify it disappears from `Cargo.lock`.
- [ ] **Step 6.4:** Existing TLS tests in `rust-junosmcp/src/tls.rs` must still pass (self-signed pair, malformed PEM rejected).
- [ ] **Step 6.5:** `cargo audit && cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`. `cargo audit` should now show zero warnings.
- [ ] **Step 6.6:** Commit `chore(tls): migrate to rustls-pki-types PEM parsing (SEC-006)`.

---

## Task 7: Version bump, CHANGELOG, smoke test

**Files:**
- Modify: workspace `Cargo.toml`
- Modify: `CHANGELOG.md`
- Modify: `rust-junosmcp/tests/stdio_smoke.rs` (only if tool count changed — it shouldn't here)

- [ ] **Step 7.1:** Bump `[workspace.package] version = "0.5.1"` → `"0.5.2"`.
- [ ] **Step 7.2:** Add `CHANGELOG.md` entry for `v0.5.2` summarizing the 6 fixes with `SEC-NNN` cross-references and a "Breaking" note for the YAML removal.
- [ ] **Step 7.3:** Run full verification gate once more from a clean target dir: `cargo clean && cargo build --release && cargo audit && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`.
- [ ] **Step 7.4:** Commit `chore: bump to v0.5.2 + CHANGELOG (security audit)`.
- [ ] **Step 7.5:** `git push -u origin fix/security-audit-v0.5.2` and open a single PR titled `Security audit fixes (v0.5.2) — SEC-001..006`. Body must include:
  - One-line summary per finding with `SEC-NNN` → commit hash mapping.
  - **Breaking change** callout for YAML removal (operator already confirmed only 6-vSRX lab uses this path; no migration needed).
  - **Deploy command sequence** for LXC 601 (per `rust_junosmcp_container_601.md` memory):
    ```bash
    # Build release binary
    cargo build --release --target x86_64-unknown-linux-gnu

    # Push to host
    scp target/x86_64-unknown-linux-gnu/release/rust-junosmcp root@pve3.mechub.org:/tmp/

    # Stop unit, push into container (text-file-busy fix), restart
    ssh root@pve3.mechub.org "systemctl stop rust-junosmcp.service && \
      pct push 601 /tmp/rust-junosmcp /usr/local/bin/rust-junosmcp && \
      systemctl start rust-junosmcp.service && \
      pct exec 601 -- /usr/local/bin/rust-junosmcp --version"
    ```
  - Reminder to pre-populate `/etc/jmcp/known_hosts` via `scripts/scan-known-hosts.sh` **before** the new binary starts handling `transfer_file` calls (otherwise transfers fail with `KnownHostsMissing`).

---

## Post-merge

- [ ] Tag `v0.5.2`, generate release artifacts.
- [ ] Deploy to LXC 601 (`192.168.1.194:30031`) following the per-host upgrade dance from `rust_junosmcp_container_601.md` memory (stop unit → `pct push` → start → `--version` check).
- [ ] If any operator currently relies on YAML `vars_content`, alert them before deploy.
- [ ] Remove `SECURITY_CODE_REVIEW_REPORT.md` from repo root or move under `docs/security/` once findings are closed.
