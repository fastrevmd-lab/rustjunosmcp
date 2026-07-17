# Unified Junos and SRX MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two Juniper MCP servers with one version-0.8.0 `rust-junosmcp` server that exposes the existing Junos and feature-gated SRX tool surfaces on one endpoint and safely retires the legacy SRX deployment.

**Architecture:** Keep one `JmcpHandler` and compose separate rmcp-generated Junos and SRX `ToolRouter`s on that handler. Rename the SRX workflow crate, move HTTP limits into Junos core, resolve all configuration once during bootstrap, and reuse the existing Junos transport, authentication, inventory, lease, TLS, and SIGHUP paths. Package only the unified binary/service and explicitly remove stale SRX runtime artifacts during upgrade while preserving support-bundle state.

**Tech Stack:** Rust 2021, Cargo features, rmcp 2.x tool macros, Tokio, Axum, clap 4, serde/schemars, systemd, Bash packaging tests, Docker, GitHub Actions.

## Global Constraints

- Work only in `/home/mharman/Projects/RustJunosMCP/.worktrees/issue-163-unify-server` on branch `issue-163-unify-server`.
- Preserve the exact 17 Junos and 9 SRX tool names, schemas, annotations, scopes, audit behavior, stable errors, confirmation binding, timeouts, and device-safety checks.
- Set every surviving workspace package to version `0.8.0`.
- Use `default = ["tls", "srx"]`; `--no-default-features` is the minimal Junos build and `--no-default-features --features tls` is Junos-only with TLS.
- Keep `rust-junosmcp-auth` and `rust-junosmcp-audit` as separate crates.
- Add no new dependency. Move existing dependencies with their code and regenerate `Cargo.lock` only through Cargo.
- Keep the packaged listener at `127.0.0.1:30030/mcp`; remove the binary, unit, registration, and listener at port 30032.
- CLI values override canonical `JMCP_*`; canonical values override one-release `JMCP_SRX_*` fallbacks; `JMCP_SRX_HTTP_PORT` always warns and is ignored.
- Preserve `/etc/jmcp`, inventories, tokens, known hosts, lease state, transfer staging, and `/var/lib/jmcp/srx-staging/bundles` during upgrade.
- Do not hand-edit `Cargo.lock`, generated schema fixtures, package archives, or build output.
- Do not run ignored real-device tests without `CONFIRM_LAB_INTEGRATION=yes`; ordinary execution remains offline.
- Use `apply_patch` for edits and `git mv` only for history-preserving file/directory moves.
- Each task must be reviewed and committed before starting the next task.

---

## File and Responsibility Map

### Created or moved

- `rust-junosmcp-srx-core/` — renamed, version-aligned SRX workflow feature boundary.
- `rust-junosmcp-core/src/limits/mod.rs` and sibling limit modules — former limits crate inside core.
- `rust-junosmcp-core/tests/limits_public_api.rs` — proves the moved limits API remains public.
- `rust-junosmcp/src/env_compat.rs` — canonical/legacy environment resolution and deprecation diagnostics.
- `rust-junosmcp/src/server/srx.rs` — existing SRX tool adapters moved onto `JmcpHandler`.
- `rust-junosmcp/tests/fixtures/junos-tools-v0.7.json` — generated pre-merge Junos schema baseline.
- `rust-junosmcp/tests/fixtures/srx-tools-v0.3.6.json` — generated pre-merge SRX schema baseline.
- `rust-junosmcp/tests/srx_*.rs` — migrated SRX HTTP, TLS, audit, limits, metrics, and ignored live tests.
- `docs/archive/rust-srxmcp-changelog.md` — immutable history from the removed binary crate.

### Modified

- Root and surviving crate `Cargo.toml` files plus `Cargo.lock` — membership, features, dependencies, and version 0.8.0.
- `rust-junosmcp-core/src/lib.rs` — exports `limits`.
- `rust-junosmcp/src/cli.rs`, `cli_validate.rs`, `main.rs`, `http_transport.rs`, and `server.rs` — unified configuration, state, transport, and router composition.
- `rust-junosmcp-srx-core/src/workflows/support_bundle/{mod.rs,staging.rs}` — explicit typed staging configuration.
- Existing Junos integration harness/tests — combined tool count and shared binary behavior.
- `scripts/package-lxc.sh`, `packaging/lxc/install.sh`, `packaging/systemd/rust-junosmcp.service`, packaging smokes, and `Dockerfile` — one artifact/service plus upgrade cleanup.
- `.github/workflows/ci.yml`, `.github/workflows/release-image.yml`, and `justfile` — surviving package and feature matrix.
- `README.md`, `CHANGELOG.md`, `AGENTS.md`, `TODO.md`, `docs/AUDIT.md`, `docs/METRICS.md`, surviving crate instructions/docs, and logrotate comments — current single-server contract.

### Deleted

- `rust-srxmcp/` after its server/test/history content is migrated.
- `rust-srxmcp-core/` old path after the history-preserving rename.
- `rust-junosmcp-limits/` after its modules move into core.
- `packaging/systemd/rust-srxmcp.service`.
- Duplicate SRX CLI, main, TLS, HTTP transport, and test harness code.

---

### Task 1: Rename the SRX workflow crate and align release versions

**Files:**
- Move: `rust-srxmcp-core/` → `rust-junosmcp-srx-core/`
- Modify: `Cargo.toml`
- Modify: `rust-junosmcp/Cargo.toml`
- Modify: `rust-junosmcp-core/Cargo.toml`
- Modify: `rust-junosmcp-auth/Cargo.toml`
- Modify: `rust-junosmcp-audit/Cargo.toml`
- Modify: `rust-srxmcp/Cargo.toml`
- Modify: `rust-junosmcp-srx-core/Cargo.toml`
- Modify: `rust-srxmcp/src/server.rs`
- Modify: `rust-srxmcp/src/main.rs`
- Modify: `rust-srxmcp-core` references under current source/docs
- Generated: `Cargo.lock`

**Interfaces:**
- Consumes: Existing `rust-srxmcp-core` public API unchanged.
- Produces: Package `rust-junosmcp-srx-core` version `0.8.0`, imported as `rust_junosmcp_srx_core`.

- [ ] **Step 1: Record the pre-rename package identity**

Run:

```bash
cargo metadata --no-deps --format-version 1 | rg '"name":"rust-srxmcp-core"'
```

Expected: one package record names `rust-srxmcp-core` and points at `rust-srxmcp-core/Cargo.toml`.

- [ ] **Step 2: Move the crate with history**

Run:

```bash
git mv rust-srxmcp-core rust-junosmcp-srx-core
```

Expected: `git status --short` reports renames, not an unrelated delete/recreate.

- [ ] **Step 3: Update workspace membership and manifests**

Apply this resulting root membership:

```toml
[workspace]
members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
    "rust-srxmcp",
    "rust-junosmcp-srx-core",
    "rust-junosmcp-limits",
    "rust-junosmcp-audit",
]
default-members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
]
resolver = "2"
```

Set these surviving package versions exactly:

```toml
# rust-junosmcp/Cargo.toml
version = "0.8.0"

# rust-junosmcp-core/Cargo.toml
version = "0.8.0"

# rust-junosmcp-auth/Cargo.toml
version = "0.8.0"

# rust-junosmcp-audit/Cargo.toml
version = "0.8.0"

# rust-junosmcp-srx-core/Cargo.toml
name = "rust-junosmcp-srx-core"
version = "0.8.0"
description = "SRX-specific workflow core for rust-junosmcp."
```

Keep `rust-srxmcp` at its historical version until the binary crate is removed in Task 5, but change its path dependency:

```toml
rust-junosmcp-srx-core = { path = "../rust-junosmcp-srx-core" }
```

- [ ] **Step 4: Update the Rust import identity without changing behavior**

In the temporary legacy binary, replace every exact crate path:

```rust
rust_srxmcp_core::...
```

with:

```rust
rust_junosmcp_srx_core::...
```

Update crate-level current-facing prose from “core logic for rust-srxmcp” to “SRX workflow core for rust-junosmcp.” Do not rename stable `srxmcp_status`, `srxmcp-*` bundle filenames, error fields, schema values, or historical capture names.

- [ ] **Step 5: Regenerate and verify Cargo metadata**

Run:

```bash
cargo check --workspace
cargo check --workspace --locked
cargo test -p rust-junosmcp-srx-core --locked
cargo metadata --no-deps --format-version 1 | rg '"name":"rust-junosmcp-srx-core"'
```

Expected: all commands pass; metadata points to `rust-junosmcp-srx-core/Cargo.toml`.

- [ ] **Step 6: Prove the old package identity is gone from active manifests/code**

Run:

```bash
rg -n --glob 'Cargo.toml' --glob '*.rs' 'rust-srxmcp-core|rust_srxmcp_core' .
```

Expected: no matches.

- [ ] **Step 7: Commit the rename/version checkpoint**

```bash
git add Cargo.toml Cargo.lock rust-junosmcp/Cargo.toml rust-junosmcp-core/Cargo.toml rust-junosmcp-auth/Cargo.toml rust-junosmcp-audit/Cargo.toml rust-srxmcp rust-junosmcp-srx-core
git commit -m "refactor(#163): rename SRX workflow core"
```

---

### Task 2: Fold HTTP limits into `rust-junosmcp-core`

**Files:**
- Create: `rust-junosmcp-core/tests/limits_public_api.rs`
- Move: `rust-junosmcp-limits/src/lib.rs` → `rust-junosmcp-core/src/limits/mod.rs`
- Move: `rust-junosmcp-limits/src/{config,concurrency,overload,prometheus,rate_limit,router,session}.rs` → `rust-junosmcp-core/src/limits/`
- Delete: `rust-junosmcp-limits/Cargo.toml`
- Modify: `Cargo.toml`
- Modify: `rust-junosmcp-core/Cargo.toml`
- Modify: `rust-junosmcp-core/src/lib.rs`
- Modify: `rust-junosmcp/src/http_transport.rs`
- Modify: `rust-junosmcp/src/main.rs`
- Modify: `rust-junosmcp/Cargo.toml`
- Modify: temporary `rust-srxmcp/{Cargo.toml,src/http_transport.rs,src/main.rs}`
- Generated: `Cargo.lock`

**Interfaces:**
- Consumes: Existing `rust_junosmcp_limits::{LimitsConfig, ...}` API.
- Produces: The same names under `rust_junosmcp_core::limits::{LimitsConfig, ...}`.

- [ ] **Step 1: Write the failing public-API test**

Create `rust-junosmcp-core/tests/limits_public_api.rs`:

```rust
use rust_junosmcp_core::limits::{LimitsConfig, LimitsConfigError};

#[test]
fn limits_remain_a_public_core_api() {
    let defaults = LimitsConfig::default();
    assert_eq!(defaults.validate(), Ok(()));

    let invalid = LimitsConfig {
        max_requests_per_second_per_token: 1,
        max_request_burst_per_token: 0,
        ..LimitsConfig::default()
    };
    assert_eq!(
        invalid.validate(),
        Err(LimitsConfigError::IncompleteTokenRateLimit { rate: 1, burst: 0 })
    );
}
```

- [ ] **Step 2: Run the test and verify the missing module failure**

Run:

```bash
cargo test -p rust-junosmcp-core --test limits_public_api
```

Expected: compilation fails because `rust_junosmcp_core::limits` does not exist.

- [ ] **Step 3: Move the implementation modules**

Run:

```bash
mkdir -p rust-junosmcp-core/src/limits
git mv rust-junosmcp-limits/src/lib.rs rust-junosmcp-core/src/limits/mod.rs
git mv rust-junosmcp-limits/src/config.rs rust-junosmcp-core/src/limits/config.rs
git mv rust-junosmcp-limits/src/concurrency.rs rust-junosmcp-core/src/limits/concurrency.rs
git mv rust-junosmcp-limits/src/overload.rs rust-junosmcp-core/src/limits/overload.rs
git mv rust-junosmcp-limits/src/prometheus.rs rust-junosmcp-core/src/limits/prometheus.rs
git mv rust-junosmcp-limits/src/rate_limit.rs rust-junosmcp-core/src/limits/rate_limit.rs
git mv rust-junosmcp-limits/src/router.rs rust-junosmcp-core/src/limits/router.rs
git mv rust-junosmcp-limits/src/session.rs rust-junosmcp-core/src/limits/session.rs
git rm rust-junosmcp-limits/Cargo.toml
```

Export the module in `rust-junosmcp-core/src/lib.rs`:

```rust
pub mod limits;
```

Inside the moved concurrency tests, replace:

```rust
use rust_junosmcp_core::DeviceLeaseManager;
```

with:

```rust
use crate::DeviceLeaseManager;
```

Because the modules now live below `crate::limits`, update all former
crate-root sibling paths with this exact mapping:

```text
crate::config                  crate::limits::config
crate::ConcurrencyState        crate::limits::ConcurrencyState
crate::concurrency_middleware  crate::limits::concurrency_middleware
crate::overload                crate::limits::overload
crate::prometheus              crate::limits::prometheus
crate::router                  crate::limits::router
crate::session                 crate::limits::session
```

Keep module visibility private inside `limits`; consumers continue through the
existing `pub use` surface in `limits/mod.rs`.

- [ ] **Step 4: Move the limits dependency set into core**

Add the former limits dependencies to `rust-junosmcp-core/Cargo.toml`:

```toml
axum         = { workspace = true }
tower-http   = { workspace = true, features = ["limit"] }
http         = { workspace = true }
http-body    = { workspace = true }
http-body-util = { workspace = true }
rmcp         = { version = "2", features = ["server", "transport-streamable-http-server"] }
rust-junosmcp-auth = { path = "../rust-junosmcp-auth" }
dashmap      = { workspace = true }
futures      = "0.3"
metrics                     = { workspace = true }
metrics-exporter-prometheus = { workspace = true }
```

Keep the existing Tokio, Tokio-util, serde_json, tracing, and tempfile dependencies rather than duplicating entries. Add `tower = { workspace = true }` to core dev-dependencies for the moved middleware tests.

- [ ] **Step 5: Repoint both temporary consumers and remove the workspace member**

Replace:

```rust
use rust_junosmcp_limits::{ ... };
rust_junosmcp_limits::LimitsConfig
```

with:

```rust
use rust_junosmcp_core::limits::{ ... };
rust_junosmcp_core::limits::LimitsConfig
```

Remove `rust-junosmcp-limits` dependencies from both binary manifests and remove `"rust-junosmcp-limits"` from root workspace members.

- [ ] **Step 6: Run the moved unit and integration tests**

Run:

```bash
cargo fmt --all --check
cargo test -p rust-junosmcp-core --locked
cargo test -p rust-junosmcp-core --test limits_public_api --locked
cargo test -p rust-junosmcp --test http_limits --test http_metrics --locked
cargo test -p rust-srxmcp --test http_limits --test http_metrics --locked
cargo check --workspace --locked
```

Expected: every command passes; the stable 413/429/503 and metric tests still run through the moved code.

- [ ] **Step 7: Prove the old limits crate is absent**

Run:

```bash
test ! -e rust-junosmcp-limits
rg -n --glob 'Cargo.toml' --glob '*.rs' 'rust-junosmcp-limits|rust_junosmcp_limits' .
```

Expected: directory absent and no active manifest/Rust matches.

- [ ] **Step 8: Commit the core consolidation**

```bash
git add Cargo.toml Cargo.lock rust-junosmcp-core rust-junosmcp rust-srxmcp
git commit -m "refactor(#163): fold HTTP limits into core"
```

---

### Task 3: Make support-bundle staging explicit typed state

**Files:**
- Modify: `rust-junosmcp-srx-core/src/workflows/support_bundle/staging.rs`
- Modify: `rust-junosmcp-srx-core/src/workflows/support_bundle/mod.rs`
- Modify: temporary `rust-srxmcp/src/server.rs`

**Interfaces:**
- Produces:
  - `SupportBundleStagingConfig::new(directory: PathBuf, max_bytes: u64) -> Self`
  - `SupportBundleStagingConfig::default()`
  - `support_bundle::run(device, args, config: &SupportBundleStagingConfig)`
- Removes: per-call reads of `JMCP_SRX_STAGING_DIR` and `JMCP_SRX_STAGING_MAX_BYTES`.

- [ ] **Step 1: Write failing explicit-config tests**

Add to `staging.rs` tests:

```rust
#[test]
fn explicit_config_controls_all_host_paths() {
    let root = tempfile::tempdir().unwrap();
    let config = SupportBundleStagingConfig::new(root.path().to_path_buf(), 123_456);

    assert_eq!(config.directory(), root.path());
    assert_eq!(config.max_bytes(), 123_456);
    assert_eq!(
        bundle_tarball_path(&config, "srx-01", "srxmcp-request-1").unwrap(),
        root.path().join("srx-01/srxmcp-request-1.tgz")
    );
}

#[test]
fn packaged_defaults_are_stable() {
    let config = SupportBundleStagingConfig::default();
    assert_eq!(
        config.directory(),
        Path::new("/var/lib/jmcp/srx-staging/bundles")
    );
    assert_eq!(config.max_bytes(), 500 * 1024 * 1024);
}
```

- [ ] **Step 2: Run the tests and confirm missing-type/signature failures**

Run:

```bash
cargo test -p rust-junosmcp-srx-core explicit_config_controls_all_host_paths
```

Expected: compilation fails because `SupportBundleStagingConfig` and config-taking path helpers do not exist.

- [ ] **Step 3: Implement the typed configuration**

Replace the environment readers in `staging.rs` with:

```rust
pub const DEFAULT_STAGING_DIR: &str = "/var/lib/jmcp/srx-staging/bundles";
pub const DEFAULT_STAGING_MAX_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleStagingConfig {
    directory: PathBuf,
    max_bytes: u64,
}

impl SupportBundleStagingConfig {
    pub fn new(directory: PathBuf, max_bytes: u64) -> Self {
        Self {
            directory,
            max_bytes,
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

impl Default for SupportBundleStagingConfig {
    fn default() -> Self {
        Self::new(
            PathBuf::from(DEFAULT_STAGING_DIR),
            DEFAULT_STAGING_MAX_BYTES,
        )
    }
}
```

Change the host-path APIs to:

```rust
pub fn router_staging_dir(
    config: &SupportBundleStagingConfig,
    router: &str,
) -> Result<PathBuf, SrxError>;

pub fn bundle_tarball_path(
    config: &SupportBundleStagingConfig,
    router: &str,
    filesystem_id: &str,
) -> Result<PathBuf, SrxError>;

pub fn bundle_manifest_path(
    config: &SupportBundleStagingConfig,
    router: &str,
    filesystem_id: &str,
) -> Result<PathBuf, SrxError>;

impl PreparedBundlePaths {
    pub fn prepare(
        config: &SupportBundleStagingConfig,
        router: &str,
        filesystem_id: &str,
    ) -> Result<Self, SrxError> {
        Self::prepare_under(config.directory(), router, filesystem_id)
    }
}
```

Update the existing staging unit calls to construct one
`SupportBundleStagingConfig::default()` and pass `&config` as the first
argument to `bundle_tarball_path` and `bundle_manifest_path`. Keep
`prepare_under` tests explicit so symlink/confinement cases continue to choose
their temporary root directly.

- [ ] **Step 4: Thread the config through the workflow**

Use this public entry point:

```rust
pub async fn run(
    device: &mut PooledDevice,
    mut args: SupportBundleArgs,
    staging: &SupportBundleStagingConfig,
) -> Result<SrxToolResponse<SupportBundleData>, SrxError>
```

Add `staging: &SupportBundleStagingConfig` to `collect_generic`, `collect_per_type`, and `finalize_lxc_bundle`. Pass it at every call, use `PreparedBundlePaths::prepare(staging, ...)`, and replace the cap lookup with:

```rust
let _ = enforce_staging_cap(staging.max_bytes());
```

Re-export the type from `support_bundle`:

```rust
pub use staging::SupportBundleStagingConfig;
```

- [ ] **Step 5: Keep the temporary legacy binary compiling**

Until Task 5 removes it, change its support-bundle call to:

```rust
let staging = rust_junosmcp_srx_core::workflows::support_bundle::
    SupportBundleStagingConfig::default();
let result = rust_junosmcp_srx_core::workflows::support_bundle::run(
    &mut device,
    args,
    &staging,
)
.await;
```

- [ ] **Step 6: Run all SRX core and adapter tests**

Run:

```bash
cargo fmt --all --check
cargo test -p rust-junosmcp-srx-core --locked
cargo test -p rust-srxmcp --locked
rg -n 'staging_dir_from_env|staging_max_bytes_from_env|std::env::var\\("JMCP_SRX_STAGING' rust-junosmcp-srx-core
```

Expected: tests pass and the search has no matches.

- [ ] **Step 7: Commit explicit staging configuration**

```bash
git add rust-junosmcp-srx-core rust-srxmcp/src/server.rs
git commit -m "refactor(#163): make SRX staging configuration explicit"
```

---

### Task 4: Reconcile canonical and legacy environment configuration

**Files:**
- Create: `rust-junosmcp/src/env_compat.rs`
- Create: `rust-junosmcp/tests/env_compat.rs`
- Modify: `rust-junosmcp/src/main.rs`
- Modify: `rust-junosmcp/src/cli.rs`
- Modify: `rust-junosmcp/Cargo.toml`

**Interfaces:**
- Produces:
  - `env_compat::parse() -> ParsedCli`
  - `ParsedCli { cli: Cli, warnings: Vec<LegacyEnvWarning> }`
  - `emit_warnings(&[LegacyEnvWarning])`
- Precedence: command line → canonical environment → deprecated legacy environment → CLI default.

- [ ] **Step 1: Add the `srx` dependency boundary without enabling it by default yet**

Use:

```toml
[features]
default = ["tls"]
tls = ["dep:rustls", "dep:rustls-pki-types", "dep:axum-server"]
srx = ["dep:rust-junosmcp-srx-core"]

[dependencies]
rust-junosmcp-srx-core = {
    path = "../rust-junosmcp-srx-core",
    optional = true,
}
```

This lets configuration compile and test under `--features srx` before Task 5 adds the router and changes the default.
Because all environment reads now live in `env_compat.rs`, reduce the Junos
clap feature set to:

```toml
clap = { version = "4", features = ["derive"] }
```

- [ ] **Step 2: Add CLI fields and remove direct clap environment reads**

Keep existing flags/defaults, remove `env = "..."` attributes, and add canonical shared fields:

```rust
#[arg(short = 'f', long, default_value = "devices.json", global = true)]
pub device_mapping: PathBuf;

#[arg(short = 'H', long, default_value = "127.0.0.1")]
pub host: String;

#[arg(short = 'p', long, default_value_t = 30030)]
pub port: u16;

#[arg(long)]
pub tokens_file: Option<PathBuf>;

#[arg(long, default_value = "/var/lib/jmcp/device-leases")]
pub device_lease_dir: PathBuf;

#[cfg(feature = "srx")]
#[arg(
    long,
    default_value =
        rust_junosmcp_srx_core::workflows::support_bundle::DEFAULT_STAGING_DIR
)]
pub support_bundle_staging_dir: PathBuf;

#[cfg(feature = "srx")]
#[arg(
    long,
    default_value_t =
        rust_junosmcp_srx_core::workflows::support_bundle::DEFAULT_STAGING_MAX_BYTES
)]
pub support_bundle_staging_max_bytes: u64;
```

Make the two default constants public from the support-bundle module rather than importing a private module path:

```rust
pub use staging::{
    SupportBundleStagingConfig,
    DEFAULT_STAGING_DIR,
    DEFAULT_STAGING_MAX_BYTES,
};
```

Then use `support_bundle::DEFAULT_*` in `cli.rs`.

- [ ] **Step 3: Write failing resolver unit tests**

Create `env_compat.rs` with the interfaces and tests first. Use this test-only
environment:

```rust
#[cfg(test)]
#[derive(Default)]
struct TestEnv(std::collections::BTreeMap<&'static str, OsString>);

#[cfg(test)]
impl<const N: usize> From<[(&'static str, &'static str); N]> for TestEnv {
    fn from(entries: [(&'static str, &'static str); N]) -> Self {
        Self(
            entries
                .into_iter()
                .map(|(name, value)| (name, OsString::from(value)))
                .collect(),
        )
    }
}

#[cfg(test)]
impl EnvSource for TestEnv {
    fn get(&self, name: &'static str) -> Option<OsString> {
        self.0.get(name).cloned()
    }
}
```

```rust
#[test]
fn legacy_only_host_is_applied_and_warned() {
    let env = TestEnv::from([("JMCP_SRX_HTTP_HOST", "192.0.2.10")]);
    let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
    assert_eq!(parsed.cli.host, "192.0.2.10");
    assert_eq!(
        parsed.warnings,
        vec![LegacyEnvWarning::Applied {
            legacy: "JMCP_SRX_HTTP_HOST",
            canonical: "JMCP_HTTP_HOST",
        }]
    );
}

#[test]
fn command_line_beats_both_environment_names() {
    let env = TestEnv::from([
        ("JMCP_HTTP_HOST", "192.0.2.20"),
        ("JMCP_SRX_HTTP_HOST", "192.0.2.30"),
    ]);
    let parsed = try_parse_from_with_env(
        ["rust-junosmcp", "--host", "127.0.0.9"],
        &env,
    )
    .unwrap();
    assert_eq!(parsed.cli.host, "127.0.0.9");
    assert_eq!(
        parsed.warnings,
        vec![LegacyEnvWarning::Ignored {
            legacy: "JMCP_SRX_HTTP_HOST",
            canonical: Some("JMCP_HTTP_HOST"),
        }]
    );
}

#[test]
fn canonical_environment_beats_legacy() {
    let env = TestEnv::from([
        ("JMCP_MAX_SESSIONS", "77"),
        ("JMCP_SRX_MAX_SESSIONS", "88"),
    ]);
    let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
    assert_eq!(parsed.cli.max_sessions, 77);
    assert!(matches!(
        parsed.warnings.as_slice(),
        [LegacyEnvWarning::Ignored {
            legacy: "JMCP_SRX_MAX_SESSIONS",
            canonical: Some("JMCP_MAX_SESSIONS"),
        }]
    ));
}

#[test]
fn legacy_port_is_never_applied() {
    let env = TestEnv::from([("JMCP_SRX_HTTP_PORT", "30032")]);
    let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
    assert_eq!(parsed.cli.port, 30030);
    assert_eq!(
        parsed.warnings,
        vec![LegacyEnvWarning::Ignored {
            legacy: "JMCP_SRX_HTTP_PORT",
            canonical: None,
        }]
    );
}

#[test]
fn invalid_applied_legacy_value_is_a_startup_error() {
    let env = TestEnv::from([("JMCP_SRX_MAX_SESSIONS", "many")]);
    let error = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap_err();
    assert!(error.to_string().contains("JMCP_SRX_MAX_SESSIONS"));
    assert!(error.to_string().contains("many"));
}

#[cfg(feature = "srx")]
#[test]
fn legacy_support_bundle_settings_are_applied_and_warned() {
    let env = TestEnv::from([
        ("JMCP_SRX_STAGING_DIR", "/tmp/legacy-srx-bundles"),
        ("JMCP_SRX_STAGING_MAX_BYTES", "123456"),
    ]);
    let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
    assert_eq!(
        parsed.cli.support_bundle_staging_dir,
        PathBuf::from("/tmp/legacy-srx-bundles")
    );
    assert_eq!(parsed.cli.support_bundle_staging_max_bytes, 123456);
    assert_eq!(parsed.warnings.len(), 2);
    assert!(parsed.warnings.contains(&LegacyEnvWarning::Applied {
        legacy: "JMCP_SRX_STAGING_DIR",
        canonical: "JMCP_SUPPORT_BUNDLE_STAGING_DIR",
    }));
    assert!(parsed.warnings.contains(&LegacyEnvWarning::Applied {
        legacy: "JMCP_SRX_STAGING_MAX_BYTES",
        canonical: "JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES",
    }));
}
```

- [ ] **Step 4: Run the tests and verify they fail**

Run:

```bash
cargo test -p rust-junosmcp --features srx env_compat
```

Expected: compilation fails because resolver types/functions are not implemented.

- [ ] **Step 5: Implement deterministic resolver primitives**

Use these core interfaces:

```rust
use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches};
use std::ffi::{OsStr, OsString};

pub(crate) trait EnvSource {
    fn get(&self, name: &'static str) -> Option<OsString>;
}

struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, name: &'static str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LegacyEnvWarning {
    Applied {
        legacy: &'static str,
        canonical: &'static str,
    },
    Ignored {
        legacy: &'static str,
        canonical: Option<&'static str>,
    },
}

pub(crate) struct ParsedCli {
    pub cli: Cli,
    pub warnings: Vec<LegacyEnvWarning>,
}

pub(crate) fn parse() -> ParsedCli {
    try_parse_from_with_env(std::env::args_os(), &ProcessEnv)
        .unwrap_or_else(|error| error.exit())
}
```

Implement one generic resolver:

```rust
fn resolve<T>(
    current: &mut T,
    matches: &clap::ArgMatches,
    arg_id: &str,
    canonical: &'static str,
    legacy: Option<&'static str>,
    env: &impl EnvSource,
    parse: impl Fn(&'static str, &OsStr) -> Result<T, clap::Error>,
    warnings: &mut Vec<LegacyEnvWarning>,
) -> Result<(), clap::Error> {
    let command_line = matches.value_source(arg_id) == Some(ValueSource::CommandLine);
    let canonical_value = env.get(canonical);
    let legacy_value = legacy.and_then(|name| env.get(name).map(|value| (name, value)));

    if command_line {
        if let Some((legacy, _)) = legacy_value {
            warnings.push(LegacyEnvWarning::Ignored {
                legacy,
                canonical: Some(canonical),
            });
        }
        return Ok(());
    }

    if let Some(value) = canonical_value {
        *current = parse(canonical, &value)?;
        if let Some((legacy, _)) = legacy_value {
            warnings.push(LegacyEnvWarning::Ignored {
                legacy,
                canonical: Some(canonical),
            });
        }
        return Ok(());
    }

    if let Some((legacy, value)) = legacy_value {
        *current = parse(legacy, &value)?;
        warnings.push(LegacyEnvWarning::Applied { legacy, canonical });
    }
    Ok(())
}
```

Use these strict parsers:

```rust
fn invalid_value(name: &'static str, value: &OsStr, detail: &str) -> clap::Error {
    clap::Error::raw(
        clap::error::ErrorKind::ValueValidation,
        format!(
            "invalid value {:?} for environment variable {name}: {detail}",
            value
        ),
    )
}

fn parse_utf8<'a>(
    name: &'static str,
    value: &'a OsStr,
) -> Result<&'a str, clap::Error> {
    value
        .to_str()
        .ok_or_else(|| invalid_value(name, value, "value must be UTF-8"))
}

fn parse_string(name: &'static str, value: &OsStr) -> Result<String, clap::Error> {
    Ok(parse_utf8(name, value)?.to_owned())
}

fn parse_path(_name: &'static str, value: &OsStr) -> Result<PathBuf, clap::Error> {
    Ok(PathBuf::from(value))
}

fn parse_optional_path(
    _name: &'static str,
    value: &OsStr,
) -> Result<Option<PathBuf>, clap::Error> {
    Ok(Some(PathBuf::from(value)))
}

fn parse_number<T>(name: &'static str, value: &OsStr) -> Result<T, clap::Error>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = parse_utf8(name, value)?;
    raw.parse::<T>()
        .map_err(|error| invalid_value(name, value, &error.to_string()))
}

fn parse_bool(name: &'static str, value: &OsStr) -> Result<bool, clap::Error> {
    match parse_utf8(name, value)?.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(invalid_value(
            name,
            value,
            "expected true/false, 1/0, yes/no, or on/off",
        )),
    }
}
```

The generic closure parameter lets `parse_number::<usize>`,
`parse_number::<u64>`, and `parse_number::<u16>` type-check without separate
resolvers.

- [ ] **Step 6: Apply the complete mapping**

Call `resolve` for these exact pairs:

```text
host                                      JMCP_HTTP_HOST                                 JMCP_SRX_HTTP_HOST
tls_cert                                  JMCP_TLS_CERT                                  JMCP_SRX_TLS_CERT
tls_key                                   JMCP_TLS_KEY                                   JMCP_SRX_TLS_KEY
enable_metrics                            JMCP_ENABLE_METRICS                             JMCP_SRX_ENABLE_METRICS
max_request_body_bytes                    JMCP_MAX_REQUEST_BODY_BYTES                    JMCP_SRX_MAX_REQUEST_BODY_BYTES
max_inflight_requests                     JMCP_MAX_INFLIGHT_REQUESTS                     JMCP_SRX_MAX_INFLIGHT_REQUESTS
max_inflight_requests_per_token           JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN           JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_TOKEN
max_requests_per_second_per_token         JMCP_MAX_REQUESTS_PER_SECOND_PER_TOKEN         JMCP_SRX_MAX_REQUESTS_PER_SECOND_PER_TOKEN
max_request_burst_per_token               JMCP_MAX_REQUEST_BURST_PER_TOKEN               JMCP_SRX_MAX_REQUEST_BURST_PER_TOKEN
max_inflight_requests_per_router          JMCP_MAX_INFLIGHT_REQUESTS_PER_ROUTER          JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_ROUTER
max_sessions                              JMCP_MAX_SESSIONS                              JMCP_SRX_MAX_SESSIONS
max_sessions_per_token                    JMCP_MAX_SESSIONS_PER_TOKEN                    JMCP_SRX_MAX_SESSIONS_PER_TOKEN
session_idle_timeout_secs                 JMCP_SESSION_IDLE_TIMEOUT_SECS                 JMCP_SRX_SESSION_IDLE_TIMEOUT_SECS
session_max_lifetime_secs                 JMCP_SESSION_MAX_LIFETIME_SECS                 JMCP_SRX_SESSION_MAX_LIFETIME_SECS
audit_format                              JMCP_AUDIT_FORMAT                              JMCP_SRX_AUDIT_FORMAT
audit_log_file                            JMCP_AUDIT_LOG_FILE                            JMCP_SRX_AUDIT_LOG_FILE
audit_journald                            JMCP_AUDIT_JOURNALD                            JMCP_SRX_AUDIT_JOURNALD
audit_redact                              JMCP_AUDIT_REDACT                              JMCP_SRX_AUDIT_REDACT
audit_hmac_key_file                       JMCP_AUDIT_HMAC_KEY_FILE                       JMCP_SRX_AUDIT_HMAC_KEY_FILE
support_bundle_staging_dir                JMCP_SUPPORT_BUNDLE_STAGING_DIR                JMCP_SRX_STAGING_DIR
support_bundle_staging_max_bytes          JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES          JMCP_SRX_STAGING_MAX_BYTES
```

Apply canonical-only mappings for:

```text
port                 JMCP_HTTP_PORT
tokens_file          JMCP_TOKENS_PATH
device_mapping       JMCP_DEVICES_PATH
device_lease_dir     JMCP_DEVICE_LEASE_DIR
```

Implement parsing around the resolver as:

```rust
pub(crate) fn try_parse_from_with_env<I, T>(
    args: I,
    env: &impl EnvSource,
) -> Result<ParsedCli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = Cli::command().try_get_matches_from(args)?;
    let mut cli = Cli::from_arg_matches(&matches)?;
    let mut warnings = Vec::new();

    resolve(
        &mut cli.host,
        &matches,
        "host",
        "JMCP_HTTP_HOST",
        Some("JMCP_SRX_HTTP_HOST"),
        env,
        parse_string,
        &mut warnings,
    )?;
    resolve(
        &mut cli.port,
        &matches,
        "port",
        "JMCP_HTTP_PORT",
        None,
        env,
        parse_number::<u16>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.tokens_file,
        &matches,
        "tokens_file",
        "JMCP_TOKENS_PATH",
        None,
        env,
        parse_optional_path,
        &mut warnings,
    )?;
    resolve(
        &mut cli.device_mapping,
        &matches,
        "device_mapping",
        "JMCP_DEVICES_PATH",
        None,
        env,
        parse_path,
        &mut warnings,
    )?;
    resolve(
        &mut cli.device_lease_dir,
        &matches,
        "device_lease_dir",
        "JMCP_DEVICE_LEASE_DIR",
        None,
        env,
        parse_path,
        &mut warnings,
    )?;

    resolve(
        &mut cli.tls_cert,
        &matches,
        "tls_cert",
        "JMCP_TLS_CERT",
        Some("JMCP_SRX_TLS_CERT"),
        env,
        parse_optional_path,
        &mut warnings,
    )?;
    resolve(
        &mut cli.tls_key,
        &matches,
        "tls_key",
        "JMCP_TLS_KEY",
        Some("JMCP_SRX_TLS_KEY"),
        env,
        parse_optional_path,
        &mut warnings,
    )?;
    resolve(
        &mut cli.enable_metrics,
        &matches,
        "enable_metrics",
        "JMCP_ENABLE_METRICS",
        Some("JMCP_SRX_ENABLE_METRICS"),
        env,
        parse_bool,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_request_body_bytes,
        &matches,
        "max_request_body_bytes",
        "JMCP_MAX_REQUEST_BODY_BYTES",
        Some("JMCP_SRX_MAX_REQUEST_BODY_BYTES"),
        env,
        parse_number::<usize>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_inflight_requests,
        &matches,
        "max_inflight_requests",
        "JMCP_MAX_INFLIGHT_REQUESTS",
        Some("JMCP_SRX_MAX_INFLIGHT_REQUESTS"),
        env,
        parse_number::<usize>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_inflight_requests_per_token,
        &matches,
        "max_inflight_requests_per_token",
        "JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN",
        Some("JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_TOKEN"),
        env,
        parse_number::<usize>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_requests_per_second_per_token,
        &matches,
        "max_requests_per_second_per_token",
        "JMCP_MAX_REQUESTS_PER_SECOND_PER_TOKEN",
        Some("JMCP_SRX_MAX_REQUESTS_PER_SECOND_PER_TOKEN"),
        env,
        parse_number::<u64>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_request_burst_per_token,
        &matches,
        "max_request_burst_per_token",
        "JMCP_MAX_REQUEST_BURST_PER_TOKEN",
        Some("JMCP_SRX_MAX_REQUEST_BURST_PER_TOKEN"),
        env,
        parse_number::<u64>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_inflight_requests_per_router,
        &matches,
        "max_inflight_requests_per_router",
        "JMCP_MAX_INFLIGHT_REQUESTS_PER_ROUTER",
        Some("JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_ROUTER"),
        env,
        parse_number::<usize>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_sessions,
        &matches,
        "max_sessions",
        "JMCP_MAX_SESSIONS",
        Some("JMCP_SRX_MAX_SESSIONS"),
        env,
        parse_number::<usize>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.max_sessions_per_token,
        &matches,
        "max_sessions_per_token",
        "JMCP_MAX_SESSIONS_PER_TOKEN",
        Some("JMCP_SRX_MAX_SESSIONS_PER_TOKEN"),
        env,
        parse_number::<usize>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.session_idle_timeout_secs,
        &matches,
        "session_idle_timeout_secs",
        "JMCP_SESSION_IDLE_TIMEOUT_SECS",
        Some("JMCP_SRX_SESSION_IDLE_TIMEOUT_SECS"),
        env,
        parse_number::<u64>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.session_max_lifetime_secs,
        &matches,
        "session_max_lifetime_secs",
        "JMCP_SESSION_MAX_LIFETIME_SECS",
        Some("JMCP_SRX_SESSION_MAX_LIFETIME_SECS"),
        env,
        parse_number::<u64>,
        &mut warnings,
    )?;
    resolve(
        &mut cli.audit_format,
        &matches,
        "audit_format",
        "JMCP_AUDIT_FORMAT",
        Some("JMCP_SRX_AUDIT_FORMAT"),
        env,
        parse_string,
        &mut warnings,
    )?;
    resolve(
        &mut cli.audit_log_file,
        &matches,
        "audit_log_file",
        "JMCP_AUDIT_LOG_FILE",
        Some("JMCP_SRX_AUDIT_LOG_FILE"),
        env,
        parse_optional_path,
        &mut warnings,
    )?;
    resolve(
        &mut cli.audit_journald,
        &matches,
        "audit_journald",
        "JMCP_AUDIT_JOURNALD",
        Some("JMCP_SRX_AUDIT_JOURNALD"),
        env,
        parse_bool,
        &mut warnings,
    )?;
    resolve(
        &mut cli.audit_redact,
        &matches,
        "audit_redact",
        "JMCP_AUDIT_REDACT",
        Some("JMCP_SRX_AUDIT_REDACT"),
        env,
        parse_string,
        &mut warnings,
    )?;
    resolve(
        &mut cli.audit_hmac_key_file,
        &matches,
        "audit_hmac_key_file",
        "JMCP_AUDIT_HMAC_KEY_FILE",
        Some("JMCP_SRX_AUDIT_HMAC_KEY_FILE"),
        env,
        parse_optional_path,
        &mut warnings,
    )?;
    #[cfg(feature = "srx")]
    resolve(
        &mut cli.support_bundle_staging_dir,
        &matches,
        "support_bundle_staging_dir",
        "JMCP_SUPPORT_BUNDLE_STAGING_DIR",
        Some("JMCP_SRX_STAGING_DIR"),
        env,
        parse_path,
        &mut warnings,
    )?;
    #[cfg(feature = "srx")]
    resolve(
        &mut cli.support_bundle_staging_max_bytes,
        &matches,
        "support_bundle_staging_max_bytes",
        "JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES",
        Some("JMCP_SRX_STAGING_MAX_BYTES"),
        env,
        parse_number::<u64>,
        &mut warnings,
    )?;

    if env.get("JMCP_SRX_HTTP_PORT").is_some() {
        warnings.push(LegacyEnvWarning::Ignored {
            legacy: "JMCP_SRX_HTTP_PORT",
            canonical: None,
        });
    }

    Ok(ParsedCli { cli, warnings })
}
```

After normal port resolution, inspect `JMCP_SRX_HTTP_PORT` only to append:

```rust
LegacyEnvWarning::Ignored {
    legacy: "JMCP_SRX_HTTP_PORT",
    canonical: None,
}
```

- [ ] **Step 7: Emit warnings once after tracing starts**

In `main.rs`:

```rust
mod env_compat;

let env_compat::ParsedCli {
    cli: args,
    warnings,
} = env_compat::parse();

// construct AuditConfig and initialize tracing first
env_compat::emit_warnings(&warnings);
```

Use structured warnings containing `legacy`, optional `canonical`, and either “deprecated environment alias applied” or “deprecated environment variable ignored.” Never log values.

Implement:

```rust
pub(crate) fn emit_warnings(warnings: &[LegacyEnvWarning]) {
    for warning in warnings {
        match warning {
            LegacyEnvWarning::Applied { legacy, canonical } => {
                tracing::warn!(
                    legacy,
                    canonical,
                    "deprecated environment alias applied; migrate to canonical name"
                );
            }
            LegacyEnvWarning::Ignored { legacy, canonical } => {
                tracing::warn!(
                    legacy,
                    canonical = canonical.unwrap_or("none"),
                    "deprecated environment variable ignored"
                );
            }
        }
    }
}
```

- [ ] **Step 8: Add process-level warning/error tests**

In `rust-junosmcp/tests/env_compat.rs`, run the real binary with `stdin` null and an empty inventory:

```rust
mod common;

use std::process::{Command, Stdio};

#[test]
fn legacy_port_warns_and_does_not_move_stdio_startup() {
    common::ensure_built();
    let inventory = common::write_inv("{}");
    let output = Command::new(common::binary_path())
        .args([
            "--device-mapping",
            inventory.path().to_str().unwrap(),
            "--transport",
            "stdio",
        ])
        .env_remove("JMCP_HTTP_PORT")
        .env("JMCP_SRX_HTTP_PORT", "30032")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("JMCP_SRX_HTTP_PORT"));
    assert!(stderr.contains("ignored"));
}

#[test]
fn canonical_value_prevents_invalid_legacy_from_being_parsed() {
    common::ensure_built();
    let tokens = common::write_tokens(r#"{"version":1,"tokens":[]}"#);
    let output = Command::new(common::binary_path())
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.path().to_str().unwrap(),
        ])
        .env("JMCP_MAX_SESSIONS", "9")
        .env("JMCP_SRX_MAX_SESSIONS", "not-a-number")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("JMCP_SRX_MAX_SESSIONS"));
    assert!(stderr.contains("ignored"));
}
```

- [ ] **Step 9: Run canonical, legacy, validation, and feature tests**

Run:

```bash
cargo fmt --all --check
cargo test -p rust-junosmcp --features srx env_compat --locked
cargo test -p rust-junosmcp --features srx --test env_compat --locked
cargo test -p rust-junosmcp cli_validate --locked
cargo build -p rust-junosmcp --no-default-features --locked
```

Expected: all pass; no test mutates process-global environment in-process.

- [ ] **Step 10: Commit environment compatibility**

```bash
git add rust-junosmcp rust-junosmcp-srx-core Cargo.lock
git commit -m "feat(#163): unify server environment configuration"
```

---

### Task 5: Compose the Junos and SRX routers on one handler

**Files:**
- Generate: `rust-junosmcp/tests/fixtures/junos-tools-v0.7.json`
- Generate: `rust-junosmcp/tests/fixtures/srx-tools-v0.3.6.json`
- Create/move: `rust-junosmcp/src/server/srx.rs`
- Modify: `rust-junosmcp/src/server.rs`
- Modify: `rust-junosmcp/src/main.rs`
- Modify: `rust-junosmcp/src/cli.rs`
- Modify: `rust-junosmcp/Cargo.toml`
- Modify: `rust-junosmcp/tests/stdio_smoke.rs`
- Delete: `rust-srxmcp/src/`, `rust-srxmcp/Cargo.toml`
- Modify: `Cargo.toml`
- Generated: `Cargo.lock`

**Interfaces:**
- Produces: One cloneable `JmcpHandler` with a stored combined `ToolRouter<JmcpHandler>`.
- Produces: Default runtime surface of 26 tools; no-`srx` runtime surface of 17 tools.
- Preserves: Schema fixtures captured from the two pre-merge generated routers.

- [ ] **Step 1: Add temporary ignored schema generators before deleting either handler**

In each current server module, temporarily add an ignored test that serializes a `BTreeMap<String, serde_json::Value>` keyed by tool name:

```rust
fn write_tool_fixture(
    path: &std::path::Path,
    tools: Vec<rmcp::model::Tool>,
) {
    let normalized: std::collections::BTreeMap<String, serde_json::Value> = tools
        .into_iter()
        .map(|tool| {
            let name = tool.name.to_string();
            (name, serde_json::to_value(tool).unwrap())
        })
        .collect();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(&normalized).unwrap()).unwrap();
}
```

Junos generator target:

```rust
#[test]
#[ignore = "one-time baseline generator for issue #163"]
fn capture_junos_tool_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/junos-tools-v0.7.json");
    write_tool_fixture(&path, JmcpHandler::tool_router().list_all());
}
```

SRX generator target:

```rust
#[test]
#[ignore = "one-time baseline generator for issue #163"]
fn capture_srx_tool_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rust-junosmcp/tests/fixtures/srx-tools-v0.3.6.json");
    write_tool_fixture(&path, JmcpSrxHandler::tool_router().list_all());
}
```

- [ ] **Step 2: Generate fixtures, inspect them, then remove generator code**

Run:

```bash
cargo test -p rust-junosmcp capture_junos_tool_fixture -- --ignored
cargo test -p rust-srxmcp capture_srx_tool_fixture -- --ignored
test -s rust-junosmcp/tests/fixtures/junos-tools-v0.7.json
test -s rust-junosmcp/tests/fixtures/srx-tools-v0.3.6.json
```

Expected: the files contain 17 and 9 keyed schema objects respectively. Remove both temporary generator tests with `apply_patch`; do not edit fixture JSON manually.

- [ ] **Step 3: Write failing combined-surface tests**

Update `stdio_smoke.rs` to build the expected names from exact arrays:

```rust
const JUNOS_TOOLS: &[&str] = &[
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "commit_check_config",
    "discard_candidate",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",
    "add_device",
    "reload_devices",
    "transfer_file",
    "fetch_file",
    "list_staged_files",
    "upgrade_junos",
];

#[cfg(feature = "srx")]
const SRX_TOOLS: &[&str] = &[
    "srxmcp_status",
    "get_chassis_cluster_status",
    "get_srx_security_services_status",
    "check_srx_feature_license",
    "vpn_lifecycle_report",
    "manage_idp_security_package",
    "manage_appid_signature_package",
    "validate_chassis_cluster_health",
    "collect_jtac_support_bundle",
];
```

The test asserts exact set equality and count 26 under `srx`. Rename the test
function to `lists_expected_tools` so the focused commands below select it
exactly.

In `server.rs`, add feature-sensitive router-count tests:

```rust
#[test]
#[cfg(feature = "srx")]
fn combined_router_has_exact_endpoint_union() {
    let handler = make_handler();
    let names: std::collections::HashSet<String> = handler
        .tool_router
        .list_all()
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    let expected: std::collections::HashSet<String> =
        rust_junosmcp_auth::file::KNOWN_TOOLS
            .iter()
            .map(|name| (*name).to_string())
            .collect();
    assert_eq!(names, expected);
    assert_eq!(names.len(), 26);
}

#[test]
#[cfg(not(feature = "srx"))]
fn junos_only_router_has_seventeen_tools() {
    assert_eq!(JmcpHandler::junos_tool_router().list_all().len(), 17);
}

#[test]
#[cfg(feature = "srx")]
fn junos_and_srx_share_the_same_device_lease_manager() {
    let handler = make_handler();
    assert!(Arc::ptr_eq(
        &handler.device_leases,
        &handler.upgrade_cfg.device_leases,
    ));
}
```

Add a stdio regression under `#[cfg(feature = "srx")]`:

```rust
#[test]
fn srx_status_allows_stdio_even_when_a_token_file_is_loaded() {
    let inventory = common::write_inv("{}");
    let tokens = common::write_tokens(r#"{"version":1,"tokens":[]}"#);
    let mut server = common::spawn_stdio_server_with_args(&[
        "--device-mapping",
        inventory.path().to_str().unwrap(),
        "--tokens-file",
        tokens.path().to_str().unwrap(),
    ]);
    let result = common::call_tool(&mut server, "srxmcp_status", json!({}));
    assert_eq!(result["endpoint"], "srxmcp");
}
```

- [ ] **Step 4: Run the default test and verify the pre-merge failure**

Run:

```bash
cargo test -p rust-junosmcp --test stdio_smoke lists_expected_tools
```

Expected: failure reports only 17 tools instead of the expected 26.

- [ ] **Step 5: Move the SRX adapters and remove duplicate binary infrastructure**

Run:

```bash
mkdir -p rust-junosmcp/src/server
git mv rust-srxmcp/src/server.rs rust-junosmcp/src/server/srx.rs
git rm rust-srxmcp/src/cli.rs
git rm rust-srxmcp/src/cli_validate.rs
git rm rust-srxmcp/src/http_transport.rs
git rm rust-srxmcp/src/lib.rs
git rm rust-srxmcp/src/main.rs
git rm rust-srxmcp/src/tls.rs
git rm rust-srxmcp/Cargo.toml
```

Remove `"rust-srxmcp"` from workspace members. Leave its tests and documentation tracked until Task 6 migrates/archive-removes them.

- [ ] **Step 6: Add named router composition to `JmcpHandler`**

Change the Junos router attribute:

```rust
#[tool_router(router = junos_tool_router, vis = "pub(crate)")]
impl JmcpHandler {
    // existing 17 methods unchanged
}
```

Add this field and feature-gated state:

```rust
use rmcp::handler::server::router::tool::ToolRouter;

#[derive(Clone)]
pub struct JmcpHandler {
    pub(super) dm: Arc<DeviceManager>,
    policy: Arc<arc_swap::ArcSwap<Policy>>,
    transfer_cfg: rust_junosmcp_core::TransferConfig,
    upgrade_cfg: rust_junosmcp_core::UpgradeConfig,
    tool_router: ToolRouter<Self>,
    #[cfg(feature = "srx")]
    pub(super) started: Arc<tokio::time::Instant>,
    #[cfg(feature = "srx")]
    pub(super) authorization_required: bool,
    #[cfg(feature = "srx")]
    pub(super) device_leases: Arc<rust_junosmcp_core::DeviceLeaseManager>,
    #[cfg(feature = "srx")]
    pub(super) confirmation_store:
        rust_junosmcp_srx_core::workflows::signature_package::ConfirmationStore,
    #[cfg(feature = "srx")]
    pub(super) support_bundle_staging:
        rust_junosmcp_srx_core::workflows::support_bundle::SupportBundleStagingConfig,
}
```

Construct the router and shared lease state:

```rust
let tool_router = Self::junos_tool_router();
#[cfg(feature = "srx")]
let tool_router = tool_router + Self::srx_tool_router();
#[cfg(feature = "srx")]
let device_leases = upgrade_cfg.device_leases.clone();

Self {
    dm,
    policy: Arc::new(arc_swap::ArcSwap::from(policy)),
    transfer_cfg,
    upgrade_cfg,
    tool_router,
    #[cfg(feature = "srx")]
    started: Arc::new(tokio::time::Instant::now()),
    #[cfg(feature = "srx")]
    authorization_required: false,
    #[cfg(feature = "srx")]
    device_leases,
    #[cfg(feature = "srx")]
    confirmation_store: Default::default(),
    #[cfg(feature = "srx")]
    support_bundle_staging: Default::default(),
}
```

Add:

```rust
#[cfg(feature = "srx")]
pub fn with_srx_runtime(
    mut self,
    authorization_required: bool,
    support_bundle_staging:
        rust_junosmcp_srx_core::workflows::support_bundle::SupportBundleStagingConfig,
) -> Self {
    self.authorization_required = authorization_required;
    self.support_bundle_staging = support_bundle_staging;
    self
}
```

Change the handler macro:

```rust
#[tool_handler(router = self.tool_router)]
impl ServerHandler for JmcpHandler {
    // unified server info
}
```

- [ ] **Step 7: Adapt the moved SRX module without rewriting tool bodies**

At the top of `server/srx.rs`, import shared state:

```rust
use super::{caller_ctx, mint_request_id, JmcpHandler};
```

Make `caller_ctx` and `mint_request_id` in `server.rs` `pub(super)`. Keep the SRX-specific coded scope error enum in `srx.rs` so stable `[code=...]` messages remain exact.

Apply these exact structural replacements:

```text
JmcpSrxHandler                         JmcpHandler
self.device_manager                   self.dm
rust_junosmcp_srx_core                rust_junosmcp_srx_core
#[tool_router]                        #[tool_router(router = srx_tool_router, vis = "pub(crate)")]
```

Remove the SRX `ServerHandler` implementation and its duplicate `Implementation`, `ServerCapabilities`, and `ServerInfo` imports. Keep all 9 tool methods, response types, audit calls, confirmation checks, error mapping, and unit tests.
Delete the duplicate local `caller_ctx` and `mint_request_id` definitions from
the moved file after importing the shared implementations.

Pass explicit support configuration:

```rust
let result = rust_junosmcp_srx_core::workflows::support_bundle::run(
    &mut device,
    args,
    &self.support_bundle_staging,
)
.await;
```

Replace the moved module's handler test factory with:

```rust
fn make_handler(authorization_required: bool) -> JmcpHandler {
    let inventory = Arc::new(rust_junosmcp_core::Inventory::empty());
    let dm = Arc::new(DeviceManager::new(inventory.clone()));
    let policy = Arc::new(rust_junosmcp_core::Policy::build(&inventory).unwrap());
    let transfer_cfg = rust_junosmcp_core::TransferConfig {
        staging_dir: std::path::PathBuf::from("/tmp/staging"),
        known_hosts_file: std::path::PathBuf::from("/tmp/known_hosts"),
        scp_runner: Arc::new(rust_junosmcp_core::OpenSshScpRunner),
        transfer_locks: Arc::new(
            rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
        ),
        accept_new_host_keys: false,
    };
    let lease_dir = tempfile::tempdir().unwrap();
    let device_leases =
        Arc::new(DeviceLeaseManager::for_directory(lease_dir.path()).unwrap());
    let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
        device_leases,
    };
    JmcpHandler::new(dm, policy, transfer_cfg, upgrade_cfg).with_srx_runtime(
        authorization_required,
        Default::default(),
    )
}
```

Strengthen the existing confirmation test to validate through a handler clone:

```rust
let cloned_handler = handler.clone();
assert!(cloned_handler
    .validate_confirmation_request(
        true,
        Some(token),
        Some("alice"),
        "srx-01",
        "srx-01|192.0.2.1|830|netconf",
    )
    .is_ok());
```

This proves rmcp session handler clones share one `ConfirmationStore`.

Declare the module:

```rust
#[cfg(feature = "srx")]
mod srx;
```

Keep a single server metadata implementation:

```rust
fn get_info(&self) -> ServerInfo {
    ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
        .with_server_info(Implementation::new(
            "jmcp-server",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(
            "Junos and SRX MCP server. Use get_router_list to enumerate \
             visible routers, then select generic Junos primitives or \
             SRX-specific operational workflows.",
        )
}
```

- [ ] **Step 8: Wire SRX runtime state into the unified bootstrap**

After constructing `JmcpHandler`:

```rust
let handler = JmcpHandler::new(
    dev_manager.clone(),
    policy,
    transfer_cfg,
    upgrade_cfg,
);

#[cfg(feature = "srx")]
let handler = handler.with_srx_runtime(
    token_store.is_some()
        && matches!(args.transport, Transport::StreamableHttp),
    rust_junosmcp_srx_core::workflows::support_bundle::
        SupportBundleStagingConfig::new(
            args.support_bundle_staging_dir.clone(),
            args.support_bundle_staging_max_bytes,
        ),
);
```

This must reuse the lease `Arc` cloned from `UpgradeConfig`, not create a second manager.
The transport check is load-bearing: stdio has no HTTP `CallerCtx`, so even a
stdio process given `--tokens-file` must retain the local no-context behavior.

- [ ] **Step 9: Enable SRX by default**

Set:

```toml
[features]
default = ["tls", "srx"]
tls = ["dep:rustls", "dep:rustls-pki-types", "dep:axum-server"]
srx = ["dep:rust-junosmcp-srx-core"]
```

Keep the SRX dependency optional.

- [ ] **Step 10: Add exact schema compatibility assertions**

In `server.rs` tests:

```rust
fn normalized_tools(
    tools: Vec<rmcp::model::Tool>,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    tools
        .into_iter()
        .map(|tool| {
            let name = tool.name.to_string();
            (name, serde_json::to_value(tool).unwrap())
        })
        .collect()
}

#[test]
fn junos_schemas_match_pre_merge_baseline() {
    let expected: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(include_str!(
        "../tests/fixtures/junos-tools-v0.7.json"
    ))
    .unwrap();
    assert_eq!(
        normalized_tools(JmcpHandler::junos_tool_router().list_all()),
        expected
    );
}

#[cfg(feature = "srx")]
#[test]
fn srx_schemas_match_pre_merge_baseline() {
    let expected: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(include_str!(
        "../tests/fixtures/srx-tools-v0.3.6.json"
    ))
    .unwrap();
    assert_eq!(
        normalized_tools(JmcpHandler::srx_tool_router().list_all()),
        expected
    );
}
```

- [ ] **Step 11: Run default and opt-out feature tests**

Run:

```bash
cargo fmt --all --check
cargo test -p rust-junosmcp --bin rust-junosmcp --locked
cargo test -p rust-junosmcp --test stdio_smoke lists_expected_tools --locked
cargo test -p rust-junosmcp --no-default-features --bin rust-junosmcp --locked
cargo build -p rust-junosmcp --no-default-features --locked
cargo build -p rust-junosmcp --no-default-features --features tls --locked
cargo check --workspace --locked
```

Expected: schema tests and 26-tool default pass; no-SRX router test reports exactly 17.

- [ ] **Step 12: Commit the unified handler**

```bash
git add Cargo.toml Cargo.lock rust-junosmcp rust-srxmcp
git commit -m "feat(#163): serve Junos and SRX tools together"
```

---

### Task 6: Migrate SRX tests and remove the legacy crate tree

**Files:**
- Move: `rust-srxmcp/tests/audit.rs` → `rust-junosmcp/tests/srx_audit.rs`
- Move: `rust-srxmcp/tests/http_limits.rs` → `rust-junosmcp/tests/srx_http_limits.rs`
- Move: `rust-srxmcp/tests/http_metrics.rs` → `rust-junosmcp/tests/srx_http_metrics.rs`
- Move: `rust-srxmcp/tests/http_smoke.rs` → `rust-junosmcp/tests/srx_http_smoke.rs`
- Move: `rust-srxmcp/tests/http_tls.rs` → `rust-junosmcp/tests/srx_http_tls.rs`
- Move: `rust-srxmcp/tests/live_smoke.rs` → `rust-junosmcp/tests/srx_live_smoke.rs`
- Move: `rust-srxmcp/CHANGELOG.md` → `docs/archive/rust-srxmcp-changelog.md`
- Modify: `rust-junosmcp/src/server/srx.rs`
- Modify: `rust-junosmcp/tests/common/mod.rs`
- Modify: `rust-junosmcp/AGENTS.md`
- Modify: `rust-junosmcp-srx-core/AGENTS.md`
- Delete: `rust-srxmcp/tests/common/mod.rs`
- Delete: `rust-srxmcp/tests/status_tool.rs`
- Delete: `rust-srxmcp/README.md`
- Delete: `rust-srxmcp/AGENTS.md`

**Interfaces:**
- Consumes: Existing Junos test harness, already a superset of the SRX harness.
- Produces: All unique SRX behavior tests targeting `rust-junosmcp`.

- [ ] **Step 1: Move test/history files with unambiguous names**

Run:

```bash
mkdir -p docs/archive
git mv rust-srxmcp/tests/audit.rs rust-junosmcp/tests/srx_audit.rs
git mv rust-srxmcp/tests/http_limits.rs rust-junosmcp/tests/srx_http_limits.rs
git mv rust-srxmcp/tests/http_metrics.rs rust-junosmcp/tests/srx_http_metrics.rs
git mv rust-srxmcp/tests/http_smoke.rs rust-junosmcp/tests/srx_http_smoke.rs
git mv rust-srxmcp/tests/http_tls.rs rust-junosmcp/tests/srx_http_tls.rs
git mv rust-srxmcp/tests/live_smoke.rs rust-junosmcp/tests/srx_live_smoke.rs
git mv rust-srxmcp/CHANGELOG.md docs/archive/rust-srxmcp-changelog.md
```

- [ ] **Step 2: Adapt all migrated process tests to the one binary**

Each moved file keeps `mod common;`, which now resolves to the Junos harness. Update prose/package names and apply these behavior changes:

```text
binary built/spawned                 rust-junosmcp
transport                            explicitly streamable-http
metrics server label                 junos
tools/list exact count               26
status endpoint field                srxmcp (unchanged)
live URL variable                    JMCP_LIVE_URL
live token variable                  JMCP_LIVE_TOKEN
live cargo command                   cargo test -p rust-junosmcp --test srx_live_smoke -- --ignored
```

In the custom TLS spawn, add:

```rust
"--transport",
"streamable-http",
```

The combined `tools/list` assertion must compare a set against `KNOWN_TOOLS`, not only assert the count.

- [ ] **Step 3: Preserve status and fail-closed tests inside the SRX module**

Move the useful status assertion from the removed integration test into `server/srx.rs`:

```rust
#[tokio::test]
async fn srxmcp_status_preserves_shape() {
    let handler = make_handler(false);
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let response = handler.srxmcp_status_body(SrxmcpStatusArgs::default());
    assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(response.endpoint, "srxmcp");
    assert!(response.uptime_seconds < 60);
}
```

Retain the existing missing-caller fail-closed, wildcard scope, and destructive confirmation binding tests on `JmcpHandler`.

- [ ] **Step 4: Consolidate metrics coverage without losing the SRX tool path**

Keep the migrated SRX metrics test, change expected labels from `server="srx"` to `server="junos"`, and call `srxmcp_status`. This proves both domains emit through the same installed recorder. Keep the existing Junos metrics test calling `get_router_list`.

- [ ] **Step 5: Merge safety instructions and archive context**

Move SRX-specific safety rules from `rust-srxmcp/AGENTS.md` into `rust-junosmcp/AGENTS.md` or `rust-junosmcp-srx-core/AGENTS.md` according to ownership. Add this preface to the archived changelog:

```markdown
> Historical changelog for the former standalone `rust-srxmcp` binary.
> Version 0.8.0 merged this server into `rust-junosmcp`; current changes are
> recorded in the repository root `CHANGELOG.md`.
```

- [ ] **Step 6: Delete the remaining orphaned legacy tree**

Run:

```bash
git rm rust-srxmcp/tests/common/mod.rs
git rm rust-srxmcp/tests/status_tool.rs
git rm rust-srxmcp/README.md
git rm rust-srxmcp/AGENTS.md
rmdir rust-srxmcp/tests
rmdir rust-srxmcp
```

Expected: the old directory is absent.

- [ ] **Step 7: Run all migrated offline contracts**

Run:

```bash
cargo fmt --all --check
cargo test -p rust-junosmcp --test srx_audit --locked
cargo test -p rust-junosmcp --test srx_http_smoke --locked
cargo test -p rust-junosmcp --test srx_http_limits --locked
cargo test -p rust-junosmcp --test srx_http_metrics --locked
cargo test -p rust-junosmcp --test srx_http_tls --locked
cargo test -p rust-junosmcp --test srx_live_smoke --locked
cargo test -p rust-junosmcp --locked
```

Expected: ordinary tests pass; live tests are compiled and reported ignored, with no device connection.

- [ ] **Step 8: Prove no active binary/import remains**

Run:

```bash
test ! -e rust-srxmcp
rg -n --glob 'Cargo.toml' --glob '*.rs' --glob 'justfile' 'rust-srxmcp|rust_srxmcp' .
```

Expected: no active build/code matches. Stable tool/bundle identifiers containing lowercase `srxmcp` remain allowed.

- [ ] **Step 9: Commit test migration and crate removal**

```bash
git add -A
git commit -m "test(#163): migrate SRX coverage to unified server"
```

---

### Task 7: Retire the legacy package, service, and port safely

**Files:**
- Modify: `packaging/tests/package-smoke.sh`
- Modify: `packaging/tests/distribution-smoke.sh`
- Modify: `scripts/package-lxc.sh`
- Modify: `packaging/lxc/install.sh`
- Modify: `packaging/systemd/rust-junosmcp.service`
- Delete: `packaging/systemd/rust-srxmcp.service`
- Modify: `Dockerfile`

**Interfaces:**
- Produces: one archive binary/unit and an idempotent installer that removes stale runtime artifacts.
- Preserves: old SRX support-bundle directory and contents.

- [ ] **Step 1: Change package smoke expectations first**

Require only these payload files:

```text
install.sh
usr/local/bin/rust-junosmcp
etc/jmcp/devices.json.example
etc/systemd/system/rust-junosmcp.service
```

Add explicit archive-absence assertions:

```bash
[[ ! -e "$PACKAGE_ROOT/usr/local/bin/rust-srxmcp" ]]
[[ ! -e "$PACKAGE_ROOT/etc/systemd/system/rust-srxmcp.service" ]]
```

Update the corrupt-package preflight case to delete
`usr/local/bin/rust-junosmcp` and assert the installer refuses the missing
unified binary before creating target state.

Before staged install, seed an old installation:

```bash
mkdir -p "$ROOTFS/usr/local/bin" "$ROOTFS/etc/systemd/system"
printf '%s\n' legacy-binary >"$ROOTFS/usr/local/bin/rust-srxmcp"
printf '%s\n' legacy-unit >"$ROOTFS/etc/systemd/system/rust-srxmcp.service"
mkdir -p "$ROOTFS/var/lib/jmcp/srx-staging/bundles"
printf '%s\n' preserve-me >"$ROOTFS/var/lib/jmcp/srx-staging/bundles/existing.tgz"
```

After each install, assert:

```bash
[[ ! -e "$ROOTFS/usr/local/bin/rust-srxmcp" ]]
[[ ! -e "$ROOTFS/etc/systemd/system/rust-srxmcp.service" ]]
grep -Fqx preserve-me "$ROOTFS/var/lib/jmcp/srx-staging/bundles/existing.tgz"
```

Verify only `rust-junosmcp.service` with `systemd-analyze`.

- [ ] **Step 2: Run the smoke against the current package and see it fail**

Run:

```bash
./scripts/package-lxc.sh
./packaging/tests/package-smoke.sh dist/rust-junosmcp_*_amd64.tar.gz
```

Expected: failure because the current package still contains the SRX binary/unit or the installer retains stale artifacts.

- [ ] **Step 3: Build and archive one binary**

In `scripts/package-lxc.sh`, use:

```bash
cargo build --release -p rust-junosmcp
test -x target/release/rust-junosmcp
```

Install only:

```bash
install -m 0755 target/release/rust-junosmcp \
    "$PKGROOT/usr/local/bin/rust-junosmcp"
install -m 0644 packaging/systemd/rust-junosmcp.service \
    "$PKGROOT/etc/systemd/system/rust-junosmcp.service"
```

Remove every SRX binary/unit payload reference.

- [ ] **Step 4: Implement live and staged legacy cleanup**

The installer preflight `required_files` contains only the unified payload. After validating the payload and permissions, define:

```bash
remove_legacy_runtime() {
    local legacy_binary legacy_unit
    legacy_binary="$(target_path /usr/local/bin/rust-srxmcp)"
    legacy_unit="$(target_path /etc/systemd/system/rust-srxmcp.service)"

    if [[ "$INSTALL_ROOT" == "/" && -e "$legacy_unit" ]]; then
        command -v systemctl >/dev/null 2>&1 \
            || fail "systemctl is required to retire rust-srxmcp.service"
        if systemctl is-active --quiet rust-srxmcp.service; then
            systemctl stop rust-srxmcp.service
        fi
        systemctl disable rust-srxmcp.service >/dev/null
    fi

    rm -f "$legacy_binary" "$legacy_unit"
}
```

Call `remove_legacy_runtime` before installing the new binary/unit. On live install, run one `systemctl daemon-reload` after both deletion and installation unless `JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1`.

Do not put the support-bundle directory in this cleanup function.

- [ ] **Step 5: Keep preserved state and configure the unified unit**

Continue creating:

```bash
SRX_STAGING_DIR="$STATE_DIR/srx-staging/bundles"
install -d -m 0750 "$SRX_STAGING_DIR"
```

Add to `rust-junosmcp.service`:

```ini
Environment=JMCP_SUPPORT_BUNDLE_STAGING_DIR=/var/lib/jmcp/srx-staging/bundles
Environment=JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES=524288000
```

Keep `ReadWritePaths=/var/lib/jmcp`, port 30030, auth, inventory-readonly, and the existing hardening directives.

- [ ] **Step 6: Remove the old unit and update Docker state**

Run:

```bash
git rm packaging/systemd/rust-srxmcp.service
```

In the Docker image create both:

```text
/var/lib/jmcp/staging
/var/lib/jmcp/srx-staging/bundles
```

with UID/GID 65532 and existing restrictive ownership. Set the two canonical support-bundle variables with `ENV` or equivalent entrypoint arguments.

- [ ] **Step 7: Extend endpoint smoke to prove both domains**

After authenticated initialize, retain the returned `Mcp-Session-Id`, send `notifications/initialized`, call `tools/list`, and assert the response contains:

```text
"name":"get_router_list"
"name":"srxmcp_status"
```

Also assert no second listener/unit is present in the staged root.

- [ ] **Step 8: Update distribution smoke with an upgrade fixture**

Before the first live-root install in the distribution container, seed:

```bash
install -m 0755 /bin/true /usr/local/bin/rust-srxmcp
printf '%s\n' \
    '[Unit]' \
    'Description=legacy SRX MCP' \
    '[Service]' \
    'ExecStart=/usr/local/bin/rust-srxmcp' \
    '[Install]' \
    'WantedBy=multi-user.target' \
    >/etc/systemd/system/rust-srxmcp.service
install -d /etc/systemd/system/multi-user.target.wants
ln -s ../rust-srxmcp.service \
    /etc/systemd/system/multi-user.target.wants/rust-srxmcp.service
install -d /var/lib/jmcp/srx-staging/bundles
printf '%s\n' preserve-me \
    >/var/lib/jmcp/srx-staging/bundles/existing.tgz
```

After two installs, assert the old files and the old
`multi-user.target.wants/rust-srxmcp.service` symlink are absent, the data is
unchanged, and only the unified unit verifies.

- [ ] **Step 9: Run shell, package, distribution, and container tests**

Run:

```bash
shellcheck scripts/package-lxc.sh scripts/test-lxc-distributions.sh packaging/lxc/install.sh packaging/tests/*.sh packaging/tests/fixtures/scp-server/entrypoint.sh
rm -rf dist
./scripts/package-lxc.sh
./packaging/tests/package-smoke.sh dist/rust-junosmcp_*_amd64.tar.gz
./scripts/test-lxc-distributions.sh dist/rust-junosmcp_*_amd64.tar.gz
./packaging/tests/container-scp-smoke.sh
```

Expected: all pass; archive contains one executable and one service.

- [ ] **Step 10: Commit deployment consolidation**

```bash
git add Dockerfile scripts packaging
git commit -m "build(#163): retire standalone SRX deployment"
```

---

### Task 8: Update current documentation, CI, and release wiring

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `AGENTS.md`
- Modify: `TODO.md`
- Modify: `docs/AUDIT.md`
- Modify: `docs/METRICS.md`
- Modify: `justfile`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release-image.yml`
- Modify: `rust-junosmcp-audit/Cargo.toml`
- Modify: `rust-junosmcp-audit/src/lib.rs`
- Modify: `rust-junosmcp-core/src/bootstrap.rs`
- Modify: `rust-junosmcp-srx-core/{Cargo.toml,src/lib.rs,AGENTS.md}`
- Modify: `packaging/logrotate/rust-junosmcp-audit`

**Interfaces:**
- Produces: one current-facing server/deployment contract and CI matrix for default and Junos-only builds.

- [ ] **Step 1: Capture the current stale-reference inventory**

Run:

```bash
rg -n --glob '!target/**' --glob '!docs/superpowers/**' --glob '!docs/archive/**' \
    'rust-srxmcp|rust_srxmcp|30032|JMCP_SRX_' .
```

Expected: matches in current docs, CI/just, comments, and changelog sections that need classification.

- [ ] **Step 2: Add the 0.8.0 breaking-release changelog entry**

Under `[Unreleased]`, add `Changed`, `Deprecated`, and `Removed` entries covering:

```markdown
- **#163 — unified Junos/SRX server.** `rust-junosmcp` now exposes the existing
  Junos and SRX tools from one process and endpoint. The `srx` feature is on by
  default; use `--no-default-features` for a minimal Junos-only build or add
  `--features tls` to retain TLS without SRX.
- Canonical server configuration uses `JMCP_*`. Corresponding `JMCP_SRX_*`
  variables are deprecated fallbacks for 0.8.0 only; `JMCP_SRX_HTTP_PORT` is
  ignored with a warning.
- Removed the `rust-srxmcp` binary, service, and port 30032. Package upgrades
  stop/disable and remove the legacy service/binary while preserving
  `/var/lib/jmcp/srx-staging/bundles`.
- Renamed `rust-srxmcp-core` to `rust-junosmcp-srx-core` and folded
  `rust-junosmcp-limits` into `rust-junosmcp-core`.
```

State that all surviving packages are version 0.8.0.

- [ ] **Step 3: Rewrite current usage and MCP registration**

README requirements:

- one architecture description and one endpoint at `127.0.0.1:30030/mcp`;
- one service enable/reload command;
- one MCP registration entry containing all tools;
- default and opt-out Cargo commands;
- canonical environment table plus one-release legacy notes;
- support-bundle state path;
- upgrade removal/preservation warning;
- no instruction to build, run, or register `rust-srxmcp`.

Keep historical release notes historical rather than rewriting old events.

- [ ] **Step 4: Update audit and metrics contracts**

`docs/AUDIT.md` describes one binary and one canonical flag/env table. SRX-only event kinds remain documented as tool-domain events, not as a second process. Journald examples use:

```bash
journalctl -t rust-junosmcp TARGET=audit
```

`docs/METRICS.md` describes one `/metrics` endpoint and `server="junos"` label for both tool domains. Remove the `rust-srxmcp` scrape job and port 30032.

- [ ] **Step 5: Update repository and crate instructions**

Root `AGENTS.md` target architecture becomes:

```text
rust-junosmcp/             one Junos/SRX MCP server
rust-junosmcp-core/        device I/O, base tools, and HTTP limits
rust-junosmcp-srx-core/    optional SRX workflows
rust-junosmcp-auth/        auth security boundary
rust-junosmcp-audit/       audit/compliance boundary
```

Keep high-risk workflow guidance. Update renamed core docs and audit descriptions to name only the current server. Remove stale completed SRX authorization/transport items from `TODO.md` without adding speculative scope.

- [ ] **Step 6: Update `just` and CI feature coverage**

Use this `e2e` recipe:

```make
e2e:
    cargo run -p rust-junosmcp -- --help >/dev/null
    cargo run -p rust-junosmcp --no-default-features -- --help >/dev/null
    cargo run -p rust-junosmcp --no-default-features --features tls -- --help >/dev/null
```

CI format/clippy package lists contain only surviving packages, including `rust-junosmcp-srx-core`. Add a feature-matrix step:

```yaml
- name: Junos-only feature builds
  working-directory: RustJunosMCP
  run: |
    cargo build -p rust-junosmcp --no-default-features --locked
    cargo build -p rust-junosmcp --no-default-features --features tls --locked
    cargo test -p rust-junosmcp --no-default-features --bin rust-junosmcp --locked
```

Keep workspace build/tests and packaging jobs. Update release workflow comments so version tags build the one default-feature image; remove obsolete SRX tag commentary.

- [ ] **Step 7: Run current-reference gates**

Run:

```bash
rg -n --glob 'Cargo.toml' --glob '*.rs' --glob 'justfile' \
    'rust-srxmcp|rust_srxmcp|rust-junosmcp-limits|rust_junosmcp_limits' .
rg -n 'name = "rust-srxmcp"|name = "rust-srxmcp-core"|name = "rust-junosmcp-limits"' Cargo.lock
rg -n --glob '!target/**' --glob '!docs/superpowers/**' --glob '!docs/archive/**' \
    --glob '!CHANGELOG.md' 'rust-srxmcp|rust_srxmcp|30032|JMCP_SRX_' .
```

Expected: the first and second commands have no active code/build or lockfile
matches. The third has only deliberate 0.8 migration/deprecation explanation
where that text lives outside the changelog; every such match is current and
accurate.

- [ ] **Step 8: Run doc/build wiring checks**

Run:

```bash
cargo fmt --all --check
cargo metadata --no-deps --format-version 1
cargo run -p rust-junosmcp -- --help
cargo run -p rust-junosmcp --no-default-features -- --help
cargo run -p rust-junosmcp --no-default-features --features tls -- --help
shellcheck scripts/package-lxc.sh scripts/test-lxc-distributions.sh packaging/lxc/install.sh packaging/tests/*.sh packaging/tests/fixtures/scp-server/entrypoint.sh
```

Expected: commands pass and help contains no removed binary/port.

- [ ] **Step 9: Commit docs and CI**

```bash
git add README.md CHANGELOG.md AGENTS.md TODO.md docs justfile .github rust-junosmcp-audit rust-junosmcp-core rust-junosmcp-srx-core packaging/logrotate
git commit -m "docs(#163): document unified Junos and SRX server"
```

---

### Task 9: Run the full requirement and release verification

**Files:**
- Inspect: all changed files and generated artifacts
- Modify only if a verification failure exposes a real defect

**Interfaces:**
- Produces: evidence for every #163 requirement before publication.

- [ ] **Step 1: Verify clean structure and exact workspace packages**

Run:

```bash
git status --short
cargo metadata --no-deps --format-version 1
test ! -e rust-srxmcp
test ! -e rust-srxmcp-core
test ! -e rust-junosmcp-limits
test ! -e packaging/systemd/rust-srxmcp.service
```

Expected: clean worktree; metadata lists exactly the five surviving 0.8.0 packages.

- [ ] **Step 2: Verify schema, surface, and feature matrices**

Run:

```bash
cargo test -p rust-junosmcp --bin rust-junosmcp junos_schemas_match_pre_merge_baseline --locked
cargo test -p rust-junosmcp --bin rust-junosmcp srx_schemas_match_pre_merge_baseline --locked
cargo test -p rust-junosmcp --test stdio_smoke lists_expected_tools --locked
cargo test -p rust-junosmcp --no-default-features --bin rust-junosmcp --locked
cargo build -p rust-junosmcp --no-default-features --locked
cargo build -p rust-junosmcp --no-default-features --features tls --locked
```

Expected: default surface is the exact 26-tool union and both schema fixtures match; no-SRX surface is exactly 17.

- [ ] **Step 3: Run the required offline project checks**

If `just` is available:

```bash
just fmt
just lint
just test
just guard
just e2e
```

If `just` is unavailable, run the exact recipes:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo run -p rust-junosmcp -- --help >/dev/null
cargo run -p rust-junosmcp --no-default-features -- --help >/dev/null
cargo run -p rust-junosmcp --no-default-features --features tls -- --help >/dev/null
```

Expected: all pass.

- [ ] **Step 4: Run security and release checks**

If installed:

```bash
just security
just release-check
cargo audit
cargo deny check bans sources
```

If `just` is unavailable, substitute:

```bash
trivy fs --scanners vuln,misconfig,secret --exit-code 1 .
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

Expected: all available checks pass. Report unavailable workstation tools explicitly rather than claiming their checks ran.

- [ ] **Step 5: Run package and container verification from a fresh archive**

Run:

```bash
rm -rf dist
shellcheck scripts/package-lxc.sh scripts/test-lxc-distributions.sh packaging/lxc/install.sh packaging/tests/*.sh packaging/tests/fixtures/scp-server/entrypoint.sh
./scripts/package-lxc.sh
./packaging/tests/package-smoke.sh dist/rust-junosmcp_*_amd64.tar.gz
./scripts/test-lxc-distributions.sh dist/rust-junosmcp_*_amd64.tar.gz
./packaging/tests/container-scp-smoke.sh
```

Expected: one service/binary, successful combined endpoint smoke, preserved state, and no stale artifacts.

- [ ] **Step 6: Audit every issue requirement against authoritative evidence**

Build a handoff matrix with these rows and evidence:

```text
one binary/process/listener/service
26-tool default union
17-tool Junos-only opt-out
pre-merge schema equality
confirmation store and shared device lease
renamed SRX core
limits folded into core
auth/audit boundaries retained
canonical/legacy environment precedence and warnings
legacy port ignored
version 0.8.0
package upgrade cleanup and state preservation
SRX unit/HTTP/TLS/audit/limit/metrics/live test migration
README/CHANGELOG/AGENTS/MCP registration updates
required checks and explicitly skipped real-device checks
```

For each row, cite a file/test/command result. Treat missing evidence as unfinished work.

- [ ] **Step 7: Review the full diff for unintended behavior changes**

Run:

```bash
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git log --oneline --decorate origin/main..HEAD
git status --short --branch
```

Inspect every deletion and rename, especially tool method diffs and installer cleanup. Confirm fixture JSON was generated before the merge and never hand-edited.

- [ ] **Step 8: Commit verification fixes, if any**

If verification required edits:

```bash
git status --short
git add -A
git diff --cached --check
git commit -m "fix(#163): address final verification findings"
```

Then rerun the failed command and the nearest broader gate. If no edits were needed, do not create an empty commit.

- [ ] **Step 9: Hand off to review and publication workflows**

Use `superpowers:requesting-code-review`, then `github:yeet` to push and open the PR. After review, use `github:gh-fix-ci` to inspect all GitHub Actions checks and logs. When required checks are green, use `superpowers:finishing-a-development-branch` to squash-merge and clean the remote branch/worktree. Finally verify the merged main branch and closed issue before marking the goal complete.
