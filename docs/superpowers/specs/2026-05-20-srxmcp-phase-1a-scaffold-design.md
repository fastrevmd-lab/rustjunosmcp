# Phase 1A — `rust-srxmcp` workspace scaffolding + `srxmcp_status` endpoint

**Date:** 2026-05-20
**Type:** Feature — first release of the opt-in SRX MCP binary
**Target release:** `rust-srxmcp` `0.0.1` (tag `srxmcp-v0.0.1`)
**Tracks:** strategy doc `2026-05-20-srx-mcp-strategy-design.md` (Phase 1, split into A scaffold + B real tools)

## Goal

Stand up an opt-in second MCP endpoint binary on LXC 601 alongside the
live `rust-junosmcp:30031`. `0.0.1` ships **one trivial diagnostic tool**
(`srxmcp_status`) — enough to verify:

- The new binary builds under `cargo build -p rust-srxmcp`.
- Workspace `default-members` correctly excludes SRX crates so
  `cargo build` (no args) is unchanged for generic users.
- The new systemd unit binds `:30032`, bearer auth works, SIGHUP reloads
  cleanly, and the rmcp tool registry wires up end-to-end.

**No real SRX workflow tools.** Those land in Phase 1B as
`srxmcp-v0.1.0` (separate spec).

## Non-goals

- The 4 read-only workflow tools (`check_srx_feature_license`,
  `get_srx_security_services_status`, `get_chassis_cluster_status`,
  `vpn_lifecycle_report`) — Phase 1B.
- Parsers (`parsers/*.rs`), the `polling.rs` abstraction, NETCONF use
  from the SRX binary.
- Per-endpoint bearer-token scoping (shared `/etc/jmcp/tokens.json`).
- Cross-process session-pool sharing.
- Release automation / CI artifact uploads — manual scp+pct push for
  this PR.
- Republishing `rust-junosmcp-core` outside the workspace.
- Extracting a third `mcp-shared` crate. (Strategy doc defers this.)

## Architecture

### Workspace layout

```text
RustJunosMCP/
├── Cargo.toml                 # workspace; default-members excludes SRX crates
├── rust-junosmcp/             # existing generic binary; main.rs switches to helpers
├── rust-junosmcp-core/        # existing shared lib + NEW pub fn bootstrap helpers
├── rust-junosmcp-auth/        # existing, unchanged
├── rust-srxmcp/               # NEW — opt-in binary
│   ├── Cargo.toml
│   └── src/main.rs            # bootstrap orchestrator (calls core helpers)
└── rust-srxmcp-core/          # NEW — opt-in lib (stub for now)
    ├── Cargo.toml
    └── src/lib.rs             # empty; placeholder for Phase 1B workflows/parsers
```

### Workspace `Cargo.toml`

```toml
[workspace]
members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
    "rust-srxmcp",
    "rust-srxmcp-core",
]
default-members = [
    "rust-junosmcp",
    "rust-junosmcp-core",
    "rust-junosmcp-auth",
]
resolver = "2"

[workspace.package]
# version field intentionally dropped — per-crate versioning (see Versioning).
edition    = "2021"
license    = "MIT OR Apache-2.0"
repository = "https://github.com/fastrevmd-lab/RustJunosMCP"
authors    = ["fastrevmd-lab"]

[workspace.dependencies]
# Unchanged from v0.6.2.
```

Generic `cargo build` / `cargo test` (no args) honor `default-members`
and stay byte-for-byte equivalent to today. SRX operators run
`cargo build --workspace` or `cargo build -p rust-srxmcp`.

### Versioning

Drop shared `workspace.package.version`. Each crate's own
`[package]` block declares `version = "..."`:

| Crate | Version |
|---|---|
| `rust-junosmcp` | `0.6.2` |
| `rust-junosmcp-core` | `0.6.2` |
| `rust-junosmcp-auth` | `0.6.2` |
| `rust-srxmcp` | `0.0.1` |
| `rust-srxmcp-core` | `0.0.1` |

The three existing crates keep their current version unchanged. SRX
crates start at `0.0.1`. Future bumps are independent per binary.

### Mid-ground bootstrap extraction

New `pub fn`s land in `rust-junosmcp-core` (likely under a new
`bootstrap` submodule, e.g. `rust-junosmcp-core/src/bootstrap/mod.rs`):

```rust
pub fn build_auth_layer(tokens_path: &Path) -> Result<AuthLayer, JmcpError>;
pub fn build_audit_logger(audit_path: &Path) -> Result<AuditLogger, JmcpError>;
pub fn load_inventory_and_blocklist(
    devices_path: &Path,
    blocklist_path: Option<&Path>,
) -> Result<(Inventory, Blocklist), JmcpError>;
pub fn install_sighup_handler<F>(reload_fn: F) -> tokio::task::JoinHandle<()>
where
    F: Fn() + Send + Sync + 'static;
```

The body of each helper is a **byte-for-byte extraction** of the
existing inline code from `rust-junosmcp/src/main.rs`. No behavior
change; only call-site relocation. The diff in `rust-junosmcp/src/main.rs`
is mechanical: inline block deleted, single helper call inserted.

The bind+serve loop (axum `serve()` against the listener) stays in each
binary's own `main.rs` because:

- Port env var differs (`JMCP_HTTP_PORT` vs `JMCP_SRX_HTTP_PORT`).
- Tool registry differs (rmcp's `#[tool]` registry is per-binary).
- TLS config (if/when added) may differ between endpoints.

### `srxmcp_status` tool

The only tool in `0.0.1`. Signature:

```rust
#[derive(serde::Deserialize, schemars::JsonSchema)]
struct SrxmcpStatusArgs {
    // no fields — diagnostic call, no router needed
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct SrxmcpStatusResponse {
    version: String,         // env!("CARGO_PKG_VERSION")
    endpoint: String,        // literal "srxmcp"
    uptime_seconds: u64,     // monotonic since process start
}
```

Implementation:

- Record `tokio::time::Instant` at process start, store in `Arc<Instant>`
  passed into the tool struct.
- Tool body: `Instant::now().duration_since(start).as_secs()`.
- No NETCONF, no SCP, no inventory dependency, no auth side effects
  beyond the standard bearer-token gate already applied by `AuthLayer`.

### Runtime configuration (LXC 601)

| Aspect | Value |
|---|---|
| Binary path | `/usr/local/bin/rust-srxmcp` |
| Systemd unit | `/etc/systemd/system/rust-srxmcp.service` (new file `systemd/rust-srxmcp.service` in repo) |
| Port | `30032` (default in code, override `JMCP_SRX_HTTP_PORT`) |
| Bind | `0.0.0.0` (LXC 601 already exposed; no Tailscale change) |
| User / group | `jmcp:jmcp` (same as generic) |
| Tokens file | shared `/etc/jmcp/tokens.json` |
| Devices file | shared `/etc/jmcp/devices.json` (not used by `srxmcp_status`) |
| Audit log | `/var/log/jmcp/srxmcp_audit.jsonl` (separate file from generic) |
| Service dependency | none (independent of `rust-junosmcp.service`) |
| SIGHUP | wired but no-op in `0.0.1` (no per-process state needs reloading yet) |

### Systemd unit (`systemd/rust-srxmcp.service`)

Mirrors the existing `rust-junosmcp.service` shape:

```ini
[Unit]
Description=Rust SRX MCP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=jmcp
Group=jmcp
Environment=JMCP_SRX_HTTP_PORT=30032
Environment=JMCP_TOKENS_PATH=/etc/jmcp/tokens.json
Environment=JMCP_DEVICES_PATH=/etc/jmcp/devices.json
Environment=JMCP_SRX_AUDIT_LOG=/var/log/jmcp/srxmcp_audit.jsonl
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/rust-srxmcp
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
```

The exact set of `Protect*=`/`Restrict*=` hardening directives copies
from the live `rust-junosmcp.service` so both binaries run under
identical confinement.

## Tag and release shape

- Branch: `feat/srxmcp-scaffold`
- PR title: `feat(srxmcp): workspace scaffolding + status endpoint (v0.0.1)`
- Annotated tag: `srxmcp-v0.0.1` at the merged commit.
- Existing un-prefixed generic tags (`v0.6.0` .. `v0.6.2`) stay as-is;
  future generic releases keep using `vMAJOR.MINOR.PATCH` (no
  `junosmcp-` prefix). The `srxmcp-` prefix is only on the new series.
- Changelog: **new file** `rust-srxmcp/CHANGELOG.md` recording the
  initial release. The existing top-level `CHANGELOG.md` continues to
  track the generic binary. No cross-referencing required.

## CI changes

- Existing `build-and-test` workflow's `cargo build` / `cargo test`
  steps stay default-members-only and are byte-for-byte unchanged.
- **New steps appended** to the same job:
  - `cargo build --workspace`
  - `cargo test --workspace`
- `cargo fmt -- --check` already runs across all members — unchanged.
- `cargo clippy --workspace --all-targets -- -D warnings` — already
  workspace-wide; new crates inherit.
- Release-artifact automation: **out of scope for this PR.** Manual
  scp+pct push remains the deploy path.

## LXC 601 deploy procedure (post-merge)

1. Build on host: `cargo build --release -p rust-srxmcp` →
   `target/release/rust-srxmcp` (~20 MB).
2. `scp target/release/rust-srxmcp root@pve3.mechub.org:/tmp/rust-srxmcp-0.0.1`.
3. `ssh root@pve3 pct push 601 /tmp/rust-srxmcp-0.0.1 /usr/local/bin/rust-srxmcp --perms 0755`.
4. `ssh root@pve3 pct push 601 systemd/rust-srxmcp.service /etc/systemd/system/rust-srxmcp.service --perms 0644`.
5. `ssh root@pve3 pct exec 601 -- systemctl daemon-reload`.
6. `ssh root@pve3 pct exec 601 -- systemctl enable --now rust-srxmcp.service`.
7. `ssh root@pve3 pct exec 601 -- systemctl is-active rust-srxmcp.service` → `active`.
8. `ssh root@pve3 pct exec 601 -- /usr/local/bin/rust-srxmcp --version` → `rust-srxmcp 0.0.1`.

## Smoke tests (LXC 601, post-deploy)

1. **Unauthenticated 401.** `curl -sS -o /dev/null -w '%{http_code}'
   http://192.168.1.194:30032/mcp` returns `401`. Body is the RFC 6749
   JSON `{"error":"invalid_token","error_description":"missing"}` shape
   shared with `rust-junosmcp` v0.5.10+.
2. **Authenticated handshake.** `curl -H "Authorization: Bearer
   <token-from-tokens.json>" -X POST ...` MCP initialize succeeds.
3. **Tool registry.** `tools/list` returns exactly one tool:
   `srxmcp_status`.
4. **Tool dispatch.** `tools/call srxmcp_status` returns JSON
   `{"version":"0.0.1","endpoint":"srxmcp","uptime_seconds":<small>}`.
5. **SIGHUP reload.** `systemctl kill -s HUP rust-srxmcp.service`
   leaves `systemctl is-active` at `active`; no `ERROR`-level lines in
   `journalctl -u rust-srxmcp.service --since="1 minute ago"`.
6. **Stop / start cycle.** `systemctl stop` then `start` → clean
   cycle; no `Address already in use` in journal.
7. **Generic regression.** `rust-junosmcp` at `:30031` still works —
   call `fetch_file` and `transfer_file` against `vSRX-test10` with the
   already-staged `smoke-v0.5.2.txt` (both should `status="skipped"`
   on sha match).

## Test plan (CI)

### Unit tests

- `rust-junosmcp-core/src/bootstrap/` — each new helper gets at least
  one test:
  - `build_auth_layer` with a fixture tokens file → returns a working
    `AuthLayer`.
  - `build_audit_logger` with a tempdir path → opens an appendable
    file, journal-cleanup-safe.
  - `load_inventory_and_blocklist` with a fixture devices.json →
    returns expected count of devices.
  - `install_sighup_handler` is exercised indirectly by the existing
    `rust-junosmcp` SIGHUP integration test if one exists; otherwise
    add a smoke test that drives a oneshot channel from the closure.
- `rust-srxmcp/src/main.rs`'s `srxmcp_status` tool — unit test that
  constructs the tool struct with a known `Instant`, calls the handler,
  asserts the response shape and that `uptime_seconds` is small.

### Integration / regression

- Existing `rust-junosmcp` test suite must pass unchanged after the
  bootstrap-helper extraction.
- New `rust-srxmcp` binary's `--version` flag prints `rust-srxmcp 0.0.1`.
- `cargo build --workspace` succeeds (CI gate).
- `cargo test --workspace` succeeds (CI gate).

## Risks and tradeoffs

| Risk | Mitigation |
|---|---|
| Touching `rust-junosmcp/src/main.rs` to switch to extracted helpers risks regression in the v0.6.2 production binary. | Helpers are pure extractions — the body of each helper is byte-for-byte the existing inline code. CI runs the full existing test suite + a fresh round of regression smoke against `:30031` after deploy. |
| Two binaries on LXC 601 contend for the same `jmcp` user / staging dir / audit dir. | `:30032` does not write to `/var/lib/jmcp/staging/` (no transfer/fetch tools in 0.0.1). Audit log is a separate file. Distinct ports. SIGHUP handlers are per-process. No shared state at runtime. |
| Tag-prefix split (`v0.6.2` generic, `srxmcp-v0.0.1` SRX) confuses someone scanning `git tag --list`. | README gets a short note. The two prefixes sort lexicographically — `srxmcp-*` clusters separately from `v*`. |
| Dropping `workspace.package.version` is a Cargo.toml-shape change that touches all 3 existing Cargo.toml files. | Mechanical edit — each crate gets `version = "0.6.2"` added to its `[package]`. Verified by `cargo build --workspace` before commit. |
| New port `30032` may conflict with something already bound inside LXC 601. | Pre-deploy check: `ss -tlnp \| grep 30032`. If occupied, surface the conflict before the systemd unit lands. |
| The opt-in `default-members` change subtly alters `cargo test` behavior in the workspace root for developers who don't pass `--workspace`. | Documented in `rust-srxmcp/README.md` (new short file): "to test the full workspace, use `cargo test --workspace`". |

## Out-of-scope follow-ups (Phase 1B and later)

- The 4 read-only SRX workflow tools (`srxmcp-v0.1.0`).
- The `polling.rs` and `precheck.rs` modules in `rust-srxmcp-core`.
- IDP / AppID lifecycle (Phase 2 — `srxmcp-v0.2.0`).
- Cluster health + support bundle (Phase 3 — `srxmcp-v0.3.0`).
- Flow trace with commit-confirm (Phase 4 — `srxmcp-v0.4.0`).
- Chassis cluster upgrade (Phase 5 — `srxmcp-v0.5.0`).
- Release-artifact automation (separate concern, multi-phase).
- Per-endpoint bearer token scoping.

## Success criteria

- `cargo build` and `cargo test` (no args) in the workspace root remain
  byte-for-byte identical to today's output (modulo per-crate version
  field migration).
- `cargo build --workspace` succeeds; `cargo test --workspace` runs
  the existing tests plus the new bootstrap-helper + `srxmcp_status`
  tests, all green.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo fmt -- --check` clean.
- LXC 601 hosts both `rust-junosmcp.service` (`:30031`) and
  `rust-srxmcp.service` (`:30032`) concurrently, both `active` and
  both passing their respective smoke tests.
- `srxmcp-v0.0.1` annotated tag pushed.
- Generic regression smoke against `:30031` unchanged after deploy.
