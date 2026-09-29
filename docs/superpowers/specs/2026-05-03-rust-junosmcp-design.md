# Rust JunosMCP — Design Spec

**Date:** 2026-05-03
**Status:** Approved (brainstorm complete, awaiting implementation plan)
**Scope:** v0.1 of a 1:1 Rust port of [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server), built on [rustEZ](https://github.com/mechubsec/rustez) and [rustnetconf](https://github.com/mechubsec/rustnetconf) instead of PyEZ/ncclient.

---

## 1. Goal

Provide a Model Context Protocol (MCP) server that lets MCP-compatible LLM clients (Claude Desktop, VSCode + Copilot, etc.) operate Juniper Junos network devices, with the same tool surface as the Python reference implementation but with the performance, type-safety, and async concurrency of Rust.

**Non-goals (this project):**

- Multi-vendor support — Junos only, matching rustEZ.
- Reimplementing rustEZ features here. If a needed Junos primitive is missing from rustEZ, we file an upstream issue rather than working around it locally.
- v0.1 does not include the Python repo's HTTP transport, auth tokens, blocklists, Jinja2 templates, batch/PFE commands, or interactive `add_device`/`reload_devices`. These are scoped to v0.2.

---

## 2. Reference

The port targets [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server) (Python, Apache-2.0). Tool names, input JSON schemas, and `devices.json` format are reproduced verbatim so an existing Python deployment can switch binaries with no inventory or client-config changes.

---

## 3. Stack decisions

| Concern | Choice | Rationale |
|---|---|---|
| MCP SDK | `rmcp` (official Anthropic Rust SDK) | Maintained, supports stdio + streamable-http, closest analogue to the Python repo's MCP usage. |
| Junos client | `rustez` 0.8.x | The whole point of this project. Provides `Device`, `Facts`, `ConfigManager`, `RpcExecutor`, `cli()`. |
| NETCONF transport | `rustnetconf` 0.8.x (transitive via rustEZ) | Pure-Rust SSH (russh + aws-lc-rs), no OpenSSL/libssh2. |
| Async runtime | `tokio` 1.x | rustEZ + rmcp both build on it. |
| CLI parsing | `clap` 4.x | Standard. |
| Logging | `tracing` + `tracing-subscriber` to stderr | Stdout reserved for MCP framing on stdio transport. |
| Errors | `thiserror` 2.x | Matches rustEZ. |
| Serde | `serde` + `serde_json` | Tool args/results, `devices.json`. |
| License | MIT OR Apache-2.0 | Matches rustEZ/rustnetconf, compatible with the upstream Python project. |

---

## 4. v0.1 / v0.2 split

**v0.1 ships:**

- 6 MCP tools: `get_router_list`, `gather_device_facts`, `execute_junos_command`, `get_junos_config`, `junos_config_diff`, `load_and_commit_config`.
- stdio transport only.
- `devices.json` drop-in compatible with the Python repo (`auth.type` ∈ {`password`, `ssh_key`}; `ssh_config` field parsed but not yet honored — clean error if used).
- Dockerfile (distroless runtime).
- LXC release tarball + systemd unit (unit ships in v0.1 but is documented as primarily useful once v0.2's HTTP transport lands).
- Minimal CI (build + test on Linux x86_64).

**v0.2 fills in (not in this spec, separate spec at v0.2 brainstorm):**

- `execute_junos_pfe_command`, `execute_junos_command_batch`, `render_and_apply_j2_template` (using `minijinja` for Jinja2 fidelity), `add_device` (rmcp elicitation), `reload_devices`.
- streamable-http transport.
- Bearer-token auth, `.tokens` file format compatible with the Python repo.
- `block.cfg` / `block.cmd` guardrail blocklists.
- Optional `rust-junosmcp-token-manager` binary crate.
- ssh_config / jumphost handling.

---

## 5. Workspace layout

```
RustJunosMCP/
├── Cargo.toml                        # workspace
├── README.md
├── LICENSE-MIT, LICENSE-APACHE
├── devices-template.json             # 1:1 with Python repo
├── Dockerfile
├── scripts/package-lxc.sh
├── packaging/
│   ├── systemd/rust-junosmcp.service
│   └── lxc/install.sh
├── docs/superpowers/specs/           # this spec lives here
├── rust-junosmcp-core/               # pure logic, no MCP, no transport
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── error.rs                  # JmcpError enum (thiserror)
│   │   ├── inventory.rs              # devices.json parser + Inventory
│   │   ├── device_manager.rs         # connect rustez::Device per call
│   │   └── tools/
│   │       ├── mod.rs
│   │       ├── execute_command.rs    # execute_junos_command
│   │       ├── get_config.rs         # get_junos_config
│   │       ├── config_diff.rs        # junos_config_diff
│   │       ├── load_commit.rs        # load_and_commit_config
│   │       ├── facts.rs              # gather_device_facts
│   │       └── router_list.rs        # get_router_list
│   └── tests/                        # #[ignore]'d real-device integration tests
└── rust-junosmcp/                    # binary: rmcp wiring + CLI
    ├── Cargo.toml
    └── src/
        ├── main.rs                   # arg parsing, transport selection
        ├── server.rs                 # rmcp Server, tool registration, dispatch
        └── cli.rs                    # clap args
```

The workspace mirrors the rustEZ / rustnetconf style. v0.2 may add `rust-junosmcp-token-manager/` and a guardrails crate.

---

## 6. Inventory & devices.json

Drop-in compatible with the Python repo. Parsed once at startup, validated, held as `Arc<Inventory>`.

```rust
// rust-junosmcp-core/src/inventory.rs
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceEntry {
    pub ip: String,
    #[serde(default = "default_port")]
    pub port: u16,                          // 22
    pub username: String,
    pub auth: AuthConfig,
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,        // jumphost / proxy file (v0.2)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    Password { password: String },
    SshKey   { private_key_path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct Inventory {
    devices: HashMap<String, DeviceEntry>,
    source_path: PathBuf,
}

impl Inventory {
    pub fn load(path: &Path) -> Result<Self, JmcpError> { /* parse + validate */ }
    pub fn get(&self, name: &str) -> Result<&DeviceEntry, JmcpError> { /* unknown router error */ }
    pub fn names(&self) -> Vec<&str> { /* → get_router_list */ }
}
```

**Validation at load time** (matches Python `validate_all_devices`): required fields present, `auth.type` is one of the two variants, `port` non-zero, `private_key_path` exists on disk if `ssh_key`. Failure exits the process with a clear error before the MCP server starts.

**`ssh_config` jumphost handling in v0.1:** the field is parsed and stored, but if it's set on a router used by a tool call we return `JmcpError::SshConfigUnsupported(router)`. v0.2 implements actual support.

**Mutation:** `Inventory` is read-only in v0.1 — `add_device` and `reload_devices` are v0.2 concerns and will introduce interior mutability (`Arc<RwLock<…>>`) at that point.

**Secret hygiene:** hand-written `Display`/`Debug` for `AuthConfig::Password` redact the password. We never include a `DeviceEntry` in error text.

---

## 7. Device connection management

```rust
// rust-junosmcp-core/src/device_manager.rs
pub struct DeviceManager {
    inventory: Arc<Inventory>,
}

impl DeviceManager {
    pub fn new(inventory: Arc<Inventory>) -> Self { /* … */ }

    /// Open a fresh rustez::Device for this router. Caller closes it.
    pub async fn open(&self, router_name: &str) -> Result<Device, JmcpError> {
        let entry = self.inventory.get(router_name)?;
        let mut builder = Device::connect(&entry.ip)
            .port(entry.port)
            .username(&entry.username);
        builder = match &entry.auth {
            AuthConfig::Password { password } => builder.password(password),
            AuthConfig::SshKey { private_key_path } =>
                builder.private_key_file(private_key_path),
        };
        if entry.ssh_config.is_some() {
            return Err(JmcpError::SshConfigUnsupported(router_name.into()));
        }
        builder.open().await.map_err(JmcpError::from)
    }
}
```

**Connection strategy: open-per-call.** Every tool invocation opens a fresh `Device`, runs the operation, calls `dev.close().await`. Rationale:

- Matches Python/PyEZ behavior.
- Avoids stale-session timeouts.
- Sidesteps vSRX/branch-SRX 3-session-per-device limit during interleaved tool calls.
- rustEZ connect time is sub-second on fast links.

**Pooling is upstream.** A `DevicePool` with per-platform session limits is on rustEZ's v0.3 roadmap (see [rustEZ README §Roadmap](https://github.com/mechubsec/rustez#roadmap)). When published, this project consumes it. Pool logic does not live here.

**Concurrency:** every tool handler is `async fn`, takes `Arc<DeviceManager>` + `Arc<Inventory>` clones, no `&mut self`. rmcp dispatches concurrently; same-router contention surfaces as a clean rustEZ error to the LLM.

**Per-call timeout:** every tool with a `timeout` parameter wraps the rustEZ call in `tokio::time::timeout(...)`. Default 360 s (matches Python).

---

## 8. Tool surface (v0.1)

All tool names, input schemas, and output content shapes match the Python reference exactly.

| Tool | Input fields | Output | rustEZ call |
|---|---|---|---|
| `get_router_list` | `{}` | `[String]` | `Inventory::names()` — no device contact |
| `gather_device_facts` | `{router_name, timeout?=360}` | facts JSON object | `dev.facts().await` → `serde_json::to_value(facts)` |
| `execute_junos_command` | `{router_name, command, timeout?=360}` | text | `dev.cli(&command).await` |
| `get_junos_config` | `{router_name}` | text (full config) | `dev.cli("show configuration").await` |
| `junos_config_diff` | `{router_name, version?=1}` (clamp 1..=49) | text diff | `dev.cli(&format!("show \| compare rollback {version}")).await` |
| `load_and_commit_config` | `{router_name, config_text, config_format?="set"\|"text"\|"xml", commit_comment?}` | `{success, diff, error?}` JSON | `ConfigManager` lock → load → diff → commit (with comment) → unlock; rollback + unlock on commit failure |

**`load_and_commit_config` flow:**

```rust
let mut dev = manager.open(&router_name).await?;
let mut cfg = dev.config()?;
cfg.lock().await?;
let load_format = match config_format.as_deref() {
    Some("set") | None => LoadFormat::Set,
    Some("text")       => LoadFormat::Text,
    Some("xml")        => LoadFormat::Xml,
    Some(other)        => return Err(JmcpError::BadFormat(other.into())),
};
cfg.load(ConfigPayload::with_format(config_text, load_format)).await?;
let diff = cfg.diff().await?.unwrap_or_default();
let result = match cfg.commit_with_comment(&commit_comment).await {
    Ok(_)  => Ok(json!({ "success": true,  "diff": diff })),
    Err(e) => {
        cfg.rollback().await.ok();
        Ok(json!({ "success": false, "diff": diff, "error": e.to_string() }))
    }
};
cfg.unlock().await.ok();
result
```

The exact `ConfigPayload` constructor and `commit_with_comment` method are validated against rustEZ's current API during implementation. If a method is missing, file an upstream rustEZ issue rather than working around it.

**Output convention:** every tool handler returns `Result<serde_json::Value, JmcpError>`. The binary maps:
- `Ok(Value::String(s))` → MCP text content block with `s`.
- `Ok(value)` (object/array/etc.) → MCP text content block with `serde_json::to_string_pretty(&value)`.
- `Err(e)` → `CallToolResult { is_error: true, content: [text(e.to_string())] }`.

This matches the Python repo's content shaping (string outputs raw, structured outputs JSON-stringified).

**Tools deferred to v0.2 are absent from the v0.1 server** — not registered as "not implemented" stubs. The LLM should not see tools it can't call.

---

## 9. MCP server wiring (rmcp)

The binary is thin: parse args, load inventory, build the rmcp server with one handler per tool, run stdio transport.

```rust
// rust-junosmcp/src/main.rs
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let args        = Cli::parse();
    let inventory   = Arc::new(Inventory::load(&args.device_mapping)?);
    let dev_manager = Arc::new(DeviceManager::new(inventory.clone()));
    server::run_stdio(inventory, dev_manager).await
}
```

```rust
// rust-junosmcp/src/cli.rs
#[derive(clap::Parser)]
pub struct Cli {
    /// JSON file with device mapping (Juniper junos-mcp-server compatible).
    #[arg(short = 'f', long, default_value = "devices.json")]
    pub device_mapping: PathBuf,

    /// Transport. v0.1 supports only "stdio".
    #[arg(short = 't', long, default_value = "stdio")]
    pub transport: Transport,
}
```

`-H/--host`, `-p/--port` from the Python repo are accepted as flags but rejected with a clear error if `--transport=streamable-http` is passed in v0.1, so users don't think HTTP is silently working.

**Server handler dispatch (rmcp API names finalized at implementation):**

```rust
// rust-junosmcp/src/server.rs
pub async fn run_stdio(inv: Arc<Inventory>, dm: Arc<DeviceManager>) -> Result<()> {
    let handler = JmcpHandler { inv, dm };
    /* register the 6 tools with their schemas, then: */
    server.serve_stdio().await
}
```

Each tool handler:
1. Deserialize JSON args into the tool's typed struct.
2. Call `rust_junosmcp_core::tools::<tool>::handle(args, dm.clone(), inv.clone()).await`.
3. Convert `Result<serde_json::Value, JmcpError>` → `CallToolResult` per §8 conventions.

Logging defaults to `info` on stderr; `RUST_LOG` overrides.

---

## 10. Errors

Single `JmcpError` enum in `rust-junosmcp-core/src/error.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum JmcpError {
    #[error("router '{0}' not found in device mapping")]
    UnknownRouter(String),

    #[error("invalid devices.json: {0}")]
    InventoryInvalid(String),

    #[error("private key file not found: {0}")]
    KeyFileMissing(PathBuf),

    #[error("ssh_config jumphost is not yet supported in the Rust port (router '{0}')")]
    SshConfigUnsupported(String),

    #[error("invalid config_format '{0}' (expected set, text, or xml)")]
    BadFormat(String),

    #[error("rollback version {0} out of range (1..=49)")]
    BadRollbackVersion(i64),

    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error(transparent)]
    Rustez(#[from] rustez::RustEzError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
```

`Display` text is what reaches the LLM. No stack traces, no passwords, no full `DeviceEntry` ever rendered.

---

## 11. Testing

| Layer | What | Where | Gating |
|---|---|---|---|
| Unit | Inventory parsing & validation, version-range clamp, `config_format` mapping, error display, secret redaction | `rust-junosmcp-core/src/**` `#[cfg(test)]` | Always run. |
| Integration (real device) | One `#[ignore]`'d test per tool handler against a live Junos device | `rust-junosmcp-core/tests/` | `cargo test --ignored` with `JMCP_TEST_HOST`, `JMCP_TEST_USER`, `JMCP_TEST_PASS` env vars (mirrors rustEZ pattern). |
| Smoke | Spawn the binary with a fake `devices.json`, send MCP `initialize` + `tools/list` over stdin, assert the 6 tools are advertised | `rust-junosmcp/tests/stdio_smoke.rs` | Always run. No device needed. |

CI on GitHub Actions runs unit + smoke tests on push. Integration tests are manual / lab-bound.

---

## 12. Security checklist

- `cargo audit` runs in CI; results documented in README.
- No `unsafe` in this project's code (rustEZ/rustnetconf already pure-Rust modulo russh's aws-lc-rs).
- `clippy::all` + `clippy::pedantic` clean (with documented allows where needed).
- Password redaction enforced by `Display`/`Debug` impls on `AuthConfig::Password`.
- README inherits the security warnings from the Python repo (LLM access to network gear, prefer SSH keys, audit configs before allowing commit).
- Distroless Docker runtime, non-root user.
- Systemd unit hardened (`ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`, `ReadWritePaths=/var/lib/jmcp`).

---

## 13. Deployment

Two artifacts produced from one source tree.

### 13.1 Docker image

Multi-stage `Dockerfile`:

```dockerfile
FROM rust:1.83-slim AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --bin rust-junosmcp

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /src/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
ENV RUST_LOG=info
USER nonroot
ENTRYPOINT ["/usr/local/bin/rust-junosmcp", "-f", "/etc/jmcp/devices.json"]
```

Operator mounts `/etc/jmcp/devices.json` and any private-key files at `/etc/jmcp/keys/...`. Image target ~15-25 MB.

### 13.2 LXC release tarball (Proxmox-friendly)

`scripts/package-lxc.sh` produces:

```
rust-junosmcp_<ver>_amd64/
├── usr/local/bin/rust-junosmcp
├── etc/jmcp/devices.json.example
├── etc/systemd/system/rust-junosmcp.service
└── install.sh             # creates 'jmcp' user, copies files, enables service
```

Built against a stock unprivileged Debian 12 / Ubuntu 24.04 LXC template (Proxmox `pveam`). Target install:

```sh
pct exec 115 -- bash -c "tar xzf /tmp/rust-junosmcp_*.tar.gz -C / && /install.sh"
```

The systemd unit is shipped in v0.1 but is documented as primarily useful in v0.2 once streamable-http transport lands. For v0.1, practical usage on the LXC is either:
- `pct exec 115 -- rust-junosmcp -f /etc/jmcp/devices.json` invoked by the MCP client, or
- a wrapper that bridges stdio in/out of the container.

This is called out explicitly in the LXC README so users aren't surprised.

### 13.3 CI

A GitHub Actions workflow builds both artifacts on tag push (`v*.*.*`). Local builds documented in README so CI is not a hard dependency.

---

## 14. Followups

Tracked here so they don't pollute v0.1 implementation. Each becomes a separate ticket / brainstorm at the right time.

1. **rustEZ — DevicePool with per-platform session limits.** On rustEZ v0.3 roadmap; consume here when published. File-or-track upstream.
2. **rustEZ — confirm `commit_with_comment` API surface.** If absent in current rustEZ, file upstream issue or PR rather than working around in this repo.
3. **rust-junosmcp v0.2 brainstorm.** Scope: `execute_junos_pfe_command`, `execute_junos_command_batch`, `render_and_apply_j2_template` (`minijinja`), `add_device` (rmcp elicitation), `reload_devices`, streamable-http transport, bearer-token auth (`.tokens` Python-compatible), `block.cfg` / `block.cmd` guardrails, optional `rust-junosmcp-token-manager` binary.
4. **ssh_config jumphost support** (v0.2). Decide between parsing OpenSSH config ourselves vs. shelling out to `ssh -W` ProxyCommand.

---

## 15. Open questions

None at brainstorm sign-off. Any new questions surfaced during plan-writing or implementation are recorded as plan checkpoints, not by editing this spec.
