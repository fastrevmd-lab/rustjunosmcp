# rust-srxmcp

MCP server for Juniper **SRX-specific** operational workflows. Sibling to
`rust-junosmcp` — shares the same workspace, auth crate, inventory format,
and SSH/NETCONF plumbing, but runs as an independent binary on a separate
port so the generic Junos MCP service is unaffected.

## Phase 1A status (v0.0.1)

This release is **scaffolding only**. It exists to prove that the second
binary builds, deploys, and serves MCP over streamable-HTTP with the same
bearer-token auth and SIGHUP hot-reload behaviour as `rust-junosmcp`.

Tool surface: exactly one diagnostic tool — `srxmcp_status` — which returns
the binary version, uptime, and the caller's authenticated scope.

Real SRX workflows (security policy, NAT, IDP, chassis cluster, etc.) land
in Phase 1B as `srxmcp-v0.1.0`.

## Build

The SRX crates are **opt-in** — they are workspace members but not default
members, so plain `cargo build` / `cargo test` at the workspace root behave
exactly as they did before Phase 1A. To exercise the SRX binary:

```bash
cargo build -p rust-srxmcp
cargo test  -p rust-srxmcp
cargo run   -p rust-srxmcp -- --help
```

## Run

```bash
rust-srxmcp \
    --tokens-file /etc/jmcp/tokens.json \
    --device-mapping /etc/jmcp/devices.json
```

Default HTTP port: **30032** (overridable with `--port` /
`JMCP_SRX_HTTP_PORT`). The companion `rust-junosmcp` listens on 30031.

The two binaries share `/etc/jmcp/tokens.json` and `/etc/jmcp/devices.json`
but have independent systemd units and independent process lifecycles.

## Endpoint

```
http://<host>:30032/mcp
```

Streamable-HTTP MCP, bearer-token auth (RFC 6750), `Authorization: Bearer
<token>` required on every call.

## Hot reload

```bash
systemctl kill -s HUP rust-srxmcp.service
```

Re-reads `tokens.json` and `devices.json` atomically (`ArcSwap`); no
in-flight requests are dropped.

## Relationship to `rust-junosmcp`

| | `rust-junosmcp` | `rust-srxmcp` |
|---|---|---|
| Crate version | `0.6.x` | `0.0.x` |
| Default port | 30031 | 30032 |
| Tool surface | 15 generic Junos tools | 1 status tool (Phase 1A) |
| Auth | shared `rust-junosmcp-auth` crate | shared `rust-junosmcp-auth` crate |
| Inventory | shared `devices.json` | shared `devices.json` |

See the top-level `README.md` for the overall project description.
