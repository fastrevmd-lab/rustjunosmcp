# rust-srxmcp

MCP server for Juniper **SRX-specific** operational workflows. Sibling to
`rust-junosmcp` — shares the same workspace, auth crate, inventory format,
and SSH/NETCONF plumbing, but runs as an independent binary on a separate
port so the generic Junos MCP service is unaffected.

## Status (v0.1.0)

Phase 1B + Phase 2 — read-only SRX status tools plus destructive
signature-package lifecycle tools. Tool surface is 8: one diagnostic, four
typed read-only workflows backed by NETCONF RPCs (`SrxToolResponse<T>`
envelopes with `state=active` / `state=not_configured`), and two
destructive lifecycle tools that use a two-call confirmation protocol
with per-router transfer locks.

## Tools

| Tool | Purpose |
|---|---|
| `srxmcp_status` | Diagnostic — server version, endpoint, uptime |
| `get_chassis_cluster_status` | Chassis-cluster topology + RG health (returns `not_configured` for standalone SRX) |
| `check_srx_feature_license` | Closed-enum feature → license-record mapping (IDP, AppID, UTM-AV, Web Filtering, Anti-Spam, SecIntel, ATP Cloud, SSL Proxy) |
| `get_srx_security_services_status` | IDP / AppID / UTM-AV / SecIntel / ATP-Cloud per-node health snapshot |
| `vpn_lifecycle_report` | Correlated IKE Phase-1 + IPsec Phase-2 view with optional `peer` / `tunnel` substring filters |
| `manage_idp_security_package` | **DESTRUCTIVE** — IDP signature-package lifecycle. Actions: `check_server`, `download_and_install`, `rollback`. Two-call confirmation. |
| `manage_appid_signature_package` | **DESTRUCTIVE** — AppID application signature-package lifecycle. Actions: `check_server`, `download_and_install`, `uninstall`. Two-call confirmation. |

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
| Crate version | `0.6.x` | `0.1.x` |
| Default port | 30031 | 30032 |
| Tool surface | 15 generic Junos tools | 5 SRX-specific tools |
| Auth | shared `rust-junosmcp-auth` crate | shared `rust-junosmcp-auth` crate |
| Inventory | shared `devices.json` | shared `devices.json` |

See the top-level `README.md` for the overall project description.
