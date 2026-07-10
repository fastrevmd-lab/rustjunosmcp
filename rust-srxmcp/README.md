# rust-srxmcp

MCP server for Juniper **SRX-specific** operational workflows. Sibling to
`rust-junosmcp` — shares the same workspace, auth crate, inventory format,
and SSH/NETCONF plumbing, but runs as an independent binary on a separate
port so the generic Junos MCP service is unaffected.

## Status (v0.3.x)

The server exposes nine SRX-specific tools covering status, chassis-cluster
health, VPN lifecycle, licensing, security services, signature-package
lifecycle, and JTAC support-bundle collection.

## Tools

| Tool | Purpose |
|---|---|
| `srxmcp_status` | Diagnostic — server version, endpoint, uptime |
| `get_chassis_cluster_status` | Chassis-cluster topology + RG health (returns `not_configured` for standalone SRX) |
| `check_srx_feature_license` | Closed-enum feature → license-record mapping (IDP, AppID, UTM-AV, Web Filtering, Anti-Spam, SecIntel, ATP Cloud, SSL Proxy) |
| `get_srx_security_services_status` | IDP / AppID / UTM-AV / SecIntel / ATP-Cloud per-node health snapshot |
| `vpn_lifecycle_report` | Correlated IKE Phase-1 + IPsec Phase-2 view with optional `peer` / `tunnel` substring filters |
| `manage_idp_security_package` | **DESTRUCTIVE** — IDP signature-package lifecycle. Actions: `check_server`, `download_and_install`, `rollback`. Token-bound two-call confirmation. |
| `manage_appid_signature_package` | **DESTRUCTIVE** — AppID application signature-package lifecycle. Actions: `check_server`, `download_and_install`, `uninstall`. Token-bound two-call confirmation. |
| `validate_chassis_cluster_health` | Runs the full chassis-cluster diagnostic set and returns ordered findings with a rolled-up verdict. |
| `collect_jtac_support_bundle` | Collects and redacts a JTAC-ready diagnostic bundle. |

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
    --host 127.0.0.1 \
    --tokens-file /etc/jmcp/tokens.json \
    --device-mapping /etc/jmcp/devices.json
```

The secure default bind is **127.0.0.1:30032** (overridable with `--host`,
`--port`, `JMCP_SRX_HTTP_HOST`, and `JMCP_SRX_HTTP_PORT`). The companion
`rust-junosmcp` defaults to port 30030.

The two binaries share `/etc/jmcp/tokens.json` and `/etc/jmcp/devices.json`
but have independent systemd units and independent process lifecycles.

Both binaries must also use the same device lease directory (default
`/var/lib/jmcp/device-leases`). Kernel-backed file locks serialize Junos
upgrades with destructive IDP/AppID package operations for the same inventory
router. A process crash closes its file descriptor and releases the lease;
waiters return `device_lease_busy` after 30 seconds instead of waiting forever.
Lock files are persistent metadata records and must not be manually deleted
while either service is running.

## Destructive confirmations

IDP and AppID package changes require a fresh preview. Call the destructive
action with `confirm=false`; the `confirmation_required` plan includes a
short-lived `confirmation_token`, expiry, and correlation ID. Review that
exact plan, then repeat the same action, router, and target with `confirm=true`
and `confirmation_token` set to the returned value.

Tokens are one-time and bound to the authenticated token name, inventory
endpoint, router, action, target, and observed device plan. Missing, expired,
replayed, wrong-caller, and changed-plan confirmations fail closed. A server
restart intentionally invalidates every outstanding confirmation.

Packaged support bundles default to
`/var/lib/jmcp/srx-staging/bundles`, which is owned by the `jmcp` service user
and included in the systemd unit's writable state path. Override it with
`JMCP_SRX_STAGING_DIR` when running outside the packaged service.

## Endpoint

For a local plaintext deployment, the endpoint is
`http://127.0.0.1:30032/mcp`. Bearer-token authentication remains required.

### Remote TLS deployment

Non-loopback binds require TLS by default:

```bash
rust-srxmcp \
    --host 0.0.0.0 \
    --tokens-file /etc/jmcp/tokens.json \
    --device-mapping /etc/jmcp/devices.json \
    --tls-cert /etc/jmcp/tls/server.crt \
    --tls-key /etc/jmcp/tls/server.key \
    --allowed-host srxmcp.example.internal
```

The endpoint is then `https://srxmcp.example.internal:30032/mcp`.

`--allow-insecure-bind` permits authenticated plaintext HTTP on a non-loopback
address. Use it only when a trusted reverse proxy or service mesh provides
transport security. `--allow-no-auth` is always restricted to a loopback bind;
TLS and `--allow-insecure-bind` do not override that restriction.

Host-header validation is independent of TLS and bearer authentication.
Off-loopback clients must send an authority listed with `--allowed-host`
(repeatable). `--disable-host-check` disables this DNS-rebinding defense and is
not recommended.

## Hot reload

```bash
systemctl kill -s HUP rust-srxmcp.service
```

Re-reads `tokens.json` and `devices.json` atomically (`ArcSwap`); no
in-flight requests are dropped.

## Relationship to `rust-junosmcp`

| | `rust-junosmcp` | `rust-srxmcp` |
|---|---|---|
| Crate version | `0.7.x` | `0.3.x` |
| Default port | 30030 | 30032 |
| Tool surface | 17 generic Junos tools | 9 SRX-specific tools |
| Auth | shared `rust-junosmcp-auth` crate | shared `rust-junosmcp-auth` crate |
| Inventory | shared `devices.json` | shared `devices.json` |

See the top-level `README.md` for the overall project description.
