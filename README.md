# rust-junosmcp

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Juniper Junos
devices, written in Rust. Drop-in compatible with [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
on the inventory format and tool surface, but built on async Rust ([rustEZ](https://github.com/fastrevmd-lab/rustEZ) + [rustnetconf](https://github.com/fastrevmd-lab/rustnetconf))
instead of PyEZ.

## Performance

Benchmarked against [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
(Python/PyEZ) on the same vSRX lab devices, same network path.

| Test | rust-junosmcp (v0.3.0) | junos-mcp (Python) | Speedup |
|------|------------------------|--------------------|---------| 
| 5 sequential commands | 30.4s (6.1s/cmd) | 52.2s (10.4s/cmd) | **1.7x** |
| 5 parallel commands | 8.1s (1.6s/cmd) | 11.1s (2.2s/cmd) | **1.4x** |
| 4 routers x 3 commands (batch) | 16.1s (1.3s/cmd) | N/A | Rust-only |

Session pooling (`PooledDevice`) eliminates SSH/NETCONF handshake overhead
on sequential commands to the same router. The batch tool runs routers in
parallel with a configurable concurrency cap.

> ## v0.3.0 released
>
> Session pooling, reliability fixes, and commit confirm. NETCONF sessions
> are now pooled per-router with a `PooledDevice` RAII guard (300s idle
> timeout, 30s SSH keepalive, background reaper). Five bug fixes: XML
> wrapper stripping for `get_junos_config` / `junos_config_diff`, correct
> `show configuration | compare rollback` command, timeout now covers SSH
> handshake, batch returns partial results for unknown routers. New
> `confirm_timeout_mins` parameter on `load_and_commit_config` for
> confirmed commits with auto-rollback. Switched `rustez` dependency from
> path to crates.io 0.10.1.
>
> See the [v0.3.0 release notes](https://github.com/fastrevmd-lab/RustJunosMCP/releases/tag/v0.3.0).

## Feature scope

### v0.1 (released)

- 6 tools: `get_router_list`, `gather_device_facts`, `execute_junos_command`,
  `get_junos_config`, `junos_config_diff`, `load_and_commit_config`.
- stdio transport only.
- `devices.json` drop-in compatible (`auth.type` ∈ {`password`, `ssh_key`}).
- Docker image (distroless) and LXC release tarball with systemd unit.

### v0.2 (released)

- streamable-http transport (with optional rustls TLS).
- bearer-token auth with per-token router/tool scopes.
- SIGHUP hot-reload of the token store.

### v0.2 follow-up: PFE + batch (released)

- `execute_junos_pfe_command` — single PFE-shell call against an explicit FPC target.
- `execute_junos_command_batch` — N routers x M operational CLI commands, parallel across routers, per-command and optional whole-batch timeouts. Pre-flight blocklist + unknown-router checks; continue-on-error after pre-flight.
- New `pfe_commands` rule list under `_blocklist_defaults` and per-device `blocklist`. Independent from `commands`.

### v0.2 follow-up: Templates (released)

- `render_and_apply_j2_template` — render a Jinja2 template (inline `template_content`) with JSON or YAML `vars_content`. Supports single (`router_name`) or multiple routers (`router_names`), dry-run, and full commit. Reuses the same blocklist + format gating as `load_and_commit_config`.
- Vars sniff: first non-whitespace `{` → JSON, otherwise YAML. Both must produce a top-level object.
- Strict-undefined: missing variables fail with the variable name rather than rendering empty.
- Auto-format detection: leading `<` → `xml`, any `set ` / `delete ` line → `set`, otherwise `text`. Override via `config_format`.
- Result shape: one row per router with `rendered_template`, `config_format`, and either `diff` (dry-run), `commit_comment` (apply-mode echo of the supplied comment — rustez does not return a server-issued commit id), or `error`.

### v0.2 follow-up: Inventory mutation (released)

- `add_device` — add a Junos device to the in-memory inventory and persist to `devices.json`. Atomic write (tempfile + rename), preserves `_blocklist_defaults`, per-device `blocklist`, and other top-level fields. SHA-256-based TOCTOU guard rejects calls that race with external edits.
- `reload_devices` — re-read the current `--device-mapping` (no args) or swap to a new inventory file (`file_name`). Reports added / removed / changed device names.
- New CLI flags: `--inventory-readonly` (rejects both tools unconditionally), `--allow-password-auth-add` (permits `auth.type=password` in `add_device`; mutually exclusive with `--inventory-readonly`).
- SIGHUP now also re-reads the inventory in addition to the token store.

**Documented sharp edge:** `add_device` does not modify the token store. If a token has `--routers 'edge-*'` and you `add_device` for `core-3`, the existing token will not see the new router. Mint a new token or rotate scopes after `add_device`.

### v0.3 (released)

- **NETCONF session pooling** — `PooledDevice` RAII guard with per-router single-slot pool (300s idle timeout, 30s SSH keepalive, background reaper). Eliminates SSH handshake overhead on sequential commands.
- **Tool reliability fixes** — XML wrapper stripping for `get_junos_config` and `junos_config_diff`, corrected `show configuration | compare rollback N` command, timeout now covers SSH connect + NETCONF handshake (not just CLI execution).
- **Batch partial results** — `execute_junos_command_batch` returns inline error rows for unknown routers instead of aborting the entire batch. Blocklist violations remain strict.
- **Confirmed commits** — `load_and_commit_config` gains `confirm_timeout_mins` parameter for `commit confirmed N` with auto-rollback safety net.
- **crates.io dependency** — `rustez` switched from path dep to crates.io 0.10.1; CI no longer requires sibling repo checkout.

## Blocklist guardrails (v0.2)

`devices.json` may carry an optional `_blocklist_defaults` block plus an
optional `blocklist` field on each device entry. Rules use simple globs
(`*`, `?`) and an `action` of `"deny"` or `"allow"`. Most-specific match
wins; per-device rules tiebreak top-level defaults. See
[`devices-template.json`](devices-template.json) for an example, and
[`docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md`](docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md)
for the full design.

The `pfe_commands` rule list is independent: a deny on `commands` does not gate `execute_junos_pfe_command` and vice versa. Use it to restrict PFE inputs (e.g. `set *`) without affecting the operational CLI.

The blocklist applies to `execute_junos_command` and `load_and_commit_config`.
For `load_and_commit_config`, `config_format` must be `set` whenever the
device has any effective config rules; `text` and `xml` payloads are
rejected pre-flight in that case.

> **Compat note:** files using `_blocklist_defaults` or per-device
> `blocklist` are not cross-compatible with Juniper/junos-mcp-server's
> inventory format. Files without these fields remain drop-in compatible.

## Confirmed commits (v0.3)

`load_and_commit_config` supports Junos `commit confirmed` via the
`confirm_timeout_mins` parameter. The router auto-rolls back after N
minutes unless a follow-up commit confirms the change — a critical safety
net for remote config pushes that might break management connectivity.

```json
{
  "router_name": "core-1",
  "config_text": "set interfaces ge-0/0/0 description test",
  "confirm_timeout_mins": 10,
  "commit_comment": "safe change with rollback window"
}
```

Response:
```json
{
  "success": true,
  "diff": "[edit interfaces ge-0/0/0]\n+   description test;",
  "confirmed": true,
  "rollback_in_minutes": 10,
  "message": "Commit confirmed: auto-rollback in 10 minutes unless confirmed. Send another commit to confirm."
}
```

To confirm (prevent rollback), send another `load_and_commit_config` with
the same config (or any valid config) without `confirm_timeout_mins`.

## Security warning

This server lets an LLM run commands and push configuration changes against
your Junos devices. Read [Juniper/junos-mcp-server's security notice](https://github.com/Juniper/junos-mcp-server#important-security-notice)
before deploying. The same warnings apply.

- Prefer SSH key authentication over passwords.
- Review configurations before allowing commit tools to run.
- Restrict network access to the MCP server.
- Don't deploy to untrusted networks.
- Set `devices.json` permissions to `0600` — it contains SSH credentials.
- `get_junos_config` returns the full config including `## SECRET-DATA`
  hashed password lines. Restrict this tool's scope to trusted tokens.
- `reload_devices` restricts `file_name` to the same directory as the
  original `--device-mapping` path (no `..` traversal).
- Text input fields (`command`, `config_text`, `template_content`,
  `pfe_command`) are capped at 1 MB. Batch lists are capped at 100
  routers and 50 commands.

## Quick start (local)

```bash
git clone https://github.com/fastrevmd-lab/RustJunosMCP.git
cd RustJunosMCP

# Build (rustez pulled from crates.io automatically).
cargo build --release

# Configure devices.
cp devices-template.json devices.json
$EDITOR devices.json   # set ip / username / auth

# Run as MCP stdio server.
./target/release/rust-junosmcp -f devices.json
```

## Claude Desktop config

```json
{
  "mcpServers": {
    "junos": {
      "command": "/path/to/rust-junosmcp",
      "args": ["-f", "/path/to/devices.json"]
    }
  }
}
```

## Docker

```bash
docker build -t rust-junosmcp:0.3 .

# Run.
docker run --rm -i \
  -v $PWD/devices.json:/etc/jmcp/devices.json:ro \
  -v $PWD/keys:/etc/jmcp/keys:ro \
  rust-junosmcp:0.3
```

## LXC (Proxmox)

```bash
# Build the tarball.
./scripts/package-lxc.sh

# Push and install on VM 115 (Debian 12 / Ubuntu 24.04 LXC).
pct push 115 dist/rust-junosmcp_0.3.0_amd64.tar.gz /tmp/jmcp.tar.gz
pct exec 115 -- bash -c "tar xzf /tmp/jmcp.tar.gz -C /tmp && /tmp/rust-junosmcp_0.3.0_amd64/install.sh"

# Edit /etc/jmcp/devices.json on the LXC, then:
pct exec 115 -- systemctl enable --now rust-junosmcp
```

> **v0.1 caveat on the systemd unit:** stdio doesn't suit a long-running
> daemon. The unit is shipped for forward-compat with v0.2's HTTP transport.
> For v0.1, the practical pattern is invoking the binary on demand from an
> MCP client running outside the LXC.

## Remote transport + auth (v0.2)

### Mint a token

```bash
cargo run -- token add \
  --tokens-file tokens.json \
  --name ops \
  --routers '*' \
  --tools execute_junos_command,gather_device_facts
```

> **Note:** See [`tokens-template.json`](tokens-template.json) for the file
> shape. Use `token add` rather than editing the file by hand — the hash field
> must be a SHA-256 of the secret, not the plaintext.

### Run with auth (streamable-http)

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 127.0.0.1 \
  -p 8765 \
  --tokens-file tokens.json
```

### Loopback escape hatch (no auth, local only)

```bash
cargo run -- --device-mapping devices.json --transport streamable-http \
  -H 127.0.0.1 -p 8765 --allow-no-auth
```

`--allow-no-auth` is refused if the bind address is not loopback.

### Non-loopback requires TLS

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 0.0.0.0 \
  -p 8765 \
  --tokens-file tokens.json \
  --tls-cert cert.pem \
  --tls-key key.pem
```

To bind off-loopback over plain HTTP (e.g., behind a TLS-terminating proxy on
the same host), add `--allow-insecure-bind`. This flag overrides the TLS
requirement and should be used with care — only when you have an external
guarantee of transport security.

### Hot reload

After revoking or rotating a token, the server reloads the token store without
restarting. Pass `--server-pid <pid>` to any write subcommand and the SIGHUP
is sent automatically after the file is written:

```bash
# Revoke — writes file, then signals the server.
cargo run -- token revoke --tokens-file tokens.json --name ops --server-pid <pid>

# Rotate (mints a new secret, preserves scopes) — same pattern.
cargo run -- token rotate --tokens-file tokens.json --name ops --server-pid <pid>

# Add a new token and signal in one step.
cargo run -- token add \
  --tokens-file tokens.json \
  --name ops2 \
  --routers '*' \
  --tools execute_junos_command,gather_device_facts \
  --server-pid <pid>
```

If you need to trigger a reload without a token change (e.g., after editing the
file by hand), send SIGHUP directly:

```bash
kill -HUP <pid>
```

### Refusal matrix

| Flags | Bind address | Result |
|---|---|---|
| _(none)_ | any | Refused — `--tokens-file` or `--allow-no-auth` required for streamable-http |
| `--allow-no-auth` only | non-loopback | Refused — `--allow-no-auth` is loopback-only |
| `--allow-no-auth` only | loopback | OK — but note: if you also supply `--tls-cert`/`--tls-key`, auth is still disabled; TLS gives confidentiality but any client that can reach the port has full tool access (foot-gun) |
| `--tokens-file` only | non-loopback, no TLS | Refused — add `--tls-cert`/`--tls-key` or `--allow-insecure-bind` |
| `--tokens-file --allow-insecure-bind` | non-loopback, no TLS | OK — tokens are checked; you are asserting external transport security |
| `--tokens-file --tls-cert cert.pem --tls-key key.pem` | any | OK |

## CLI

```
Junos MCP server (Rust)

Usage: rust-junosmcp [OPTIONS] [COMMAND]

Commands:
  token  Manage the bearer-token store
  help   Print this message or the help of the given subcommand(s)

Options:
  -f, --device-mapping <DEVICE_MAPPING>
          JSON file with device mapping (Juniper junos-mcp-server compatible) [default: devices.json]
  -t, --transport <TRANSPORT>
          Transport [default: stdio] [possible values: stdio, streamable-http]
  -H, --host <HOST>
          Bind host (streamable-http only) [default: 127.0.0.1]
  -p, --port <PORT>
          Bind port (streamable-http only) [default: 30030]
      --tokens-file <TOKENS_FILE>
          Bearer-token file. Required for streamable-http unless --allow-no-auth
      --tls-cert <TLS_CERT>
          PEM-encoded TLS cert (streamable-http only). Pair with --tls-key
      --tls-key <TLS_KEY>
          PEM-encoded TLS key (streamable-http only). Pair with --tls-cert
      --allow-no-auth
          Disable bearer-token auth. Refuses to bind off-loopback
      --allow-insecure-bind
          Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured
      --inventory-readonly
          Reject add_device and reload_devices unconditionally
      --allow-password-auth-add
          Permit add_device to accept auth.type=password (mutually exclusive
          with --inventory-readonly)
  -h, --help
          Print help
  -V, --version
          Print version
```

## Testing against a real device

```bash
JMCP_TEST_HOST=10.0.0.1 \
JMCP_TEST_USER=admin \
JMCP_TEST_PASS=secret \
cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --nocapture
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
