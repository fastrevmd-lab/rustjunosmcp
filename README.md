# rust-junosmcp

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Juniper Junos
devices, written in Rust. Drop-in compatible with [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
on the inventory format and tool surface, but built on async Rust ([rustEZ](https://github.com/fastrevmd-lab/rustEZ) + [rustnetconf](https://github.com/fastrevmd-lab/rustnetconf))
instead of PyEZ.

> ## v0.2.1 released
>
> PFE + batch tools: `execute_junos_pfe_command` (single FPC-targeted PFE call)
> and `execute_junos_command_batch` (N routers x M commands, parallel across
> routers). New independent `pfe_commands` blocklist list.
>
> See the [v0.2.1 release notes](https://github.com/fastrevmd-lab/RustJunosMCP/releases/tag/v0.2.1)
> and the [v0.2 follow-up: PFE + batch](#v02-follow-up-pfe--batch-released)
> section below. v0.2.0 (remote transport + auth) notes remain at
> [v0.2.0](https://github.com/fastrevmd-lab/RustJunosMCP/releases/tag/v0.2.0).

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

**Coming after v0.2.2:** `add_device` / `reload_devices` interactive tools (sub-project #4 PR #7).

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

## Security warning

This server lets an LLM run commands and push configuration changes against
your Junos devices. Read [Juniper/junos-mcp-server's security notice](https://github.com/Juniper/junos-mcp-server#important-security-notice)
before deploying. The same warnings apply.

- Prefer SSH key authentication over passwords.
- Review configurations before allowing commit tools to run.
- Restrict network access to the MCP server.
- Don't deploy to untrusted networks.

## Quick start (local)

```bash
# Clone alongside rustEZ (path dependency in v0.1).
git clone https://github.com/fastrevmd-lab/rustEZ.git
git clone https://github.com/fastrevmd-lab/RustJunosMCP.git
cd RustJunosMCP

# Build.
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
# Build (must run from parent dir containing both RustJunosMCP and rustEZ).
docker build -f RustJunosMCP/Dockerfile -t rust-junosmcp:0.2 .

# Run.
docker run --rm -i \
  -v $PWD/devices.json:/etc/jmcp/devices.json:ro \
  -v $PWD/keys:/etc/jmcp/keys:ro \
  rust-junosmcp:0.2
```

## LXC (Proxmox)

```bash
# Build the tarball.
./scripts/package-lxc.sh

# Push and install on VM 115 (Debian 12 / Ubuntu 24.04 LXC).
pct push 115 dist/rust-junosmcp_0.2.1_amd64.tar.gz /tmp/jmcp.tar.gz
pct exec 115 -- bash -c "tar xzf /tmp/jmcp.tar.gz -C /tmp && /tmp/rust-junosmcp_0.2.1_amd64/install.sh"

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
