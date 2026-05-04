# rust-junosmcp

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Juniper Junos
devices, written in Rust. Drop-in compatible with [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
on the inventory format and tool surface, but built on async Rust ([rustEZ](https://github.com/fastrevmd-lab/rustEZ) + [rustnetconf](https://github.com/fastrevmd-lab/rustnetconf))
instead of PyEZ.

## v0.1 scope

- 6 tools: `get_router_list`, `gather_device_facts`, `execute_junos_command`,
  `get_junos_config`, `junos_config_diff`, `load_and_commit_config`.
- stdio transport only.
- `devices.json` drop-in compatible (`auth.type` ∈ {`password`, `ssh_key`}).
- Docker image (distroless) and LXC release tarball with systemd unit.

**Coming in v0.2:** PFE commands, batch execution, Jinja2 templates,
streamable-http transport, bearer-token auth, blocklist guardrails,
`add_device` / `reload_devices` interactive tools.

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
docker build -f RustJunosMCP/Dockerfile -t rust-junosmcp:0.1 .

# Run.
docker run --rm -i \
  -v $PWD/devices.json:/etc/jmcp/devices.json:ro \
  -v $PWD/keys:/etc/jmcp/keys:ro \
  rust-junosmcp:0.1
```

## LXC (Proxmox)

```bash
# Build the tarball.
./scripts/package-lxc.sh

# Push and install on VM 115 (Debian 12 / Ubuntu 24.04 LXC).
pct push 115 dist/rust-junosmcp_0.1.0_amd64.tar.gz /tmp/jmcp.tar.gz
pct exec 115 -- bash -c "tar xzf /tmp/jmcp.tar.gz -C /tmp && /tmp/rust-junosmcp_0.1.0_amd64/install.sh"

# Edit /etc/jmcp/devices.json on the LXC, then:
pct exec 115 -- systemctl enable --now rust-junosmcp
```

> **v0.1 caveat on the systemd unit:** stdio doesn't suit a long-running
> daemon. The unit is shipped for forward-compat with v0.2's HTTP transport.
> For v0.1, the practical pattern is invoking the binary on demand from an
> MCP client running outside the LXC.

## CLI

```
rust-junosmcp 0.1.0
Junos MCP server (Rust)

Usage: rust-junosmcp [OPTIONS]

Options:
  -f, --device-mapping <DEVICE_MAPPING>  [default: devices.json]
  -t, --transport <TRANSPORT>            [default: stdio] [possible values: stdio, streamable-http]
  -H, --host <HOST>                      [default: 127.0.0.1]
  -p, --port <PORT>                      [default: 30030]
  -h, --help                             Print help
  -V, --version                          Print version
```

`--transport streamable-http` is parsed but rejected at runtime in v0.1.

## Testing against a real device

```bash
JMCP_TEST_HOST=10.0.0.1 \
JMCP_TEST_USER=admin \
JMCP_TEST_PASS=secret \
cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --nocapture
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
