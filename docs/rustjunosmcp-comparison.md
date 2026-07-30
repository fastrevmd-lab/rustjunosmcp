# rustjunosmcp vs Juniper junos-mcp-server

## Overview

`rustjunosmcp` is a substantially broader and more production-oriented MCP server than Juniper's official `junos-mcp-server`. It keeps compatibility with the basic `devices.json` inventory shape and core Junos tool surface, but adds a much larger tool catalog, stronger authorization boundaries, transport hardening, SRX-specific workflows, file transfer and software lifecycle operations, and operational controls for concurrency, metrics, and auditability.[cite:4][cite:3]

The official Juniper server is intentionally simpler. Its README centers on core Junos access, stdio and streamable-http transport modes, token support for HTTP mode, Claude Desktop and VS Code integration, and a small set of baseline tools, with explicit warnings about secure deployment and review of LLM-generated configurations before commit.[cite:3]

## Repository shape

The `rustjunosmcp` repository is structured as a Rust workspace with multiple crates, including `rust-junosmcp`, `rust-junosmcp-core`, `rust-junosmcp-srx-core`, and `rust-junosmcp-auth`, plus packaging, scripts, and documentation directories.[cite:3][cite:4]

By contrast, Juniper's repository is a smaller Python project centered around `jmcp.py`, `jmcp_token_manager.py`, a Docker workflow, and a single-server architecture built on PyEZ.[cite:3]

## Capability matrix

| Area | rustjunosmcp | Juniper/junos-mcp-server |
|---|---|---|
| Implementation language | Rust, async, based on `rustEZ` and `rustnetconf`.[cite:4] | Python, based on PyEZ.[cite:3] |
| Core compatibility | Drop-in compatible with the basic `devices.json` format and core Junos tools.[cite:4] | Native reference implementation for its own inventory and core tools.[cite:3] |
| Tool count | 27 tools by default, 18 in Junos-only builds.[cite:4] | Core Junos tools plus `add_device`; the README's handler registry examples show a much smaller surface.[cite:3] |
| SRX-specific workflows | Included by default via the `srx` feature, including security-package workflows and chassis/security status tooling.[cite:4] | Not described in the README as part of the standard tool surface.[cite:3] |
| Session reuse | NETCONF session pooling with idle timeout and reaper.[cite:4] | No session pool is described in the README.[cite:3] |
| Batch execution | Parallel multi-router command batching is built in.[cite:4] | No comparable batch command facility is documented.[cite:3] |
| Config safety | `commit_check_config`, `discard_candidate`, confirmed commits, rollback tooling.[cite:4] | Supports loading and committing config, but the README emphasizes operator review rather than additional safety primitives.[cite:3] |
| File lifecycle | `transfer_file`, `fetch_file`, staged files, `upgrade_junos`.[cite:4] | Not described in the README.[cite:3] |
| HTTP auth model | Bearer tokens with router and tool scopes, file permission checks, host allowlist, optional TLS.[cite:4] | Token-based authentication for streamable-http, but without the same documented scope model or host allowlist controls.[cite:3] |
| Audit/metrics/resource controls | Structured audit logging, journald fan-out, Prometheus, request/session/router limits.[cite:4] | Not described in the README.[cite:3] |

## Where rustjunosmcp is stronger

The strongest technical advantage is that `rustjunosmcp` is designed as a real control-plane service rather than only a local bridge. It supports streamable HTTP with bearer-token scoping, TLS, host-header allowlisting, hot token reload, concurrency controls, Prometheus metrics, structured audit logs, and packaging paths for Docker and Proxmox LXC deployment.[cite:4]

The second major differentiator is operational safety. `rustjunosmcp` adds `commit_check_config`, `discard_candidate`, confirmed commits with rollback timers, rollback archives, scoped write-tool authorization, SHA-256 verified SCP flows, staging directories, known-hosts enforcement, and destructive-operation leases shared across processes.[cite:4]

The third major differentiator is product scope. `rustjunosmcp` is positioned as a unified Junos and SRX server, with SRX security workflows enabled by default, while the Juniper Python server README is focused on core Junos device operations and developer extension patterns rather than a broad security-operations surface.[cite:4][cite:3]

## Where Juniper's server is simpler

Juniper's implementation is easier to understand and extend for small deployments. The README documents a direct three-step tool extension model inside `jmcp.py`: add a handler, register it in `TOOL_HANDLERS`, and define metadata in `list_tools()`.[cite:3]

That simplicity may be attractive for labs, quick prototypes, and users who want a minimal Python MCP server with only baseline read/write Junos tasks. The project also documents Claude Desktop and VS Code integration clearly, including a VS Code-only elicitation flow for `add_device`.[cite:3]

## MCP 2026-07-28 changes

The MCP project published the 2026-07-28 specification on July 28, 2026, and described it as the largest revision since launch.[cite:7][cite:5]

The most important transport-level changes for an HTTP MCP server are a new stateless core, removal of the `initialize` and `initialized` handshake, removal of `Mcp-Session-Id`, new required `Mcp-Method` and `Mcp-Name` headers, and version signaling through the `MCP-Protocol-Version` header rather than one-time initialization negotiation.[cite:5][cite:6]

The same release also changes elicitation semantics, standardizes more schema and metadata behavior, and adds cache hints such as `ttlMs` and `cacheScope` on list results.[cite:5]

## What rustjunosmcp likely needs

The most urgent compatibility work is in the shared HTTP and protocol layer. Any `rustjunosmcp` logic built around server-side sessions, `Mcp-Session-Id`, or session admission limits will need refactoring for the new stateless core.[cite:4][cite:5]

The next priority is header validation. The HTTP stack should parse and validate `Mcp-Method`, `Mcp-Name`, and `MCP-Protocol-Version`, and reject mismatches between headers and JSON-RPC payloads because the new spec treats those headers as part of the protocol contract.[cite:5][cite:6]

The elicitation path also needs review. Juniper's Python server uses elicitation for `add_device` in VS Code, and `rustjunosmcp` or its shared foundation should avoid assuming the older long-lived request model because the new spec reworks elicitation into an input-request and replay pattern.[cite:3][cite:5]

## Recommended implementation order

1. Update the shared foundation layer first, especially anything now hosted in `mecmcp` or equivalent transport/auth crates, so the stateless protocol and header validation logic is implemented once.[cite:4]
2. Preserve backward compatibility during the transition because the spec notes clients must handle compatibility across protocol revisions, and major MCP clients may not all switch at once.[cite:6]
3. Add dual-mode handling for old and new HTTP behavior before removing legacy session code, so deployed clients are not broken during rollout.[cite:5][cite:6]
4. After transport compatibility lands, update tool schemas and elicitation behavior, then add cache hints and trace metadata support as quality improvements.[cite:5]

## Practical conclusion

For a production-oriented Junos and SRX automation stack, `rustjunosmcp` is already ahead of Juniper's official server in scale, security boundaries, operational safety, and feature depth.[cite:4][cite:3]

The main near-term risk is not feature parity with Juniper's server, but protocol drift with the newly finalized MCP 2026-07-28 spec. The fastest path is to treat the work as a foundation-layer transport migration first and a per-tool cleanup second.[cite:5][cite:6]
