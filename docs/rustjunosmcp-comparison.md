# rustjunosmcp vs Juniper junos-mcp-server

## Overview

`rustjunosmcp` is a substantially broader and more production-oriented MCP server than Juniper's official `junos-mcp-server`. It keeps compatibility with the basic `devices.json` inventory shape and core Junos tool surface, but adds a much larger tool catalog, stronger authorization boundaries, transport hardening, SRX-specific workflows, file transfer and software lifecycle operations, and operational controls for concurrency, metrics, and auditability.

The official Juniper server is intentionally simpler. Its README centers on core Junos access, stdio and streamable-http transport modes, token support for HTTP mode, Claude Desktop and VS Code integration, and a small set of baseline tools, with explicit warnings about secure deployment and review of LLM-generated configurations before commit.

## Repository shape

The `rustjunosmcp` repository is structured as a Rust workspace with multiple crates, including `rust-junosmcp`, `rust-junosmcp-core`, `rust-junosmcp-srx-core`, and `rust-junosmcp-auth`, plus packaging, scripts, and documentation directories.

By contrast, Juniper's repository is a smaller Python project centered around `jmcp.py`, `jmcp_token_manager.py`, a Docker workflow, and a single-server architecture built on PyEZ.

## Capability matrix

| Area | rustjunosmcp | Juniper/junos-mcp-server |
|---|---|---|
| Implementation language | Rust, async, based on `rustEZ` and `rustnetconf`. | Python, based on PyEZ. |
| Core compatibility | Drop-in compatible with the basic `devices.json` format and core Junos tools. | Native reference implementation for its own inventory and core tools. |
| Tool count | 27 tools by default, 18 in Junos-only builds. | Core Junos tools plus `add_device`; the README's handler registry examples show a much smaller surface. |
| SRX-specific workflows | Included by default via the `srx` feature, including security-package workflows and chassis/security status tooling. | Not described in the README as part of the standard tool surface. |
| Session reuse | NETCONF session pooling with idle timeout and reaper. | No session pool is described in the README. |
| Batch execution | Parallel multi-router command batching is built in. | No comparable batch command facility is documented. |
| Config safety | `commit_check_config`, `discard_candidate`, confirmed commits, rollback tooling. | Supports loading and committing config, but the README emphasizes operator review rather than additional safety primitives. |
| File lifecycle | `transfer_file`, `fetch_file`, staged files, `upgrade_junos`. | Not described in the README. |
| HTTP auth model | Bearer tokens with router and tool scopes, file permission checks, host allowlist, optional TLS. | Token-based authentication for streamable-http, but without the same documented scope model or host allowlist controls. |
| Audit/metrics/resource controls | Structured audit logging, journald fan-out, Prometheus, request/session/router limits. | Not described in the README. |

## Where rustjunosmcp is stronger

The strongest technical advantage is that `rustjunosmcp` is designed as a real control-plane service rather than only a local bridge. It supports streamable HTTP with bearer-token scoping, TLS, host-header allowlisting, hot token reload, concurrency controls, Prometheus metrics, structured audit logs, and packaging paths for Docker and Proxmox LXC deployment.

The second major differentiator is operational safety. `rustjunosmcp` adds `commit_check_config`, `discard_candidate`, confirmed commits with rollback timers, rollback archives, scoped write-tool authorization, SHA-256 verified SCP flows, staging directories, known-hosts enforcement, and destructive-operation leases shared across processes.

The third major differentiator is product scope. `rustjunosmcp` is positioned as a unified Junos and SRX server, with SRX security workflows enabled by default, while the Juniper Python server README is focused on core Junos device operations and developer extension patterns rather than a broad security-operations surface.

## Where Juniper's server is simpler

Juniper's implementation is easier to understand and extend for small deployments. The README documents a direct three-step tool extension model inside `jmcp.py`: add a handler, register it in `TOOL_HANDLERS`, and define metadata in `list_tools()`.

That simplicity may be attractive for labs, quick prototypes, and users who want a minimal Python MCP server with only baseline read/write Junos tasks. The project also documents Claude Desktop and VS Code integration clearly, including a VS Code-only elicitation flow for `add_device`.

## Practical conclusion

For a production-oriented Junos and SRX automation stack, `rustjunosmcp` is already ahead of Juniper's official server in scale, security boundaries, operational safety, and feature depth.

The main near-term risk is not feature parity with Juniper's server, but protocol drift with the newly finalized MCP 2026-07-28 spec. The fastest path is to treat the work as a foundation-layer transport migration first and a per-tool cleanup second.[cite:5][cite:6]
