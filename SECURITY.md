# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/mechubsec/rustjunosmcp/security/advisories/new

(Security tab → Advisories → "Report a vulnerability".)

Include what you'd include in a bug report — affected version, reproduction
steps, and impact — but keep it in the private report, not a public issue,
PR, or discussion.

## Scope

This is an MCP server that automates Juniper Junos and SRX devices —
firewall and network infrastructure. Vulnerability classes we especially
want to hear about:

- Authentication or authorization bypass in `rust-junosmcp-auth` (token
  handling, scopes, session binding).
- Anything that lets a configuration load, commit, upgrade, or other
  device-changing operation fire without the caller's explicit intent, or
  without the safety checks (validated target, diff shown, confirmed
  commit/rollback) that are supposed to gate it.
- Path traversal, injection, or unsafe handling in file-transfer/SCP,
  support-bundle, or package-lifecycle tools.
- Parsing issues (config output, templated commands) that could let a
  malicious or malformed device response affect the server beyond the
  intended session.
- Anything that would let an LLM/model output reach a device-changing RPC
  without passing through the deterministic checks in front of it — that
  boundary is a hard project rule, not just a preference.

## Response

This is a community-maintained project. There's no guaranteed SLA. A human maintainer is responsible for triaging every report and for all disclosure and fix decisions.
