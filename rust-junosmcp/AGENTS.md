# Junos MCP server instructions

- Keep tool schemas, annotations, stable error codes, and auth scopes explicit.
- Read tools must not mutate devices. Write/disruptive/destructive tools require
  correct annotations and server-enforced approval/scope checks.
- Preserve confirmed-commit and rollback behavior for configuration writes.

## SRX adapter safety

- Keep SRX tool schemas and annotations aligned with actual side effects.
- Preserve license and preflight gates, target validation, auth scopes,
  timeouts, output bounds, and audit fields.
- Never weaken approval requirements for package, bundle, or cluster
  operations.
