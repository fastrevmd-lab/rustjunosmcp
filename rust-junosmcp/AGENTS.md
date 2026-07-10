# Junos MCP server instructions

- Keep tool schemas, annotations, stable error codes, and auth scopes explicit.
- Read tools must not mutate devices. Write/disruptive/destructive tools require
  correct annotations and server-enforced approval/scope checks.
- Preserve confirmed-commit and rollback behavior for configuration writes.
