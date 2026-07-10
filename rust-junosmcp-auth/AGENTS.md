# Authentication library instructions

- Treat token parsing, hashing, reload, scope evaluation, TLS, and host/origin
  checks as security boundaries.
- Never log raw bearer values or include them in errors.
- Add negative tests for missing, expired, malformed, revoked, and out-of-scope
  credentials; preserve constant-time comparison where applicable.
