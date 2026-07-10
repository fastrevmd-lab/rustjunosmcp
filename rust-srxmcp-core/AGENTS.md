# SRX core instructions

- Keep security-service operations bounded, observable, and safe across
  standalone and clustered SRX targets.
- Status and validation calls are read-only. Package lifecycle and support
  collection require scope checks, explicit targets, and rollback/cleanup.
- Add offline parser/decision tests for every operational branch.
