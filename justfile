set dotenv-load := false
set export := false

setup:
    rustup toolchain install
    cargo fetch --locked
    pre-commit install

dev:
    cargo run -p rust-junosmcp -- --help

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace --locked

guard: lint test

integration:
    @if [ "${CONFIRM_LAB_INTEGRATION:-}" != "yes" ]; then echo "Set CONFIRM_LAB_INTEGRATION=yes after reviewing inventory and targets."; exit 2; fi
    cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --nocapture

e2e:
    cargo run -p rust-junosmcp -- --help >/dev/null
    cargo run -p rust-junosmcp --no-default-features -- --help >/dev/null
    cargo run -p rust-junosmcp --no-default-features --features tls -- --help >/dev/null

security:
    trivy fs --scanners vuln,misconfig,secret --exit-code 1 .

release-check: fmt lint test security
