//! Process bootstrap helpers shared by `rust-junosmcp` and `rust-srxmcp`.
//!
//! These are byte-for-byte extractions of code that used to live inline in
//! the rust-junosmcp binary's `main.rs`. The function bodies are unchanged;
//! only the call sites move into helper-call form so the same setup logic
//! is reused by both binaries.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber.
///
/// Reads `RUST_LOG` via env-filter, defaults to `info`. Writes to stderr so
/// stdout stays clean for stdio-mode MCP transport.
///
/// Idempotent: calling twice silently no-ops the second call (uses
/// `try_init` instead of `init` so the second call's "global default has
/// already been set" error is discarded).
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing();
        init_tracing(); // must not panic on second call
    }
}
