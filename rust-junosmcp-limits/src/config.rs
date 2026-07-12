//! Tunable resource limits for the streamable-HTTP endpoints.

use std::time::Duration;

/// All HTTP resource / session limits. Every numeric field uses `0` as an
/// "unlimited / disabled" escape hatch.
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    /// Max request body size in bytes before rejecting with 413. `0` disables.
    pub max_request_body_bytes: usize,
    /// Max concurrent in-flight requests across all callers. `0` disables.
    pub max_inflight_requests: usize,
    /// Max concurrent in-flight requests per bearer token. `0` disables.
    pub max_inflight_requests_per_token: usize,
    /// Max concurrent MCP sessions. `0` disables.
    pub max_sessions: usize,
    /// Idle timeout (seconds) after which a session is reaped. `0` disables.
    pub session_idle_timeout_secs: u64,
    /// Max session lifetime (seconds) after which it is reaped. `0` disables.
    pub session_max_lifetime_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 10 * 1024 * 1024,
            max_inflight_requests: 64,
            max_inflight_requests_per_token: 16,
            max_sessions: 128,
            session_idle_timeout_secs: 300,
            session_max_lifetime_secs: 3600,
        }
    }
}

impl LimitsConfig {
    /// Idle timeout as a `Duration`, or `None` when disabled (`0`).
    pub fn idle_timeout(&self) -> Option<Duration> {
        (self.session_idle_timeout_secs > 0)
            .then(|| Duration::from_secs(self.session_idle_timeout_secs))
    }

    /// Max lifetime as a `Duration`, or `None` when disabled (`0`).
    pub fn max_lifetime(&self) -> Option<Duration> {
        (self.session_max_lifetime_secs > 0)
            .then(|| Duration::from_secs(self.session_max_lifetime_secs))
    }

    /// Emit the effective configuration at startup.
    pub fn log_effective(&self) {
        tracing::info!(
            max_request_body_bytes = self.max_request_body_bytes,
            max_inflight_requests = self.max_inflight_requests,
            max_inflight_requests_per_token = self.max_inflight_requests_per_token,
            max_sessions = self.max_sessions,
            session_idle_timeout_secs = self.session_idle_timeout_secs,
            session_max_lifetime_secs = self.session_max_lifetime_secs,
            "http resource limits configured"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_generous_and_enabled() {
        let c = LimitsConfig::default();
        assert_eq!(c.max_request_body_bytes, 10 * 1024 * 1024);
        assert_eq!(c.max_inflight_requests, 64);
        assert_eq!(c.max_sessions, 128);
        assert_eq!(c.idle_timeout(), Some(Duration::from_secs(300)));
        assert_eq!(c.max_lifetime(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn zero_disables_timeouts() {
        let c = LimitsConfig {
            session_idle_timeout_secs: 0,
            session_max_lifetime_secs: 0,
            ..Default::default()
        };
        assert_eq!(c.idle_timeout(), None);
        assert_eq!(c.max_lifetime(), None);
    }
}
