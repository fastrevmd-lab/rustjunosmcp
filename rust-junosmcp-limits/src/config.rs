//! Tunable resource limits for the streamable-HTTP endpoints.

use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsConfigError {
    IncompleteTokenRateLimit { rate: u64, burst: u64 },
}

impl fmt::Display for LimitsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteTokenRateLimit { rate, burst } => write!(
                f,
                "per-token request rate and burst must both be zero (disabled) or both be positive (rate={rate}, burst={burst})"
            ),
        }
    }
}

impl std::error::Error for LimitsConfigError {}

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
    /// Max requests per second per bearer token. `0` disables with burst `0`.
    pub max_requests_per_second_per_token: u64,
    /// Max immediate request burst per bearer token. `0` disables with rate `0`.
    pub max_request_burst_per_token: u64,
    /// Max concurrent in-flight requests per target router. `0` disables.
    pub max_inflight_requests_per_router: usize,
    /// Max concurrent MCP sessions. `0` disables.
    pub max_sessions: usize,
    /// Max concurrent MCP sessions per bearer token. `0` disables.
    pub max_sessions_per_token: usize,
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
            max_requests_per_second_per_token: 0,
            max_request_burst_per_token: 0,
            max_inflight_requests_per_router: 4,
            max_sessions: 128,
            max_sessions_per_token: 16,
            session_idle_timeout_secs: 300,
            session_max_lifetime_secs: 3600,
        }
    }
}

impl LimitsConfig {
    pub fn validate(&self) -> Result<(), LimitsConfigError> {
        let rate = self.max_requests_per_second_per_token;
        let burst = self.max_request_burst_per_token;
        if (rate == 0) != (burst == 0) {
            return Err(LimitsConfigError::IncompleteTokenRateLimit { rate, burst });
        }
        Ok(())
    }

    pub fn token_rate_limit_enabled(&self) -> bool {
        self.max_requests_per_second_per_token > 0 && self.max_request_burst_per_token > 0
    }

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
            max_requests_per_second_per_token = self.max_requests_per_second_per_token,
            max_request_burst_per_token = self.max_request_burst_per_token,
            max_inflight_requests_per_router = self.max_inflight_requests_per_router,
            max_sessions = self.max_sessions,
            max_sessions_per_token = self.max_sessions_per_token,
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
        assert_eq!(c.max_inflight_requests_per_token, 16);
        assert_eq!(c.max_inflight_requests_per_router, 4);
        assert_eq!(c.max_sessions, 128);
        assert_eq!(c.max_sessions_per_token, 16);
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

    #[test]
    fn token_rate_defaults_disabled_and_valid() {
        let config = LimitsConfig::default();
        assert_eq!(config.max_requests_per_second_per_token, 0);
        assert_eq!(config.max_request_burst_per_token, 0);
        assert!(!config.token_rate_limit_enabled());
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn token_rate_requires_rate_and_burst_together() {
        for (rate, burst) in [(5, 0), (0, 8)] {
            let config = LimitsConfig {
                max_requests_per_second_per_token: rate,
                max_request_burst_per_token: burst,
                ..Default::default()
            };
            assert_eq!(
                config.validate(),
                Err(LimitsConfigError::IncompleteTokenRateLimit { rate, burst })
            );
            assert!(!config.token_rate_limit_enabled());
        }

        let enabled = LimitsConfig {
            max_requests_per_second_per_token: 5,
            max_request_burst_per_token: 8,
            ..Default::default()
        };
        assert_eq!(enabled.validate(), Ok(()));
        assert!(enabled.token_rate_limit_enabled());
    }
}
