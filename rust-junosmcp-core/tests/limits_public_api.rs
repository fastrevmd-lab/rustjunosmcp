use rust_junosmcp_core::limits::{LimitsConfig, LimitsConfigError};

#[test]
fn limits_remain_a_public_core_api() {
    let defaults = LimitsConfig::default();
    assert_eq!(defaults.validate(), Ok(()));

    let invalid = LimitsConfig {
        max_requests_per_second_per_token: 1,
        max_request_burst_per_token: 0,
        ..LimitsConfig::default()
    };
    assert_eq!(
        invalid.validate(),
        Err(LimitsConfigError::IncompleteTokenRateLimit { rate: 1, burst: 0 })
    );
}
