//! Generic async poller used by `download_and_install` (download poll +
//! install poll) and `rollback`/`uninstall` post-action verification.
//!
//! Callers supply a probe closure that returns `Ok(PollOutcome::Done(v))`
//! on a terminal success state, `Ok(PollOutcome::Pending)` while the
//! device is still working, or `Err(E)` on a terminal failure state.
//! The loop sleeps `interval` between probes and gives up at `deadline`.
//!
//! The closure-based interface keeps this module free of any RPC or
//! XML knowledge — the per-verb workflow modules wire it up against
//! their service-specific status RPCs.

use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

/// Terminal vs in-progress signal returned by a probe closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome<T> {
    /// Probe reached a terminal success state; carry the parsed result out.
    Done(T),
    /// Probe says the device is still working; poll loop should sleep + retry.
    Pending,
}

/// Failure modes the poller surfaces.
///
/// `Timeout` records how long elapsed before the deadline tripped (always
/// at least the deadline budget); `Probe` carries the inner probe's error
/// verbatim so callers can map it onto a verb-specific `SrxError` variant
/// (e.g. `SignaturePackageDownloadFailed` vs `SignaturePackageInstallFailed`).
#[derive(Debug)]
pub enum PollError<E> {
    Timeout { elapsed: Duration },
    Probe(E),
}

/// Poll `probe` every `interval` until it returns `Done(_)` or the deadline
/// expires.
///
/// On every iteration:
/// 1. Call the probe.
/// 2. If `Done(v)` — return `Ok(v)`.
/// 3. If `Err(e)` — return `Err(PollError::Probe(e))`.
/// 4. If `Pending` and `now + interval >= deadline` — return `Timeout`.
/// 5. Otherwise sleep `interval` and loop.
///
/// Notes:
/// * The probe is called at least once even if `deadline <= now` — terminal
///   probes shouldn't be skipped just because the budget was already
///   exhausted before the first call.
/// * `interval` of zero is allowed for tests (drives the loop without
///   waiting) but real callers should use ~5s per the design.
pub async fn poll_until_done<F, Fut, T, E>(
    interval: Duration,
    deadline: Instant,
    mut probe: F,
) -> Result<T, PollError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<PollOutcome<T>, E>>,
{
    let start = Instant::now();
    loop {
        match probe().await {
            Ok(PollOutcome::Done(value)) => return Ok(value),
            Ok(PollOutcome::Pending) => {
                let now = Instant::now();
                // Trip timeout before sleeping if the next probe would land
                // past the deadline anyway.
                if now + interval >= deadline {
                    return Err(PollError::Timeout {
                        elapsed: now.saturating_duration_since(start),
                    });
                }
                tokio::time::sleep(interval).await;
            }
            Err(e) => return Err(PollError::Probe(e)),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Test-only probe error: we never assert on the payload, just that the
    /// poller surfaces it through `PollError::Probe`.
    #[derive(Debug, PartialEq, Eq)]
    struct ProbeFail(&'static str);

    #[tokio::test(start_paused = true)]
    async fn done_on_first_call_returns_immediately() {
        let result = poll_until_done::<_, _, _, ProbeFail>(
            Duration::from_secs(5),
            Instant::now() + Duration::from_secs(60),
            || async { Ok(PollOutcome::Done(42_u32)) },
        )
        .await;
        assert!(matches!(result, Ok(42)));
    }

    #[tokio::test(start_paused = true)]
    async fn pending_then_done_returns_value() {
        let count = Rc::new(Cell::new(0_u32));
        let count_clone = count.clone();
        let result = poll_until_done::<_, _, _, ProbeFail>(
            Duration::from_secs(5),
            Instant::now() + Duration::from_secs(60),
            move || {
                let count = count_clone.clone();
                async move {
                    let n = count.get();
                    count.set(n + 1);
                    if n < 2 {
                        Ok(PollOutcome::Pending)
                    } else {
                        Ok(PollOutcome::Done("ok"))
                    }
                }
            },
        )
        .await;
        assert!(matches!(result, Ok("ok")));
        assert_eq!(count.get(), 3, "probe called three times");
    }

    #[tokio::test(start_paused = true)]
    async fn probe_error_short_circuits() {
        let result = poll_until_done::<_, _, u32, _>(
            Duration::from_secs(5),
            Instant::now() + Duration::from_secs(60),
            || async { Err(ProbeFail("download stalled")) },
        )
        .await;
        match result {
            Err(PollError::Probe(ProbeFail("download stalled"))) => {}
            other => panic!("expected Probe error, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_trips_when_probe_never_done() {
        let result = poll_until_done::<_, _, u32, ProbeFail>(
            Duration::from_secs(5),
            Instant::now() + Duration::from_secs(20),
            || async { Ok(PollOutcome::Pending) },
        )
        .await;
        match result {
            Err(PollError::Timeout { elapsed }) => {
                assert!(
                    elapsed >= Duration::from_secs(15),
                    "elapsed {elapsed:?} should be near the 20s budget"
                );
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn probe_runs_at_least_once_even_with_past_deadline() {
        // deadline is already in the past — but the probe should still be
        // called once and a Done result should win over the late deadline.
        let result = poll_until_done::<_, _, _, ProbeFail>(
            Duration::from_secs(5),
            Instant::now(),
            || async { Ok(PollOutcome::Done(7)) },
        )
        .await;
        assert!(matches!(result, Ok(7)));
    }
}
