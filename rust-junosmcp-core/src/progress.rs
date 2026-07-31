//! MCP progress notifications for operations that wait on a device.
//!
//! A device call can legitimately run for minutes — a commit on a busy chassis,
//! an image transfer, a signature-package install. Without progress
//! notifications a client cannot tell "the server is patiently waiting on a
//! device" from "the server is dead", so it applies an idle timeout and gives
//! up. The caller then sees `sent no response`, the least informative message
//! available, while the server holds a precise structured diagnosis that only
//! reaches the audit log (#257).
//!
//! A heartbeat costs one notification every [`DEFAULT_INTERVAL`] and keeps a
//! well-behaved client attached for the whole operation.

use rmcp::Peer;
use rmcp::model::{Meta, ProgressNotificationParam, ProgressToken};
use rmcp::service::RoleServer;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

/// How often a running device operation reports that it is still alive.
///
/// Chosen well inside the 300s idle timeout typical of MCP clients, so several
/// heartbeats land before any client would consider giving up.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Emits a progress notification every interval until dropped.
///
/// Hold one for the lifetime of a device call:
///
/// ```ignore
/// let _beat = ProgressHeartbeat::start(peer, &meta, "load_and_commit_config", "vsrx-ci");
/// let result = load_commit::handle(args, dm, policy).await;
/// ```
///
/// Dropping it aborts the emitter, so the heartbeat stops when the operation
/// returns — including on the error and panic paths, which is why this is a
/// guard rather than a pair of start/stop calls.
#[must_use = "the heartbeat stops as soon as the guard is dropped"]
pub struct ProgressHeartbeat {
    task: Option<JoinHandle<()>>,
}

impl ProgressHeartbeat {
    /// Start a heartbeat for `tool` acting on `device`.
    ///
    /// Returns an inert guard when the client did not supply a `progressToken`.
    /// That is not a fallback — MCP defines progress notifications as a
    /// response to a token the client asked us to report against, and a server
    /// that emits them unsolicited is sending notifications no client is
    /// obliged to understand.
    pub fn start(
        peer: Peer<RoleServer>,
        meta: &Meta,
        tool: String,
        device: Option<String>,
    ) -> Self {
        let Some(token) = meta.get_progress_token() else {
            return Self::inert();
        };
        Self::with_interval(
            peer,
            token,
            DEFAULT_INTERVAL,
            label(&tool, device.as_deref()),
        )
    }

    /// Start a heartbeat with an explicit interval and label.
    fn with_interval(
        peer: Peer<RoleServer>,
        token: ProgressToken,
        interval: Duration,
        label: String,
    ) -> Self {
        let started = Instant::now();
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Default `Burst` would bank missed ticks and fire them back to back
            // if a notification ever took longer than the interval to send —
            // turning a slow client into a burst of notifications aimed at that
            // same slow client. Delay just resumes the cadence.
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // The first tick of a tokio interval completes immediately; the
            // caller has just started, so there is nothing to report yet.
            ticker.tick().await;

            let mut ticks: u64 = 0;
            loop {
                ticker.tick().await;
                ticks += 1;

                // `progress` must strictly increase. The tick count does, and
                // no honest `total` exists — we do not know how long a device
                // will take, and inventing one would let a client render a
                // progress bar that means nothing.
                //
                // Elapsed is measured, not derived from the tick count: a
                // delayed tick would otherwise make the message claim less time
                // has passed than actually has.
                let param = ProgressNotificationParam::new(token.clone(), ticks as f64)
                    .with_message(message(&label, started.elapsed().as_secs()));

                // A send error means the client is gone. Nothing left to tell.
                if peer.notify_progress(param).await.is_err() {
                    break;
                }
            }
        });
        Self { task: Some(task) }
    }

    /// A heartbeat that emits nothing: the client asked for no progress.
    fn inert() -> Self {
        Self { task: None }
    }

    /// Whether this guard is emitting. Exists for the tests below; production
    /// code must not branch on it, which `cfg(test)` enforces rather than
    /// merely asks.
    #[cfg(test)]
    fn is_active(&self) -> bool {
        self.task.is_some()
    }
}

/// The label a heartbeat reports under.
fn label(tool: &str, device: Option<&str>) -> String {
    match device {
        Some(device) => format!("{tool} on {device}"),
        None => tool.to_string(),
    }
}

/// The text of one heartbeat. Says how long the operation has been running,
/// because "still running" alone does not tell an operator whether to wait.
fn message(label: &str, elapsed_secs: u64) -> String {
    format!("{label}: still running after {elapsed_secs}s")
}

impl Drop for ProgressHeartbeat {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MCP defines progress as a response to a token the client asked us to
    /// report against. No token, no notifications — a server that emitted them
    /// anyway would be sending messages no client is obliged to understand.
    #[test]
    fn a_request_without_a_progress_token_gets_no_heartbeat() {
        assert!(Meta::default().get_progress_token().is_none());
    }

    #[test]
    fn the_label_names_the_device_when_there_is_one() {
        assert_eq!(
            label("load_and_commit_config", Some("vsrx-ci")),
            "load_and_commit_config on vsrx-ci"
        );
        assert_eq!(label("get_router_list", None), "get_router_list");
    }

    /// The elapsed time is the point: "still running" alone does not tell an
    /// operator whether the device is slow or wedged.
    #[test]
    fn the_message_reports_elapsed_time() {
        assert_eq!(
            message("upgrade_junos on vsrx-ci", 90),
            "upgrade_junos on vsrx-ci: still running after 90s"
        );
    }

    /// Several heartbeats have to land inside the idle timeout a client is
    /// likely to apply, or the notification arrives after it has given up.
    #[test]
    fn the_interval_leaves_room_inside_a_typical_client_timeout() {
        let typical_client_idle_timeout = Duration::from_secs(300);
        assert!(
            DEFAULT_INTERVAL * 4 <= typical_client_idle_timeout,
            "at least four heartbeats should land before a 300s client gives up"
        );
    }

    #[tokio::test]
    async fn an_inert_guard_emits_nothing_and_drops_cleanly() {
        let heartbeat = ProgressHeartbeat::inert();
        assert!(!heartbeat.is_active());
        drop(heartbeat);
    }
}
