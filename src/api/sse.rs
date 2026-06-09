use crate::api::middleware::AuthenticatedUser;
use crate::errors::AppError;
use crate::handlers::AppState;
use axum::{
    Extension,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tagged_channels::TaggedChannels;
use time::OffsetDateTime;

/// Maximum number of concurrent SSE connections allowed per device.
pub const MAX_SSE_CONNECTIONS_PER_DEVICE: u32 = 2;

/// Tag enum for identifying SSE channels by device ID
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum ChannelTag {
    DeviceId(String),
}

/// Bounds the number of concurrent SSE connections held per device.
pub struct SseConnectionLimiter {
    max_per_device: u32,
    counts: Mutex<HashMap<String, u32>>,
}

impl SseConnectionLimiter {
    /// Create a new limiter capping concurrent connections per device.
    ///
    /// ### Arguments:
    /// - `max_per_device`: maximum number of simultaneous SSE connections allowed for one device
    ///
    /// ### Returns:
    /// - `SseConnectionLimiter`: the initialized limiter with no active connections
    pub fn new(max_per_device: u32) -> Self {
        Self {
            max_per_device,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Attempt to reserve a connection slot for a device.
    ///
    /// ### Arguments:
    /// - `device_id`: the public device identifier to reserve a slot for
    ///
    /// ### Returns:
    /// - `Some(SseConnectionGuard)`: a guard releasing the slot on drop, when below the cap
    /// - `None`: when the device already holds the maximum number of connections
    pub fn try_acquire(self: &Arc<Self>, device_id: &str) -> Option<SseConnectionGuard> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = counts.entry(device_id.to_string()).or_insert(0);
        if *count >= self.max_per_device {
            return None;
        }
        *count += 1;
        Some(SseConnectionGuard {
            limiter: Arc::clone(self),
            device_id: device_id.to_string(),
        })
    }
}

/// RAII guard that releases a device's SSE connection slot when dropped.
///
/// Holding the guard for the lifetime of the SSE stream guarantees the per-device count is
/// decremented exactly once, regardless of how the stream ends.
pub struct SseConnectionGuard {
    limiter: Arc<SseConnectionLimiter>,
    device_id: String,
}

impl Drop for SseConnectionGuard {
    /// Decrement the active connection count for the device, removing the entry at zero.
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.device_id) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.device_id);
            }
        }
    }
}

/// Lightweight SSE notification: only carries the share id for the client to call `GET /api/shares`
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShareNotification {
    pub share_id: String,
}

/// Initial snapshot of currently pending share ids, sent once on SSE connect
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PendingSharesSnapshot {
    pub share_ids: Vec<String>,
}

/// Type alias for SSE channel manager
pub type SseChannelManager = TaggedChannels<ShareNotification, ChannelTag>;

/// SSE endpoint handler for device connections
///
/// ### Arguments:
/// - `state`: Application state containing SSE manager and configuration
/// - `auth_user`: Authenticated user and device information from middleware
///
/// ### Returns:
/// - `Ok(Sse)`: SSE stream that yields heartbeat and `share_available` events
/// - `Err(AppError::TooManyConnections)`: when the device already holds the maximum number
///   of concurrent SSE connections
pub async fn handle_sse_connection(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    let device_id = auth_user.device_id.clone();
    let Some(connection_guard) = state.sse_connection_limiter.try_acquire(&device_id) else {
        tracing::warn!(
            device_id = ?device_id,
            user_id = auth_user.user.id,
            max = MAX_SSE_CONNECTIONS_PER_DEVICE,
            "Rejected SSE connection: per-device connection limit reached"
        );
        return Err(AppError::TooManyConnections);
    };
    tracing::info!(
        device_id = ?device_id,
        user_id = auth_user.user.id,
        "SSE connection established"
    );
    let mut channel = state
        .sse_manager
        .create_channel([ChannelTag::DeviceId(device_id.clone())]);
    let heartbeat_interval = Duration::from_secs(state.sse_heartbeat_seconds);
    let initial_share_ids = match state
        .share_repository
        .list_share_ids_for_device(&device_id)
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(
                error = ?e,
                device_id = ?device_id,
                "Failed to load pending share ids for SSE snapshot; sending empty list"
            );
            Vec::new()
        }
    };
    let stream = async_stream::stream! {
        // Hold the connection slot for as long as the stream is alive; dropped on disconnect.
        let _connection_guard = connection_guard;
        let snapshot = PendingSharesSnapshot {
            share_ids: initial_share_ids,
        };
        tracing::info!(
            device_id = ?device_id,
            count = snapshot.share_ids.len(),
            "Sending pending shares snapshot via SSE"
        );
        match serde_json::to_string(&snapshot) {
            Ok(data) => {
                yield Ok(Event::default()
                    .event("pending_shares")
                    .data(data));
            }
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    device_id = ?device_id,
                    "Failed to serialize pending shares snapshot"
                );
            }
        }
        let mut interval = tokio::time::interval(heartbeat_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let timestamp = OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default();
                    let heartbeat = serde_json::json!({
                        "timestamp": timestamp
                    });
                    tracing::debug!(device_id = ?device_id, "Sending heartbeat");
                    yield Ok(Event::default()
                        .event("heartbeat")
                        .data(heartbeat.to_string()));
                }
                Some(notification) = channel.recv() => {
                    tracing::info!(
                        share_id = ?notification.share_id,
                        device_id = ?device_id,
                        "Sending share notification via SSE"
                    );
                    match serde_json::to_string(&notification) {
                        Ok(data) => {
                            yield Ok(Event::default()
                                .event("share_available")
                                .data(data));
                        }
                        Err(e) => {
                            tracing::error!(
                                error = ?e,
                                share_id = ?notification.share_id,
                                "Failed to serialize share notification"
                            );
                        }
                    }
                }
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_succeeds_up_to_cap_then_rejects() {
        let limiter = Arc::new(SseConnectionLimiter::new(2));
        let first = limiter.try_acquire("device-a");
        let second = limiter.try_acquire("device-a");
        assert!(first.is_some());
        assert!(second.is_some());
        assert!(
            limiter.try_acquire("device-a").is_none(),
            "third connection for the same device must be rejected"
        );
    }

    #[test]
    fn dropping_a_guard_frees_a_slot() {
        let limiter = Arc::new(SseConnectionLimiter::new(1));
        let guard = limiter.try_acquire("device-a");
        assert!(guard.is_some());
        assert!(limiter.try_acquire("device-a").is_none());
        drop(guard);
        assert!(
            limiter.try_acquire("device-a").is_some(),
            "slot must be reclaimed after the guard is dropped"
        );
    }

    #[test]
    fn limits_are_tracked_per_device() {
        let limiter = Arc::new(SseConnectionLimiter::new(1));
        let _guard_a = limiter.try_acquire("device-a");
        assert!(
            limiter.try_acquire("device-b").is_some(),
            "a different device must not be affected by another device's cap"
        );
        assert!(limiter.try_acquire("device-a").is_none());
    }

    #[test]
    fn count_entry_removed_when_last_connection_closes() {
        let limiter = Arc::new(SseConnectionLimiter::new(2));
        {
            let _guard = limiter.try_acquire("device-a");
        }
        let counts = limiter
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !counts.contains_key("device-a"),
            "device entry must be removed once no connections remain"
        );
    }
}
