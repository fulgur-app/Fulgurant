use crate::api::middleware::AuthenticatedUser;
use crate::handlers::AppState;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    Extension,
};
use chrono::Utc;
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, time::Duration};
use tagged_channels::TaggedChannels;

/// Tag enum for identifying SSE channels by device ID
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum ChannelTag {
    DeviceId(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShareNotification {
    pub share_id: String,
    pub source_device_id: String,
    pub destination_device_id: String,
    pub file_name: String,
    pub file_size: i64,
    pub file_hash: String,
    pub content: String,
    pub created_at: String,
    pub expires_at: String,
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
/// SSE stream that yields heartbeat and share_available events
pub async fn handle_sse_connection(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let device_id = auth_user.device_id.clone();
    let device_name = auth_user.device_name.clone();
    tracing::info!(
        device_id = ?device_id,
        device_name = ?device_name,
        user_email = ?auth_user.user.email,
        "SSE connection established"
    );
    let mut channel = state
        .sse_manager
        .create_channel([ChannelTag::DeviceId(device_id.clone())]);
    let heartbeat_interval = Duration::from_secs(state.sse_heartbeat_seconds);
    let stream = async_stream::stream! {
        let mut interval = tokio::time::interval(heartbeat_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let heartbeat = serde_json::json!({
                        "timestamp": Utc::now().to_rfc3339()
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
                        file_name = ?notification.file_name,
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
    Sse::new(stream).keep_alive(KeepAlive::default())
}
