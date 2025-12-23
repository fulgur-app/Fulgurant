// src/api/rate_limit.rs
use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

/// Simple in-memory rate limiter
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// ### Description
    /// This function creates a new rate limiter.
    /// It initializes the requests map and sets the maximum number of requests per window.``
    ///
    /// ### Arguments
    /// - `max_requests`: The maximum number of requests per window
    /// - `window`: The time window
    ///
    /// ### Returns
    /// - `RateLimiter`: The rate limiter
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    /// Check the rate limit for a key
    ///
    /// ### Arguments
    /// - `key`: The key to check
    ///
    /// ### Returns
    /// - bool: True if the rate limit is exceeded, false otherwise
    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let mut requests = self.requests.lock().await;
        let now = Instant::now();
        let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);
        entry.retain(|&time| now.duration_since(time) < self.window);
        if entry.len() < self.max_requests {
            entry.push(now);
            true
        } else {
            false
        }
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            requests: Arc::clone(&self.requests),
            max_requests: self.max_requests,
            window: self.window,
        }
    }
}

/// Middleware that rate limits API requests based on IP address
///
/// ### Arguments
/// - `addr`: The address of the request
/// - `request`: The request
/// - `next`: The next middleware
///
/// ### Returns
/// - `Ok(Response)`: The response
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the rate limit is exceeded
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let rate_limiter = RateLimiter::new(5, Duration::from_secs(60));
    if !rate_limiter.check_rate_limit(&addr.ip().to_string()).await {
        tracing::warn!("Rate limit exceeded for IP: {}", addr.ip());
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "Too many requests. Please try again later.".to_string(),
            }),
        )
            .into_response());
    }
    Ok(next.run(request).await)
}
