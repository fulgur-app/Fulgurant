use axum::{extract::ConnectInfo, http::HeaderMap, http::Request};
use std::net::{IpAddr, SocketAddr};
use tower_governor::{GovernorError, key_extractor::KeyExtractor};

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_REAL_IP: &str = "x-real-ip";

/// Rate-limiting key extractor keyed on the client IP address.
///
/// By default only the TCP peer address is used, so clients cannot pick their
/// own bucket by sending forged proxy headers. When `trust_proxy_headers` is
/// enabled (Fulgurant reachable only through a reverse proxy), the key is the
/// rightmost `X-Forwarded-For` entry, i.e. the address appended by the proxy
/// itself, falling back to `X-Real-Ip` and then to the peer address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIpKeyExtractor {
    trust_proxy_headers: bool,
}

impl ClientIpKeyExtractor {
    /// Create a key extractor
    ///
    /// ### Arguments
    /// - `trust_proxy_headers`: Whether `X-Forwarded-For` / `X-Real-Ip` set by a reverse proxy are trusted
    ///
    /// ### Returns
    /// - `ClientIpKeyExtractor`: The configured key extractor
    #[must_use]
    pub const fn new(trust_proxy_headers: bool) -> Self {
        Self {
            trust_proxy_headers,
        }
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    /// Extract the rate-limiting key from a request
    ///
    /// ### Arguments
    /// - `req`: The incoming request
    ///
    /// ### Returns
    /// - `Ok(IpAddr)`: The client IP used as the bucket key
    /// - `Err(GovernorError::UnableToExtractKey)`: No usable address was found
    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let from_headers = if self.trust_proxy_headers {
            rightmost_forwarded_for(req.headers()).or_else(|| real_ip(req.headers()))
        } else {
            None
        };
        from_headers
            .or_else(|| peer_ip(req))
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Parse the rightmost valid address of the `X-Forwarded-For` header
///
/// ### Arguments
/// - `headers`: The request headers
///
/// ### Returns
/// - `Some(IpAddr)`: The last parseable entry across all `X-Forwarded-For` headers
/// - `None`: The header is absent or holds no valid address
fn rightmost_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
        .next_back()
}

/// Parse the `X-Real-Ip` header
///
/// ### Arguments
/// - `headers`: The request headers
///
/// ### Returns
/// - `Some(IpAddr)`: The address carried by the header
/// - `None`: The header is absent or invalid
fn real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_REAL_IP)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
}

/// Read the TCP peer address injected by `into_make_service_with_connect_info`
///
/// ### Arguments
/// - `req`: The incoming request
///
/// ### Returns
/// - `Some(IpAddr)`: The peer IP address
/// - `None`: The server was not built with connect info
fn peer_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "10.0.0.1:4000";

    fn request_with(headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder().uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder.body(()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(PEER.parse::<SocketAddr>().unwrap()));
        req
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn test_untrusted_ignores_forwarded_headers() {
        let extractor = ClientIpKeyExtractor::new(false);
        let req = request_with(&[(X_FORWARDED_FOR, "1.2.3.4"), (X_REAL_IP, "5.6.7.8")]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("10.0.0.1"));
    }

    #[test]
    fn test_trusted_uses_rightmost_forwarded_for_entry() {
        let extractor = ClientIpKeyExtractor::new(true);
        let req = request_with(&[(X_FORWARDED_FOR, "6.6.6.6, 203.0.113.7")]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("203.0.113.7"));
    }

    #[test]
    fn test_trusted_uses_last_forwarded_for_header_line() {
        let extractor = ClientIpKeyExtractor::new(true);
        let req = request_with(&[
            (X_FORWARDED_FOR, "6.6.6.6"),
            (X_FORWARDED_FOR, "203.0.113.7"),
        ]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("203.0.113.7"));
    }

    #[test]
    fn test_trusted_skips_invalid_forwarded_for_entries() {
        let extractor = ClientIpKeyExtractor::new(true);
        let req = request_with(&[(X_FORWARDED_FOR, "203.0.113.7, unknown")]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("203.0.113.7"));
    }

    #[test]
    fn test_trusted_falls_back_to_real_ip() {
        let extractor = ClientIpKeyExtractor::new(true);
        let req = request_with(&[(X_REAL_IP, "2001:db8::1")]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("2001:db8::1"));
    }

    #[test]
    fn test_trusted_falls_back_to_peer_without_headers() {
        let extractor = ClientIpKeyExtractor::new(true);
        let req = request_with(&[]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("10.0.0.1"));
    }

    #[test]
    fn test_missing_connect_info_is_an_error() {
        let extractor = ClientIpKeyExtractor::new(false);
        let req = Request::builder().uri("/").body(()).unwrap();
        assert!(matches!(
            extractor.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }
}
