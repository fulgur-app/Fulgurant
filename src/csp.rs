use axum::{
    extract::Request,
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};

/// Set a static Content-Security-Policy header (no inline scripts/styles needed).
///
/// ### Arguments:
/// - `request`: Incoming HTTP request
/// - `next`: Next middleware/handler in the chain
///
/// ### Returns:
/// - `Response`: Response with `Content-Security-Policy` header set
pub async fn add_csp_header(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';"
        ),
    );
    response
}
