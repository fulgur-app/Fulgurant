use axum::{
    extract::Request,
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;

/// Per-request CSP nonce used to authorize inline scripts/styles.
#[derive(Clone, Debug)]
pub struct CspNonce(pub String);

/// Build a fresh CSP nonce value.
///
/// ### Returns:
/// - `String`: URL-safe Base64 nonce string without padding
fn generate_csp_nonce() -> String {
    let mut nonce_bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut nonce_bytes);
    URL_SAFE_NO_PAD.encode(nonce_bytes)
}

/// Attach a CSP nonce to request extensions and set a nonce-based CSP header.
///
/// ### Arguments:
/// - `request`: Incoming HTTP request
/// - `next`: Next middleware/handler in the chain
///
/// ### Returns:
/// - `Response`: Response with `Content-Security-Policy` header set
pub async fn add_csp_nonce_and_header(mut request: Request, next: Next) -> Response {
    let nonce = generate_csp_nonce();
    request.extensions_mut().insert(CspNonce(nonce.clone()));

    let mut response = next.run(request).await;
    let csp_value = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}' https://unpkg.com; style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';",
    );

    if let Ok(header_value) = HeaderValue::from_str(&csp_value) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, header_value);
    }

    response
}
