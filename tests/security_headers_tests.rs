mod common;

use axum::http::header::{AUTHORIZATION, HeaderValue};
use axum_test::TestResponse;
use common::{api_helpers::setup_api_user, auth_helpers::extract_csrf_token, test_app::TestApp};
use serde::Serialize;

#[derive(Serialize)]
struct LoginFormData<'a> {
    email: &'a str,
    password: &'a str,
}

/// Assert that the response carries every security header applied by `build_app`
fn assert_security_headers(response: &TestResponse) {
    assert_eq!(response.header("x-frame-options"), "DENY");
    assert_eq!(response.header("x-content-type-options"), "nosniff");
    assert_eq!(response.header("x-xss-protection"), "0");
    assert_eq!(
        response.header("referrer-policy"),
        "strict-origin-when-cross-origin"
    );
    assert_eq!(
        response.header("strict-transport-security"),
        "max-age=31536000; includeSubDomains"
    );
    let csp = response.header("content-security-policy");
    let csp = csp.to_str().unwrap();
    assert!(csp.contains("frame-src 'none'"));
    assert!(csp.contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn test_security_headers_on_web_page() {
    let app = TestApp::new().await;

    let response = app.server.get("/login").await;

    assert_security_headers(&response);
}

#[tokio::test]
async fn test_security_headers_on_auth_route() {
    let app = TestApp::new().await;
    let page = app.server.get("/login").await;
    let token = extract_csrf_token(&page.text());

    let response = app
        .server
        .post("/login")
        .add_header("x-csrf-token", token)
        .form(&LoginFormData {
            email: "nobody@test.com",
            password: "Password123!",
        })
        .await;

    assert_security_headers(&response);
}

#[tokio::test]
async fn test_security_headers_on_api_route() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let response = app
        .server
        .get("/api/ping")
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
        )
        .await;

    assert_security_headers(&response);
}

#[tokio::test]
async fn test_security_headers_on_healthz() {
    let app = TestApp::new().await;

    let response = app.server.get("/healthz").await;

    assert_security_headers(&response);
}

#[tokio::test]
async fn test_security_headers_on_not_found_fallback() {
    let app = TestApp::new().await;

    let response = app.server.get("/does-not-exist").expect_failure().await;

    assert_security_headers(&response);
}

#[tokio::test]
async fn test_security_headers_on_static_assets() {
    let app = TestApp::new().await;

    let response = app.server.get("/assets/favicon.svg").await;

    assert_security_headers(&response);
}
