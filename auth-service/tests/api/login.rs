use auth_service::utils::constants::JWT_COOKIE_NAME;
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        json!({
            "password": "password123",
            "requires2FA": true
        }),
        json!({
            "email": random_email
        }),
        json!({
            "email": random_email,
            "password": "password123",
        }),
        json!({
            "password": "password123"
        }),
        json!({
            "password": true
        }),
        json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "test123456";

    let signup_response = app
        .post_signup(&json!({
            "email": random_email,
            "password": password,
            "requires2FA": true
        }))
        .await;

    assert_eq!(signup_response.status().as_u16(), 201);

    let login_response = app
        .post_login(&json!({
            "email": random_email,
            "password": "avc"
        }))
        .await;

    assert_eq!(login_response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "test123456";

    let signup_response = app
        .post_signup(&json!({
            "email": random_email,
            "password": password,
            "requires2FA": true
        }))
        .await;

    assert_eq!(signup_response.status().as_u16(), 201);

    let login_response = app
        .post_login(&json!({
            "email": random_email,
            "password": "testing12345"
        }))
        .await;

    assert_eq!(login_response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}
