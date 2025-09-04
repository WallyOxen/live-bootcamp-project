use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};
use secrecy::{ExposeSecret, Secret};
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;

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
            "password": "password123"
        }),
        json!({
            "password": true
        }),
        json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResposne");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let email = Email::parse(Secret::new(random_email)).unwrap();

    let result = app.two_fa_code_store.read().await.get_code(&email).await;

    if let Ok((login_attempt_id, _)) = result {
        assert_eq!(
            json_body.login_attempt_id,
            login_attempt_id.as_ref().expose_secret().to_owned()
        );
    }

    app.clean_up().await;
}
