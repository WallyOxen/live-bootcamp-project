use crate::helpers::{get_random_email, TestApp};

use auth_service::{
    domain::{data_stores::LoginAttemptId, Email},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
};
use serde_json::json;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
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
        json!({
            "email": random_email,
            "loginAttemptId": "abc1234"
        }),
        json!({
            "email": random_email,
            "loginAttemptId": LoginAttemptId::parse("d5783dff-c1b4-4ae3-81c6-cb71674a0d1e".to_owned()).unwrap()
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(&test_case).await;

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

    let test_cases = [
        json!({
            "email": random_email,
            "loginAttemptId": "d5783dff-c1b4-4ae3-81c6-cb71674a0d1e",
            "2FACode": "1"
        }),
        json!({
            "email": random_email,
            "loginAttemptId": "abc",
            "2FACode": "123456"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .post_verify_2fa(&json!({
            "email": random_email,
            "loginAttemptId": "d5783dff-c1b4-4ae3-81c6-cb71674a0d1e",
            "2FACode": "123456"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": password,
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": password,
    });

    let response = app.post_login(&login_body).await;

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResposne");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let email = Email::parse(random_email.clone()).unwrap();

    let result = app.two_fa_code_store.read().await.get_code(&email).await;

    if let Ok((login_attempt_id, two_fa_code)) = result {
        assert_eq!(json_body.login_attempt_id, login_attempt_id);

        let _ = app.post_login(&login_body).await;

        let response = app
            .post_verify_2fa(&json!({
                "email": random_email,
                "loginAttemptId": login_attempt_id,
                "2FACode": two_fa_code
            }))
            .await;

        assert_eq!(response.status().as_u16(), 401);
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
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

    let email = Email::parse(random_email.clone()).unwrap();

    let result = app.two_fa_code_store.read().await.get_code(&email).await;

    if let Ok((login_attempt_id, two_fa_code)) = result {
        assert_eq!(json_body.login_attempt_id, login_attempt_id);

        let response = app
            .post_verify_2fa(&json!({
                "email": random_email,
                "loginAttemptId": login_attempt_id,
                "2FACode": two_fa_code
            }))
            .await;

        assert_eq!(response.status().as_u16(), 200);

        let auth_cookie = response
            .cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");

        assert!(!auth_cookie.value().is_empty());
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
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

    let email = Email::parse(random_email.clone()).unwrap();

    let result = app.two_fa_code_store.read().await.get_code(&email).await;

    if let Ok((login_attempt_id, two_fa_code)) = result {
        assert_eq!(json_body.login_attempt_id, login_attempt_id);

        let response = app
            .post_verify_2fa(&json!({
                "email": random_email,
                "loginAttemptId": login_attempt_id,
                "2FACode": two_fa_code
            }))
            .await;

        assert_eq!(response.status().as_u16(), 200);

        let auth_cookie = response
            .cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");

        assert!(!auth_cookie.value().is_empty());

        let response = app
            .post_verify_2fa(&json!({
                "email": random_email,
                "loginAttemptId": login_attempt_id,
                "2FACode": two_fa_code
            }))
            .await;

        assert_eq!(response.status().as_u16(), 401);
    }

    app.clean_up().await;
}
