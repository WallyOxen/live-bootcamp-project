use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

use auth_service::{routes::SignupResponse, ErrorResponse};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        json!({
            "password": "password123",
            "requires2FA": true
        }),
        json!({
            "email": random_email,
            "requires2FA": true
        }),
        json!({
            "email": random_email,
            "password": "password123",
        }),
        json!({
            "password": "password123"
        }),
        json!({
            "password": true,
            "requires2FA": true
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
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .post_signup(&json!({
            "email": random_email,
            "password": "test123456",
            "requires2FA": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to SignupResponse"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        json!({
            "email": "testing.com", // No @ email
            "password": "test123456",
            "requires2FA": true
        }),
        json!({
            "email": "t@t.com", // Too short
            "password": "test123456",
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    let user = json!({
        "email": "test@test.com",
        "password": "test123456",
        "requires2FA": true
    });

    let response = app.post_signup(&user).await;

    assert_eq!(response.status().as_u16(), 201);

    let response2 = app.post_signup(&user).await;

    assert_eq!(response2.status().as_u16(), 409);

    assert_eq!(
        response2
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to Error Response")
            .error,
        "User already exists".to_owned()
    );
}
