use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{error::AuthAPIError, user::User},
};

pub async fn signup(
    state: State<AppState>,
    Json(request): Json<SignupRequest>,
) -> impl IntoResponse {
    let email = request.email;
    let password = request.password;

    if email.len() < 8 || !email.contains("@") {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user = User {
        email: email.clone(),
        password,
        requires_2fa: request.requires_2fa,
    };

    let mut user_store = state.user_store.write().await;

    if let Ok(_) = user_store.get_user(email.as_str()) {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    if let Err(_) = user_store.add_user(user) {
        return Err(AuthAPIError::UnexpectedError);
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SignupResponse {
    pub message: String,
}
