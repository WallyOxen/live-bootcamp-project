use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{email::Email, error::AuthAPIError, user::User},
};

pub async fn signup(
    state: State<AppState>,
    Json(request): Json<SignupRequest>,
) -> impl IntoResponse {
    let email = request.email;
    let password = request.password;

    if let Ok(user) = User::parse(email.clone(), password, request.requires_2fa) {
        let mut user_store = state.user_store.write().await;

        if let Ok(_) = user_store.get_user(&Email::parse(email).unwrap()) {
            return Err(AuthAPIError::UserAlreadyExists);
        }

        if let Err(_) = user_store.add_user(user) {
            return Err(AuthAPIError::UnexpectedError);
        }

        let response = Json(SignupResponse {
            message: "User created successfully!".to_string(),
        });

        Ok((StatusCode::CREATED, response))
    } else {
        return Err(AuthAPIError::InvalidCredentials);
    }
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
