use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::{self, AppState},
    domain::{
        data_stores::{LoginAttemptId, TwoFACode},
        error::AuthAPIError,
        Email, Password,
    },
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let password = match Password::parse(request.password) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let user_store = state.user_store.write().await;

    if user_store.validate_user(&email, &password).is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let user = match user_store.get_user(&email) {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    match user.requires_2fa {
        true => handle_2fa(&user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let login_attempt_id = match LoginAttemptId::parse(uuid::Uuid::new_v4().to_string()) {
        Ok(id) => id,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };
    let two_fa_code =
        match TwoFACode::parse(format!("{:06}", rand::thread_rng().gen_range(0..100000))) {
            Ok(code) => code,
            Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
        };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    match two_fa_code_store
        .add_code(
            email.to_owned(),
            login_attempt_id.clone(),
            two_fa_code.clone(),
        )
        .await
    {
        Ok(_) => {
            match state
                .email_client
                .read()
                .await
                .send_email(
                    &email,
                    "Two Factor Authentication Code",
                    &format!("Your code is: {:#?}", two_fa_code),
                )
                .await
            {
                Ok(_) => {
                    return (
                        jar,
                        Ok((
                            StatusCode::PARTIAL_CONTENT,
                            axum::Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
                                message: "2FA required".to_owned(),
                                login_attempt_id,
                            })),
                        )),
                    );
                }
                Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
            }
        }
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    }
}

async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::OK, axum::Json(LoginResponse::RegularAuth))),
    )
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: LoginAttemptId,
}
