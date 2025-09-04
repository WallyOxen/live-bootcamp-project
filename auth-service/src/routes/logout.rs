use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::Secret;

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = Secret::new(cookie.value().to_owned());

    let _ = match validate_token(&token, state.banned_token_store.clone()).await {
        Ok(claims) => claims,
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    };

    let mut banned_token_store = state.banned_token_store.write().await;
    match banned_token_store.add_token(token).await {
        Ok(_) => (),
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }

    let updated_jar = jar.remove(JWT_COOKIE_NAME);

    (updated_jar, Ok(StatusCode::OK))
}
