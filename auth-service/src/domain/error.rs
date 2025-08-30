use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid Credentials")]
    InvalidCredentials,
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Missing Token")]
    MissingToken,
    #[error("Invalid Token")]
    InvalidToken,
    #[error("Unexpected Error")]
    UnexpectedError(#[source] Report),
}
