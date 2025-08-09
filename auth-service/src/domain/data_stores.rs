use crate::domain::{email::Email, password::Password};

use super::user::User;

#[async_trait::async_trait]
pub trait UserStore {
    fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    fn add_token(&mut self, token: String) -> Result<(), String>;
    fn get_token(&self, token: String) -> bool;
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}
