use std::collections::HashMap;

use crate::domain::user::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if let Ok(_) = self.get_user(user.email.as_str()) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }
    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        if let Some(user) = self.users.get(email) {
            Ok(user.clone())
        } else {
            Err(UserStoreError::UserNotFound)
        }
    }
    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        if let Ok(user) = self.get_user(email) {
            if user.password == password {
                Ok(())
            } else {
                Err(UserStoreError::InvalidCredentials)
            }
        } else {
            Err(UserStoreError::UserNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_user_should_succeed() {
        let mut user_store = HashmapUserStore::default();
        let user = User {
            email: "test@test.com".to_owned(),
            password: "test123".to_owned(),
            requires_2fa: false,
        };

        let result = user_store.add_user(user);
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn add_user_should_return_error_for_same_email() {
        let mut user_store = HashmapUserStore::default();
        let user = User {
            email: "test@test.com".to_owned(),
            password: "test123".to_owned(),
            requires_2fa: false,
        };

        let result = user_store.add_user(user);
        assert_eq!(result, Ok(()));
        let user2 = User {
            email: "test@test.com".to_owned(),
            password: "abc123".to_owned(),
            requires_2fa: true,
        };
        let result2 = user_store.add_user(user2);
        assert_eq!(result2, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn get_user_should_return_not_found() {
        let user_store = HashmapUserStore::default();
        let email = "test@test.com";

        let result = user_store.get_user(email);
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn get_user_should_return_user() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com";
        let user = User {
            email: email.to_owned(),
            password: "test123".to_owned(),
            requires_2fa: false,
        };

        if let Ok(_) = user_store.add_user(user.clone()) {
            let result = user_store.get_user(email);
            assert_eq!(result, Ok(user));
        }
    }

    #[tokio::test]
    async fn validate_user_should_succeed() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com";
        let password = "test123";
        let user = User {
            email: email.to_owned(),
            password: password.to_owned(),
            requires_2fa: false,
        };

        if let Ok(_) = user_store.add_user(user) {
            let result = user_store.validate_user(email, password);
            assert_eq!(result, Ok(()));
        }
    }

    #[tokio::test]
    async fn validate_user_should_return_invalid_cred_error() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com";
        let password = "test123";
        let user = User {
            email: email.to_owned(),
            password: password.to_owned(),
            requires_2fa: false,
        };

        if let Ok(_) = user_store.add_user(user) {
            let result = user_store.validate_user(email, "abc");
            assert_eq!(result, Err(UserStoreError::InvalidCredentials));
        }
    }

    #[tokio::test]
    async fn validate_user_should_return_user_not_found_error() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com";
        let password = "test123";
        let user = User {
            email: email.to_owned(),
            password: password.to_owned(),
            requires_2fa: false,
        };

        if let Ok(_) = user_store.add_user(user) {
            let result = user_store.validate_user("abc@test.com", password);
            assert_eq!(result, Err(UserStoreError::UserNotFound));
        }
    }
}
