use std::collections::HashMap;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    email::Email,
    password::Password,
    user::User,
};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if let Ok(_) = self.get_user(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }
    fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        if let Some(user) = self.users.get(email) {
            Ok(user.clone())
        } else {
            Err(UserStoreError::UserNotFound)
        }
    }
    fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        if let Ok(user) = self.get_user(email) {
            if user.password.eq(password) {
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
        let user = User::new(
            Email::parse("test@test.com".to_owned()).unwrap(),
            Password::parse("test123456".to_owned()).unwrap(),
            false,
        );
        let result = user_store.add_user(user);
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn add_user_should_return_error_for_same_email() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@test.com".to_owned()).unwrap(),
            Password::parse("test123456".to_owned()).unwrap(),
            false,
        );
        let result = user_store.add_user(user);
        assert_eq!(result, Ok(()));

        let user2 = User::new(
            Email::parse("test@test.com".to_owned()).unwrap(),
            Password::parse("abc123456".to_owned()).unwrap(),
            true,
        );
        let result2 = user_store.add_user(user2);
        assert_eq!(result2, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn get_user_should_return_not_found() {
        let user_store = HashmapUserStore::default();
        let email = Email::parse("test@test.com".to_owned()).unwrap();

        let result = user_store.get_user(&email);
        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn get_user_should_return_user() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com".to_owned();

        let user = User::new(
            Email::parse(email.clone()).unwrap(),
            Password::parse("abc123456".to_owned()).unwrap(),
            true,
        );
        if let Ok(_) = user_store.add_user(user.clone()) {
            let result = user_store.get_user(&Email::parse(email).unwrap());
            assert_eq!(result, Ok(user));
        }
    }

    #[tokio::test]
    async fn validate_user_should_succeed() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com".to_owned();
        let password = "abc123456".to_owned();
        let user = User::new(
            Email::parse(email.clone()).unwrap(),
            Password::parse(password.clone()).unwrap(),
            false,
        );
        if let Ok(_) = user_store.add_user(user) {
            let result = user_store.validate_user(
                &Email::parse(email).unwrap(),
                &Password::parse(password).unwrap(),
            );
            assert_eq!(result, Ok(()));
        }
    }

    #[tokio::test]
    async fn validate_user_should_return_invalid_cred_error() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com".to_owned();
        let password = "abc123456".to_owned();
        let user = User::new(
            Email::parse(email.clone()).unwrap(),
            Password::parse(password).unwrap(),
            true,
        );
        if let Ok(_) = user_store.add_user(user) {
            let result = user_store.validate_user(
                &Email::parse(email).unwrap(),
                &Password::parse("abc654321".to_owned()).unwrap(),
            );
            assert_eq!(result, Err(UserStoreError::InvalidCredentials));
        }
    }

    #[tokio::test]
    async fn validate_user_should_return_user_not_found_error() {
        let mut user_store = HashmapUserStore::default();
        let email = "test@test.com".to_owned();
        let password = "abc123456".to_owned();
        let user = User::new(
            Email::parse(email).unwrap(),
            Password::parse(password.clone()).unwrap(),
            true,
        );
        if let Ok(_) = user_store.add_user(user) {
            let result = user_store.validate_user(
                &Email::parse("abc@test.com".to_owned()).unwrap(),
                &Password::parse(password).unwrap(),
            );
            assert_eq!(result, Err(UserStoreError::UserNotFound));
        }
    }
}
