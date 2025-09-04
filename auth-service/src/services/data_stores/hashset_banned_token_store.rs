use std::collections::HashSet;

use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, Secret};

use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    pub tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        if self.tokens.insert(token.expose_secret().to_owned()) == true {
            Ok(())
        } else {
            Err(BannedTokenStoreError::UnexpectedError(eyre!(
                "failed to insert banned token into hashset banned token store"
            )))
        }
    }

    async fn contains_token(&self, token: Secret<String>) -> Result<bool, BannedTokenStoreError> {
        match self.tokens.get(token.expose_secret()) {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_token_should_succeed() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        let result = banned_token_store
            .add_token(Secret::new("TestToken".to_string()))
            .await;
        assert_eq!(result, Ok(()))
    }

    #[tokio::test]
    async fn get_token_should_return_true_if_token_exists() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        let result = banned_token_store
            .add_token(Secret::new("TestToken".to_string()))
            .await
            .unwrap();
        assert_eq!(result, ());

        let result = banned_token_store
            .contains_token(Secret::new("TestToken".to_string()))
            .await;
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn get_token_should_return_false_if_token_does_not_exist() {
        let banned_token_store = HashsetBannedTokenStore::default();

        let result = banned_token_store
            .contains_token(Secret::new("TestToken".to_string()))
            .await;
        assert_eq!(result, Ok(false));
    }
}
