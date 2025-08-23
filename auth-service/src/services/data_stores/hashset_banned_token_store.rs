use std::collections::HashSet;

use crate::domain::data_stores::BannedTokenStore;

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    pub tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    fn add_token(&mut self, token: String) -> Result<(), String> {
        if self.tokens.insert(token) == true {
            Ok(())
        } else {
            Err("There was a problem inserting the banned token".to_string())
        }
    }

    fn get_token(&self, token: String) -> bool {
        match self.tokens.get(&token) {
            Some(_) => true,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_token_should_succeed() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        let result = banned_token_store.add_token("TestToken".to_string());
        assert_eq!(result, Ok(()))
    }

    #[test]
    fn get_token_should_return_true_if_token_exists() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        let result = banned_token_store
            .add_token("TestToken".to_string())
            .unwrap();
        assert_eq!(result, ());

        let result = banned_token_store.get_token("TestToken".to_string());
        assert_eq!(result, true);
    }

    #[test]
    fn get_token_should_return_false_if_token_does_not_exist() {
        let banned_token_store = HashsetBannedTokenStore::default();

        let result = banned_token_store.get_token("TestToken".to_string());
        assert_eq!(result, false);
    }
}
