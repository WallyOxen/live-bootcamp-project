use std::collections::HashMap;

use color_eyre::eyre::eyre;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        if self.codes.contains_key(&email) {
            self.codes.remove(&email);
        }

        match self.codes.insert(email, (login_attempt_id, code)) {
            Some(_) => Err(TwoFACodeStoreError::UnexpectedError(eyre!(
                "failed to insert code into hashset two fa code store"
            ))),
            None => Ok(()),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some((login_attempt_id, two_fa_code)) => {
                Ok((login_attempt_id.to_owned(), two_fa_code.to_owned()))
            }
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {}
