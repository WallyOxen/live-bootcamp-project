use crate::domain::{email::Email, password::Password};

#[derive(Clone, Debug, PartialEq)]
pub struct User {
    email: Email,
    password: Password,
    requires_2fa: bool,
}

impl User {
    pub fn parse(
        email: String,
        password: String,
        requires_2fa: bool,
    ) -> Result<Self, UserParseError> {
        if let Ok(email) = Email::parse(email) {
            if let Ok(password) = Password::parse(password) {
                return Ok(User {
                    email,
                    password,
                    requires_2fa,
                });
            } else {
                return Err(UserParseError::CannotParsePassword);
            }
        } else {
            return Err(UserParseError::CannotParseEmail);
        }
    }

    pub fn get_email(&self) -> &Email {
        &self.email
    }

    pub fn get_password(&self) -> &Password {
        &self.password
    }
}

pub enum UserParseError {
    CannotParseEmail,
    CannotParsePassword,
}
