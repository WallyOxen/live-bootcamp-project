#[derive(Clone, Debug, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, PasswordParseError> {
        if password.len() < 8 {
            return Err(PasswordParseError::PasswordTooShort);
        }
        Ok(Password(password))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Debug)]
pub enum PasswordParseError {
    PasswordTooShort,
}
