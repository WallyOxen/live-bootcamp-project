#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, EmailParseError> {
        if email.len() < 8 {
            return Err(EmailParseError::EmailTooShort);
        }
        if !email.contains("@") {
            return Err(EmailParseError::EmailMustContainAtSymbol);
        }
        if !email.contains(".") {
            return Err(EmailParseError::EmailMustContainPeriod);
        }
        Ok(Email(email))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Debug)]
pub enum EmailParseError {
    EmailTooShort,
    EmailMustContainAtSymbol,
    EmailMustContainPeriod,
}
