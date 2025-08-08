use validator::ValidateEmail;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, String> {
        if email.validate_email() {
            Ok(Self(email))
        } else {
            Err(format!("{} is not a valid email", email))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    #[test]
    fn empty_string_is_rejected() {
        let email = "".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = "persondomain.com".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_missing_subject_is_rejected() {
        let email = "@domain.com".to_string();
        assert!(Email::parse(email).is_err());
    }
}
