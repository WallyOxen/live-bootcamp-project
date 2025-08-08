#[derive(Clone, Debug, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, String> {
        if validate_password(&password) {
            Ok(Password(password))
        } else {
            Err("Failed to parse string to Password type".to_owned())
        }
    }
}

fn validate_password(s: &str) -> bool {
    s.len() >= 8
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    #[test]
    fn empty_string_is_rejected() {
        let password = "".to_string();
        assert!(Password::parse(password).is_err());
    }

    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = "1234567".to_string();
        assert!(Password::parse(password).is_err());
    }
}
