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
