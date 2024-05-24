pub mod user;

use secrecy::ExposeSecret;
use serde::Deserialize;

/// New type for `secrecy::SecretString`.
#[derive(Debug, Deserialize)]
pub struct SecretString(secrecy::SecretString);

impl SecretString {
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(secrecy::SecretString::new(s))
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        s.to_owned().into()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl Eq for SecretString {}
