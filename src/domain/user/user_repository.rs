use crate::domain::{
    user::{User, Username},
    SecretString,
};
use anyhow::Result;
use email_address::EmailAddress;
use regex::Regex;
use serde::Deserialize;
use std::{fmt::Debug, future::Future, str::FromStr, sync::LazyLock};
use thiserror::Error;
use uuid::Uuid;

static PASSWORD_ALPHA: LazyLock<Regex> = LazyLock::new(|| {
    let password = r"^.*[A-Za-z].*$";
    Regex::new(password).expect("create regex for numeric password")
});

static PASSWORD_NUMERIC: LazyLock<Regex> = LazyLock::new(|| {
    let password = r"^.*[0-9].*$";
    Regex::new(password).expect("create regex for numeric password")
});

static PASSWORD_SPECIAL: LazyLock<Regex> = LazyLock::new(|| {
    let password = r"^.*[@#$%^&*\-_+=?].*$";
    Regex::new(password).expect("create regex for numeric password")
});

pub trait UserRepository: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn add_user(
        &self,
        id: Uuid,
        username: &Username,
        email: &EmailAddress,
        password_hash: &SecretString,
    ) -> impl Future<Output = Result<(), AddUserError<Self::Error>>> + Send;

    fn find_user_by_id(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<Option<User>, ImplError<Self::Error>>> + Send;

    fn find_user_and_password_hash_by_email(
        &self,
        email: &EmailAddress,
    ) -> impl Future<Output = Result<Option<UserAndPasswordHash>, ImplError<Self::Error>>> + Send;
}

/// A password.
#[derive(Debug, Clone, Deserialize)]
pub struct Password(SecretString);

impl Password {
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl TryFrom<SecretString> for Password {
    type Error = InvalidPassword;

    fn try_from(secret_string: SecretString) -> Result<Self, Self::Error> {
        let s = secret_string.expose_secret();
        if s.len() >= 8
            && PASSWORD_ALPHA.is_match(s)
            && PASSWORD_NUMERIC.is_match(s)
            && PASSWORD_SPECIAL.is_match(s)
        {
            Ok(Self(secret_string))
        } else {
            Err(InvalidPassword)
        }
    }
}

impl FromStr for Password {
    type Err = InvalidPassword;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let secret_string = SecretString::from(s.to_string());
        secret_string.try_into()
    }
}

#[derive(Debug, Error)]
#[error("invalid password: at least eight characters, one character, one digit and one special character out of @#$%^&*-_+=? required")]
pub struct InvalidPassword;

#[derive(Debug, Clone)]
pub struct UserAndPasswordHash {
    user: User,
    password_hash: SecretString,
}

impl UserAndPasswordHash {
    pub fn new(user: User, password_hash: SecretString) -> Self {
        Self {
            user,
            password_hash,
        }
    }

    pub fn dissolve(self) -> (User, SecretString) {
        let Self {
            user,
            password_hash,
        } = self;
        (user, password_hash)
    }
}

#[derive(Debug, Error)]
pub enum AddUserError<E> {
    #[error("email taken")]
    EmailTaken,

    #[error("username taken")]
    UsernameTaken,

    #[error(transparent)]
    ImplError(#[from] E),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ImplError<E>(#[from] pub E);

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches::assert_matches;

    #[test]
    fn test_password_try_from() {
        let password_secret = SecretString::from("a+b-567".to_string());
        assert_matches!(Password::try_from(password_secret), Err(InvalidPassword));

        let password_secret = SecretString::from("a2345678".to_string());
        assert_matches!(Password::try_from(password_secret), Err(InvalidPassword));

        let password_secret = SecretString::from("12345678".to_string());
        assert_matches!(Password::try_from(password_secret), Err(InvalidPassword));

        let password_secret = SecretString::from("abcdefg+".to_string());
        assert_matches!(Password::try_from(password_secret), Err(InvalidPassword));

        for c in "@#$%^&*-_+=?".chars() {
            let password = format!("a{c}2345678");
            let password_secret = SecretString::from(password.clone());
            assert_matches!(
                Password::try_from(password_secret),
                Ok(Password(s)) if s.expose_secret() == password
            );
        }
    }
}
