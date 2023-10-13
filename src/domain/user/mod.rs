use crate::domain::SecretString;
use anyhow::Result;
use email_address::EmailAddress;
use regex::Regex;
use serde::Deserialize;
use std::{
    convert::Infallible,
    fmt::{self, Debug, Display},
    future::Future,
    str::FromStr,
    sync::LazyLock,
};
use thiserror::Error;
use uuid::Uuid;

// =================================================================================================
// Model                                                                                           =
// =================================================================================================

// User ============================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    id: Uuid,
    username: Username,
    email: EmailAddress,
    bio: Option<Bio>,
}

impl User {
    pub fn new(id: Uuid, username: Username, email: EmailAddress, bio: Option<Bio>) -> Self {
        Self {
            id,
            username,
            email,
            bio,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn dissolve(self) -> (Uuid, Username, EmailAddress, Option<Bio>) {
        let Self {
            id,
            username,
            email,
            bio,
        } = self;
        (id, username, email, bio)
    }
}

// UserAndPasswordHash =============================================================================

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

// Username ========================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username(String);

impl TryFrom<String> for Username {
    type Error = InvalidUsername;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() >= 3 {
            Ok(Self(s))
        } else {
            Err(InvalidUsername(s))
        }
    }
}

impl FromStr for Username {
    type Err = InvalidUsername;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

impl From<Username> for String {
    fn from(username: Username) -> Self {
        username.0
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Error)]
#[error("invalid username {0}: length must be 3 or more characters")]
pub struct InvalidUsername(String);

// Bio =============================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bio(String);

impl TryFrom<String> for Bio {
    type Error = Infallible;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Self(s))
    }
}

impl FromStr for Bio {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

impl From<Bio> for String {
    fn from(username: Bio) -> Self {
        username.0
    }
}

impl AsRef<str> for Bio {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for Bio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Password ========================================================================================

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

// =================================================================================================
// Services                                                                                        =
// =================================================================================================

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
    fn test_username_try_from() {
        let username_str = "ab".to_string();
        assert_matches!(
            Username::try_from(username_str.clone()),
            Err(InvalidUsername(u)) if u == username_str
        );

        let username_str = "abc".to_string();
        assert_matches!(
            Username::try_from(username_str.clone()),
            Ok(Username(u)) if u == username_str
        );
    }

    #[test]
    fn test_username_from_str() {
        let username_str = "ab";
        assert_matches!(Username::from_str(username_str), Err(InvalidUsername(u)) if u == username_str);

        let username_str = "abc";
        assert_matches!(Username::from_str(username_str), Ok(Username(u)) if u == username_str);
    }

    #[test]
    fn test_string_from_username() {
        let username_str = "abc";
        assert_eq!(
            String::from(Username::from_str(username_str).unwrap()),
            username_str
        );
    }

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
