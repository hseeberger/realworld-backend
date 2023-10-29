pub mod user_repository;

use self::user_repository::{AddUserError, ImplError, UserRepository};
use crate::domain::SecretString;
use anyhow::Result;
use argon2::{
    password_hash::{self, rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use email_address::EmailAddress;
use regex::Regex;
use serde::Deserialize;
use std::{
    convert::Infallible,
    fmt::{self, Debug, Display},
    ops::Deref,
    str::FromStr,
    sync::LazyLock,
};
use thiserror::Error;
use tracing::{debug, info};
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

impl Deref for Bio {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Bio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
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

pub struct UserService<U> {
    user_repository: U,
}

impl<U> UserService<U>
where
    U: UserRepository,
{
    pub fn new(user_repository: U) -> Self {
        Self { user_repository }
    }

    pub async fn user_by_id(&self, id: Uuid) -> Result<User, GetUserError<U::Error>>
    where
        U: UserRepository,
    {
        self.user_repository
            .user_by_id(id)
            .await?
            .ok_or_else(|| GetUserError::UnknownUser(id))
    }

    pub async fn update_user(
        &self,
        id: Uuid,
        username: Option<Username>,
        email: Option<EmailAddress>,
        password: Option<Password>,
        bio: Option<Option<Bio>>,
    ) -> Result<User, UpdateUserError<U::Error>> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = password
            .map(|password| {
                Argon2::default()
                    .hash_password(password.expose_secret().as_bytes(), &salt)
                    .map_err(UpdateUserError::PasswordHash)
            })
            .transpose()?
            .map(|x| x.to_string().into());

        self.user_repository
            .update_user(id, username, email, password_hash, bio)
            .await?;

        let user = self.user_by_id(id).await?;

        Ok(user)
    }

    pub async fn register_user(
        &self,
        username: Username,
        email: EmailAddress,
        password: Password,
    ) -> Result<User, RegisterUserError<U::Error>> {
        let id = Uuid::now_v7();
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map_err(RegisterUserError::PasswordHash)?
            .to_string()
            .into();

        self.user_repository
            .add_user(id, &username, &email, &password_hash)
            .await?;

        let user = User::new(id, username, email, None);
        info!(?user, "user registered");
        Ok(user)
    }

    pub async fn login_user(
        &self,
        email: &EmailAddress,
        password: &Password,
    ) -> Result<User, LoginError<U::Error>> {
        let (user, password_hash) = self
            .user_repository
            .find_user_and_password_hash_by_email(email)
            .await?
            .ok_or(LoginError::UnknownUser(email.to_owned()))?
            .dissolve();

        let password_hash =
            PasswordHash::new(password_hash.expose_secret()).map_err(LoginError::PasswordHash)?;
        Argon2::default()
            .verify_password(password.expose_secret().as_bytes(), &password_hash)
            .map_err(|_| LoginError::InvalidCredentials)?;

        debug!(?user, "user logged in");
        Ok(user)
    }
}

#[derive(Debug, Error)]
pub enum GetUserError<E> {
    #[error("unknown user for ID {0}")]
    UnknownUser(Uuid),

    #[error(transparent)]
    UserRepository(#[from] ImplError<E>),
}

#[derive(Debug, Error)]
pub enum UpdateUserError<E> {
    #[error("unknown user for ID {0}")]
    UnknownUser(Uuid),

    #[error("username taken")]
    UsernameTaken,

    #[error("email taken")]
    EmailTaken,

    #[error(transparent)]
    UserRepository(#[from] E),

    #[error("{0}")]
    PasswordHash(password_hash::Error),
}

impl<E> From<user_repository::UpdateUserError<E>> for UpdateUserError<E> {
    fn from(error: user_repository::UpdateUserError<E>) -> Self {
        match error {
            user_repository::UpdateUserError::UsernameTaken => UpdateUserError::UsernameTaken,
            user_repository::UpdateUserError::EmailTaken => UpdateUserError::EmailTaken,
            user_repository::UpdateUserError::ImplError(error) => {
                UpdateUserError::UserRepository(error)
            }
        }
    }
}

impl<E> From<GetUserError<E>> for UpdateUserError<E> {
    fn from(error: GetUserError<E>) -> Self {
        match error {
            GetUserError::UnknownUser(id) => UpdateUserError::UnknownUser(id),
            GetUserError::UserRepository(ImplError(error)) => {
                UpdateUserError::UserRepository(error)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum RegisterUserError<E> {
    #[error("username taken")]
    UsernameTaken,

    #[error("email taken")]
    EmailTaken,

    #[error(transparent)]
    UserRepository(E),

    #[error("{0}")]
    PasswordHash(password_hash::Error),
}

impl<E> From<AddUserError<E>> for RegisterUserError<E> {
    fn from(error: AddUserError<E>) -> Self {
        match error {
            AddUserError::EmailTaken => RegisterUserError::EmailTaken,
            AddUserError::UsernameTaken => RegisterUserError::UsernameTaken,
            AddUserError::ImplError(error) => RegisterUserError::UserRepository(error),
        }
    }
}

#[derive(Debug, Error)]
pub enum LoginError<E> {
    #[error("unknown user for email {0}")]
    UnknownUser(EmailAddress),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error(transparent)]
    UserRepository(#[from] ImplError<E>),

    #[error("{0}")]
    PasswordHash(password_hash::Error),
}

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
