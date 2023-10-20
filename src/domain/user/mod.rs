mod user_repository;

pub use user_repository::*;

use anyhow::Result;
use argon2::{
    password_hash::{self, rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use email_address::EmailAddress;
use std::{
    convert::Infallible,
    fmt::{self, Debug, Display},
    str::FromStr,
};
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

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

impl Display for Bio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub async fn register<U>(
    user_repository: &U,
    username: Username,
    email: EmailAddress,
    password: Password,
) -> Result<User, RegisterUserError<U::Error>>
where
    U: UserRepository,
{
    let id = Uuid::now_v7();
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(RegisterUserError::PasswordHash)?
        .to_string()
        .into();

    user_repository
        .add_user(id, &username, &email, &password_hash)
        .await?;

    let user = User::new(id, username, email, None);
    info!(?user, "user registered");
    Ok(user)
}

#[derive(Debug, Error)]
pub enum RegisterUserError<E> {
    #[error("email taken")]
    EmailTaken,

    #[error("username taken")]
    UsernameTaken,

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

pub async fn login<U>(
    user_repository: &U,
    email: &EmailAddress,
    password: &Password,
) -> Result<User, LoginError<U::Error>>
where
    U: UserRepository,
{
    let (user, password_hash) = user_repository
        .find_user_and_password_hash_by_email(email)
        .await?
        .ok_or(LoginError::InvalidCredentials)?
        .dissolve();

    let password_hash =
        PasswordHash::new(password_hash.expose_secret()).map_err(LoginError::PasswordHash)?;
    Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &password_hash)
        .map_err(|_| LoginError::InvalidCredentials)?;

    debug!(?user, "user logged in");
    Ok(user)
}

#[derive(Debug, Error)]
pub enum LoginError<E> {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error(transparent)]
    UserRepositoryError(E),

    #[error("{0}")]
    PasswordHash(password_hash::Error),
}

impl<E> From<ImplError<E>> for LoginError<E> {
    fn from(ImplError(error): ImplError<E>) -> Self {
        LoginError::UserRepositoryError(error)
    }
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
}
