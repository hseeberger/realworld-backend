pub mod user;

use self::user::{AddUserError, ImplError, Password, User, UserRepository, Username};
use anyhow::Result;
use argon2::{
    password_hash::{self, rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use email_address::EmailAddress;
use thiserror::Error;
use uuid::Uuid;

// =================================================================================================
// Model                                                                                           =
// =================================================================================================

use secrecy::ExposeSecret;
use serde::Deserialize;

/// New type for `secrecy::SecretString`.
#[derive(Debug, Clone, Deserialize)]
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

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl Eq for SecretString {}

// =================================================================================================
// Services                                                                                        =
// =================================================================================================

pub async fn register_user<U>(
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

    Ok(user)
}

#[derive(Debug, Error)]
pub enum RegisterUserError<E> {
    #[error("email taken")]
    EmailTaken,

    #[error("username taken")]
    UsernameTaken,

    #[error(transparent)]
    UserRepositoryError(E),

    #[error("{0}")]
    PasswordHash(password_hash::Error),
}

impl<E> From<AddUserError<E>> for RegisterUserError<E> {
    fn from(error: AddUserError<E>) -> Self {
        match error {
            AddUserError::EmailTaken => RegisterUserError::EmailTaken,
            AddUserError::UsernameTaken => RegisterUserError::UsernameTaken,
            AddUserError::ImplError(error) => RegisterUserError::UserRepositoryError(error),
        }
    }
}

pub async fn login_user<U>(
    user_repository: &U,
    email: &EmailAddress,
    password: &Password,
) -> Result<User, LoginUserError<U::Error>>
where
    U: UserRepository,
{
    let (user, password_hash) = user_repository
        .find_user_and_password_hash_by_email(email)
        .await?
        .ok_or(LoginUserError::InvalidCredentials)?
        .dissolve();

    let password_hash =
        PasswordHash::new(password_hash.expose_secret()).map_err(LoginUserError::PasswordHash)?;
    Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &password_hash)
        .map_err(|_| LoginUserError::InvalidCredentials)?;

    Ok(user)
}

#[derive(Debug, Error)]
pub enum LoginUserError<E> {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error(transparent)]
    UserRepositoryError(E),

    #[error("{0}")]
    PasswordHash(password_hash::Error),
}

impl<E> From<ImplError<E>> for LoginUserError<E> {
    fn from(ImplError(error): ImplError<E>) -> Self {
        LoginUserError::UserRepositoryError(error)
    }
}

#[cfg(test)]
mod tests {

    // #[test]
    // fn test_register_user() {
    //     todo!()
    // }
}
