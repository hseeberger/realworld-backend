//! A repository (DDD) for users.

use crate::domain::user::{EmailAddress, User, Username};
use argon2::password_hash::PasswordHashString;
use nutype::nutype;
use std::{
    collections::HashSet,
    error::Error as StdError,
    fmt::Debug,
    hash::{Hash, Hasher},
};
use thiserror::Error;
use uuid::Uuid;

/// A repository (DDD) for users.
#[trait_variant::make(Send)]
pub trait UserRepository
where
    Self: Clone + Send + Sync + 'static,
{
    type InfraError: StdError;

    /// Add a user with the given attributes.
    async fn add_user(
        &self,
        id: Uuid,
        username: &Username,
        email_address: &EmailAddress,
        password_hash: &PasswordHash,
    ) -> Result<(), Error<AddUserError, Self::InfraError>>;

    /// Update the user with the given ID with the give attributes.
    async fn update_user(
        &self,
        id: Uuid,
        attributes: HashSet<UserAttribute>,
    ) -> Result<User, Error<UpdateUserError, Self::InfraError>>;

    /// Get the user with the given ID.
    async fn get_user_by_id(
        &self,
        id: Uuid,
    ) -> Result<User, Error<GetUserByIdError, Self::InfraError>>;

    /// Get the user and its password hash for the given email address.
    async fn get_user_and_pwh_by_email_address(
        &self,
        email_address: &EmailAddress,
    ) -> Result<(User, PasswordHash), Error<GetUserAndPwhByEmailAddressError, Self::InfraError>>;
}

/// A user attribute, e.g. its username.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserAttribute {
    Username(Username),
    EmailAddress(EmailAddress),
    PasswordHash(PasswordHash),
}

/// A password hash.
#[nutype(derive(Debug, Display, Clone, PartialEq, Eq, From, Deref))]
pub struct PasswordHash(PasswordHashString);

impl Hash for PasswordHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

/// Domain and infra/implementation errors for the user repository.
#[derive(Debug, Error)]
pub enum Error<D, I> {
    /// A domain error.
    #[error(transparent)]
    Domain(D),

    /// An infra/implementation error.
    #[error(transparent)]
    Infra(I),
}

/// Possible errors for for adding a user.
#[derive(Debug, Error)]
pub enum AddUserError {
    #[error("username {0} taken")]
    UsernameTaken(Username),

    #[error("email address {0} taken")]
    EmailAddressTaken(EmailAddress),
}

/// Possible errors for for updating a user.
#[derive(Debug, Error)]
pub enum UpdateUserError {
    #[error("user with ID {0} not found")]
    NotFound(Uuid),

    #[error("username taken")]
    UsernameTaken,

    #[error("email address taken")]
    EmailAddressTaken,
}

/// Possible errors for for getting a user by ID.
#[derive(Debug, Error)]
pub enum GetUserByIdError {
    /// A user with the given ID cannot be found.
    #[error("user with ID {0} not found")]
    NotFound(Uuid),
}

/// Possible errors for for getting a user by email address.
#[derive(Debug, Error)]
pub enum GetUserAndPwhByEmailAddressError {
    /// A user with the given email address cannot be found.
    #[error("user with email address {0} not found")]
    NotFound(EmailAddress),
}
