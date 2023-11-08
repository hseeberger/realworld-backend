use crate::domain::{
    user::{Bio, Email, User, UserAndPasswordHash, Username},
    SecretString,
};
use anyhow::Result;
use std::{fmt::Debug, future::Future};
use thiserror::Error;
use uuid::Uuid;

pub trait UserRepository: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn user_by_id(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<Option<User>, ImplError<Self::Error>>> + Send;

    fn find_user_and_password_hash_by_email(
        &self,
        email: &Email,
    ) -> impl Future<Output = Result<Option<UserAndPasswordHash>, ImplError<Self::Error>>> + Send;

    fn add_user(
        &self,
        id: Uuid,
        username: &Username,
        email: &Email,
        password_hash: &SecretString,
    ) -> impl Future<Output = Result<(), AddUserError<Self::Error>>> + Send;

    fn update_user(
        &self,
        id: Uuid,
        username: Option<Username>,
        email: Option<Email>,
        password_hash: Option<SecretString>,
        bio: Option<Option<Bio>>,
    ) -> impl Future<Output = Result<(), UpdateUserError<Self::Error>>> + Send;
}

#[derive(Debug, Error)]
pub enum AddUserError<E> {
    #[error("username taken")]
    UsernameTaken,

    #[error("email taken")]
    EmailTaken,

    #[error(transparent)]
    ImplError(#[from] E),
}

#[derive(Debug, Error)]
pub enum UpdateUserError<E> {
    #[error("username taken")]
    UsernameTaken,

    #[error("email taken")]
    EmailTaken,

    #[error(transparent)]
    ImplError(#[from] E),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ImplError<E>(#[from] pub E);
