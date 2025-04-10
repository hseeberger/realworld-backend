//! A user service.

use crate::domain::{
    user::{EmailAddress, Password, User, Username},
    user_repository::{self, PasswordHash, UserAttribute, UserRepository},
};
use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use secrecy::ExposeSecret;
use std::{collections::HashSet, convert::Infallible};
use thiserror::Error;
use uuid::Uuid;

/// A service (DDD) for users.
#[trait_variant::make(Send)]
pub trait UserService {
    type InfraError;

    /// Register a user with the given username, email address and password.
    async fn register(
        &self,
        username: Username,
        email_address: EmailAddress,
        password: Password,
    ) -> Result<User, Error<Infallible, user_repository::AddUserError, Self::InfraError>>;

    /// Login a user with the given username and password.
    async fn login(
        &self,
        email_address: &EmailAddress,
        password: &Password,
    ) -> Result<
        User,
        Error<LoginError, user_repository::GetUserAndPwhByEmailAddressError, Self::InfraError>,
    >;

    /// Get the user with the given ID.
    async fn get_user_by_id(
        &self,
        id: Uuid,
    ) -> Result<User, Error<Infallible, user_repository::GetUserByIdError, Self::InfraError>>;

    async fn update_user(
        &self,
        id: Uuid,
        username: Option<Username>,
        email_address: Option<EmailAddress>,
        password: Option<Password>,
    ) -> Result<User, Error<Infallible, user_repository::UpdateUserError, Self::InfraError>>;
}

/// A user service using a user repository.
#[derive(Debug, Clone)]
pub struct UserRepositoryUserService<R> {
    user_repository: R,
    argon_2: Argon2<'static>,
}

impl<R> UserRepositoryUserService<R> {
    #[allow(missing_docs)]
    pub fn new(user_repository: R) -> Self {
        let argon_2 = Argon2::default();

        Self {
            user_repository,
            argon_2,
        }
    }
}

impl<R> UserService for UserRepositoryUserService<R>
where
    R: UserRepository,
{
    type InfraError = R::InfraError;

    async fn register(
        &self,
        username: Username,
        email_address: EmailAddress,
        password: Password,
    ) -> Result<User, Error<Infallible, user_repository::AddUserError, R::InfraError>> {
        let user = User {
            id: Uuid::now_v7(),
            username,
            email_address,
        };

        let password_hash = self.hash_password(&password);

        self.user_repository
            .add_user(user.id, &user.username, &user.email_address, &password_hash)
            .await?;

        Ok(user)
    }

    async fn login(
        &self,
        email_address: &EmailAddress,
        password: &Password,
    ) -> Result<
        User,
        Error<LoginError, user_repository::GetUserAndPwhByEmailAddressError, R::InfraError>,
    > {
        let (user, password_hash) = self
            .user_repository
            .get_user_and_pwh_by_email_address(email_address)
            .await?;

        let valid_password = self
            .argon_2
            .verify_password(
                password.expose_secret().as_bytes(),
                &password_hash.password_hash(),
            )
            .is_ok();
        if !valid_password {
            return Err(Error::Domain(LoginError::InvalidPassword(
                email_address.to_owned(),
            )));
        }

        Ok(user)
    }

    async fn get_user_by_id(
        &self,
        id: Uuid,
    ) -> Result<User, Error<Infallible, user_repository::GetUserByIdError, Self::InfraError>> {
        let user = self.user_repository.get_user_by_id(id).await?;
        Ok(user)
    }

    async fn update_user(
        &self,
        id: Uuid,
        username: Option<Username>,
        email_address: Option<EmailAddress>,
        password: Option<Password>,
    ) -> Result<User, Error<Infallible, user_repository::UpdateUserError, Self::InfraError>> {
        let username = username.map(UserAttribute::Username);
        let email_address = email_address.map(UserAttribute::EmailAddress);
        let password_hash = password.map(|p| UserAttribute::PasswordHash(self.hash_password(&p)));

        let attributes = [username, email_address, password_hash]
            .into_iter()
            .flatten()
            .collect::<HashSet<_>>();

        let user = self.user_repository.update_user(id, attributes).await?;

        Ok(user)
    }
}

impl<R> UserRepositoryUserService<R> {
    fn hash_password(&self, password: &Password) -> PasswordHash {
        self.argon_2
            .hash_password(
                password.expose_secret().as_bytes(),
                &SaltString::generate(&mut OsRng),
            )
            .expect("password can be hashed")
            .serialize()
            .into()
    }
}

/// Domain, repository and infra errors for the user service.
#[derive(Debug, Error)]
pub enum Error<D, R, I> {
    /// A domain error.
    #[error(transparent)]
    Domain(D),

    /// A repository error.
    #[error(transparent)]
    Repository(R),

    /// An infra/implementation error.
    #[error(transparent)]
    Infra(I),
}

impl<D, R, I> From<user_repository::Error<R, I>> for Error<D, R, I> {
    fn from(error: user_repository::Error<R, I>) -> Self {
        match error {
            user_repository::Error::Domain(r) => Self::Repository(r),
            user_repository::Error::Infra(i) => Self::Infra(i),
        }
    }
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("invalid password for login with email address {0}")]
    InvalidPassword(EmailAddress),
}

#[cfg(test)]
mod tests {
    #![allow(unused)]

    use crate::domain::{
        user::{EmailAddress, Password, User, Username},
        user_repository::{
            self, AddUserError, GetUserAndPwhByEmailAddressError, GetUserByIdError, PasswordHash,
            UpdateUserError, UserAttribute, UserRepository,
        },
        user_service::{Error, LoginError, UserRepositoryUserService, UserService},
    };
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };
    use assert_matches::assert_matches;
    use secrecy::ExposeSecret;
    use std::{
        collections::HashSet, convert::Infallible, error::Error as StdError, sync::LazyLock,
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn test_register() -> Result<(), Box<dyn StdError>> {
        let user_repository = MockUserRepository;
        let user_service = UserRepositoryUserService::new(user_repository);

        let result = user_service
            .register(
                USER.username.to_owned(),
                USER.email_address.to_owned(),
                PASSWORD.to_owned(),
            )
            .await;
        assert_matches!(
            result,
            Ok(user) if user.username == USER.username && user.email_address == USER.email_address
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_login() -> Result<(), Box<dyn StdError>> {
        let user_repository = MockUserRepository;
        let user_service = UserRepositoryUserService::new(user_repository);

        let email_address = "unknown@realworld.dev".parse().unwrap();
        let result = user_service.login(&email_address, &PASSWORD).await;
        assert_matches!(
            result,
            Err(Error::Repository(user_repository::GetUserAndPwhByEmailAddressError::NotFound(e)))
                if e == email_address
        );

        let password = Password::try_new("invalid-password".into()).unwrap();
        let result = user_service.login(&USER.email_address, &password).await;
        assert_matches!(
            result,
            Err(Error::Domain(LoginError::InvalidPassword(e)))
                if e == USER.email_address
        );

        let result = user_service.login(&USER.email_address, &PASSWORD).await;
        assert_matches!(result, Ok(u) if u == *USER);

        Ok(())
    }

    static USER: LazyLock<User> = LazyLock::new(|| User {
        id: Uuid::now_v7(),
        username: "user".parse().unwrap(),
        email_address: "user@realworld.dev".parse().unwrap(),
    });

    static PASSWORD: LazyLock<Password> =
        LazyLock::new(|| Password::try_new("password".into()).unwrap());

    static PASSWORD_HASH: LazyLock<PasswordHash> = LazyLock::new(|| {
        Argon2::default()
            .hash_password(
                PASSWORD.expose_secret().as_bytes(),
                &SaltString::generate(&mut OsRng),
            )
            .expect("password can be hashed")
            .serialize()
            .into()
    });

    #[derive(Clone)]
    struct MockUserRepository;

    impl UserRepository for MockUserRepository {
        type InfraError = Infallible;

        async fn add_user(
            &self,
            id: Uuid,
            username: &Username,
            email_address: &EmailAddress,
            password_hash: &PasswordHash,
        ) -> Result<(), user_repository::Error<AddUserError, Self::InfraError>> {
            Ok(())
        }

        async fn update_user(
            &self,
            id: Uuid,
            attributes: HashSet<UserAttribute>,
        ) -> Result<User, user_repository::Error<UpdateUserError, Self::InfraError>> {
            todo!()
        }

        async fn get_user_by_id(
            &self,
            id: Uuid,
        ) -> Result<User, user_repository::Error<GetUserByIdError, Self::InfraError>> {
            todo!()
        }

        async fn get_user_and_pwh_by_email_address(
            &self,
            email_address: &EmailAddress,
        ) -> Result<
            (User, PasswordHash),
            user_repository::Error<GetUserAndPwhByEmailAddressError, Self::InfraError>,
        > {
            if email_address == &USER.email_address {
                Ok((USER.to_owned(), PASSWORD_HASH.to_owned()))
            } else {
                Err(user_repository::Error::Domain(
                    GetUserAndPwhByEmailAddressError::NotFound(email_address.to_owned()),
                ))
            }
        }
    }
}
