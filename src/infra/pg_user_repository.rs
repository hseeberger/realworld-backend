//! PostgreSQL based implementation of user repository.

use crate::{
    domain::{
        user::{EmailAddress, User, Username},
        user_repository::{
            AddUserError, Error, GetUserAndPwhByEmailAddressError, GetUserByIdError, PasswordHash,
            UpdateUserError, UserAttribute, UserRepository,
        },
    },
    infra::pg_pool::PgPool,
};
use argon2::password_hash::PasswordHashString;
use indoc::indoc;
use sqlx::{FromRow, Postgres, QueryBuilder, Row};
use std::collections::HashSet;
use uuid::Uuid;

/// PostgreSQL based implementation of user repository.
#[derive(Debug, Clone)]
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    /// Create a new PostgreSQL based user repository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl UserRepository for PgUserRepository {
    type InfraError = sqlx::Error;

    async fn add_user(
        &self,
        id: Uuid,
        username: &Username,
        email_address: &EmailAddress,
        password_hash: &PasswordHash,
    ) -> Result<(), Error<AddUserError, Self::InfraError>> {
        let query = indoc! {"
            INSERT INTO users (id, username, email_address, password_hash) 
            VALUES($1, $2, $3, $4)
        "};

        sqlx::query(query)
            .bind(id)
            .bind(&**username)
            .bind(&**email_address)
            .bind(password_hash.as_str())
            .execute(&*self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::Database(e) if unique_violation(e.as_ref(), "username") => {
                    Error::Domain(AddUserError::UsernameTaken(username.to_owned()))
                }

                sqlx::Error::Database(e) if unique_violation(e.as_ref(), "email_address") => {
                    Error::Domain(AddUserError::EmailAddressTaken(email_address.to_owned()))
                }

                other => Error::Infra(other),
            })?;

        Ok(())
    }

    async fn update_user(
        &self,
        id: Uuid,
        attributes: HashSet<UserAttribute>,
    ) -> Result<User, Error<UpdateUserError, Self::InfraError>> {
        let mut query = QueryBuilder::<Postgres>::new("UPDATE users SET");
        attributes.iter().fold(
            // We set the ID to make the query valid even for empty attributes.
            query
                .separated(", ")
                .push(" id = ")
                .push_bind_unseparated(id),
            |query, attribute| {
                match attribute {
                    UserAttribute::Username(username) => query
                        .push(" username = ")
                        .push_bind_unseparated(&**username),

                    UserAttribute::EmailAddress(email_address) => query
                        .push(" email_address = ")
                        .push_bind_unseparated(&**email_address),

                    UserAttribute::PasswordHash(password_hash) => query
                        .push(" password_hash = ")
                        .push_bind_unseparated(password_hash.as_str()),
                };

                query
            },
        );
        query
            .push(" WHERE id = ")
            .push_bind(id)
            .push(" RETURNING *");

        let user = query
            .build_query_as::<User>()
            .fetch_optional(&*self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::Database(e) if unique_violation(e.as_ref(), "username") => {
                    Error::Domain(UpdateUserError::UsernameTaken)
                }

                sqlx::Error::Database(e) if unique_violation(e.as_ref(), "email_address") => {
                    Error::Domain(UpdateUserError::EmailAddressTaken)
                }

                other => Error::Infra(other),
            })?
            .ok_or_else(|| Error::Domain(UpdateUserError::NotFound(id)))?;

        Ok(user)
    }

    async fn get_user_by_id(
        &self,
        id: Uuid,
    ) -> Result<User, Error<GetUserByIdError, Self::InfraError>> {
        let query = indoc! {"
            SELECT *
            FROM users
            WHERE id = $1
        "};

        let user = sqlx::query_as(query)
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;

        user.ok_or(Error::Domain(GetUserByIdError::NotFound(id)))
    }

    async fn get_user_and_pwh_by_email_address(
        &self,
        email_address: &EmailAddress,
    ) -> Result<(User, PasswordHash), Error<GetUserAndPwhByEmailAddressError, Self::InfraError>>
    {
        let query = indoc! {"
            SELECT *
            FROM users
            WHERE email_address = $1
        "};

        let row = sqlx::query(query)
            .bind(&**email_address)
            .fetch_optional(&*self.pool)
            .await?
            .ok_or_else(|| {
                Error::Domain(GetUserAndPwhByEmailAddressError::NotFound(
                    email_address.to_owned(),
                ))
            })?;

        let user = User::from_row(&row)?;
        let password_hash = row.try_get::<&str, _>("password_hash")?;
        let password_hash = PasswordHashString::new(password_hash)
            .expect("password hash is valid")
            .into();

        Ok((user, password_hash))
    }
}

impl<D> From<sqlx::Error> for Error<D, sqlx::Error> {
    fn from(error: sqlx::Error) -> Self {
        Error::Infra(error)
    }
}

fn unique_violation(error: &dyn sqlx::error::DatabaseError, column: &str) -> bool {
    error.is_unique_violation() && error.message().contains(column)
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::{
            user::{EmailAddress, User, Username},
            user_repository::{
                AddUserError, Error, GetUserAndPwhByEmailAddressError, GetUserByIdError,
                PasswordHash, UpdateUserError, UserAttribute, UserRepository,
            },
        },
        infra::{
            pg_pool::{self, PgPool},
            pg_user_repository::PgUserRepository,
        },
    };
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };
    use assert_matches::assert_matches;
    use sqlx::postgres::PgSslMode;
    use std::{collections::HashSet, error::Error as StdError};
    use testcontainers::{ImageExt, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;
    use uuid::Uuid;

    #[tokio::test]
    async fn test() -> Result<(), Box<dyn StdError>> {
        let postgres_container = Postgres::default()
            .with_db_name("realworld")
            .with_user("realworld")
            .with_password("realworld")
            .with_tag("17.1-alpine")
            .start()
            .await?;
        let postgres_port = postgres_container.get_host_port_ipv4(5432).await?;

        let config = pg_pool::Config {
            host: "localhost".into(),
            port: postgres_port,
            dbname: "realworld".into(),
            user: "realworld".into(),
            password: "realworld".into(),
            sslmode: PgSslMode::Prefer,
        };
        let pool = PgPool::new(config).await?;

        sqlx::migrate!("migrations/pg").run(&*pool).await?;
        let repository = PgUserRepository::new(pool);

        let argon_2 = Argon2::default();

        let password_hash = argon_2
            .hash_password(b"password", &SaltString::generate(&mut OsRng))
            .expect("password can be hashed")
            .serialize()
            .into();

        let user = User {
            id: Uuid::now_v7(),
            username: "user".parse()?,
            email_address: "user@realworld.dev".parse()?,
        };

        let result = repository
            .add_user(user.id, &user.username, &user.email_address, &password_hash)
            .await;
        assert!(result.is_ok());

        let username = "user".parse()?;
        let result = repository
            .add_user(
                Uuid::now_v7(),
                &username,
                &"user_@realworld.dev".parse()?,
                &password_hash,
            )
            .await;
        assert_matches!(
            result,
            Err(Error::Domain(AddUserError::UsernameTaken(u))) if u == username
        );

        let email_address = "user@realworld.dev".parse()?;
        let result = repository
            .add_user(
                Uuid::now_v7(),
                &"user_".parse()?,
                &email_address,
                &password_hash,
            )
            .await;
        assert_matches!(
            result,
            Err(Error::Domain(AddUserError::EmailAddressTaken(e))) if e == email_address
        );

        let id = Uuid::now_v7();
        let result = repository.get_user_by_id(id).await;
        assert_matches!(
            result,
            Err(Error::Domain(GetUserByIdError::NotFound(i))) if i == id
        );

        let result = repository.get_user_by_id(user.id).await;
        assert_matches!(
            result,
            Ok(user) if user == user
        );

        let email_address = "unknown@realworld.dev".parse()?;
        let result = repository
            .get_user_and_pwh_by_email_address(&email_address)
            .await;
        assert_matches!(
            result,
            Err(Error::Domain(GetUserAndPwhByEmailAddressError::NotFound(e))) if e == email_address
        );

        let result = repository
            .get_user_and_pwh_by_email_address(&user.email_address)
            .await;
        assert_matches!(
            result,
            Ok((user, p)) if user == user && p == password_hash
        );

        let id = Uuid::now_v7();
        let attributes = HashSet::from_iter([UserAttribute::Username("user1_".parse()?)]);
        let result = repository.update_user(id, attributes).await;
        assert_matches!(
            result,
            Err(Error::Domain(UpdateUserError::NotFound(i))) if i == id
        );

        let username = "user_".parse::<Username>()?;
        let email_address = "user_@realworld.dev".parse::<EmailAddress>()?;
        let password_hash = PasswordHash::from(
            argon_2
                .hash_password(b"test_", &SaltString::generate(&mut OsRng))
                .expect("password can be hashed")
                .serialize(),
        );
        let attributes = HashSet::from_iter([
            UserAttribute::Username(username.clone()),
            UserAttribute::EmailAddress(email_address.clone()),
            UserAttribute::PasswordHash(password_hash.clone()),
        ]);
        let updated_user_1 = User {
            username,
            email_address,
            ..user
        };
        let result = repository.update_user(user.id, attributes).await;
        assert_matches!(
            result,
            Ok(user) if user == updated_user_1
        );

        let result = repository.get_user_by_id(user.id).await;
        assert_matches!(
            result,
            Ok(user) if user == updated_user_1
        );

        let result = repository
            .get_user_and_pwh_by_email_address(&updated_user_1.email_address)
            .await;
        assert_matches!(
            result,
            Ok((user, p)) if user == updated_user_1 && p == password_hash
        );

        Ok(())
    }
}
