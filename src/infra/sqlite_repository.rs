use crate::domain::{
    user::{
        user_repository::{AddUserError, ImplError, UpdateUserError, UserRepository},
        Bio, User, UserAndPasswordHash, Username,
    },
    SecretString,
};
use anyhow::{Context, Result};
use email_address::EmailAddress;
use serde::Deserialize;
use sqlx::{
    error::DatabaseError,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow},
    FromRow, Row, SqlitePool,
};
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

pub struct SqliteRepository {
    pool: SqlitePool,
}

impl SqliteRepository {
    pub async fn new(config: Config) -> Result<Self> {
        let Config { cnn_url } = config;
        let cnn_options = SqliteConnectOptions::from_str(&cnn_url)
            .with_context(|| format!("create SqliteConnectOptions from connection URL {cnn_url}"))?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(cnn_options)
            .await
            .context("create sqlite connection pool")?;

        sqlx::migrate!()
            .run(&pool)
            .await
            .context("run database migrations")?;

        Ok(Self { pool })
    }
}

impl UserRepository for SqliteRepository {
    type Error = Error;

    async fn user_by_id(&self, id: Uuid) -> Result<Option<User>, ImplError<Self::Error>> {
        sqlx::query_as("SELECT * FROM user where id = ?")
            .bind(id.as_bytes().to_vec())
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| ImplError(Error(error)))
    }

    async fn find_user_and_password_hash_by_email(
        &self,
        email: &EmailAddress,
    ) -> Result<Option<UserAndPasswordHash>, ImplError<Self::Error>> {
        sqlx::query_as("SELECT * FROM user where email = ?")
            .bind(email.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| ImplError(Error(error)))
    }

    async fn add_user(
        &self,
        id: Uuid,
        username: &Username,
        email: &EmailAddress,
        password_hash: &SecretString,
    ) -> Result<(), AddUserError<Self::Error>> {
        sqlx::query("INSERT INTO user (id, username, email, password_hash) VALUES(?, ?, ?, ?)")
            .bind(id.as_bytes().to_vec())
            .bind(username.as_ref())
            .bind(email.as_ref())
            .bind(password_hash.expose_secret())
            .execute(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::Database(e) if is_unique_violation(e.as_ref(), "email") => {
                    AddUserError::EmailTaken
                }

                sqlx::Error::Database(e) if is_unique_violation(e.as_ref(), "username") => {
                    AddUserError::UsernameTaken
                }

                other => AddUserError::ImplError(Error(other)),
            })
            .map(|_| ())
    }

    async fn update_user(
        &self,
        id: Uuid,
        username: Option<Username>,
        email: Option<EmailAddress>,
        password_hash: Option<SecretString>,
        bio: Option<Option<Bio>>,
    ) -> Result<(), UpdateUserError<Self::Error>> {
        let mut query = "UPDATE user SET".to_string();
        if username.is_some() {
            query = format!("{query} username = ?, ")
        };
        if email.is_some() {
            query = format!("{query} email = ?, ")
        };
        if password_hash.is_some() {
            query = format!("{query} password_hash = ?, ")
        };
        query = format!("{query} bio = ? WHERE id = ?");

        let mut query = sqlx::query(&query);
        if let Some(username) = username {
            query = query.bind(username.to_string());
        };
        if let Some(email) = email {
            query = query.bind(email.to_string());
        };
        if let Some(password_hash) = password_hash {
            query = query.bind(password_hash.expose_secret().to_string());
        };
        if let Some(bio) = bio {
            query = query.bind(bio.map(|bio| bio.to_string()));
        };

        query
            .bind(id.as_bytes().to_vec())
            .execute(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::Database(e) if is_unique_violation(e.as_ref(), "email") => {
                    UpdateUserError::EmailTaken
                }

                sqlx::Error::Database(e) if is_unique_violation(e.as_ref(), "username") => {
                    UpdateUserError::UsernameTaken
                }

                other => UpdateUserError::ImplError(Error(other)),
            })
            .map(|_| ())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    cnn_url: String,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] sqlx::Error);

impl FromRow<'_, SqliteRow> for User {
    fn from_row(row: &SqliteRow) -> sqlx::Result<Self> {
        let id = row.try_get::<Vec<u8>, _>("id")?;
        let id = Uuid::from_slice(&id).map_err(|error| sqlx::Error::Decode(Box::new(error)))?;

        let username = row
            .try_get::<String, _>("username")?
            .try_into()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;

        let email = row
            .try_get::<String, _>("email")?
            .parse()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;

        let bio = row
            .try_get::<Option<String>, _>("bio")?
            .map(|s| {
                s.try_into()
                    .map_err(|error| sqlx::Error::Decode(Box::new(error)))
            })
            .transpose()?;

        Ok(User::new(id, username, email, bio))
    }
}

impl FromRow<'_, SqliteRow> for UserAndPasswordHash {
    fn from_row(row: &SqliteRow) -> sqlx::Result<Self> {
        let user = User::from_row(row)?;
        let password_hash = row.try_get::<String, _>("password_hash")?;

        Ok(UserAndPasswordHash::new(user, password_hash.into()))
    }
}

fn is_unique_violation(error: &dyn DatabaseError, column: &str) -> bool {
    error.is_unique_violation() && error.message().contains(column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use argon2::{password_hash::Encoding, PasswordHash};
    use std::assert_matches::assert_matches;

    #[tokio::test]
    async fn test_add_user() -> Result<()> {
        let repository = SqliteRepository::new(Config {
            cnn_url: "sqlite::memory:".to_string(),
        })
        .await?;

        let password_hash = PasswordHash::parse("$argon2id$v=19$m=19456,t=2,p=1$7LuchIjYjQ+JXIMUxhSEIQ$kdk4nmqN1KOloTD2EcAdARgwAnvX3XbpLBEJodga+NY", Encoding::B64).map_err(|error| anyhow!(error))?.to_string().into();

        let result = repository
            .add_user(
                Uuid::now_v7(),
                &"user1".parse()?,
                &"user1@realworld.dev".parse()?,
                &password_hash,
            )
            .await;
        assert_matches!(result, Ok(()));

        let result = repository
            .add_user(
                Uuid::now_v7(),
                &"user1".parse()?,
                &"user2@realworld.dev".parse()?,
                &password_hash,
            )
            .await;
        assert_matches!(result, Err(AddUserError::UsernameTaken));

        let result = repository
            .add_user(
                Uuid::now_v7(),
                &"user2".parse()?,
                &"user1@realworld.dev".parse()?,
                &password_hash,
            )
            .await;
        assert_matches!(result, Err(AddUserError::EmailTaken));

        let result = repository
            .add_user(
                Uuid::now_v7(),
                &"user2".parse()?,
                &"user2@realworld.dev".parse()?,
                &password_hash,
            )
            .await;
        assert_matches!(result, Ok(()));

        Ok(())
    }

    #[tokio::test]
    async fn test_find_user() -> Result<()> {
        let repository = SqliteRepository::new(Config {
            cnn_url: "sqlite::memory:".to_string(),
        })
        .await?;

        let password_hash = PasswordHash::parse("$argon2id$v=19$m=19456,t=2,p=1$7LuchIjYjQ+JXIMUxhSEIQ$kdk4nmqN1KOloTD2EcAdARgwAnvX3XbpLBEJodga+NY", Encoding::B64).map_err(|error| anyhow!(error))?.to_string().into();

        let id = Uuid::now_v7();
        let username = "user1".parse()?;
        let email = "user1@realworld.dev".parse()?;

        let result = repository
            .add_user(id, &username, &email, &password_hash)
            .await;
        assert_matches!(result, Ok(()));

        let user = User::new(id, username.clone(), email.clone(), None);

        let result = repository.user_by_id(id).await;
        assert_matches!(result, Ok(Some(u)) if u == user);

        let result = repository.user_by_id(Uuid::now_v7()).await;
        assert_matches!(result, Ok(None));

        let result = repository
            .find_user_and_password_hash_by_email(&email)
            .await;
        assert_matches!(result, Ok(Some(_)));
        let (u, p) = result.unwrap().unwrap().dissolve();
        assert_eq!(u, user);
        assert_eq!(p.expose_secret(), password_hash.expose_secret());

        let result = repository
            .find_user_and_password_hash_by_email(&"unknown@realworld.dev".parse()?)
            .await;
        assert_matches!(result, Ok(None));

        Ok(())
    }
}
