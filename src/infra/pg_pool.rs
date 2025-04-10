//! A PostgreSQL connection pool.

use log::debug;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_with::{DisplayFromStr, serde_as};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::ops::Deref;
use thiserror::Error;

/// A PostgreSQL connection pool, allowing for some custom extensions as well as security.
///
/// To use as `&sqlx::PgPool` in `Query::execute`, use its `Deref` implementation: `&*pool` or
/// `pool.deref()`. If an owned `sqlx::PgPool` is needed, use `Into::into`.
#[derive(Debug, Clone)]
pub struct PgPool(sqlx::PgPool);

impl PgPool {
    /// Create a new PostgreSQL connection pool with the given config.
    pub async fn new(config: Config) -> Result<Self, Error> {
        let value = PgPoolOptions::new().connect_with(config.into()).await?;

        let pool = Self(value);
        debug!(pool:?; "created PostgreSQL connection pool");

        Ok(pool)
    }
}

impl Deref for PgPool {
    type Target = sqlx::PgPool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Configuration for a [PgPool].
#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub dbname: String,
    pub user: String,
    pub password: SecretString,
    #[serde_as(as = "DisplayFromStr")]
    pub sslmode: PgSslMode,
}

impl From<Config> for PgConnectOptions {
    fn from(config: Config) -> Self {
        PgConnectOptions::new()
            .host(&config.host)
            .database(&config.dbname)
            .username(&config.user)
            .password(config.password.expose_secret())
            .port(config.port)
            .ssl_mode(config.sslmode)
    }
}

/// Error possibly returned by [PgPool::new].
#[derive(Debug, Error)]
#[error("cannot create PostgreSQL connection pool")]
pub struct Error(#[from] sqlx::Error);

#[cfg(test)]
mod tests {
    use crate::infra::pg_pool::{Config, PgPool};
    use sqlx::postgres::PgSslMode;
    use std::error::Error as StdError;
    use testcontainers::{ImageExt, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;

    #[tokio::test]
    async fn test_pool() -> Result<(), Box<dyn StdError>> {
        let postgres_container = Postgres::default()
            .with_db_name("realworld")
            .with_user("realworld")
            .with_password("realworld")
            .with_tag("17.1-alpine")
            .start()
            .await?;
        let postgres_port = postgres_container.get_host_port_ipv4(5432).await?;

        let config = Config {
            host: "localhost".into(),
            port: postgres_port,
            dbname: "realworld".into(),
            user: "realworld".into(),
            password: "realworld".into(),
            sslmode: PgSslMode::Prefer,
        };

        let pool = PgPool::new(config).await;
        assert!(pool.is_ok());
        let pool = pool.unwrap();

        let result = sqlx::query("CREATE TABLE test (id integer PRIMARY KEY)")
            .execute(&*pool)
            .await;
        assert!(result.is_ok());

        Ok(())
    }
}
