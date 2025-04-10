pub mod api;
pub mod pg_migrations;
pub mod pg_pool;
pub mod pg_user_repository;

use serde::Deserialize;

/// Infra configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(rename = "api")]
    pub api_config: api::Config,

    #[serde(rename = "pool")]
    pub pool_config: pg_pool::Config,
}
