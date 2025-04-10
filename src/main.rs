mod config;
mod domain;
mod infra;
mod telemetry;

use crate::{
    config::{Config, MainConfig},
    infra::api,
};
use anyhow::Context;
use config::ConfigExt;
use domain::user_service::UserRepositoryUserService;
use infra::{pg_migrations, pg_pool::PgPool, pg_user_repository::PgUserRepository};
use log::{error, info};
use std::panic;

/// The entry point into the application.
#[tokio::main]
pub async fn main() {
    // Initialize logging.
    telemetry::init_logging();

    // Replace the default panic hook with one that uses structured logging at ERROR level.
    panic::set_hook(Box::new(|panic| error!(panic:%; "process panicked")));

    // Run and log any error.
    if let Err(error) = run().await {
        let backtrace = error.backtrace();
        let error = format!("{error:#}");
        error!(error, backtrace:%; "process exited with ERROR")
    }
}

async fn run() -> anyhow::Result<()> {
    let MainConfig {
        config,
        tracing_config,
    } = MainConfig::load().context("load configuration")?;

    telemetry::init_tracing(tracing_config);

    info!(config:?; "starting");

    let Config {
        infra_config: infra::Config {
            api_config,
            pool_config,
        },
    } = config;

    let pool = PgPool::new(pool_config)
        .await
        .context("create PostgreSQL connection pool")?;

    pg_migrations::run(&pool)
        .await
        .context("run PostgreSQL database migrations")?;

    let user_repository = PgUserRepository::new(pool);
    let user_service = UserRepositoryUserService::new(user_repository);

    api::serve(api_config, user_service).await
}
