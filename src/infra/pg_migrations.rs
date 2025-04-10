use crate::infra::pg_pool::PgPool;
use thiserror::Error;

/// Run the database migrations for PostgreSQL.
pub async fn run(pool: &PgPool) -> Result<(), Error> {
    sqlx::migrate!("migrations/pg").run(&**pool).await?;
    Ok(())
}

/// Error for running database migrations for PostgreSQL.
#[derive(Debug, Error)]
#[error("cannot run PostgreSQL migrations")]
pub struct Error(#[from] sqlx::migrate::MigrateError);
