//! Database connection configuration.

use crate::DbError;

/// Connection configuration for [`crate::ScanRepository`].
///
/// The connection string is never hard-coded: it is always read from the `DATABASE_URL`
/// environment variable, optionally populated from a local `.env` file (see
/// [`DbConfig::from_env`]). `.env` is git-ignored; only `.env.example` (with a fake
/// connection string) is committed.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// PostgreSQL connection string, e.g. `postgres://user:password@localhost:5432/recon_rs`.
    pub database_url: String,
}

impl DbConfig {
    /// Loads the configuration from the `DATABASE_URL` environment variable.
    ///
    /// Before reading the variable, this attempts to load a `.env` file (via
    /// [`dotenvy::dotenv`]) from the current directory or one of its parents, for local
    /// development convenience. A missing `.env` file is not an error — in production,
    /// `DATABASE_URL` is expected to already be set in the process environment.
    ///
    /// # Errors
    /// Returns [`DbError::Config`] if `DATABASE_URL` is not set.
    pub fn from_env() -> Result<Self, DbError> {
        let _ = dotenvy::dotenv();
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| DbError::Config("DATABASE_URL is not set".to_string()))?;
        Ok(Self { database_url })
    }

    /// Connects to `self.database_url` and runs any pending schema migrations from
    /// [`crate::MIGRATOR`] before returning the pool, so callers never need a manual
    /// `sqlx migrate run` step on a fresh database.
    ///
    /// # Errors
    /// Returns [`DbError::Query`] if the connection fails, or [`DbError::Migrate`] if a
    /// migration fails to apply.
    pub async fn connect(&self) -> Result<sqlx::PgPool, DbError> {
        let pool = sqlx::PgPool::connect(&self.database_url).await?;
        crate::MIGRATOR.run(&pool).await?;
        Ok(pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_reports_a_config_error_when_unset() {
        // SAFETY: no other test in this process depends on DATABASE_URL being set, and
        // tests run single-threaded within this module.
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        // Point HOME/PWD-relative dotenv lookup away from any real `.env` file that
        // might exist in an ancestor directory during local development.
        let previous_dir = std::env::current_dir().expect("current dir must be readable");
        std::env::set_current_dir(std::env::temp_dir()).expect("temp dir must be accessible");

        let result = DbConfig::from_env();

        std::env::set_current_dir(previous_dir).expect("restoring current dir must succeed");

        assert!(matches!(result, Err(DbError::Config(_))));
    }
}
