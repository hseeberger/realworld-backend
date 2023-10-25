use crate::{
    domain::user::{user_repository::UserRepository, UserService},
    infra::token_factory::TokenFactory,
};
use anyhow::Result;
use serde::Deserialize;
use std::{net::IpAddr, time::Duration};

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "poem-openapi")]
pub mod poem_openapi;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    addr: IpAddr,
    port: u16,
    #[serde(with = "humantime_serde")]
    shutdown_timeout: Option<Duration>,
}

#[allow(unused)]
pub async fn serve<U>(
    config: Config,
    user_service: UserService<U>,
    token_factory: TokenFactory,
) -> Result<()>
where
    U: UserRepository,
{
    #[cfg(any(
        not(any(feature = "axum", feature = "poem-openapi")),
        all(feature = "axum", feature = "poem-openapi"),
    ))]
    anyhow::bail!("choose exactly one of axum and poem-openapi features");

    #[cfg(all(feature = "axum", not(feature = "poem-openapi")))]
    return axum::serve(config, user_service, token_factory).await;

    #[cfg(all(feature = "poem-openapi", not(feature = "axum")))]
    return poem_openapi::serve(config, user_service, token_factory).await;
}
