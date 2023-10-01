mod user;

use self::user::UserApi;
use crate::{domain::user::UserRepository, infra::token_factory::TokenFactory};
use anyhow::{Context, Result};
use futures::FutureExt;
use poem::{
    handler,
    http::{Method, StatusCode},
    listener::TcpListener,
    middleware::Cors,
    EndpointExt, Route, Server,
};
use poem_openapi::{Object, OpenApiService, Tags};
use serde::Deserialize;
use std::{fmt::Display, net::IpAddr, time::Duration};
use thiserror::Error;
use tokio::signal::unix::{signal, SignalKind};
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    addr: IpAddr,
    port: u16,
    #[serde(with = "humantime_serde")]
    shutdown_timeout: Option<Duration>,
    base_url: Option<Url>,
}

pub async fn serve(
    config: Config,
    user_repository: impl UserRepository,
    token_factory: TokenFactory,
) -> Result<()> {
    let Config {
        addr,
        port,
        shutdown_timeout,
        base_url,
    } = config;

    let user_api = UserApi::new(user_repository, token_factory);
    let base_url = base_url.unwrap_or(
        format!("http://localhost:{port}/api")
            .parse()
            .context("parse base url")?,
    );
    let api =
        OpenApiService::new(user_api, "realworld-backend-poem-openapi", "0.1").server(base_url);

    let cors = Cors::new()
        .allow_method(Method::GET)
        .allow_method(Method::POST);

    let app = Route::new()
        .nest("/", ready)
        .nest("/api-doc", api.swagger_ui())
        .nest("/api-spec", api.spec_endpoint())
        .nest("/api", api)
        .with(cors);

    Server::new(TcpListener::bind((addr, port)))
        .run_with_graceful_shutdown(
            app,
            signal(SignalKind::terminate())
                .expect("install SIGTERM handler")
                .recv()
                .map(|_| ()),
            shutdown_timeout,
        )
        .await
        .context("run server")
}

#[derive(Tags)]
enum ApiTag {
    /// Users and authentication.
    User,
}

#[handler]
fn ready() -> StatusCode {
    StatusCode::OK
}

#[derive(Debug, Object)]
struct GenericError {
    errors: GenericErrorBody,
}

impl GenericError {
    fn new<S>(msg: S) -> Self
    where
        S: Display,
    {
        Self {
            errors: GenericErrorBody {
                body: vec![msg.to_string()],
            },
        }
    }
}

#[derive(Debug, Object)]
struct GenericErrorBody {
    body: Vec<String>,
}

#[derive(Debug, Error)]
#[error("")]
struct SilentError;
