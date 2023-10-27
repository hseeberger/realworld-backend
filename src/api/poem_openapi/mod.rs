mod user;

use self::user::UserApi;
use crate::{
    api::Config,
    domain::user::{user_repository::UserRepository, UserService},
    infra::token_factory::TokenFactory,
};
use anyhow::{Context, Result};
use futures::FutureExt;
use poem::{http::Method, listener::TcpListener, middleware::Cors, EndpointExt, Route, Server};
use poem_openapi::{Object, OpenApi, OpenApiService, Tags};
use std::fmt::Display;
use thiserror::Error;
use tokio::signal::unix::{signal, SignalKind};

#[allow(dead_code)]
pub async fn serve<U>(
    config: Config,
    user_service: UserService<U>,
    token_factory: TokenFactory,
) -> Result<()>
where
    U: UserRepository,
{
    let Config {
        addr,
        port,
        shutdown_timeout,
    } = config;

    let user_api = UserApi::new(user_service, token_factory);
    let api = OpenApiService::new((Ready, user_api), "realworld-backend", "0.1");
    let api_doc = api.swagger_ui();
    let api_spec = api.spec_endpoint();

    let app = Route::new()
        .nest("/", api)
        .nest("/api-doc", api_doc)
        .nest("/api-spec", api_spec)
        .with(
            Cors::new()
                .allow_method(Method::GET)
                .allow_method(Method::POST),
        );

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
    /// Readiness.
    Ready,
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

struct Ready;

#[OpenApi]
impl Ready {
    /// Readiness probe.
    #[oai(path = "/", method = "get", tag = "ApiTag::Ready")]
    async fn ready(&self) {}
}
