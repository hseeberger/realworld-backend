mod user;

use crate::{
    api::Config,
    domain::user::{user_repository::UserRepository, UserService},
    infra::token_factory::TokenFactory,
};
use anyhow::{Context, Result};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::{error::Error as StdError, sync::Arc};
use tokio::{
    net::TcpListener,
    signal::unix::{signal, SignalKind},
};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use utoipa::{
    openapi::{
        self,
        security::{Http, HttpAuthScheme, SecurityScheme},
    },
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, OpenApi)]
#[openapi(
    components(
        schemas(
            Conflict,
            UnprocessableEntity,
        )
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

pub async fn serve<U>(
    config: Config,
    user_service: UserService<U>,
    token_factory: TokenFactory,
) -> Result<()>
where
    U: UserRepository,
{
    let Config { addr, port } = config;

    let app_state = Arc::new(AppState {
        user_service,
        token_factory,
    });

    let mut api_doc = ApiDoc::openapi();
    api_doc.merge(user::ApiDoc::openapi());

    let app = Router::new()
        .route("/", get(ready))
        .merge(user::user_routes())
        .merge(user::users_routes())
        .merge(SwaggerUi::new("/api-doc").url("/openapi.json", api_doc))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
        )
        .with_state(app_state);

    let listener = TcpListener::bind((addr, port))
        .await
        .context("bind TcpListener")?;
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal());
    server.await.context("run server")
}

struct AppState<U> {
    user_service: UserService<U>,
    token_factory: TokenFactory,
}

#[derive(Debug)]
enum Error {
    Unauthorized,
    NotFound,
    Conflict(Box<dyn StdError>),
    InvalidInput(Vec<Box<dyn StdError>>),
    Internal,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),

            Error::NotFound => StatusCode::NOT_FOUND.into_response(),

            Error::Conflict(error) => {
                let error = error.to_string();
                (StatusCode::CONFLICT, Json(Conflict { error })).into_response()
            }

            Error::InvalidInput(errors) => {
                let errors = errors.into_iter().map(|error| error.to_string()).collect();
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(UnprocessableEntity { errors }),
                )
                    .into_response()
            }

            Error::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct Conflict {
    error: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct UnprocessableEntity {
    errors: Vec<String>,
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            )
        }
    }
}

async fn ready() -> impl IntoResponse {
    StatusCode::OK
}

async fn shutdown_signal() {
    signal(SignalKind::terminate())
        .expect("install SIGTERM handler")
        .recv()
        .await;
}
