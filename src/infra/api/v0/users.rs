use crate::{
    domain::{
        user::{EmailAddress, Password, User as DomainUser, Username},
        user_repository::{
            GetUserAndPwhByEmailAddressError, GetUserByIdError, UpdateUserError, UserRepository,
        },
        user_service::{self, LoginError, UserService},
    },
    infra::api::{AppState, tokens::Token},
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use error_ext::{StdErrorExt, axum::Error};
use log::{error, info};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

pub fn routes<R>() -> Router<AppState<R>>
where
    R: UserRepository,
{
    Router::new()
        .route("/users", post(register_user))
        .route("/users/login", post(login_user))
        .route("/user", get(get_current_user).put(update_current_user))
}

#[derive(Debug, Serialize)]
struct User {
    username: Username,
    email_address: EmailAddress,
    token: String,
}

impl From<(DomainUser, Token)> for User {
    fn from((user, token): (DomainUser, Token)) -> Self {
        let DomainUser {
            username,
            email_address,
            ..
        } = user;

        Self {
            username,
            email_address,
            token: token.expose_secret().to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RegisterUserRequest {
    username: Username,
    email_address: EmailAddress,
    password: Password,
}

#[derive(Debug, Deserialize)]
struct LoginUserRequest {
    email_address: EmailAddress,
    password: Password,
}

#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    username: Option<Username>,
    email_address: Option<EmailAddress>,
    password: Option<Password>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    user: User,
}

async fn register_user<R>(
    State(app_state): State<AppState<R>>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<impl IntoResponse, Error>
where
    R: UserRepository,
{
    let RegisterUserRequest {
        username,
        email_address,
        password,
    } = request;

    let user = app_state
        .user_service
        .register(username, email_address, password)
        .await
        .map_err(|error| match error {
            user_service::Error::Repository(add_user_error) => Error::conflict(add_user_error),

            user_service::Error::Infra(error) => {
                error!(error = error.as_chain(); "cannot register user");
                Error::Internal
            }
        })?;

    let token = app_state.tokens.create_token(user.id).map_err(|error| {
        error!(error = format!("{error:#}"); "cannot register user");
        Error::Internal
    })?;

    info!(user:?; "user registered");

    let user = (user, token).into();
    let response = UserResponse { user };

    Ok((StatusCode::CREATED, Json(response)))
}

async fn login_user<R>(
    State(app_state): State<AppState<R>>,
    Json(request): Json<LoginUserRequest>,
) -> Result<impl IntoResponse, Error>
where
    R: UserRepository,
{
    let LoginUserRequest {
        email_address,
        password,
    } = request;

    let user = app_state
        .user_service
        .login(&email_address, &password)
        .await
        .map_err(|error| match error {
            user_service::Error::Domain(invalid_password @ LoginError::InvalidPassword(_)) => {
                Error::unauthorized(invalid_password)
            }

            user_service::Error::Repository(
                not_found @ GetUserAndPwhByEmailAddressError::NotFound(_),
            ) => Error::unauthorized(not_found),

            user_service::Error::Infra(error) => {
                error!(error = error.as_chain(); "cannot login user");
                Error::Internal
            }
        })?;

    let token = app_state.tokens.create_token(user.id).map_err(|error| {
        error!(error = format!("{error:#}"); "cannot login user");
        Error::Internal
    })?;

    info!(user:?; "user logged in");

    let user = (user, token).into();
    let response = UserResponse { user };

    Ok(Json(response))
}

async fn get_current_user<R>(
    State(app_state): State<AppState<R>>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<impl IntoResponse, Error>
where
    R: UserRepository,
{
    let token = bearer
        .ok_or(Error::unauthorized("missing bearer token"))
        .map(|TypedHeader(Authorization(bearer))| bearer.token().into())?;

    let id = app_state
        .tokens
        .verify_token(&token)
        .map_err(Error::unauthorized)?;

    let user = app_state
        .user_service
        .get_user_by_id(id)
        .await
        .map_err(|error| match error {
            user_service::Error::Repository(not_found @ GetUserByIdError::NotFound(_)) => {
                Error::not_found(not_found)
            }

            user_service::Error::Infra(error) => {
                error!(error = error.as_chain(); "cannot get current user");
                Error::Internal
            }
        })?;

    let user = (user, token).into();
    let response = UserResponse { user };

    Ok(Json(response))
}

async fn update_current_user<R>(
    State(app_state): State<AppState<R>>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, Error>
where
    R: UserRepository,
{
    let token = bearer
        .ok_or(Error::unauthorized("missing bearer token"))
        .map(|TypedHeader(Authorization(bearer))| bearer.token().into())?;

    let id = app_state
        .tokens
        .verify_token(&token)
        .map_err(Error::unauthorized)?;

    let UpdateUserRequest {
        username,
        email_address,
        password,
    } = request;

    let user = app_state
        .user_service
        .update_user(id, username, email_address, password)
        .await
        .map_err(|error| match error {
            user_service::Error::Repository(not_found @ UpdateUserError::NotFound(_)) => {
                Error::not_found(not_found)
            }

            user_service::Error::Repository(other) => Error::conflict(other),

            user_service::Error::Infra(error) => {
                error!(error = error.as_chain(); "cannot get current user");
                Error::Internal
            }
        })?;

    let user = (user, token).into();
    let response = UserResponse { user };

    Ok(Json(response))
}
