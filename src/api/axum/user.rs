use crate::{
    api::axum::{AppState, Error},
    domain::{
        self,
        user::{LoginError, RegisterUserError, UserRepository},
        SecretString,
    },
};
use anyhow::anyhow;
use axum::{
    extract::State,
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    routing::{get, post},
    Json, Router, TypedHeader,
};
use const_format::concatcp;
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};
use std::{ops::Deref, str::FromStr, sync::Arc};
use tracing::{error, warn};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

const USER: &str = "/user";
const USERS: &str = "/users";
const USERS_LOGIN: &str = concatcp!(USERS, "/login");

const TAG: &str = "user"; // TODO: not yet possible to be used for `openapi::tags::name`!

#[derive(Debug, OpenApi)]
#[openapi(
    paths(register, login, get_current),
    components(
        schemas(UserResponse, User, RegisterUserRequest, NewUser, LoginRequest, Credentials, Email)
    ),
    tags(
        (name = "user", description = "Users and authentication.")
    )
)]
pub struct ApiDoc;

pub fn user_routes<U>() -> Router<Arc<AppState<U>>>
where
    U: UserRepository,
{
    Router::new().route(USER, get(get_current))
}

pub fn users_routes<U>() -> Router<Arc<AppState<U>>>
where
    U: UserRepository,
{
    Router::new()
        .route(USERS, post(register))
        .route(USERS_LOGIN, post(login))
}

/// A user.
#[derive(Debug, Serialize, ToSchema)]
struct UserResponse {
    user: User,
}

impl From<(domain::user::User, SecretString)> for UserResponse {
    fn from((user, token): (domain::user::User, SecretString)) -> Self {
        let user = (user, token).into();
        Self { user }
    }
}

/// A user.
#[derive(Debug, Serialize, ToSchema)]
struct User {
    username: String,
    email: Email,
    token: String,
    bio: Option<String>,
}

impl From<(domain::user::User, SecretString)> for User {
    fn from((domain_user, token): (domain::user::User, SecretString)) -> Self {
        let (_id, username, email, bio) = domain_user.dissolve();
        Self {
            username: username.into(),
            email: email.into(),
            token: token.expose_secret().to_owned(),
            bio: bio.map(|b| b.into()),
        }
    }
}

/// Request to register a new user.
#[derive(Debug, Deserialize, ToSchema)]
struct RegisterUserRequest {
    user: NewUser,
}

/// New user to be registered.
#[derive(Debug, Deserialize, ToSchema)]
struct NewUser {
    username: String,
    email: Email,
    password: SecretString,
}

/// Request to login an existing user.
#[derive(Debug, Deserialize, ToSchema)]
struct LoginRequest {
    user: Credentials,
}

/// Credentials to login an existing user.
#[derive(Debug, Deserialize, ToSchema)]
struct Credentials {
    email: Email,
    password: SecretString,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, format = "email", example = "name@realworld.dev")]
struct Email(String);

impl From<EmailAddress> for Email {
    fn from(email_address: EmailAddress) -> Self {
        Self(email_address.into())
    }
}

impl Deref for Email {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Get the currently logged-in user.
#[utoipa::path(
    get,
    path = USER,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Currently logged-in user.", body = UserResponse),
        (status = 401, description = "Unauthorized."),
    ),
    tag = TAG
)]
async fn get_current<U>(
    State(app_state): State<Arc<AppState<U>>>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<Json<UserResponse>, Error>
where
    U: UserRepository,
{
    let token = bearer
        .ok_or_else(|| {
            warn!(error = "missing token");
            Error::from(StatusCode::UNAUTHORIZED)
        })
        .map(|TypedHeader(Authorization(bearer))| bearer.token().into())?;

    let user_id = app_state
        .token_factory
        .verify_token(&token)
        .map_err(|error| {
            warn!(error = format!("{error:#}"), "cannot verify token");
            Error::from(StatusCode::UNAUTHORIZED)
        })?;
    let user_id = Uuid::from_str(&user_id).expect("create UUID from user_id");

    let user = app_state
        .user_repository
        .find_user_by_id(user_id)
        .await
        .map_err(|error| {
            error!(%user_id, error = format!("{error:#}"), "cannot get current user");
            Error::from(StatusCode::INTERNAL_SERVER_ERROR)
        })?
        .ok_or_else(|| {
            let error = anyhow!("cannot find user for user ID {user_id}");
            error!(%user_id, error = format!("{error:#}"), "cannot get current user");
            Error::from(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

    Ok(Json((user, token).into()))
}

/// Register a new user.
#[utoipa::path(
    post,
    path = USERS,
    responses(
        (status = 201, description = "Successfully registered user.", body = UserResponse),
        (status = 409, description = "Conflicting data for new user to be registered.", body = GenericError),
        (status = 422, description = "Invalid data for new user to be registered.", body = GenericError),
    ),
    tag = TAG
)]
async fn register<U>(
    State(app_state): State<Arc<AppState<U>>>,
    Json(register_request): Json<RegisterUserRequest>,
) -> Result<Json<UserResponse>, Error>
where
    U: UserRepository,
{
    let NewUser {
        username,
        email,
        password,
    } = register_request.user;

    let username = username
        .try_into()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let email = email
        .parse()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let password = password
        .try_into()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;

    let user = domain::user::register(&app_state.user_repository, username, email, password)
        .await
        .map_err(|error| match error {
            RegisterUserError::EmailTaken | RegisterUserError::UsernameTaken => {
                (StatusCode::CONFLICT, error).into()
            }

            _ => {
                error!(error = format!("{error:#}"), "cannot register user");
                Error::from(StatusCode::INTERNAL_SERVER_ERROR)
            }
        })?;

    let token = app_state
        .token_factory
        .create_token(user.id())
        .map_err(|error| {
            error!(?user, error = format!("{error:#}"), "cannot create token");
            Error::from(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

    Ok(Json((user, token).into()))
}

/// Login for an existing user.
#[utoipa::path(
    post,
    path = USERS_LOGIN,
    responses(
        (status = 201, description = "Successfully registered user.", body = UserResponse),
        (status = 401, description = "Unauthorized."),
        (status = 422, description = "Invalid credentials.", body = GenericError),
    ),
    tag = TAG
)]
async fn login<U>(
    State(app_state): State<Arc<AppState<U>>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<UserResponse>, Error>
where
    U: UserRepository,
{
    let Credentials { email, password } = login_request.user;

    let email = email
        .parse()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let password = password
        .try_into()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;

    let user = domain::user::login(&app_state.user_repository, &email, &password)
        .await
        .map_err(|error| match error {
            LoginError::InvalidCredentials => Error::from(StatusCode::UNAUTHORIZED),

            error => {
                error!(%email, error = format!("{error:#}"), "cannot login user");
                Error::from(StatusCode::INTERNAL_SERVER_ERROR)
            }
        })?;

    let token = app_state
        .token_factory
        .create_token(user.id())
        .map_err(|error| {
            error!(?user, error = format!("{error:#}"), "cannot create token");
            Error::from(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

    Ok(Json((user, token).into()))
}
