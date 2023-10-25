use crate::{
    api::axum::{AppState, Error},
    domain::{
        self,
        user::{
            user_repository::UserRepository, GetUserError, LoginError, RegisterUserError,
            UpdateUserError,
        },
        SecretString,
    },
};
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
use std::{ops::Deref, sync::Arc};
use tracing::{error, warn};
use utoipa::{OpenApi, ToSchema};

const USER: &str = "/user";
const USERS: &str = "/users";
const USERS_LOGIN: &str = concatcp!(USERS, "/login");

const TAG: &str = "user"; // TODO: not yet possible to be used for `openapi::tags::name`!

#[derive(Debug, OpenApi)]
#[openapi(
    paths(get_current_user, update_current_user, register_user, login_user),
    components(
        schemas(UserResponse, User, UpdateUserRequest, UpdateUser, RegisterUserRequest, NewUser, LoginRequest, Credentials, Email)
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
    Router::new().route(USER, get(get_current_user).put(update_current_user))
}

pub fn users_routes<U>() -> Router<Arc<AppState<U>>>
where
    U: UserRepository,
{
    Router::new()
        .route(USERS, post(register_user))
        .route(USERS_LOGIN, post(login_user))
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

// Request to update the currently logged in user.
#[derive(Debug, Deserialize, ToSchema)]
struct UpdateUserRequest {
    user: UpdateUser,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUser {
    username: Option<String>,
    email: Option<Email>,
    password: Option<SecretString>,
    bio: Option<String>,
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
async fn get_current_user<U>(
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

    let id = app_state
        .token_factory
        .verify_token(&token)
        .map_err(|error| {
            warn!(error = format!("{error:#}"), "cannot verify token");
            Error::from(StatusCode::UNAUTHORIZED)
        })?;

    let user = app_state
        .user_service
        .user_by_id(id)
        .await
        .map_err(|error| match error {
            GetUserError::UnknownUser(_) => Error::from((StatusCode::NOT_FOUND, error)),

            GetUserError::UserRepository(_) => {
                error!(%id, error = format!("{error:#}"), "cannot get current user");
                Error::from(StatusCode::INTERNAL_SERVER_ERROR)
            }
        })?;

    Ok(Json((user, token).into()))
}

/// Update the currently logged-in user.
#[utoipa::path(
    post,
    path = USER,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Updated currently logged-in user.", body = UserResponse),
        (status = 401, description = "Unauthorized."),
    ),
    tag = TAG
)]
async fn update_current_user<U>(
    State(app_state): State<Arc<AppState<U>>>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, Error>
where
    U: UserRepository,
{
    let UpdateUser {
        username,
        email,
        password,
        bio,
    } = request.user;

    let token = bearer
        .ok_or_else(|| {
            warn!(error = "missing token");
            Error::from(StatusCode::UNAUTHORIZED)
        })
        .map(|TypedHeader(Authorization(bearer))| bearer.token().into())?;

    let id = app_state
        .token_factory
        .verify_token(&token)
        .map_err(|error| {
            warn!(error = format!("{error:#}"), "cannot verify token");
            Error::from(StatusCode::UNAUTHORIZED)
        })?;

    let username = username
        .map(TryInto::try_into)
        .transpose()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let email = email
        .map(|email| email.parse())
        .transpose()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let password = password
        .map(TryInto::try_into)
        .transpose()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let bio = bio
        .map(|bio| bio.try_into())
        .transpose()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;

    let user = app_state
        .user_service
        .update_user(id, username, email, password, bio)
        .await
        .map_err(|error| match error {
            UpdateUserError::InvalidUpdate(_) => (StatusCode::UNPROCESSABLE_ENTITY, error).into(),

            UpdateUserError::EmailTaken | UpdateUserError::UsernameTaken => {
                (StatusCode::CONFLICT, error).into()
            }

            UpdateUserError::UnknownUser(_) => Error::from((StatusCode::NOT_FOUND, error)),

            UpdateUserError::PasswordHash(_) | UpdateUserError::UserRepository(_) => {
                error!(%id, error = format!("{error:#}"), "cannot get current user");
                Error::from(StatusCode::INTERNAL_SERVER_ERROR)
            }
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
async fn register_user<U>(
    State(app_state): State<Arc<AppState<U>>>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<UserResponse>, Error>
where
    U: UserRepository,
{
    let NewUser {
        username,
        email,
        password,
    } = request.user;

    let username = username
        .try_into()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let email = email
        .parse()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let password = password
        .try_into()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;

    let user = app_state
        .user_service
        .register_user(username, email, password)
        .await
        .map_err(|error| match error {
            RegisterUserError::EmailTaken | RegisterUserError::UsernameTaken => {
                (StatusCode::CONFLICT, error).into()
            }

            RegisterUserError::PasswordHash(_) | RegisterUserError::UserRepository(_) => {
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
async fn login_user<U>(
    State(app_state): State<Arc<AppState<U>>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<UserResponse>, Error>
where
    U: UserRepository,
{
    let Credentials { email, password } = request.user;

    let email = email
        .parse()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;
    let password = password
        .try_into()
        .map_err(|error| Error::from((StatusCode::UNPROCESSABLE_ENTITY, error)))?;

    let user = app_state
        .user_service
        .login_user(&email, &password)
        .await
        .map_err(|error| match error {
            LoginError::InvalidCredentials => Error::from(StatusCode::UNAUTHORIZED),

            LoginError::PasswordHash(_) | LoginError::UserRepository(_) => {
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
