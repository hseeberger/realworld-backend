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
    routing::{get, post},
    Json, Router, TypedHeader,
};
use const_format::concatcp;
use frunk::{hlist_pat, validated::IntoValidated};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use tracing::{error, warn};
use utoipa::{OpenApi, ToSchema};

const USER: &str = "/user";
const USERS: &str = "/users";
const USERS_LOGIN: &str = concatcp!(USERS, "/login");

const TAG: &str = "user"; // TODO: not yet possible to be used for `openapi::tags::name`!

#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        get_current_user,
        login_user,
        register_user,
        update_current_user,
    ),
    components(
        schemas(
            Credentials,
            Email,
            LoginRequest,
            NewUser,
            Password,
            RegisterUserRequest,
            UpdateUser,
            UpdateUserRequest,
            User,
            Username,
            UserResponse,
        )
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

/// User.
#[derive(Debug, Serialize, ToSchema)]
struct UserResponse {
    /// User.
    user: User,
}

impl From<(domain::user::User, SecretString)> for UserResponse {
    fn from((user, token): (domain::user::User, SecretString)) -> Self {
        let user = (user, token).into();
        Self { user }
    }
}

/// User.
#[derive(Debug, Serialize, ToSchema)]
struct User {
    username: Username,

    email: Email,

    /// Bearer token used for authentication.
    token: String,

    /// Bio.
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

/// Request to update the currently logged in user.
#[derive(Debug, Deserialize, ToSchema)]
struct UpdateUserRequest {
    user: UpdateUser,
}

/// Update for the currently logged in user.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUser {
    #[schema(nullable = false)]
    username: Option<Username>,

    #[schema(nullable = false)]
    email: Option<Email>,

    #[schema(nullable = false)]
    password: Option<Password>,

    #[serde(default, deserialize_with = "deserialize_some")]
    bio: Option<Option<String>>,
}

/// Request to register a new user.
#[derive(Debug, Deserialize, ToSchema)]
struct RegisterUserRequest {
    user: NewUser,
}

/// New user to be registered.
#[derive(Debug, Deserialize, ToSchema)]
struct NewUser {
    username: Username,
    email: Email,
    password: Password,
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
    password: Password,
}

/// Unique unsername.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, format = "username", example = "john.doe")]
struct Username(String);

impl From<domain::user::Username> for Username {
    fn from(username: domain::user::Username) -> Self {
        Username(username.into())
    }
}

/// Unique email address, used for login.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, format = "email", example = "john.doe@realworld.dev")]
struct Email(String);

impl From<domain::user::Email> for Email {
    fn from(email: domain::user::Email) -> Self {
        Email(email.into())
    }
}

/// Password.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(value_type = String, format = Password, example = "abcd567+")]
struct Password(SecretString);

/// Get the currently logged-in user.
#[utoipa::path(
    get,
    path = USER,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Currently logged-in user.", body = UserResponse),
        (status = 401, description = "Unauthorized."),
        (status = 404, description = "Not found."),
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
            Error::Unauthorized
        })
        .map(|TypedHeader(Authorization(bearer))| bearer.token().into())?;

    let id = app_state
        .token_factory
        .verify_token(&token)
        .map_err(|error| {
            warn!(error = format!("{error:#}"), "cannot verify token");
            Error::Unauthorized
        })?;

    let user = app_state
        .user_service
        .user_by_id(id)
        .await
        .map_err(|error| match error {
            GetUserError::UnknownUser(id) => {
                error!(%id, error = format!("{error:#}"), "current user not found");
                Error::Internal
            }

            GetUserError::UserRepository(error) => {
                error!(%id, error = format!("{error:#}"), "cannot get current user");
                Error::Internal
            }
        })?;

    Ok(Json((user, token).into()))
}

/// Update the currently logged-in user.
#[utoipa::path(
    put,
    path = USER,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Currently logged-in user.", body = UserResponse),
        (status = 401, description = "Unauthorized."),
        (status = 404, description = "User not found."),
        (status = 409, description = "Conflicting user data."),
        (status = 422, description = "Invalid user data.", body = UnprocessableEntity),
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
    let token = bearer
        .ok_or_else(|| {
            warn!(error = "missing token");
            Error::Unauthorized
        })
        .map(|TypedHeader(Authorization(bearer))| bearer.token().into())?;

    let id = app_state
        .token_factory
        .verify_token(&token)
        .map_err(|error| {
            warn!(error = format!("{error:#}"), "cannot verify token");
            Error::Unauthorized
        })?;

    let UpdateUser {
        username,
        email,
        password,
        bio,
    } = request.user;

    let username = username
        .map(|Username(u)| u.try_into())
        .transpose()
        .map_err(Into::into);
    let email = email
        .map(|Email(e)| e.try_into())
        .transpose()
        .map_err(Into::into);
    let password = password
        .map(|Password(p)| p.try_into())
        .transpose()
        .map_err(Into::into);
    let bio = bio
        .map(|bio| bio.map(TryInto::try_into).transpose())
        .transpose()
        .map_err(Into::into);

    let (username, email, password, bio) = (username.into_validated() + email + password + bio)
        .into_result()
        .map(|hlist_pat![username, email, password, bio]| (username, email, password, bio))
        .map_err(Error::InvalidInput)?;

    let user = app_state
        .user_service
        .update_user(id, username, email, password, bio)
        .await
        .map_err(|error| match error {
            UpdateUserError::UnknownUser(id) => {
                error!(%id, error = format!("{error:#}"), "current user not found");
                Error::NotFound
            }

            UpdateUserError::EmailTaken | UpdateUserError::UsernameTaken => {
                Error::Conflict(error.into())
            }

            UpdateUserError::PasswordHash(error) => {
                error!(%id, error = format!("{error:#}"), "cannot get current user");
                Error::Internal
            }

            UpdateUserError::UserRepository(error) => {
                error!(%id, error = format!("{error:#}"), "cannot get current user");
                Error::Internal
            }
        })?;

    Ok(Json((user, token).into()))
}

/// Register a new user.
#[utoipa::path(
    post,
    path = USERS,
    responses(
        (status = 201, description = "Registered user.", body = UserResponse),
        (status = 409, description = "Conflicting user data.", body = Conflict),
        (status = 422, description = "Invalid user data.", body = UnprocessableEntity),
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
        username: Username(username),
        email: Email(email),
        password: Password(password),
    } = request.user;

    let username = username.try_into().map_err(Into::into);
    let email = email.parse().map_err(Into::into);
    let password = password.try_into().map_err(Into::into);

    let (username, email, password) = (username.into_validated() + email + password)
        .into_result()
        .map(|hlist_pat![username, email, password]| (username, email, password))
        .map_err(Error::InvalidInput)?;

    let user = app_state
        .user_service
        .register_user(username, email, password)
        .await
        .map_err(|error| match error {
            RegisterUserError::EmailTaken | RegisterUserError::UsernameTaken => {
                Error::Conflict(error.into())
            }

            RegisterUserError::PasswordHash(error) => {
                error!(error = format!("{error:#}"), "cannot register user");
                Error::Internal
            }

            RegisterUserError::UserRepository(error) => {
                error!(error = format!("{error:#}"), "cannot register user");
                Error::Internal
            }
        })?;

    let token = app_state
        .token_factory
        .create_token(user.id())
        .map_err(|error| {
            error!(?user, error = format!("{error:#}"), "cannot create token");
            Error::Internal
        })?;

    Ok(Json((user, token).into()))
}

/// Login for an existing user.
#[utoipa::path(
    post,
    path = USERS_LOGIN,
    responses(
        (status = 201, description = "Registered user.", body = UserResponse),
        (status = 401, description = "Unauthorized."),
        (status = 404, description = "User not found."),
        (status = 422, description = "Invalid credentials.", body = UnprocessableEntity),
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
    let Credentials {
        email: Email(email),
        password: Password(password),
    } = request.user;

    let email = email.parse().map_err(Into::into);
    let password = password.try_into().map_err(Into::into);

    let (email, password) = (email.into_validated() + password)
        .into_result()
        .map(|hlist_pat![email, password]| (email, password))
        .map_err(Error::InvalidInput)?;

    let user = app_state
        .user_service
        .login_user(&email, &password)
        .await
        .map_err(|error| match error {
            LoginError::UnknownUser(ref email) => {
                error!(%email, error = format!("{error:#}"), "user not found");
                Error::NotFound
            }

            LoginError::InvalidCredentials => Error::Unauthorized,

            LoginError::PasswordHash(error) => {
                error!(%email, error = format!("{error:#}"), "cannot login user");
                Error::Internal
            }

            LoginError::UserRepository(error) => {
                error!(%email, error = format!("{error:#}"), "cannot login user");
                Error::Internal
            }
        })?;

    let token = app_state
        .token_factory
        .create_token(user.id())
        .map_err(|error| {
            error!(?user, error = format!("{error:#}"), "cannot create token");
            Error::Internal
        })?;

    Ok(Json((user, token).into()))
}

/// Any value that is present is considered `Some`` value, including `null`.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}
