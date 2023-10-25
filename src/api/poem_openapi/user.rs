use crate::{
    api::poem_openapi::{ApiTag, GenericError, SilentError},
    domain::{
        self,
        user::{
            user_repository::UserRepository, GetUserError, LoginError, RegisterUserError,
            UserService,
        },
        SecretString,
    },
    infra::token_factory::TokenFactory,
};
use poem::{error::InternalServerError, Error, Result};
use poem_openapi::{
    auth::Bearer, payload::Json, types::Email, ApiResponse, Object, OpenApi, SecurityScheme,
};
use std::fmt::Display;
use tracing::{error, warn};

pub struct UserApi<U> {
    user_service: UserService<U>,
    token_factory: TokenFactory,
}

#[OpenApi]
impl<U> UserApi<U>
where
    U: UserRepository + Send + Sync,
{
    pub fn new(user_service: UserService<U>, token_factory: TokenFactory) -> Self {
        Self {
            user_service,
            token_factory,
        }
    }

    /// Get the currently logged-in user.
    #[oai(path = "/user", method = "get", tag = "ApiTag::User")]
    async fn get_current_user(&self, Auth(bearer): Auth) -> Result<GetCurrentUserResponse> {
        let token = bearer.token.into();

        let id = self.token_factory.verify_token(&token).map_err(|error| {
            warn!(error = format!("{error:#}"), "cannot verify token");
            GetCurrentUserResponse::Unauthorized
        })?;

        match self.user_service.user_by_id(id).await {
            Ok(user) => Ok(GetCurrentUserResponse::ok((user, token).into())),
            Err(GetUserError::UnknownUser(_)) => Ok(GetCurrentUserResponse::Unauthorized),

            Err(error) => {
                error!(%id, error = format!("{error:#}"), "cannot get current user");
                Err(InternalServerError(SilentError))
            }
        }
    }

    /// Register a new user.
    #[oai(path = "/users", method = "post", tag = "ApiTag::User")]
    async fn register_user(
        &self,
        Json(register_request): Json<RegisterUserRequest>,
    ) -> Result<RegisterUserResponse> {
        let NewUser {
            username,
            email,
            password,
        } = register_request.user;

        let username = username
            .try_into()
            .map_err(RegisterUserResponse::unprocessable_entity)?;
        let email = email
            .parse()
            .map_err(RegisterUserResponse::unprocessable_entity)?;
        let password = password
            .try_into()
            .map_err(RegisterUserResponse::unprocessable_entity)?;

        let user = self
            .user_service
            .register_user(username, email, password)
            .await;

        match user {
            Ok(user) => match self.token_factory.create_token(user.id()) {
                Ok(token) => Ok(RegisterUserResponse::ok((user, token).into())),

                Err(error) => {
                    error!(?user, error = format!("{error:#}"), "cannot register user");
                    Err(InternalServerError(SilentError))
                }
            },

            Err(error @ RegisterUserError::EmailTaken) => Ok(RegisterUserResponse::conflict(error)),

            Err(error @ RegisterUserError::UsernameTaken) => {
                Ok(RegisterUserResponse::conflict(error))
            }

            Err(error) => {
                error!(error = format!("{error:#}"), "cannot register user");
                Err(InternalServerError(SilentError))
            }
        }
    }

    /// Login for an existing user.
    #[oai(path = "/users/login", method = "post", tag = "ApiTag::User")]
    async fn login_user(&self, Json(login_request): Json<LoginRequest>) -> Result<LoginResponse> {
        let Credentials { email, password } = login_request.user;

        let email = email.parse().map_err(LoginResponse::unprocessable_entity)?;
        let password = password
            .try_into()
            .map_err(LoginResponse::unprocessable_entity)?;

        let user = self.user_service.login_user(&email, &password).await;

        match user {
            Ok(user) => match self.token_factory.create_token(user.id()) {
                Ok(token) => Ok(LoginResponse::ok((user, token).into())),

                Err(error) => {
                    error!(%email, error = format!("{error:#}"), "cannot login user");
                    Err(InternalServerError(SilentError))
                }
            },

            Err(LoginError::InvalidCredentials) => Ok(LoginResponse::Unauthorized),

            Err(error) => {
                error!(%email, error = format!("{error:#}"), "cannot login user");
                Err(InternalServerError(SilentError))
            }
        }
    }
}

/// Request to register a new user.
#[derive(Debug, Object)]
struct RegisterUserRequest {
    user: NewUser,
}

/// New user to be registered.
#[derive(Debug, Object)]
struct NewUser {
    username: String,
    email: Email,
    password: SecretString,
}

#[derive(Debug, ApiResponse)]
#[oai(bad_request_handler = "RegisterUserResponse::bad_request_handler")]
enum RegisterUserResponse {
    /// Successfully registered user.
    #[oai(status = 201)]
    Ok(Json<UserResponse>),

    /// Conflicting data for new user to be registered.
    #[oai(status = 409)]
    Conflict(Json<GenericError>),

    /// Invalid data for new user to be registered.
    #[oai(status = 422)]
    UnprocessableEntity(Json<GenericError>),
}

impl RegisterUserResponse {
    fn ok(user_response: UserResponse) -> Self {
        RegisterUserResponse::Ok(Json(user_response))
    }

    fn conflict<S>(msg: S) -> Self
    where
        S: Display,
    {
        RegisterUserResponse::Conflict(Json(GenericError::new(msg)))
    }

    fn unprocessable_entity<S>(msg: S) -> Self
    where
        S: Display,
    {
        RegisterUserResponse::UnprocessableEntity(Json(GenericError::new(msg)))
    }

    fn bad_request_handler(error: Error) -> Self {
        Self::unprocessable_entity(error)
    }
}

/// Request to login an existing user.
#[derive(Debug, Object)]
struct LoginRequest {
    user: Credentials,
}

/// Credentials to login an existing user.
#[derive(Debug, Object)]
struct Credentials {
    email: Email,
    password: SecretString,
}

#[derive(Debug, ApiResponse)]
#[oai(bad_request_handler = "LoginResponse::bad_request_handler")]
enum LoginResponse {
    /// Successfully logged-in user.
    #[oai(status = 200)]
    Ok(Json<UserResponse>),

    /// Unauthorized.
    #[oai(status = 401)]
    Unauthorized,

    /// Invalid credentials.
    #[oai(status = 422)]
    UnprocessableEntity(Json<GenericError>),
}

impl LoginResponse {
    fn ok(user_response: UserResponse) -> Self {
        LoginResponse::Ok(Json(user_response))
    }

    fn unprocessable_entity<S>(msg: S) -> Self
    where
        S: Display,
    {
        LoginResponse::UnprocessableEntity(Json(GenericError::new(msg)))
    }

    fn bad_request_handler(error: Error) -> Self {
        Self::unprocessable_entity(error)
    }
}

#[derive(Debug, ApiResponse)]
enum GetCurrentUserResponse {
    /// Currently logged-in user.
    #[oai(status = 200)]
    Ok(Json<UserResponse>),

    /// Unauthorized.
    #[oai(status = 401)]
    Unauthorized,
}

impl GetCurrentUserResponse {
    fn ok(user_response: UserResponse) -> Self {
        GetCurrentUserResponse::Ok(Json(user_response))
    }
}

#[derive(SecurityScheme)]
#[oai(ty = "bearer")]
struct Auth(Bearer);

/// A user.
#[derive(Debug, Object)]
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
#[derive(Debug, Object)]
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
            email: Email(email.to_string()),
            token: token.expose_secret().to_owned(),
            bio: bio.map(|b| b.into()),
        }
    }
}
