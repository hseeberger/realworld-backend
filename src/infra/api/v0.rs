mod users;

use crate::{domain::user_repository::UserRepository, infra::api::AppState};
use axum::Router;

pub fn routes<R>() -> Router<AppState<R>>
where
    R: UserRepository,
{
    Router::new().merge(users::routes())
}
