use std::sync::Arc;

use auth_service::services::mock_email_client::MockEmailClient;
use auth_service::services::postgres_user_store::PostgresUserStore;
use auth_service::utils::constants::{prod, DATABASE_URL};
use auth_service::{get_postgres_pool, Application};
use sqlx::PgPool;
use tokio::sync::RwLock;

use auth_service::app_state::AppState;
use auth_service::services::hashmap_two_fa_code_store::HashmapTwoFACodeStore;
use auth_service::services::hashset_banned_token_store::HashsetBannedTokenStore;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;

    let user_store = PostgresUserStore::new(pg_pool);
    let banned_token_store = HashsetBannedTokenStore::default();
    let two_fa_code_store = HashmapTwoFACodeStore::default();
    let email_client = MockEmailClient;
    let app_state = AppState {
        user_store: Arc::new(RwLock::new(user_store)),
        banned_token_store: Arc::new(RwLock::new(banned_token_store)),
        two_fa_code_store: Arc::new(RwLock::new(two_fa_code_store)),
        email_client: Arc::new(RwLock::new(email_client)),
    };
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed ot create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}
