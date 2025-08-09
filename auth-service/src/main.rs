use std::sync::Arc;

use auth_service::utils::constants::prod;
use auth_service::Application;
use tokio::sync::RwLock;

use auth_service::app_state::AppState;
use auth_service::services::hashmap_user_store::HashmapUserStore;

#[tokio::main]
async fn main() {
    let user_store = HashmapUserStore::default();
    let app_state = AppState {
        user_store: Arc::new(RwLock::new(user_store)),
    };
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
