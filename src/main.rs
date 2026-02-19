use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use webauthn_rs::prelude::*;

// --- Data Models ---

#[derive(Default)]
pub struct AppState {
    pub users: Mutex<HashMap<String, Passkey>>,
    pub reg_challenges: Mutex<HashMap<String, PasskeyRegistration>>,
    pub auth_challenges: Mutex<HashMap<String, PasskeyAuthentication>>,
}

#[derive(serde::Deserialize)]
struct AuthParams {
    username: String,
}

type SharedState = (Arc<Webauthn>, Arc<AppState>);

#[tokio::main]
async fn main() {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:3000").expect("Invalid URL");

    let webauthn = Arc::new(
        WebauthnBuilder::new(rp_id, &rp_origin)
            .expect("Invalid RP Configuration")
            .build()
            .expect("Failed to build WebAuthn"),
    );

    let state = Arc::new(AppState::default());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // let app = Router::new()
    //     .nest_service("/", ServeDir::new("static"))
    //     .route("/register/start", post(start_registration))
    //     .route("/register/finish", post(finish_registration))
    //     .route("/login/start", post(start_authentication))
    //     .route("/login/finish", post(finish_authentication))
    //     .layer(cors)
    //     .with_state((webauthn, state));

    let app = Router::new()
    .route("/register/start", post(start_registration))
    .route("/register/finish", post(finish_registration))
    .route("/login/start", post(start_authentication))
    .route("/login/finish", post(finish_authentication))
    .fallback_service(ServeDir::new("static")) // Use this instead
    .layer(cors)
    .with_state((webauthn, state));

    println!("🚀 Server started at http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// --- Handlers ---

async fn start_registration(
    Query(params): Query<AuthParams>,
    State((webauthn, state)): State<SharedState>,
) -> Result<Json<CreationChallengeResponse>, (StatusCode, String)> {
    let user_id = uuid::Uuid::new_v4();

    match webauthn.start_passkey_registration(user_id, &params.username, &params.username, None) {
        Ok((options, reg_state)) => {
            state.reg_challenges.lock().unwrap().insert(params.username, reg_state);
            Ok(Json(options))
        }
        Err(e) => {
            eprintln!("Registration Start Error: {:?}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn finish_registration(
    Query(params): Query<AuthParams>,
    State((webauthn, state)): State<SharedState>,
    Json(reg_response): Json<RegisterPublicKeyCredential>,
) -> Result<&'static str, (StatusCode, String)> {
    let reg_state = state
        .reg_challenges
        .lock()
        .unwrap()
        .remove(&params.username)
        .ok_or((StatusCode::BAD_REQUEST, "No challenge found".to_string()))?;

    match webauthn.finish_passkey_registration(&reg_response, &reg_state) {
        Ok(passkey) => {
            state.users.lock().unwrap().insert(params.username, passkey);
            Ok("Passkey Registered Successfully")
        }
        Err(e) => {
            eprintln!("Registration Finish Error: {:?}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn start_authentication(
    Query(params): Query<AuthParams>,
    State((webauthn, state)): State<SharedState>,
) -> Result<Json<RequestChallengeResponse>, (StatusCode, String)> {
    let users_db = state.users.lock().unwrap();
    let passkey = users_db
        .get(&params.username)
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    match webauthn.start_passkey_authentication(&[passkey.clone()]) {
        Ok((options, auth_state)) => {
            state.auth_challenges.lock().unwrap().insert(params.username, auth_state);
            Ok(Json(options))
        }
        Err(e) => {
            eprintln!("Authentication Start Error: {:?}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn finish_authentication(
    Query(params): Query<AuthParams>,
    State((webauthn, state)): State<SharedState>,
    Json(auth_response): Json<PublicKeyCredential>, // Renamed from Discoverable...
) -> Result<&'static str, (StatusCode, String)> {
    let auth_state = state
        .auth_challenges
        .lock()
        .unwrap()
        .remove(&params.username)
        .ok_or((StatusCode::BAD_REQUEST, "No challenge found".to_string()))?;

    // Note the '&auth_state' - we pass a reference here to fix your E0308 error
    match webauthn.finish_passkey_authentication(&auth_response, &auth_state) {
        Ok(_) => Ok("Login Successful"),
        Err(e) => {
            eprintln!("Authentication Finish Error: {:?}", e);
            Err((StatusCode::FORBIDDEN, "Invalid Signature".to_string()))
        }
    }
}