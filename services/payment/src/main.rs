//! TrustDID Payment Service -- Stripe billing, subscription management, and
//! plan enforcement for DID-as-a-Service.
//!
//! Endpoints:
//! - `GET  /health`                    -- health check
//! - `GET  /billing/plans`             -- list pricing plans
//! - `GET  /billing/plans/:id`         -- get single plan
//! - `POST /billing/checkout-session`  -- create Stripe Checkout Session
//! - `GET  /billing/subscription/:did` -- get subscription for DID
//! - `GET  /billing/usage/:did`        -- get usage for DID
//! - `POST /billing/portal-session`    -- create Stripe Customer Portal session
//! - `POST /webhooks/stripe`           -- Stripe webhook receiver
//! - `GET  /billing/validate/:did`     -- validate DID can perform action

mod db;
mod handlers;
mod models;
mod stripe;
mod webhook;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::db::Database;
use crate::handlers::AppState;
use crate::models::Plan;
use crate::stripe::StripeClient;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // ---------------------------------------------------------------------------
    // Configuration from environment
    // ---------------------------------------------------------------------------
    let stripe_secret = std::env::var("STRIPE_SECRET_KEY")
        .unwrap_or_else(|_| "sk_test_placeholder".into());
    let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET")
        .unwrap_or_else(|_| "whsec_placeholder".into());
    let db_path = std::env::var("DATABASE_PATH")
        .unwrap_or_else(|_| ":memory:".into());

    // Map plan IDs to Stripe price IDs from environment.
    let mut price_map = HashMap::new();
    if let Ok(pid) = std::env::var("STRIPE_PRICE_STARTUP") {
        price_map.insert("startup".to_string(), pid);
    }
    if let Ok(pid) = std::env::var("STRIPE_PRICE_SCALE") {
        price_map.insert("scale".to_string(), pid);
    }

    // ---------------------------------------------------------------------------
    // Database initialization
    // ---------------------------------------------------------------------------
    let db = Database::open(&db_path);

    // Seed plans with Stripe price IDs from env.
    let mut plans = Plan::all_plans();
    for plan in &mut plans {
        if let Some(pid) = price_map.get(&plan.id) {
            plan.stripe_price_id = Some(pid.clone());
        }
    }
    db.seed_plans(&plans);
    info!("Seeded {} pricing plans", plans.len());

    // ---------------------------------------------------------------------------
    // Application state
    // ---------------------------------------------------------------------------
    let state = Arc::new(AppState {
        db,
        stripe: StripeClient::new(stripe_secret),
        webhook_secret,
        price_map,
    });

    // ---------------------------------------------------------------------------
    // Router
    // ---------------------------------------------------------------------------
    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/billing/plans", get(handlers::list_plans))
        .route("/billing/plans/{id}", get(handlers::get_plan))
        .route(
            "/billing/checkout-session",
            post(handlers::create_checkout_session),
        )
        .route(
            "/billing/subscription/{did}",
            get(handlers::get_subscription),
        )
        .route("/billing/usage/{did}", get(handlers::get_usage))
        .route(
            "/billing/portal-session",
            post(handlers::create_portal_session),
        )
        .route("/webhooks/stripe", post(handlers::stripe_webhook))
        .route("/billing/validate/{did}", get(handlers::validate))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:3005";
    info!("trustdid-payment listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
