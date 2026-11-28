mod audit;
mod auth;
#[rustfmt::skip]
mod pos;
mod paypal;
mod sumup;
mod calendar;
mod loyalty;
mod integration_crypto;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use std::{env, net::SocketAddr, time::Duration};
use tracing_subscriber::EnvFilter;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    database: &'static str,
}

async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "tomos-pos-api",
        database: "not_checked",
    })
}

async fn ready(State(state): State<auth::AuthState>) -> Result<Json<HealthResponse>, StatusCode> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(|error| {
            tracing::error!(%error, "database readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        })?;

    Ok(Json(HealthResponse {
        status: "ok",
        service: "tomos-pos-api",
        database: "ok",
    }))
}

async fn tenant_context(
    Extension(context): Extension<auth::AuthContext>,
) -> Json<auth::TenantContextResponse> {
    Json(auth::TenantContextResponse {
        user_id: context.user_id.to_string(),
        tenant_id: context.tenant_id.to_string(),
        membership_id: context.membership_id.to_string(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be configured before starting the API");

    let db = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    sqlx::migrate!("../../database/migrations").run(&db).await?;

    tracing::info!("database connected and migrations applied");

    let auth_state = auth::AuthState {
        db,
        cookie_secure: env::var("COOKIE_SECURE")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(true),
        allowed_origin: env::var("APP_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:3000".to_string()),
    };

    let app = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/v1/auth/setup", post(auth::initial_setup))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/tenants", get(auth::list_user_tenants))
        .route(
            "/api/v1/staff/invitations/accept",
            post(auth::accept_staff_invitation),
        )
        .route(
            "/api/v1/staff/invitations",
            get(auth::list_staff_invitations)
                .post(auth::create_staff_invitation)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "roles.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/invitations/{invitation_id}",
            delete(auth::revoke_staff_invitation)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "roles.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/memberships",
            get(auth::list_staff_memberships)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "staff.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/memberships/{membership_id}",
            delete(auth::deactivate_staff_membership)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "staff.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/roles",
            get(auth::list_staff_roles)
                .post(auth::create_custom_role)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "roles.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/permissions",
            get(auth::list_permission_catalogue)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "roles.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/roles/{role_id}/permissions",
            put(auth::update_custom_role_permissions)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "roles.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/memberships/{membership_id}/roles",
            post(auth::assign_staff_role)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "roles.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/staff/memberships/{membership_id}/roles/{role_id}",
            delete(auth::remove_staff_role)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "roles.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/businesses",
            get(auth::list_businesses)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/businesses/create",
            post(auth::create_business)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/businesses/{business_id}",
            put(auth::update_business)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/businesses/{business_id}/locations",
            get(auth::list_business_locations)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/businesses/{business_id}/locations/create",
            post(auth::create_business_location)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/business-locations/{location_id}",
            put(auth::update_business_location)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/tenant/context",
            get(tenant_context)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/catalogue",
            get(pos::list_products)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.catalog.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/products",
            post(pos::create_product)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.catalog.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/tills/current",
            get(pos::current_till)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.checkout",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/tills/open",
            post(pos::open_till)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.till.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/tills/{till_id}/cash-movements",
            post(pos::record_cash_movement)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.till.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/tills/{till_id}/close",
            post(pos::close_till)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.till.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/sales",
            post(pos::checkout)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.checkout",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/paypal/connect",
            post(paypal::connect_business)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "business.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/paypal/onboarding/return",
            get(paypal::onboarding_return),
        )
        .route("/api/v1/paypal/webhook", post(paypal::webhook))
        .route(
            "/api/v1/pos/sales/{sale_id}/paypal/order",
            post(paypal::create_order)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.checkout",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/sales/{sale_id}/paypal/cancel",
            post(paypal::cancel_order)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.checkout",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/sales/{sale_id}/paypal/capture",
            post(paypal::capture_order)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.checkout",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sumup/connect",
            post(sumup::connect_business)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "integrations.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sumup/oauth/callback",
            get(sumup::oauth_callback),
        )
        .route(
            "/api/v1/sumup/select-merchant",
            post(sumup::select_merchant)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "integrations.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sumup/status",
            get(sumup::connection_status)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "integrations.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sumup/readers",
            get(sumup::list_readers)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.checkout",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/pos/sales/{sale_id}/sumup/reader-checkout",
            post(sumup::start_reader_checkout)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "pos.checkout",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sumup/reader-webhook",
            post(sumup::reader_webhook),
        )
        .route(
            "/api/v1/calendar/connect",
            post(calendar::connect)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "integrations.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/calendar/oauth/callback",
            get(calendar::oauth_callback),
        )
        .route(
            "/api/v1/calendar/status",
            get(calendar::connection_status)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "calendar.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/calendar/appointments",
            get(calendar::list_appointments)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "calendar.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/calendar/appointments/create",
            post(calendar::create_appointment)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "calendar.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/calendar/sync",
            post(calendar::sync)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "calendar.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/calendar/appointments/{appointment_id}",
            put(calendar::update_appointment)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "calendar.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/loyalty/customers",
            get(loyalty::list_customers)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "loyalty.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/loyalty/customers/create",
            post(loyalty::create_customer)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "loyalty.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/loyalty/programs",
            get(loyalty::get_program)
                .post(loyalty::save_program)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "loyalty.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/loyalty/customers/{customer_id}/redeem",
            post(loyalty::redeem_points)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "loyalty.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/loyalty/customers/{customer_id}/ledger",
            get(loyalty::customer_ledger)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "loyalty.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .with_state(auth_state);

    let host = env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("API_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8080);
    let address: SocketAddr = format!("{host}:{port}").parse()?;

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "TomOS POS API listening");

    axum::serve(listener, app).await?;
    Ok(())
}
