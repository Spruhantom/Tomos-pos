mod audit;
mod auth;
mod basket;
mod cash;
mod catalogue;
mod sales;
pub(crate) mod sumup;

use axum::{
    extract::{DefaultBodyLimit, Extension, State},
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
            "/api/v1/payments/sumup/webhook/{token}",
            post(sumup::webhook).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/api/v1/products",
            get(catalogue::list_products)
                .post(catalogue::create_product)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "catalogue.read",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sales/basket",
            post(basket::create_basket_sale)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "sales.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sales",
            post(sales::create_sale)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "sales.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sales/{sale_id}",
            get(sales::get_sale)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "sales.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sales/{sale_id}/payments/cash",
            post(cash::take_cash_payment)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "sales.manage",
                    },
                    auth::require_permission,
                ))
                .route_layer(from_fn_with_state(auth_state.clone(), auth::require_tenant)),
        )
        .route(
            "/api/v1/sales/{sale_id}/payments/sumup",
            post(sales::start_sumup_payment)
                .route_layer(from_fn_with_state(
                    auth::PermissionState {
                        auth: auth_state.clone(),
                        permission_key: "sales.manage",
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
