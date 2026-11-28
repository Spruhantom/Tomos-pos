use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::auth::{begin_tenant_transaction, AuthContext, AuthState};

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn origin_is_allowed(headers: &HeaderMap, state: &AuthState) -> bool {
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == state.allowed_origin)
}

#[derive(Deserialize)]
pub struct BusinessQuery {
    business_id: uuid::Uuid,
}

#[derive(FromRow, Serialize)]
struct CustomerRow {
    id: uuid::Uuid,
    display_name: String,
    email: Option<String>,
    phone: Option<String>,
    balance_points: i64,
    lifetime_earned: i64,
    lifetime_redeemed: i64,
}

pub async fn list_customers(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<BusinessQuery>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "loyalty customer list transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "customers could not be loaded");
        }
    };
    let rows = sqlx::query_as::<_, CustomerRow>(
        "SELECT c.id, c.display_name, c.email, c.phone, COALESCE(a.balance_points,0) AS balance_points, \
         COALESCE(a.lifetime_earned,0) AS lifetime_earned, COALESCE(a.lifetime_redeemed,0) AS lifetime_redeemed \
         FROM pos_customers c LEFT JOIN loyalty_accounts a ON a.tenant_id=c.tenant_id AND a.business_id=c.business_id AND a.customer_id=c.id \
         WHERE c.tenant_id=$1 AND c.business_id=$2 ORDER BY lower(c.display_name) LIMIT 500",
    )
    .bind(context.tenant_id)
    .bind(query.business_id)
    .fetch_all(&mut *tx)
    .await;
    match rows {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => {
            tracing::error!(%err, "loyalty customer list query failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "customers could not be loaded")
        }
    }
}

#[derive(Deserialize)]
pub struct CreateCustomerRequest {
    business_id: uuid::Uuid,
    display_name: String,
    email: Option<String>,
    phone: Option<String>,
}

pub async fn create_customer(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<CreateCustomerRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    let name = request.display_name.trim();
    if !(1..=160).contains(&name.len())
        || request.email.as_ref().is_some_and(|v| v.len() > 254)
        || request.phone.as_ref().is_some_and(|v| v.len() > 40)
    {
        return error(StatusCode::BAD_REQUEST, "customer details are invalid");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "customer create transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "customer could not be created");
        }
    };
    let customer = sqlx::query_as::<_, (uuid::Uuid, String)>(
        "INSERT INTO pos_customers (tenant_id,business_id,display_name,email,phone) \
         SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM businesses WHERE tenant_id=$1 AND id=$2) \
         RETURNING id,display_name",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(name)
    .bind(request.email.as_deref().map(str::trim).filter(|v| !v.is_empty()))
    .bind(request.phone.as_deref().map(str::trim).filter(|v| !v.is_empty()))
    .fetch_optional(&mut *tx)
    .await;
    match customer {
        Ok(Some((id, display_name))) => {
            if let Err(err) = tx.commit().await {
                tracing::error!(%err, "customer create commit failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, "customer could not be created");
            }
            (StatusCode::CREATED, Json(serde_json::json!({
                "id": id, "display_name": display_name, "balance_points": 0
            }))).into_response()
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "business was not found"),
        Err(err) => {
            tracing::error!(%err, "customer insert failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "customer could not be created")
        }
    }
}

#[derive(FromRow, Serialize)]
struct ProgramRow {
    enabled: bool,
    points_per_major_unit: i32,
    redemption_points_per_major_unit: i32,
}

pub async fn get_program(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<BusinessQuery>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "loyalty programme transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty programme could not be loaded");
        }
    };
    match sqlx::query_as::<_, ProgramRow>(
        "SELECT enabled,points_per_major_unit,redemption_points_per_major_unit FROM loyalty_programs WHERE tenant_id=$1 AND business_id=$2",
    )
    .bind(context.tenant_id)
    .bind(query.business_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(program)) => Json(program).into_response(),
        Ok(None) => Json(serde_json::json!({
            "enabled": false, "points_per_major_unit": 1, "redemption_points_per_major_unit": 100
        })).into_response(),
        Err(err) => {
            tracing::error!(%err, "loyalty programme lookup failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty programme could not be loaded")
        }
    }
}

#[derive(Deserialize)]
pub struct SaveProgramRequest {
    business_id: uuid::Uuid,
    enabled: bool,
    points_per_major_unit: i32,
    redemption_points_per_major_unit: i32,
}

pub async fn save_program(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<SaveProgramRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if !(0..=10_000).contains(&request.points_per_major_unit)
        || !(1..=100_000).contains(&request.redemption_points_per_major_unit)
    {
        return error(StatusCode::BAD_REQUEST, "loyalty programme settings are invalid");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "loyalty programme save transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty programme could not be saved");
        }
    };
    let saved = sqlx::query(
        "INSERT INTO loyalty_programs (tenant_id,business_id,enabled,points_per_major_unit,redemption_points_per_major_unit) \
         SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM businesses WHERE tenant_id=$1 AND id=$2) \
         ON CONFLICT (tenant_id,business_id) DO UPDATE SET enabled=EXCLUDED.enabled, points_per_major_unit=EXCLUDED.points_per_major_unit, redemption_points_per_major_unit=EXCLUDED.redemption_points_per_major_unit, updated_at=now()",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(request.enabled)
    .bind(request.points_per_major_unit)
    .bind(request.redemption_points_per_major_unit)
    .execute(&mut *tx)
    .await;
    match saved {
        Ok(result) if result.rows_affected() == 1 => {
            if let Err(err) = tx.commit().await {
                tracing::error!(%err, "loyalty programme commit failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty programme could not be saved");
            }
            Json(serde_json::json!({ "status": "saved" })).into_response()
        }
        Ok(_) => error(StatusCode::NOT_FOUND, "business was not found"),
        Err(err) => {
            tracing::error!(%err, "loyalty programme upsert failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty programme could not be saved")
        }
    }
}

#[derive(Deserialize)]
pub struct RedeemRequest {
    points: i64,
}

pub async fn redeem_points(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(customer_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<RedeemRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if request.points <= 0 || request.points > 10_000_000 {
        return error(StatusCode::BAD_REQUEST, "points to redeem must be positive");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "loyalty redemption transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty reward could not be redeemed");
        }
    };
    let settings = sqlx::query_as::<_, (uuid::Uuid, i32)>(
        "SELECT c.business_id, p.redemption_points_per_major_unit FROM pos_customers c \
         JOIN loyalty_programs p ON p.tenant_id=c.tenant_id AND p.business_id=c.business_id AND p.enabled=TRUE \
         WHERE c.tenant_id=$1 AND c.id=$2",
    )
    .bind(context.tenant_id)
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await;
    let (business_id, points_per_major) = match settings {
        Ok(Some(values)) => values,
        Ok(None) => return error(StatusCode::NOT_FOUND, "customer or enabled loyalty programme was not found"),
        Err(err) => {
            tracing::error!(%err, "loyalty programme lookup for redemption failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty reward could not be redeemed");
        }
    };
    let reward_value = (i128::from(request.points) * 100 / i128::from(points_per_major)) as i64;
    if reward_value <= 0 {
        return error(StatusCode::BAD_REQUEST, "not enough points for a reward");
    }
    let balance = sqlx::query_scalar::<_, i64>(
        "UPDATE loyalty_accounts SET balance_points=balance_points-$4, lifetime_redeemed=lifetime_redeemed+$4, updated_at=now() \
         WHERE tenant_id=$1 AND business_id=$2 AND customer_id=$3 AND balance_points >= $4 RETURNING balance_points",
    )
    .bind(context.tenant_id)
    .bind(business_id)
    .bind(customer_id)
    .bind(request.points)
    .fetch_optional(&mut *tx)
    .await;
    let balance = match balance {
        Ok(Some(value)) => value,
        Ok(None) => return error(StatusCode::CONFLICT, "customer does not have enough loyalty points"),
        Err(err) => {
            tracing::error!(%err, "loyalty balance debit failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty reward could not be redeemed");
        }
    };
    let reward_code = uuid::Uuid::new_v4().to_string().to_uppercase();
    let redemption_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO loyalty_redemptions (tenant_id,business_id,customer_id,reward_code,points_redeemed,reward_value_minor) \
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(business_id)
    .bind(customer_id)
    .bind(&reward_code)
    .bind(request.points)
    .bind(reward_value)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(%err, "loyalty reward record insert failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty reward could not be redeemed");
        }
    };
    if let Err(err) = sqlx::query(
        "INSERT INTO loyalty_ledger (tenant_id,business_id,customer_id,entry_type,points_delta,note,created_by) \
         VALUES ($1,$2,$3,'redeemed',$4,$5,$6)",
    )
    .bind(context.tenant_id)
    .bind(business_id)
    .bind(customer_id)
    .bind(-request.points)
    .bind(format!("Reward redeemed: {reward_code}"))
    .bind(context.user_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "loyalty redemption ledger insert failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty reward could not be redeemed");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "loyalty redemption commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty reward could not be redeemed");
    }
    (StatusCode::CREATED, Json(serde_json::json!({
        "redemption_id": redemption_id,
        "reward_code": reward_code,
        "points_redeemed": request.points,
        "reward_value_minor": reward_value,
        "balance_points": balance,
        "status": "issued"
    }))).into_response()
}

#[derive(FromRow, Serialize)]
struct LedgerRow {
    entry_type: String,
    points_delta: i64,
    note: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn customer_ledger(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(customer_id): Path<uuid::Uuid>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "loyalty ledger transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty history could not be loaded");
        }
    };
    match sqlx::query_as::<_, LedgerRow>(
        "SELECT entry_type,points_delta,note,created_at FROM loyalty_ledger \
         WHERE tenant_id=$1 AND customer_id=$2 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(context.tenant_id)
    .bind(customer_id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => {
            tracing::error!(%err, "loyalty ledger query failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "loyalty history could not be loaded")
        }
    }
}
