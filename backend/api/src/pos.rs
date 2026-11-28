use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::{
    audit::{AuditEntityType, AuditEventType},
    auth::{begin_tenant_transaction, AuthContext, AuthState},
};

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn origin_is_allowed(headers: &HeaderMap, state: &AuthState) -> bool {
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == state.allowed_origin)
}

#[derive(FromRow, Serialize)]
struct ProductRow {
    id: uuid::Uuid,
    sku: String,
    barcode: Option<String>,
    name: String,
    unit_price_minor: i64,
    currency_code: String,
    tax_rate_bps: i32,
}

#[derive(Deserialize)]
pub struct CatalogueQuery {
    business_id: uuid::Uuid,
}

pub async fn list_products(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<CatalogueQuery>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "catalogue transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "catalogue could not be loaded");
        }
    };
    let products = match sqlx::query_as::<_, ProductRow>(
        "SELECT id, sku, barcode, name, unit_price_minor, currency_code::text AS currency_code, tax_rate_bps \
         FROM products WHERE tenant_id = $1 AND business_id = $2 AND is_active = TRUE \
         ORDER BY name, sku LIMIT 500",
    )
    .bind(context.tenant_id)
    .bind(query.business_id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(products) => products,
        Err(db_error) => {
            tracing::error!(%db_error, "catalogue query failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "catalogue could not be loaded");
        }
    };
    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "catalogue transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "catalogue could not be loaded");
    }
    Json(serde_json::json!({ "products": products })).into_response()
}

#[derive(Deserialize)]
pub struct CreateProductRequest {
    business_id: uuid::Uuid,
    sku: String,
    barcode: Option<String>,
    name: String,
    description: Option<String>,
    unit_price_minor: i64,
    cost_price_minor: Option<i64>,
    tax_rate_bps: i32,
}

pub async fn create_product(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<CreateProductRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if request.sku.trim().is_empty()
        || request.sku.trim().len() > 64
        || request.name.trim().is_empty()
        || request.name.trim().len() > 200
        || request.unit_price_minor < 0
        || request.cost_price_minor.is_some_and(|price| price < 0)
        || !(0..=10_000).contains(&request.tax_rate_bps)
        || request.barcode.as_ref().is_some_and(|value| value.trim().len() > 80)
        || request.description.as_ref().is_some_and(|value| value.len() > 2000)
    {
        return error(StatusCode::BAD_REQUEST, "product details are invalid");
    }

    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "product creation transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "product could not be created");
        }
    };
    let currency: Option<String> = match sqlx::query_scalar(
        "SELECT currency_code::text FROM businesses WHERE tenant_id = $1 AND id = $2",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(currency) => currency,
        Err(db_error) => {
            tracing::error!(%db_error, "product business lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "product could not be created");
        }
    };
    let Some(currency) = currency else {
        return error(StatusCode::NOT_FOUND, "business was not found");
    };

    let product_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO products (tenant_id, business_id, sku, barcode, name, description, unit_price_minor, cost_price_minor, currency_code, tax_rate_bps) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(request.sku.trim())
    .bind(request.barcode.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(request.name.trim())
    .bind(request.description.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(request.unit_price_minor)
    .bind(request.cost_price_minor)
    .bind(currency)
    .bind(request.tax_rate_bps)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(sqlx::Error::Database(db_error)) if db_error.code().as_deref() == Some("23505") => {
            return error(StatusCode::CONFLICT, "SKU or barcode is already in use");
        }
        Err(db_error) => {
            tracing::error!(%db_error, "product insert failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "product could not be created");
        }
    };
    if let Err(db_error) = crate::audit::record_event(
        &mut tx,
        &context,
        AuditEventType::ProductCreated,
        AuditEntityType::Product,
        Some(product_id),
        serde_json::json!({ "business_id": request.business_id, "sku": request.sku.trim() }),
    )
    .await
    {
        tracing::error!(%db_error, "product audit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "product could not be created");
    }
    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "product transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "product could not be created");
    }
    (StatusCode::CREATED, Json(serde_json::json!({ "id": product_id }))).into_response()
}


#[derive(Deserialize)]
pub struct CurrentTillQuery {
    location_id: uuid::Uuid,
}

#[derive(FromRow, Serialize)]
struct TillSessionRow {
    id: uuid::Uuid,
    opening_float_minor: i64,
    currency_code: String,
}

pub async fn current_till(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<CurrentTillQuery>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "current till transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till status could not be loaded");
        }
    };
    let till = match sqlx::query_as::<_, TillSessionRow>(
        "SELECT id, opening_float_minor, currency_code::text AS currency_code \
         FROM till_sessions WHERE tenant_id = $1 AND location_id = $2 AND status = 'open'",
    )
    .bind(context.tenant_id)
    .bind(query.location_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(till) => till,
        Err(db_error) => {
            tracing::error!(%db_error, "current till lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till status could not be loaded");
        }
    };
    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "current till commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "till status could not be loaded");
    }
    Json(serde_json::json!({ "till": till })).into_response()
}

#[derive(Deserialize)]
pub struct OpenTillRequest {
    business_id: uuid::Uuid,
    location_id: uuid::Uuid,
    opening_float_minor: i64,
}

pub async fn open_till(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<OpenTillRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if request.opening_float_minor < 0 {
        return error(StatusCode::BAD_REQUEST, "opening float must not be negative");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "till opening transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be opened");
        }
    };
    let currency: Option<String> = match sqlx::query_scalar(
        "SELECT b.currency_code::text FROM businesses b JOIN business_locations l \
         ON l.tenant_id = b.tenant_id AND l.business_id = b.id \
         WHERE b.tenant_id = $1 AND b.id = $2 AND l.id = $3 AND l.is_active = TRUE",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(request.location_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "till business/location lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be opened");
        }
    };
    let Some(currency) = currency else {
        return error(StatusCode::NOT_FOUND, "business location was not found");
    };
    let till_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO till_sessions (tenant_id, business_id, location_id, opened_by, opening_float_minor, currency_code) \
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(request.location_id)
    .bind(context.user_id)
    .bind(request.opening_float_minor)
    .bind(&currency)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(sqlx::Error::Database(db_error)) if db_error.code().as_deref() == Some("23505") => {
            return error(StatusCode::CONFLICT, "this location already has an open till");
        }
        Err(db_error) => {
            tracing::error!(%db_error, "till session insert failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be opened");
        }
    };
    if let Err(db_error) = crate::audit::record_event(
        &mut tx, &context, AuditEventType::TillOpened, AuditEntityType::TillSession,
        Some(till_id), serde_json::json!({ "opening_float_minor": request.opening_float_minor }),
    ).await {
        tracing::error!(%db_error, "till opening audit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be opened");
    }
    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "till opening commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be opened");
    }
    (StatusCode::CREATED, Json(serde_json::json!({ "till_session_id": till_id, "status": "open", "currency_code": currency }))).into_response()
}

#[derive(Deserialize)]
pub struct CashMovementRequest {
    movement_type: String,
    amount_minor: i64,
    reason: String,
}

pub async fn record_cash_movement(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(till_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<CashMovementRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if !matches!(request.movement_type.as_str(), "paid_in" | "paid_out")
        || request.amount_minor <= 0
        || !(1..=240).contains(&request.reason.trim().len())
    {
        return error(StatusCode::BAD_REQUEST, "cash movement details are invalid");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "cash movement transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "cash movement could not be recorded");
        }
    };
    let available_cash: Option<i64> = match sqlx::query_scalar(
        "SELECT ts.opening_float_minor \
         + COALESCE((SELECT SUM(pt.amount_minor) FROM payment_tenders pt JOIN sales s ON s.tenant_id = pt.tenant_id AND s.id = pt.sale_id WHERE pt.tenant_id = ts.tenant_id AND s.till_session_id = ts.id AND pt.method = 'cash' AND pt.status = 'captured'), 0) \
         + COALESCE((SELECT SUM(cm.amount_minor) FROM till_cash_movements cm WHERE cm.tenant_id = ts.tenant_id AND cm.till_session_id = ts.id AND cm.movement_type = 'paid_in'), 0) \
         - COALESCE((SELECT SUM(cm.amount_minor) FROM till_cash_movements cm WHERE cm.tenant_id = ts.tenant_id AND cm.till_session_id = ts.id AND cm.movement_type = 'paid_out'), 0) \
         FROM till_sessions ts WHERE ts.tenant_id = $1 AND ts.id = $2 AND ts.status = 'open' FOR UPDATE",
    )
    .bind(context.tenant_id)
    .bind(till_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "cash drawer balance lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cash movement could not be recorded",
            );
        }
    };
    let Some(available_cash) = available_cash else {
        return error(StatusCode::NOT_FOUND, "open till was not found");
    };
    if request.movement_type == "paid_out" && request.amount_minor > available_cash {
        return error(
            StatusCode::BAD_REQUEST,
            "cash paid out cannot exceed the available drawer balance",
        );
    }

    let movement_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO till_cash_movements (tenant_id, till_session_id, movement_type, amount_minor, reason, recorded_by) \
         SELECT $1, id, $3, $4, $5, $6 FROM till_sessions WHERE tenant_id = $1 AND id = $2 AND status = 'open' RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(till_id)
    .bind(&request.movement_type)
    .bind(request.amount_minor)
    .bind(request.reason.trim())
    .bind(context.user_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(id)) => id,
        Ok(None) => return error(StatusCode::NOT_FOUND, "open till was not found"),
        Err(db_error) => {
            tracing::error!(%db_error, "cash movement insert failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "cash movement could not be recorded");
        }
    };
    if let Err(db_error) = crate::audit::record_event(
        &mut tx, &context, AuditEventType::CashMovementRecorded, AuditEntityType::CashMovement,
        Some(movement_id), serde_json::json!({ "movement_type": request.movement_type, "amount_minor": request.amount_minor }),
    ).await {
        tracing::error!(%db_error, "cash movement audit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "cash movement could not be recorded");
    }
    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "cash movement commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "cash movement could not be recorded");
    }
    (StatusCode::CREATED, Json(serde_json::json!({ "id": movement_id }))).into_response()
}

#[derive(Deserialize)]
pub struct CloseTillRequest {
    closing_count_minor: i64,
}

pub async fn close_till(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(till_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<CloseTillRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if request.closing_count_minor < 0 {
        return error(StatusCode::BAD_REQUEST, "closing cash count must not be negative");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "till closing transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be closed");
        }
    };
    let pending_card_payments: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_tenders pt JOIN sales s \
         ON s.tenant_id = pt.tenant_id AND s.id = pt.sale_id \
         WHERE pt.tenant_id = $1 AND s.till_session_id = $2 \
         AND pt.method = 'card_terminal' AND pt.status = 'pending'",
    )
    .bind(context.tenant_id)
    .bind(till_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(count) => count,
        Err(db_error) => {
            tracing::error!(%db_error, "pending card payment lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be closed");
        }
    };
    if pending_card_payments > 0 {
        return error(
            StatusCode::CONFLICT,
            "pending card-terminal payments must be resolved before closing the till",
        );
    }

    let expected: Option<i64> = match sqlx::query_scalar(
        "SELECT ts.opening_float_minor \
         + COALESCE((SELECT SUM(pt.amount_minor) FROM payment_tenders pt JOIN sales s ON s.tenant_id = pt.tenant_id AND s.id = pt.sale_id WHERE pt.tenant_id = ts.tenant_id AND s.till_session_id = ts.id AND pt.method = 'cash' AND pt.status = 'captured'), 0) \
         + COALESCE((SELECT SUM(cm.amount_minor) FROM till_cash_movements cm WHERE cm.tenant_id = ts.tenant_id AND cm.till_session_id = ts.id AND cm.movement_type = 'paid_in'), 0) \
         - COALESCE((SELECT SUM(cm.amount_minor) FROM till_cash_movements cm WHERE cm.tenant_id = ts.tenant_id AND cm.till_session_id = ts.id AND cm.movement_type = 'paid_out'), 0) \
         FROM till_sessions ts WHERE ts.tenant_id = $1 AND ts.id = $2 AND ts.status = 'open' FOR UPDATE",
    )
    .bind(context.tenant_id)
    .bind(till_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "till cash total query failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be closed");
        }
    };
    let Some(expected) = expected else {
        return error(StatusCode::NOT_FOUND, "open till was not found");
    };
    let updated = match sqlx::query(
        "UPDATE till_sessions SET closing_count_minor = $3, closed_by = $4, closed_at = now(), status = 'closed' \
         WHERE tenant_id = $1 AND id = $2 AND status = 'open'",
    )
    .bind(context.tenant_id)
    .bind(till_id)
    .bind(request.closing_count_minor)
    .bind(context.user_id)
    .execute(&mut *tx)
    .await
    {
        Ok(result) => result,
        Err(db_error) => {
            tracing::error!(%db_error, "till close update failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be closed");
        }
    };
    if updated.rows_affected() != 1 {
        return error(StatusCode::CONFLICT, "till has already been closed");
    }
    if let Err(db_error) = crate::audit::record_event(
        &mut tx, &context, AuditEventType::TillClosed, AuditEntityType::TillSession,
        Some(till_id), serde_json::json!({ "expected_cash_minor": expected, "counted_cash_minor": request.closing_count_minor, "variance_minor": request.closing_count_minor - expected }),
    ).await {
        tracing::error!(%db_error, "till closing audit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be closed");
    }
    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "till close commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "till could not be closed");
    }
    Json(serde_json::json!({ "status": "closed", "expected_cash_minor": expected, "counted_cash_minor": request.closing_count_minor, "variance_minor": request.closing_count_minor - expected })).into_response()
}

#[derive(Deserialize)]
pub struct CheckoutItem {
    product_id: uuid::Uuid,
    quantity: i32,
}

#[derive(Deserialize)]
pub struct CheckoutRequest {
    business_id: uuid::Uuid,
    location_id: uuid::Uuid,
    till_session_id: uuid::Uuid,
    idempotency_key: uuid::Uuid,
    items: Vec<CheckoutItem>,
    payment_method: String,
    cash_received_minor: Option<i64>,
    terminal_reference: Option<String>,
}

#[derive(FromRow)]
struct CheckoutProduct {
    id: uuid::Uuid,
    sku: String,
    name: String,
    unit_price_minor: i64,
    tax_rate_bps: i32,
}

#[derive(FromRow)]
struct ExistingCheckout {
    sale_id: uuid::Uuid,
    sale_number: i64,
    status: String,
    tender_id: uuid::Uuid,
    total_minor: i64,
    tax_minor: i64,
    change_due_minor: i64,
    payment_method: String,
    payment_status: String,
}

#[derive(Serialize)]
struct CheckoutResponse {
    sale_id: uuid::Uuid,
    sale_number: i64,
    status: String,
    tender_id: uuid::Uuid,
    total_minor: i64,
    tax_minor: i64,
    change_due_minor: i64,
    payment_method: String,
    payment_status: String,
    message: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
enum AmountError {
    Overflow,
}

fn tax_inclusive_amount(
    gross_minor: i64,
    rate_bps: i32,
) -> Result<(i64, i64), AmountError> {
    let denominator = 10_000_i128 + i128::from(rate_bps);
    let gross = i128::from(gross_minor);
    let tax = (gross * i128::from(rate_bps) + denominator / 2) / denominator;
    let net = gross - tax;
    let net = i64::try_from(net).map_err(|_| AmountError::Overflow)?;
    let tax = i64::try_from(tax).map_err(|_| AmountError::Overflow)?;
    Ok((net, tax))
}

pub async fn checkout(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<CheckoutRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if request.items.is_empty() || request.items.len() > 100
        || request.items.iter().any(|item| !(1..=10_000).contains(&item.quantity))
        || !matches!(request.payment_method.as_str(), "cash" | "card_terminal")
        || request.terminal_reference.as_ref().is_some_and(|value| value.trim().len() > 120)
    {
        return error(StatusCode::BAD_REQUEST, "checkout details are invalid");
    }

    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "checkout transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
        }
    };
    if let Err(db_error) = sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(request.idempotency_key.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "checkout idempotency lock failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "sale could not be created",
        );
    }
    let existing = match sqlx::query_as::<_, ExistingCheckout>(
        "SELECT s.id AS sale_id, s.sale_number, s.status, pt.id AS tender_id, \
         s.total_minor, s.tax_minor, pt.change_due_minor, pt.method AS payment_method, \
         pt.status AS payment_status \
         FROM sales s JOIN payment_tenders pt ON pt.tenant_id = s.tenant_id AND pt.sale_id = s.id \
         WHERE s.tenant_id = $1 AND s.idempotency_key = $2 ORDER BY pt.created_at LIMIT 1",
    )
    .bind(context.tenant_id)
    .bind(request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(existing) => existing,
        Err(db_error) => {
            tracing::error!(%db_error, "checkout idempotency lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sale could not be created",
            );
        }
    };
    if let Some(existing) = existing {
        if let Err(db_error) = tx.commit().await {
            tracing::error!(%db_error, "idempotent checkout commit failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sale could not be created",
            );
        }
        let message = if existing.payment_status == "captured" {
            "This checkout was already completed; no duplicate payment was taken."
        } else {
            "This checkout already exists and its card-terminal payment is still pending."
        };
        return (
            StatusCode::OK,
            Json(CheckoutResponse {
                sale_id: existing.sale_id,
                sale_number: existing.sale_number,
                status: existing.status,
                tender_id: existing.tender_id,
                total_minor: existing.total_minor,
                tax_minor: existing.tax_minor,
                change_due_minor: existing.change_due_minor,
                payment_method: existing.payment_method,
                payment_status: existing.payment_status,
                message,
            }),
        )
            .into_response();
    }

    let locked_till: Option<uuid::Uuid> = match sqlx::query_scalar(
        "SELECT id FROM till_sessions WHERE tenant_id = $1 AND id = $2 \
         AND business_id = $3 AND location_id = $4 AND status = 'open' FOR UPDATE",
    )
    .bind(context.tenant_id)
    .bind(request.till_session_id)
    .bind(request.business_id)
    .bind(request.location_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "checkout till lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sale could not be created",
            );
        }
    };
    if locked_till.is_none() {
        return error(
            StatusCode::CONFLICT,
            "an open till is required for checkout",
        );
    }

    let currency: Option<String> = match sqlx::query_scalar(
        "SELECT currency_code::text FROM businesses WHERE tenant_id = $1 AND id = $2",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "checkout business lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
        }
    };
    let Some(currency) = currency else {
        return error(StatusCode::NOT_FOUND, "business was not found");
    };

    let counter: i64 = match sqlx::query_scalar(
        "INSERT INTO business_sale_counters (tenant_id, business_id, next_number) VALUES ($1,$2,2) \
         ON CONFLICT (tenant_id, business_id) DO UPDATE SET next_number = business_sale_counters.next_number + 1 \
         RETURNING next_number - 1",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "sale number allocation failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
        }
    };

    let mut subtotal = 0_i64;
    let mut tax_total = 0_i64;
    let mut line_snapshots = Vec::with_capacity(request.items.len());
    for item in &request.items {
        let product = match sqlx::query_as::<_, CheckoutProduct>(
            "SELECT id, sku, name, unit_price_minor, tax_rate_bps FROM products \
             WHERE tenant_id = $1 AND business_id = $2 AND id = $3 AND is_active = TRUE",
        )
        .bind(context.tenant_id)
        .bind(request.business_id)
        .bind(item.product_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(Some(product)) => product,
            Ok(None) => return error(StatusCode::NOT_FOUND, "a basket product was not found or is inactive"),
            Err(db_error) => {
                tracing::error!(%db_error, "checkout product lookup failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
            }
        };
        let gross = match product.unit_price_minor.checked_mul(i64::from(item.quantity)) {
            Some(value) => value,
            None => return error(StatusCode::BAD_REQUEST, "basket total is too large"),
        };
        let (line_net, line_tax) = match tax_inclusive_amount(gross, product.tax_rate_bps) {
            Ok(values) => values,
            Err(AmountError::Overflow) => {
                return error(StatusCode::BAD_REQUEST, "basket total is too large")
            }
        };
        subtotal = match subtotal.checked_add(line_net) {
            Some(value) => value,
            None => return error(StatusCode::BAD_REQUEST, "basket total is too large"),
        };
        tax_total = match tax_total.checked_add(line_tax) {
            Some(value) => value,
            None => return error(StatusCode::BAD_REQUEST, "basket total is too large"),
        };
        line_snapshots.push((product, item.quantity, line_net, line_tax, gross));
    }
    let total = match subtotal.checked_add(tax_total) {
        Some(value) if value > 0 => value,
        _ => return error(StatusCode::BAD_REQUEST, "sale total must be greater than zero"),
    };
    let is_cash = request.payment_method == "cash";
    let received = request.cash_received_minor.unwrap_or(0);
    if is_cash && received < total {
        return error(StatusCode::BAD_REQUEST, "cash received must cover the sale total");
    }
    if !is_cash && request.cash_received_minor.is_some() {
        return error(StatusCode::BAD_REQUEST, "cash received is only valid for cash payments");
    }

    let sale_status = if is_cash { "completed" } else { "awaiting_payment" };
    let sale_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO sales (tenant_id,business_id,location_id,till_session_id,cashier_user_id,sale_number,idempotency_key,status,currency_code,subtotal_minor,tax_minor,total_minor,completed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $8 = 'completed' THEN now() ELSE NULL END) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(request.location_id)
    .bind(request.till_session_id)
    .bind(context.user_id)
    .bind(counter)
    .bind(request.idempotency_key)
    .bind(sale_status)
    .bind(&currency)
    .bind(subtotal)
    .bind(tax_total)
    .bind(total)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "sale insert failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
        }
    };

    for (product, quantity, line_net, line_tax, gross) in line_snapshots {
        if let Err(db_error) = sqlx::query(
            "INSERT INTO sale_items (tenant_id,sale_id,product_id,product_name,sku,quantity,unit_price_minor,tax_rate_bps,line_subtotal_minor,line_tax_minor,line_total_minor) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(context.tenant_id)
        .bind(sale_id)
        .bind(product.id)
        .bind(product.name)
        .bind(product.sku)
        .bind(quantity)
        .bind(product.unit_price_minor)
        .bind(product.tax_rate_bps)
        .bind(line_net)
        .bind(line_tax)
        .bind(gross)
        .execute(&mut *tx)
        .await
        {
            tracing::error!(%db_error, "sale item insert failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
        }
    }

    let payment_status = if is_cash { "captured" } else { "pending" };
    let change_due = if is_cash { received - total } else { 0 };
    let tender_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO payment_tenders (tenant_id,sale_id,method,status,amount_minor,amount_received_minor,change_due_minor,provider_key,terminal_reference,created_by,captured_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,CASE WHEN $3 = 'card_terminal' THEN 'external_terminal' ELSE NULL END,$8,$9,CASE WHEN $4 = 'captured' THEN now() ELSE NULL END) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(sale_id)
    .bind(&request.payment_method)
    .bind(payment_status)
    .bind(total)
    .bind(if is_cash { Some(received) } else { None })
    .bind(change_due)
    .bind(request.terminal_reference.as_deref().map(str::trim).filter(|value| !value.is_empty()))
    .bind(context.user_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "payment tender insert failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "payment could not be recorded");
        }
    };

    let event = if is_cash { AuditEventType::SaleCreated } else { AuditEventType::CardPaymentInitiated };
    if let Err(db_error) = crate::audit::record_event(
        &mut tx, &context, event, AuditEntityType::Sale, Some(sale_id),
        serde_json::json!({ "sale_number": counter, "total_minor": total, "currency_code": currency, "payment_method": request.payment_method.clone(), "payment_status": payment_status }),
    ).await {
        tracing::error!(%db_error, "sale audit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
    }
    if let Err(db_error) = crate::audit::record_event(
        &mut tx,
        &context,
        AuditEventType::PaymentTenderCreated,
        AuditEntityType::Tender,
        Some(tender_id),
        serde_json::json!({
            "sale_id": sale_id,
            "method": request.payment_method,
            "status": payment_status,
            "amount_minor": total
        }),
    )
    .await
    {
        tracing::error!(%db_error, "payment tender audit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment could not be recorded",
        );
    }
    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "checkout transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "sale could not be created");
    }

    let message = if is_cash {
        "Cash payment recorded. Give the customer the displayed change."
    } else {
        "Payment intent created. A configured terminal provider must confirm the card payment before the sale can be completed."
    };
    (
        StatusCode::CREATED,
        Json(CheckoutResponse {
            sale_id,
            sale_number: counter,
            status: sale_status.to_string(),
            tender_id,
            total_minor: total,
            tax_minor: tax_total,
            change_due_minor: change_due,
            payment_method: request.payment_method,
            payment_status: payment_status.to_string(),
            message,
        }),
    )
        .into_response()
}


#[cfg(test)]
mod tests {
    use super::tax_inclusive_amount;

    #[test]
    fn tax_is_extracted_from_tax_inclusive_prices_using_integer_minor_units() {
        assert_eq!(tax_inclusive_amount(1_200, 2_000), Ok((1_000, 200)));
        assert_eq!(tax_inclusive_amount(1_200, 0), Ok((1_200, 0)));
        assert_eq!(tax_inclusive_amount(120, 2_000), Ok((100, 20)));
    }

    #[test]
    fn tax_rounding_is_deterministic_for_small_values() {
        assert_eq!(tax_inclusive_amount(1, 2_000), Ok((1, 0)));
        assert_eq!(tax_inclusive_amount(6, 2_000), Ok((5, 1)));
    }
}
