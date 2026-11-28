use axum::{extract::{Extension, Path, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::{
    audit::{self, AuditEntityType, AuditEventType},
    auth::{self, AuthContext, AuthState},
};

#[derive(Debug, Deserialize)]
pub struct CashPaymentRequest {
    pub tendered_minor: u64,
}

#[derive(Debug, Serialize)]
pub struct CashPaymentResponse {
    pub sale_id: String,
    pub payment_id: String,
    pub amount_minor: i64,
    pub tendered_minor: i64,
    pub change_minor: i64,
    pub currency: String,
    pub status: &'static str,
}

#[derive(FromRow)]
struct CashSale {
    id: uuid::Uuid,
    amount_minor: i64,
    currency: String,
    status: String,
}

/// Record a cash tender and settle the sale atomically. Amounts are minor units;
/// the server computes change and never trusts a client-supplied sale total.
pub async fn take_cash_payment(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(sale_id): Path<uuid::Uuid>,
    Json(request): Json<CashPaymentRequest>,
) -> Result<(StatusCode, Json<CashPaymentResponse>), StatusCode> {
    let tendered = i64::try_from(request.tendered_minor).map_err(|_| StatusCode::BAD_REQUEST)?;
    if tendered <= 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut tx = auth::begin_tenant_transaction(&state, &context)
        .await
        .map_err(|error| {
            tracing::error!(%error, "cash payment transaction failed to start");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let sale = sqlx::query_as::<_, CashSale>(
        "SELECT id, amount_minor, currency, status FROM pos_sales WHERE id = $1 FOR UPDATE",
    )
    .bind(sale_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "cash payment sale lookup failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if sale.status != "unpaid" {
        return Err(StatusCode::CONFLICT);
    }
    if tendered < sale.amount_minor {
        return Err(StatusCode::BAD_REQUEST);
    }
    let change = tendered.checked_sub(sale.amount_minor).ok_or(StatusCode::BAD_REQUEST)?;

    let payment_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO pos_cash_payments          (tenant_id, sale_id, tendered_minor, change_minor, received_by)          VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(sale.id)
    .bind(tendered)
    .bind(change)
    .bind(context.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, sale_id = %sale.id, "cash payment record failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "UPDATE pos_sales SET status = 'paid', paid_at = now(), updated_at = now()          WHERE id = $1 AND status = 'unpaid'",
    )
    .bind(sale.id)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, sale_id = %sale.id, "cash sale settlement failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    audit::record_event(
        &mut tx,
        &context,
        AuditEventType::SalePaid,
        AuditEntityType::Sale,
        Some(sale.id),
        serde_json::json!({
            "payment_method": "cash",
            "amount_minor": sale.amount_minor,
            "tendered_minor": tendered,
            "change_minor": change,
            "currency": sale.currency,
        }),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, sale_id = %sale.id, "cash payment audit event failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "cash payment commit failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((
        StatusCode::CREATED,
        Json(CashPaymentResponse {
            sale_id: sale.id.to_string(),
            payment_id: payment_id.to_string(),
            amount_minor: sale.amount_minor,
            tendered_minor: tendered,
            change_minor: change,
            currency: sale.currency,
            status: "paid",
        }),
    ))
}
