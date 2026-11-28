use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tomos_sumup_bridge::{CheckoutRequest, Money, SumUpClient, SumUpConfig, SumUpError};

use crate::{
    audit::{self, AuditEntityType, AuditEventType},
    auth::{self, AuthContext, AuthState},
    sumup::{self, NewAttempt},
};

#[derive(Debug, Deserialize)]
pub struct CreateSaleRequest {
    pub amount_minor: u64,
    pub currency: String,
}

#[derive(Debug, Serialize)]
pub struct SaleResponse {
    pub id: String,
    pub amount_minor: i64,
    pub currency: String,
    pub status: String,
}

#[derive(FromRow)]
struct SaleRow {
    id: uuid::Uuid,
    amount_minor: i64,
    currency: String,
    status: String,
}

#[derive(Debug, Deserialize)]
pub struct StartSumUpPaymentRequest {
    /// Kept explicit so the UI can identify the reader selected by the operator.
    /// It must match the server-configured reader for this initial single-reader
    /// deployment; tenant-managed reader records are a later milestone.
    pub reader_id: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentStartedResponse {
    pub sale_id: String,
    pub payment_attempt_id: String,
    pub status: &'static str,
    pub provider_message: &'static str,
}

fn sumup_currency_minor_unit(currency: &str) -> Option<u8> {
    match currency {
        "CLP" => Some(0),
        "BRL" | "CHF" | "COP" | "CZK" | "DKK" | "EUR" | "GBP" | "HRK" | "HUF"
        | "NOK" | "PLN" | "RON" | "SEK" | "USD" => Some(2),
        _ => None,
    }
}

fn sumup_client() -> Result<(SumUpClient, String, String), StatusCode> {
    let api_key = std::env::var("SUMUP_API_KEY").map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let affiliate_key =
        std::env::var("SUMUP_AFFILIATE_KEY").map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let merchant_code =
        std::env::var("SUMUP_MERCHANT_CODE").map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let reader_id =
        std::env::var("SUMUP_READER_ID").map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let config = SumUpConfig::new(api_key, affiliate_key, merchant_code.clone())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let client = SumUpClient::new(config).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((client, merchant_code, reader_id))
}

/// Create a basic unpaid sale amount. This is the first payment-domain API;
/// product lines, tax calculation, discounts and inventory are separate work.
pub async fn create_sale(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<CreateSaleRequest>,
) -> Result<(StatusCode, Json<SaleResponse>), StatusCode> {
    if request.amount_minor == 0
        || request.currency.len() != 3
        || sumup_currency_minor_unit(&request.currency).is_none()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let amount_minor = i64::try_from(request.amount_minor).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut tx = auth::begin_tenant_transaction(&state, &context)
        .await
        .map_err(|error| {
            tracing::error!(%error, "sale creation transaction failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let sale = sqlx::query_as::<_, SaleRow>(
        "INSERT INTO pos_sales (tenant_id, amount_minor, currency, created_by) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, amount_minor, currency, status",
    )
    .bind(context.tenant_id)
    .bind(amount_minor)
    .bind(&request.currency)
    .bind(context.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "sale record could not be created");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    audit::record_event(
        &mut tx,
        &context,
        AuditEventType::SaleCreated,
        AuditEntityType::Sale,
        Some(sale.id),
        serde_json::json!({
            "amount_minor": sale.amount_minor,
            "currency": sale.currency,
        }),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, sale_id = %sale.id, "sale creation audit event failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "sale creation commit failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((
        StatusCode::CREATED,
        Json(SaleResponse {
            id: sale.id.to_string(),
            amount_minor: sale.amount_minor,
            currency: sale.currency,
            status: sale.status,
        }),
    ))
}

/// Start a Solo checkout for an existing unpaid sale. The API response means
/// only that SumUp accepted the request; the sale remains unpaid until callback.
pub async fn start_sumup_payment(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(sale_id): Path<uuid::Uuid>,
    Json(request): Json<StartSumUpPaymentRequest>,
) -> Result<(StatusCode, Json<PaymentStartedResponse>), StatusCode> {
    let (client, merchant_code, configured_reader) = sumup_client()?;
    if request.reader_id != configured_reader {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut tx = auth::begin_tenant_transaction(&state, &context)
        .await
        .map_err(|error| {
            tracing::error!(%error, "sale lookup transaction failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let sale = sqlx::query_as::<_, SaleRow>(
        "SELECT id, amount_minor, currency, status FROM pos_sales WHERE id = $1 FOR UPDATE",
    )
    .bind(sale_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "sale lookup failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if sale.status != "unpaid" {
        return Err(StatusCode::CONFLICT);
    }
    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "sale lookup transaction commit failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let public_base_url =
        std::env::var("SUMUP_PUBLIC_BASE_URL").map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let client_transaction_id = uuid::Uuid::new_v4().to_string();
    let attempt = sumup::create_attempt(
        &state.db,
        NewAttempt {
            tenant_id: context.tenant_id,
            sale_id: sale.id,
            reader_id: &configured_reader,
            client_transaction_id: &client_transaction_id,
            merchant_code: &merchant_code,
            amount_minor: sale.amount_minor as u64,
            currency: &sale.currency,
            public_base_url: &public_base_url,
        },
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, sale_id = %sale.id, "SumUp payment attempt could not be stored");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let checkout = CheckoutRequest {
        reader_id: configured_reader,
        client_transaction_id,
        amount: Money {
            currency: sale.currency,
            minor_unit: sumup_currency_minor_unit(&sale.currency).ok_or(StatusCode::BAD_REQUEST)?,
            value: sale.amount_minor as u64,
        },
        return_url: attempt.return_url,
    };

    if let Err(error) = client.create_checkout(&checkout).await {
        tracing::error!(%error, sale_id = %sale.id, attempt_id = %attempt.id, "SumUp checkout initiation returned an error");
        // Only a definitive provider 4xx rejection is safe to mark failed.
        // A timeout, transport error or provider 5xx may occur after the reader
        // accepted the checkout; leave it pending for reconciliation so a late
        // successful webhook is not discarded and no duplicate charge is started.
        if matches!(&error, SumUpError::Api { status: 400..=499, .. }) {
            let mut failure_tx = state
                .db
                .begin()
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
                .bind(context.tenant_id.to_string())
                .execute(&mut *failure_tx)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            sqlx::query(
                "UPDATE sumup_payment_attempts SET status = 'failed', \
                 failure_reason = 'SumUp definitively rejected checkout initiation', updated_at = now() \
                 WHERE id = $1 AND status = 'pending'",
            )
            .bind(attempt.id)
            .execute(&mut *failure_tx)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            failure_tx
                .commit()
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        return Err(StatusCode::BAD_GATEWAY);
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(PaymentStartedResponse {
            sale_id: sale.id.to_string(),
            payment_attempt_id: attempt.id.to_string(),
            status: "pending",
            provider_message: "Reader checkout accepted; awaiting final payment result",
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::sumup_currency_minor_unit;

    #[test]
    fn supported_sumup_currencies_use_their_minor_unit_exponent() {
        assert_eq!(sumup_currency_minor_unit("GBP"), Some(2));
        assert_eq!(sumup_currency_minor_unit("EUR"), Some(2));
        assert_eq!(sumup_currency_minor_unit("CLP"), Some(0));
        assert_eq!(sumup_currency_minor_unit("XYZ"), None);
    }
}
