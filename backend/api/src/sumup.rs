use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use tomos_sumup_bridge::{
    PaymentAttempt, PaymentOutcome, SoloWebhookEvent, SOLO_TRANSACTION_UPDATED,
};
use url::Url;

use crate::auth::AuthState;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct CreatedAttempt {
    pub id: uuid::Uuid,
    /// Secret callback token. Return it to the caller once; never persist or log it.
    pub callback_token: String,
    pub return_url: String,
}

#[allow(dead_code)]
pub(crate) struct NewAttempt<'a> {
    pub tenant_id: uuid::Uuid,
    pub sale_id: uuid::Uuid,
    pub reader_id: &'a str,
    pub client_transaction_id: &'a str,
    pub merchant_code: &'a str,
    pub amount_minor: u64,
    pub currency: &'a str,
    pub public_base_url: &'a str,
}

/// Creates a durable pending attempt before the checkout is sent to SumUp.
/// The returned URL contains a 256-bit random bearer token; only its digest is stored.
#[allow(dead_code)]
pub(crate) async fn create_attempt(
    db: &PgPool,
    input: NewAttempt<'_>,
) -> Result<CreatedAttempt, sqlx::Error> {
    let base_url = Url::parse(input.public_base_url)
        .map_err(|error| sqlx::Error::Protocol(format!("invalid public base URL: {error}")))?;
    if base_url.scheme() != "https"
        || base_url.host_str().is_none()
        || !base_url.username().is_empty()
        || base_url.password().is_some()
    {
        return Err(sqlx::Error::Protocol(
            "SumUp callback base URL must be an HTTPS origin".into(),
        ));
    }
    if input.reader_id.trim().is_empty()
        || input.client_transaction_id.trim().is_empty()
        || input.merchant_code.trim().is_empty()
        || input.currency.len() != 3
        || !input.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        || input.amount_minor == 0
    {
        return Err(sqlx::Error::Protocol(
            "invalid SumUp payment attempt details".into(),
        ));
    }

    let amount_minor = i64::try_from(input.amount_minor)
        .map_err(|_| sqlx::Error::Protocol("payment amount exceeds supported range".into()))?;

    let mut token_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let callback_token = hex::encode(token_bytes);
    let callback_token_hash = hex::encode(Sha256::digest(callback_token.as_bytes()));

    let mut return_url = base_url;
    return_url.set_path(&format!("/api/v1/payments/sumup/webhook/{callback_token}"));
    return_url.set_query(None);
    return_url.set_fragment(None);

    let id = uuid::Uuid::new_v4();
    let mut tx = db.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(input.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO sumup_payment_attempts \
         (id, tenant_id, sale_id, reader_id, client_transaction_id, merchant_code, \
          amount_minor, currency) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(input.tenant_id)
    .bind(input.sale_id)
    .bind(input.reader_id)
    .bind(input.client_transaction_id)
    .bind(input.merchant_code)
    .bind(amount_minor)
    .bind(input.currency)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO sumup_webhook_tokens (token_hash, tenant_id, attempt_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(callback_token_hash)
    .bind(input.tenant_id)
    .bind(id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(CreatedAttempt {
        id,
        callback_token,
        return_url: return_url.to_string(),
    })
}

#[derive(FromRow)]
struct WebhookTokenRow {
    tenant_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
}

#[derive(FromRow)]
struct AttemptRow {
    id: uuid::Uuid,
    client_transaction_id: String,
    merchant_code: String,
    status: String,
}

/// SumUp Solo Cloud API posts final transaction events to the return_url.
/// The callback URL's per-attempt bearer token, HTTPS, merchant and transaction
/// reference checks protect this endpoint. The Cloud API event contract does
/// not document a signature header, so no fictitious signature check is used.
pub(crate) async fn webhook(
    State(state): State<AuthState>,
    Path(token): Path<String>,
    Json(event): Json<SoloWebhookEvent>,
) -> StatusCode {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return StatusCode::NOT_FOUND;
    }

    if event.event_type != SOLO_TRANSACTION_UPDATED {
        return StatusCode::NO_CONTENT;
    }

    if event.id.trim().is_empty()
        || event.payload.client_transaction_id.trim().is_empty()
        || event.payload.merchant_code.trim().is_empty()
    {
        return StatusCode::NO_CONTENT;
    }

    let outcome = match event.payload.status.as_str() {
        "successful" => PaymentOutcome::Successful,
        "failed" => PaymentOutcome::Failed,
        _ => return StatusCode::NO_CONTENT,
    };

    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
    let token_record = match sqlx::query_as::<_, WebhookTokenRow>(
        "SELECT tenant_id, attempt_id FROM sumup_webhook_tokens WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(error) => {
            tracing::error!(%error, "SumUp webhook token lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            tracing::error!(%error, "SumUp webhook transaction could not start");
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };
    if let Err(error) = sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(token_record.tenant_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%error, "SumUp webhook tenant context could not be set");
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    let attempt = match sqlx::query_as::<_, AttemptRow>(
        "SELECT id, client_transaction_id, merchant_code, status \
         FROM sumup_payment_attempts WHERE id = $1",
    )
    .bind(token_record.attempt_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(attempt)) => attempt,
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(error) => {
            tracing::error!(%error, "SumUp webhook attempt lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };

    let mut payment = match PaymentAttempt::new(
        attempt.client_transaction_id.clone(),
        attempt.merchant_code.clone(),
    ) {
        Ok(payment) => payment,
        Err(error) => {
            tracing::error!(%error, "stored SumUp payment attempt is invalid");
            return StatusCode::NO_CONTENT;
        }
    };

    if payment.apply_webhook(&event).is_err() {
        tracing::warn!(
            attempt_id = %attempt.id,
            event_id = %event.id,
            "rejected mismatched SumUp webhook"
        );
        return StatusCode::NO_CONTENT;
    }

    let new_status = match outcome {
        PaymentOutcome::Successful => "successful",
        PaymentOutcome::Failed => "failed",
    };

    if attempt.status != "pending" {
        if attempt.status == new_status {
            return StatusCode::NO_CONTENT;
        }
        tracing::error!(
            attempt_id = %attempt.id,
            current_status = %attempt.status,
            incoming_status = new_status,
            "conflicting final SumUp webhook; reconciliation required"
        );
        return StatusCode::NO_CONTENT;
    }

    let failure_reason = event
        .payload
        .failure_reason
        .as_deref()
        .map(|reason| reason.chars().take(1000).collect::<String>());

    match sqlx::query(
        "UPDATE sumup_payment_attempts \
         SET status = $1, provider_event_id = $2, failure_reason = $3, updated_at = now() \
         WHERE id = $4 AND status = 'pending'",
    )
    .bind(new_status)
    .bind(&event.id)
    .bind(failure_reason)
    .bind(attempt.id)
    .execute(&mut *tx)
    .await
    {
        Ok(result) if result.rows_affected() == 1 => {
            if let Err(error) = tx.commit().await {
                tracing::error!(%error, attempt_id = %attempt.id, "SumUp webhook commit failed");
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            StatusCode::NO_CONTENT
        }
        Ok(_) => StatusCode::NO_CONTENT,
        Err(error) => {
            tracing::error!(%error, attempt_id = %attempt.id, "SumUp webhook persistence failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
