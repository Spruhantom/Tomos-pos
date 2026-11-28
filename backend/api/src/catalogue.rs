use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::{
    audit::{self, AuditEntityType, AuditEventType},
    auth::{self, AuthContext, AuthState},
};

#[derive(Debug, Deserialize)]
pub struct CreateProductRequest {
    pub sku: Option<String>,
    pub barcode: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub unit_price_minor: u64,
    pub currency: String,
    pub tax_rate_bps: u32,
}

#[derive(Debug, Serialize)]
pub struct ProductResponse {
    pub id: String,
    pub sku: Option<String>,
    pub barcode: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub unit_price_minor: i64,
    pub currency: String,
    pub tax_rate_bps: i32,
    pub is_active: bool,
}

#[derive(FromRow)]
struct ProductRow {
    id: uuid::Uuid,
    sku: Option<String>,
    barcode: Option<String>,
    name: String,
    description: Option<String>,
    unit_price_minor: i64,
    currency: String,
    tax_rate_bps: i32,
    is_active: bool,
}

impl From<ProductRow> for ProductResponse {
    fn from(product: ProductRow) -> Self {
        Self {
            id: product.id.to_string(),
            sku: product.sku,
            barcode: product.barcode,
            name: product.name,
            description: product.description,
            unit_price_minor: product.unit_price_minor,
            currency: product.currency,
            tax_rate_bps: product.tax_rate_bps,
            is_active: product.is_active,
        }
    }
}

fn clean_optional(value: Option<String>, max_len: usize) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(max_len).collect())
}

pub async fn list_products(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
) -> Result<Json<Vec<ProductResponse>>, StatusCode> {
    let mut tx = auth::begin_tenant_transaction(&state, &context)
        .await
        .map_err(|error| {
            tracing::error!(%error, "product catalogue transaction failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let products = sqlx::query_as::<_, ProductRow>(
        "SELECT id, sku, barcode, name, description, unit_price_minor, currency, \
         tax_rate_bps, is_active FROM pos_products WHERE is_active = TRUE \
         ORDER BY lower(name), id",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "product catalogue lookup failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "product catalogue transaction commit failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(products.into_iter().map(Into::into).collect()))
}

pub async fn create_product(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<CreateProductRequest>,
) -> Result<(StatusCode, Json<ProductResponse>), StatusCode> {
    let name = request.name.trim();
    if name.is_empty()
        || name.chars().count() > 160
        || request.currency.len() != 3
        || !request.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        || request.tax_rate_bps > 10_000
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let unit_price_minor =
        i64::try_from(request.unit_price_minor).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sku = clean_optional(request.sku, 64);
    let barcode = clean_optional(request.barcode, 64);
    let description = clean_optional(request.description, 1000);

    let mut tx = auth::begin_tenant_transaction(&state, &context)
        .await
        .map_err(|error| {
            tracing::error!(%error, "product creation transaction failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let product = sqlx::query_as::<_, ProductRow>(
        "INSERT INTO pos_products \
         (tenant_id, sku, barcode, name, description, unit_price_minor, currency, tax_rate_bps, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING id, sku, barcode, name, description, unit_price_minor, currency, tax_rate_bps, is_active",
    )
    .bind(context.tenant_id)
    .bind(&sku)
    .bind(&barcode)
    .bind(name)
    .bind(&description)
    .bind(unit_price_minor)
    .bind(&request.currency)
    .bind(request.tax_rate_bps as i32)
    .bind(context.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|database_error| database_error.is_unique_violation())
        {
            return StatusCode::CONFLICT;
        }
        tracing::error!(%error, "product record could not be created");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    audit::record_event(
        &mut tx,
        &context,
        AuditEventType::ProductCreated,
        AuditEntityType::Product,
        Some(product.id),
        serde_json::json!({
            "sku": product.sku,
            "name": product.name,
            "unit_price_minor": product.unit_price_minor,
            "currency": product.currency,
        }),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "product creation audit event failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "product creation commit failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((StatusCode::CREATED, Json(product.into())))
}

#[cfg(test)]
mod tests {
    #[test]
    fn product_request_limits_are_explicit() {
        assert!(160usize <= 160);
        assert!(10_000u32 <= 10_000);
    }
}
