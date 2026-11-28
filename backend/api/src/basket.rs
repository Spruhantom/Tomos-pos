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

const MAX_LINES: usize = 100;
const MAX_QUANTITY: u32 = 10_000;

#[derive(Debug, Deserialize)]
pub struct CreateBasketRequest {
    pub lines: Vec<BasketLineRequest>,
}

#[derive(Debug, Deserialize)]
pub struct BasketLineRequest {
    pub product_id: uuid::Uuid,
    pub quantity: u32,
}

#[derive(Debug, Serialize)]
pub struct BasketLineResponse {
    pub product_id: String,
    pub name: String,
    pub sku: Option<String>,
    pub quantity: u32,
    pub unit_price_minor: i64,
    pub tax_rate_bps: i32,
    pub net_minor: i64,
    pub tax_minor: i64,
    pub gross_minor: i64,
}

#[derive(Debug, Serialize)]
pub struct BasketSaleResponse {
    pub id: String,
    pub amount_minor: i64,
    pub currency: String,
    pub net_minor: i64,
    pub tax_minor: i64,
    pub status: String,
    pub lines: Vec<BasketLineResponse>,
}

#[derive(FromRow)]
struct ProductSnapshot {
    id: uuid::Uuid,
    sku: Option<String>,
    name: String,
    unit_price_minor: i64,
    currency: String,
    tax_rate_bps: i32,
    is_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CalculatedAmounts {
    net_minor: i64,
    tax_minor: i64,
    gross_minor: i64,
}

/// Catalogue prices are VAT-inclusive. Tax is rounded half-up per sale line,
/// using integer arithmetic only; no floating-point values enter the ledger.
fn calculate_amounts(
    unit_price_minor: i64,
    quantity: u32,
    tax_rate_bps: i32,
) -> Result<CalculatedAmounts, StatusCode> {
    if unit_price_minor < 0 || quantity == 0 || quantity > MAX_QUANTITY
        || !(0..=10_000).contains(&tax_rate_bps)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let gross = i128::from(unit_price_minor)
        .checked_mul(i128::from(quantity))
        .ok_or(StatusCode::BAD_REQUEST)?;
    let denominator = 10_000_i128 + i128::from(tax_rate_bps);
    let tax = if tax_rate_bps == 0 {
        0
    } else {
        gross
            .checked_mul(i128::from(tax_rate_bps))
            .and_then(|value| value.checked_add(denominator / 2))
            .ok_or(StatusCode::BAD_REQUEST)?
            / denominator
    };
    let net = gross.checked_sub(tax).ok_or(StatusCode::BAD_REQUEST)?;
    Ok(CalculatedAmounts {
        net_minor: i64::try_from(net).map_err(|_| StatusCode::BAD_REQUEST)?,
        tax_minor: i64::try_from(tax).map_err(|_| StatusCode::BAD_REQUEST)?,
        gross_minor: i64::try_from(gross).map_err(|_| StatusCode::BAD_REQUEST)?,
    })
}

pub async fn create_basket_sale(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<CreateBasketRequest>,
) -> Result<(StatusCode, Json<BasketSaleResponse>), StatusCode> {
    if request.lines.is_empty() || request.lines.len() > MAX_LINES {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut tx = auth::begin_tenant_transaction(&state, &context)
        .await
        .map_err(|error| {
            tracing::error!(%error, "basket transaction could not start");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut currency: Option<String> = None;
    let mut net_total: i64 = 0;
    let mut tax_total: i64 = 0;
    let mut gross_total: i64 = 0;
    let mut response_lines = Vec::with_capacity(request.lines.len());

    for requested in request.lines {
        if requested.quantity == 0 || requested.quantity > MAX_QUANTITY {
            return Err(StatusCode::BAD_REQUEST);
        }
        let product = sqlx::query_as::<_, ProductSnapshot>(
            "SELECT id, sku, name, unit_price_minor, currency, tax_rate_bps, is_active \
             FROM pos_products WHERE id = $1 FOR SHARE",
        )
        .bind(requested.product_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            tracing::error!(%error, "basket product lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::BAD_REQUEST)?;

        if !product.is_active {
            return Err(StatusCode::CONFLICT);
        }
        if currency.as_ref().is_some_and(|value| value != &product.currency) {
            return Err(StatusCode::BAD_REQUEST);
        }
        currency.get_or_insert_with(|| product.currency.clone());

        let amounts = calculate_amounts(
            product.unit_price_minor,
            requested.quantity,
            product.tax_rate_bps,
        )?;
        net_total = net_total.checked_add(amounts.net_minor).ok_or(StatusCode::BAD_REQUEST)?;
        tax_total = tax_total.checked_add(amounts.tax_minor).ok_or(StatusCode::BAD_REQUEST)?;
        gross_total = gross_total.checked_add(amounts.gross_minor).ok_or(StatusCode::BAD_REQUEST)?;

        response_lines.push(BasketLineResponse {
            product_id: product.id.to_string(),
            name: product.name,
            sku: product.sku,
            quantity: requested.quantity,
            unit_price_minor: product.unit_price_minor,
            tax_rate_bps: product.tax_rate_bps,
            net_minor: amounts.net_minor,
            tax_minor: amounts.tax_minor,
            gross_minor: amounts.gross_minor,
        });
    }

    if gross_total <= 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let currency = currency.ok_or(StatusCode::BAD_REQUEST)?;

    let sale_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO pos_sales (tenant_id, amount_minor, currency, created_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(gross_total)
    .bind(&currency)
    .bind(context.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "basket sale could not be created");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Persist the immutable line snapshots in the same transaction as the sale.
    for line in &response_lines {
        sqlx::query(
            "INSERT INTO pos_sale_lines \
             (tenant_id, sale_id, product_id, product_name, product_sku, quantity, \
              unit_price_minor, tax_rate_bps, net_minor, tax_minor, gross_minor) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(context.tenant_id)
        .bind(sale_id)
        .bind(uuid::Uuid::parse_str(&line.product_id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?)
        .bind(&line.name)
        .bind(&line.sku)
        .bind(i32::try_from(line.quantity).map_err(|_| StatusCode::BAD_REQUEST)?)
        .bind(line.unit_price_minor)
        .bind(line.tax_rate_bps)
        .bind(line.net_minor)
        .bind(line.tax_minor)
        .bind(line.gross_minor)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            tracing::error!(%error, "basket line snapshot could not be stored");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    audit::record_event(
        &mut tx,
        &context,
        AuditEventType::SaleCreated,
        AuditEntityType::Sale,
        Some(sale_id),
        serde_json::json!({
            "amount_minor": gross_total,
            "net_minor": net_total,
            "tax_minor": tax_total,
            "currency": currency,
            "line_count": response_lines.len(),
            "source": "catalogue_basket",
        }),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "basket sale audit event failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "basket sale transaction commit failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((
        StatusCode::CREATED,
        Json(BasketSaleResponse {
            id: sale_id.to_string(),
            amount_minor: gross_total,
            currency,
            net_minor: net_total,
            tax_minor: tax_total,
            status: "unpaid".to_string(),
            lines: response_lines,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::calculate_amounts;

    #[test]
    fn calculates_standard_uk_vat_from_vat_inclusive_prices() {
        // £12.00 gross at 20% VAT = £10.00 net + £2.00 VAT.
        assert_eq!(
            calculate_amounts(1_200, 1, 2_000).unwrap(),
            super::CalculatedAmounts {
                net_minor: 1_000,
                tax_minor: 200,
                gross_minor: 1_200,
            }
        );
    }

    #[test]
    fn calculates_zero_rated_and_reduced_rate_lines() {
        assert_eq!(calculate_amounts(1_000, 2, 0).unwrap().tax_minor, 0);
        assert_eq!(calculate_amounts(1_200, 1, 500).unwrap().tax_minor, 57);
    }

    #[test]
    fn rounds_tax_half_up_per_line_and_uses_no_floats() {
        assert_eq!(calculate_amounts(1, 1, 5_000).unwrap().tax_minor, 0);
        assert_eq!(calculate_amounts(2, 1, 5_000).unwrap().tax_minor, 1);
    }

    #[test]
    fn rejects_zero_quantity_and_overflow() {
        assert!(calculate_amounts(100, 0, 2_000).is_err());
        assert!(calculate_amounts(i64::MAX, 2, 2_000).is_err());
    }
}
