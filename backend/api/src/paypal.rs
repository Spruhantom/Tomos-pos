use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::{begin_tenant_transaction, AuthContext, AuthState};

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn origin_is_allowed(headers: &HeaderMap, state: &AuthState) -> bool {
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == state.allowed_origin)
}

struct PayPalConfig {
    client_id: String,
    client_secret: String,
    webhook_id: String,
    base_url: String,
    onboarding_return_url: String,
    checkout_return_url: String,
    cancel_url: String,
}

impl PayPalConfig {
    fn from_env() -> Result<Self, &'static str> {
        let required = |key: &str| std::env::var(key).map_err(|_| "PayPal is not configured");
        let sandbox = std::env::var("PAYPAL_ENVIRONMENT")
            .unwrap_or_else(|_| "sandbox".to_string()) != "live";
        Ok(Self {
            client_id: required("PAYPAL_CLIENT_ID")?,
            client_secret: required("PAYPAL_CLIENT_SECRET")?,
            webhook_id: std::env::var("PAYPAL_WEBHOOK_ID").unwrap_or_default(),
            base_url: if sandbox {
                "https://api-m.sandbox.paypal.com".to_string()
            } else {
                "https://api-m.paypal.com".to_string()
            },
            onboarding_return_url: required("PAYPAL_ONBOARDING_RETURN_URL")?,
            checkout_return_url: required("PAYPAL_CHECKOUT_RETURN_URL")?,
            cancel_url: required("PAYPAL_CANCEL_URL")?,
        })
    }

    async fn access_token(&self) -> Result<String, reqwest::Error> {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/oauth2/token", self.base_url))
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header("Accept", "application/json")
            .header("Accept-Language", "en_GB")
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok(response["access_token"].as_str().unwrap_or_default().to_string())
    }

    fn auth_assertion(&self, merchant_id: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": self.client_id,
                "payer_id": merchant_id
            }))
            .unwrap_or_default(),
        );
        format!("{header}.{payload}.")
    }
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    business_id: uuid::Uuid,
}

pub async fn connect_business(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<ConnectRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    let config = match PayPalConfig::from_env() {
        Ok(config) => config,
        Err(message) => return error(StatusCode::SERVICE_UNAVAILABLE, message),
    };
    let tracking_id = uuid::Uuid::new_v4();

    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "PayPal onboarding transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be started");
        }
    };
    let business_exists: bool = match sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM businesses WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "PayPal business lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be started");
        }
    };
    if !business_exists {
        return error(StatusCode::NOT_FOUND, "business was not found");
    }

    let token = match config.access_token().await {
        Ok(token) if !token.is_empty() => token,
        Ok(_) => return error(StatusCode::BAD_GATEWAY, "PayPal did not issue an access token"),
        Err(err) => {
            tracing::error!(%err, "PayPal token request failed");
            return error(StatusCode::BAD_GATEWAY, "PayPal could not be reached");
        }
    };
    let referral = json!({
        "tracking_id": tracking_id.to_string(),
        "products": ["PPCP"],
        "operations": [{
            "operation": "API_INTEGRATION",
            "api_integration_preference": {
                "rest_api_integration": {
                    "integration_method": "PAYPAL",
                    "integration_type": "THIRD_PARTY",
                    "third_party_details": { "features": ["PAYMENT", "REFUND"] }
                }
            }
        }],
        "partner_config_override": {
            "return_url": config.onboarding_return_url,
            "return_url_description": "Return to TomOS POS to finish connecting PayPal"
        }
    });
    let response = match reqwest::Client::new()
        .post(format!("{}/v2/customer/partner-referrals", config.base_url))
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .json(&referral)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(%err, "PayPal partner referral request failed");
            return error(StatusCode::BAD_GATEWAY, "PayPal onboarding could not be started");
        }
    };
    let referral_body = match response.error_for_status() {
        Ok(response) => match response.json::<Value>().await {
            Ok(body) => body,
            Err(err) => {
                tracing::error!(%err, "PayPal referral response was invalid");
                return error(StatusCode::BAD_GATEWAY, "PayPal returned an invalid onboarding response");
            }
        },
        Err(err) => {
            tracing::error!(%err, "PayPal rejected partner referral");
            return error(StatusCode::BAD_GATEWAY, "PayPal rejected the onboarding request");
        }
    };
    let action_url = referral_body["links"]
        .as_array()
        .and_then(|links| links.iter().find(|link| link["rel"] == "action_url"))
        .and_then(|link| link["href"].as_str())
        .unwrap_or_default()
        .to_string();
    if action_url.is_empty() || !action_url.starts_with("https://") {
        return error(StatusCode::BAD_GATEWAY, "PayPal did not return a valid onboarding link");
    }

    let saved = sqlx::query(
        "INSERT INTO business_paypal_accounts (tenant_id, business_id, onboarding_status) \
         VALUES ($1, $2, 'pending') ON CONFLICT (tenant_id, business_id) DO UPDATE \
         SET merchant_id = NULL, onboarding_status = 'pending', permissions_granted = FALSE, \
             consent_status = FALSE, connected_at = NULL, updated_at = now()",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .execute(&mut *tx)
    .await;
    if let Err(err) = saved {
        tracing::error!(%err, "PayPal account status could not be saved");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be saved");
    }
    if let Err(err) = sqlx::query(
        "INSERT INTO paypal_onboarding_sessions (tracking_id, tenant_id, business_id) VALUES ($1, $2, $3)",
    )
    .bind(tracking_id)
    .bind(context.tenant_id)
    .bind(request.business_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "PayPal onboarding session could not be saved");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be saved");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "PayPal onboarding transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be saved");
    }
    Json(json!({ "action_url": action_url, "status": "pending" })).into_response()
}

#[derive(Deserialize)]
pub struct OnboardingReturn {
    #[serde(rename = "merchantId")]
    tracking_id: uuid::Uuid,
    #[serde(rename = "merchantIdInPayPal")]
    merchant_id: String,
    #[serde(rename = "permissionsGranted")]
    permissions_granted: bool,
    #[serde(rename = "consentStatus")]
    consent_status: bool,
}

pub async fn onboarding_return(
    State(state): State<AuthState>,
    Query(query): Query<OnboardingReturn>,
) -> Response {
    if query.merchant_id.trim().is_empty() || query.merchant_id.len() > 128 {
        return error(StatusCode::BAD_REQUEST, "PayPal merchant details are invalid");
    }
    let session = match sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
        "SELECT tenant_id, business_id FROM paypal_onboarding_sessions \
         WHERE tracking_id = $1 AND completed_at IS NULL AND expires_at > now()",
    )
    .bind(query.tracking_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return error(StatusCode::GONE, "PayPal onboarding session expired or was already used"),
        Err(err) => {
            tracing::error!(%err, "PayPal onboarding session lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be completed");
        }
    };
    let (tenant_id, business_id) = session;
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "PayPal callback transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be completed");
        }
    };
    if let Err(err) = sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%err, "PayPal callback tenant context failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be completed");
    }
    let connected = query.permissions_granted && query.consent_status;
    let update = sqlx::query(
        "UPDATE business_paypal_accounts SET merchant_id = $3, \
         onboarding_status = CASE WHEN $4 THEN 'connected' ELSE 'pending' END, \
         permissions_granted = $4, consent_status = $5, \
         connected_at = CASE WHEN $4 THEN now() ELSE NULL END, updated_at = now() \
         WHERE tenant_id = $1 AND business_id = $2",
    )
    .bind(tenant_id)
    .bind(business_id)
    .bind(query.merchant_id.trim())
    .bind(connected)
    .bind(query.consent_status)
    .execute(&mut *tx)
    .await;
    if let Err(err) = update {
        tracing::error!(%err, "PayPal merchant connection update failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be completed");
    }
    let _ = sqlx::query("UPDATE paypal_onboarding_sessions SET completed_at = now() WHERE tracking_id = $1")
        .bind(query.tracking_id)
        .execute(&mut *tx)
        .await;
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "PayPal callback commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal connection could not be completed");
    }
    let destination = std::env::var("APP_ORIGIN")
        .unwrap_or_else(|_| "/".to_string());
    Redirect::to(&format!("{destination}/?paypal={}", if connected { "connected" } else { "consent_required" })).into_response()
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    business_id: uuid::Uuid,
}

#[derive(FromRow)]
struct SaleForPayPal {
    total_minor: i64,
    currency_code: String,
    status: String,
    merchant_id: Option<String>,
}

fn money_value(minor: i64) -> String {
    format!("{}.{:02}", minor / 100, minor.abs() % 100)
}

pub async fn create_order(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(sale_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateOrderRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    let config = match PayPalConfig::from_env() {
        Ok(config) => config,
        Err(message) => return error(StatusCode::SERVICE_UNAVAILABLE, message),
    };
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "PayPal order transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal order could not be created");
        }
    };
    let sale = match sqlx::query_as::<_, SaleForPayPal>(
        "SELECT s.total_minor, s.currency_code::text AS currency_code, s.status, p.merchant_id \
         FROM sales s LEFT JOIN business_paypal_accounts p \
         ON p.tenant_id = s.tenant_id AND p.business_id = s.business_id \
         WHERE s.tenant_id = $1 AND s.id = $2 AND s.business_id = $3 \
         AND EXISTS (SELECT 1 FROM payment_tenders t WHERE t.tenant_id = s.tenant_id \
           AND t.sale_id = s.id AND t.method = 'paypal' AND t.status = 'pending')",
    )
    .bind(context.tenant_id)
    .bind(sale_id)
    .bind(request.business_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(sale)) => sale,
        Ok(None) => return error(StatusCode::NOT_FOUND, "pending PayPal sale was not found"),
        Err(err) => {
            tracing::error!(%err, "PayPal sale lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal order could not be created");
        }
    };
    if sale.status != "awaiting_payment" {
        return error(StatusCode::CONFLICT, "sale is not awaiting payment");
    }
    let Some(merchant_id) = sale.merchant_id else {
        return error(StatusCode::CONFLICT, "this business has not connected a PayPal account");
    };
    let token = match config.access_token().await {
        Ok(token) if !token.is_empty() => token,
        _ => return error(StatusCode::BAD_GATEWAY, "PayPal authentication failed"),
    };
    let assertion = config.auth_assertion(&merchant_id);
    let custom_id = format!("{}:{}", context.tenant_id, sale_id);
    let order_body = json!({
        "intent": "CAPTURE",
        "purchase_units": [{
            "reference_id": sale_id.to_string(),
            "custom_id": custom_id,
            "invoice_id": format!("TOMOS-{}", sale_id),
            "payee": { "merchant_id": merchant_id },
            "amount": {
                "currency_code": sale.currency_code,
                "value": money_value(sale.total_minor)
            }
        }],
        "application_context": {
            "return_url": format!("{}?paypal_sale_id={}", config.checkout_return_url, sale_id),
            "cancel_url": format!("{}?paypal_cancelled={}", config.cancel_url, sale_id),
            "user_action": "PAY_NOW"
        }
    });
    let response = match reqwest::Client::new()
        .post(format!("{}/v2/checkout/orders", config.base_url))
        .bearer_auth(token)
        .header("PayPal-Auth-Assertion", assertion)
        .header("PayPal-Request-Id", sale_id.to_string())
        .header("Content-Type", "application/json")
        .json(&order_body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(%err, "PayPal create order request failed");
            return error(StatusCode::BAD_GATEWAY, "PayPal could not create the order");
        }
    };
    let order = match response.error_for_status() {
        Ok(response) => match response.json::<Value>().await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(%err, "PayPal create order response invalid");
                return error(StatusCode::BAD_GATEWAY, "PayPal returned an invalid order");
            }
        },
        Err(err) => {
            tracing::error!(%err, "PayPal rejected order creation");
            return error(StatusCode::BAD_GATEWAY, "PayPal rejected the order");
        }
    };
    let order_id = order["id"].as_str().unwrap_or_default().to_string();
    let approval_url = order["links"]
        .as_array()
        .and_then(|links| links.iter().find(|link| link["rel"] == "approve" || link["rel"] == "payer-action"))
        .and_then(|link| link["href"].as_str())
        .unwrap_or_default()
        .to_string();
    if order_id.is_empty() || approval_url.is_empty() || !approval_url.starts_with("https://") {
        return error(StatusCode::BAD_GATEWAY, "PayPal returned an incomplete order");
    }
    if let Err(err) = sqlx::query(
        "UPDATE payment_tenders SET provider_key = 'paypal', provider_reference = $3 \
         WHERE tenant_id = $1 AND sale_id = $2 AND method = 'paypal' AND status = 'pending'",
    )
    .bind(context.tenant_id)
    .bind(sale_id)
    .bind(&order_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "PayPal order reference could not be saved");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal order could not be saved");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "PayPal order transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal order could not be saved");
    }
    Json(json!({ "order_id": order_id, "approval_url": approval_url, "status": "pending" })).into_response()
}

pub async fn capture_order(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(sale_id): Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    let config = match PayPalConfig::from_env() {
        Ok(config) => config,
        Err(message) => return error(StatusCode::SERVICE_UNAVAILABLE, message),
    };
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "PayPal capture lookup transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal payment could not be captured");
        }
    };
    let row = match sqlx::query_as::<_, (String, String)>(
        "SELECT t.provider_reference, p.merchant_id FROM payment_tenders t \
         JOIN sales s ON s.tenant_id = t.tenant_id AND s.id = t.sale_id \
         JOIN business_paypal_accounts p ON p.tenant_id = s.tenant_id AND p.business_id = s.business_id \
         WHERE t.tenant_id = $1 AND t.sale_id = $2 AND t.method = 'paypal' \
         AND t.status = 'pending' AND t.provider_reference IS NOT NULL",
    )
    .bind(context.tenant_id)
    .bind(sale_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return error(StatusCode::NOT_FOUND, "pending PayPal order was not found"),
        Err(err) => {
            tracing::error!(%err, "PayPal capture lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal payment could not be captured");
        }
    };
    let (order_id, merchant_id) = row;
    let token = match config.access_token().await {
        Ok(token) if !token.is_empty() => token,
        _ => return error(StatusCode::BAD_GATEWAY, "PayPal authentication failed"),
    };
    let assertion = config.auth_assertion(&merchant_id);
    let response = match reqwest::Client::new()
        .post(format!("{}/v2/checkout/orders/{}/capture", config.base_url, order_id))
        .bearer_auth(token)
        .header("PayPal-Auth-Assertion", assertion)
        .header("PayPal-Request-Id", sale_id.to_string())
        .header("Content-Type", "application/json")
        .json(&json!({}))
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(%err, "PayPal capture request failed");
            return error(StatusCode::BAD_GATEWAY, "PayPal capture could not be completed");
        }
    };
    let capture = match response.error_for_status() {
        Ok(response) => match response.json::<Value>().await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(%err, "PayPal capture response invalid");
                return error(StatusCode::BAD_GATEWAY, "PayPal returned an invalid capture response");
            }
        },
        Err(err) => {
            tracing::error!(%err, "PayPal rejected capture");
            return error(StatusCode::BAD_GATEWAY, "PayPal rejected the payment capture");
        }
    };
    if capture["status"] != "COMPLETED" {
        return error(StatusCode::CONFLICT, "PayPal has not confirmed the payment as completed");
    }
    if let Err(err) = sqlx::query(
        "UPDATE payment_tenders SET status = 'captured', captured_at = now() \
         WHERE tenant_id = $1 AND sale_id = $2 AND method = 'paypal' AND status = 'pending'",
    )
    .bind(context.tenant_id)
    .bind(sale_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "PayPal tender capture update failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal payment could not be recorded");
    }
    if let Err(err) = sqlx::query(
        "UPDATE sales SET status = 'completed', completed_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND status = 'awaiting_payment'",
    )
    .bind(context.tenant_id)
    .bind(sale_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "PayPal sale completion update failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal sale could not be completed");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "PayPal capture transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "PayPal payment could not be recorded");
    }
    Json(json!({ "sale_id": sale_id, "status": "completed", "paypal_status": "COMPLETED" })).into_response()
}

pub async fn webhook(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Json(event): Json<Value>,
) -> Response {
    let config = match PayPalConfig::from_env() {
        Ok(config) if !config.webhook_id.is_empty() => config,
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "PayPal webhook is not configured"),
    };
    let token = match config.access_token().await {
        Ok(token) if !token.is_empty() => token,
        _ => return error(StatusCode::BAD_GATEWAY, "PayPal authentication failed"),
    };
    let header_value = |name: &str| headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("");
    let verification = json!({
        "auth_algo": header_value("paypal-auth-algo"),
        "cert_url": header_value("paypal-cert-url"),
        "transmission_id": header_value("paypal-transmission-id"),
        "transmission_sig": header_value("paypal-transmission-sig"),
        "transmission_time": header_value("paypal-transmission-time"),
        "webhook_id": config.webhook_id,
        "webhook_event": event.clone()
    });
    let verified = match reqwest::Client::new()
        .post(format!("{}/v1/notifications/verify-webhook-signature", config.base_url))
        .bearer_auth(token)
        .json(&verification)
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => response.json::<Value>().await.ok(),
            Err(_) => None,
        },
        Err(_) => None,
    };
    if verified.as_ref().is_none_or(|body| body["verification_status"] != "SUCCESS") {
        return error(StatusCode::UNAUTHORIZED, "PayPal webhook signature is invalid");
    }
    if event["event_type"] != "PAYMENT.CAPTURE.COMPLETED" {
        return StatusCode::NO_CONTENT.into_response();
    }
    let custom_id = event["resource"]["custom_id"].as_str().unwrap_or("");
    let Some((tenant, sale)) = custom_id.split_once(':') else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let (Ok(tenant_id), Ok(sale_id)) = (uuid::Uuid::parse_str(tenant), uuid::Uuid::parse_str(sale)) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "PayPal webhook transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "webhook could not be processed");
        }
    };
    if let Err(err) = sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%err, "PayPal webhook tenant context failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "webhook could not be processed");
    }
    let order_id = event["resource"]["supplementary_data"]["related_ids"]["order_id"]
        .as_str().unwrap_or("");
    let update = sqlx::query(
        "UPDATE payment_tenders SET status = 'captured', captured_at = now() \
         WHERE tenant_id = $1 AND sale_id = $2 AND method = 'paypal' AND status = 'pending' \
         AND ($3 = '' OR provider_reference = $3)",
    )
    .bind(tenant_id)
    .bind(sale_id)
    .bind(order_id)
    .execute(&mut *tx)
    .await;
    if let Err(err) = update {
        tracing::error!(%err, "PayPal webhook tender update failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "webhook could not be processed");
    }
    if let Err(err) = sqlx::query(
        "UPDATE sales SET status = 'completed', completed_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND status = 'awaiting_payment' \
         AND EXISTS (SELECT 1 FROM payment_tenders WHERE tenant_id = $1 AND sale_id = $2 AND method = 'paypal' AND status = 'captured')",
    )
    .bind(tenant_id)
    .bind(sale_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "PayPal webhook sale update failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "webhook could not be processed");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "PayPal webhook commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "webhook could not be processed");
    }
    StatusCode::NO_CONTENT.into_response()
}
