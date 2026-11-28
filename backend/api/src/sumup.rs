use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use url::Url;

use crate::{
    auth::{begin_tenant_transaction, AuthContext, AuthState},
    integration_crypto,
};

const API_BASE: &str = "https://api.sumup.com";

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn origin_is_allowed(headers: &HeaderMap, state: &AuthState) -> bool {
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == state.allowed_origin)
}

fn config_value(key: &str) -> Result<String, &'static str> {
    std::env::var(key).map_err(|_| "SumUp integration is not configured")
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
    let (client_id, redirect_uri) = match (
        config_value("SUMUP_CLIENT_ID"),
        config_value("SUMUP_REDIRECT_URI"),
    ) {
        (Ok(client_id), Ok(redirect_uri)) => (client_id, redirect_uri),
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "SumUp OAuth is not configured"),
    };
    let state_id = uuid::Uuid::new_v4();
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "SumUp connect transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be started");
        }
    };
    let exists: bool = match sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM businesses WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(%err, "SumUp business lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be started");
        }
    };
    if !exists {
        return error(StatusCode::NOT_FOUND, "business was not found");
    }
    if let Err(err) = sqlx::query(
        "INSERT INTO sumup_oauth_states (state, tenant_id, business_id) VALUES ($1, $2, $3)",
    )
    .bind(state_id)
    .bind(context.tenant_id)
    .bind(request.business_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "SumUp OAuth state could not be saved");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be started");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "SumUp OAuth state commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be started");
    }

    let mut url = match Url::parse("https://api.sumup.com/authorize") {
        Ok(url) => url,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp authorization URL is invalid"),
    };
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", "transactions.history user.profile_readonly payments")
        .append_pair("state", &state_id.to_string());
    Json(json!({ "action_url": url.to_string() })).into_response()
}

#[derive(Deserialize)]
pub struct OAuthCallback {
    code: Option<String>,
    state: uuid::Uuid,
    error: Option<String>,
}

pub async fn oauth_callback(
    State(state): State<AuthState>,
    Query(query): Query<OAuthCallback>,
) -> Response {
    let app_origin = std::env::var("APP_ORIGIN").unwrap_or_else(|_| "/".to_string());
    if query.error.is_some() || query.code.as_deref().unwrap_or_default().is_empty() {
        return Redirect::to(&format!("{app_origin}/integrations?sumup=denied")).into_response();
    }
    let (client_id, client_secret, redirect_uri) = match (
        config_value("SUMUP_CLIENT_ID"),
        config_value("SUMUP_CLIENT_SECRET"),
        config_value("SUMUP_REDIRECT_URI"),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "SumUp OAuth is not configured"),
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "SumUp callback transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be completed");
        }
    };
    if sqlx::query("SELECT set_config('app.sumup_oauth_state', $1, true)")
        .bind(query.state.to_string())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be completed");
    }
    let state_row = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
        "SELECT tenant_id, business_id FROM sumup_oauth_states WHERE state = $1 AND consumed_at IS NULL AND expires_at > now() FOR UPDATE",
    )
    .bind(query.state)
    .fetch_optional(&mut *tx)
    .await;
    let (tenant_id, business_id) = match state_row {
        Ok(Some(row)) => row,
        Ok(None) => return error(StatusCode::GONE, "SumUp authorization has expired; reconnect the business"),
        Err(err) => {
            tracing::error!(%err, "SumUp OAuth state lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be completed");
        }
    };
    let token_response = match reqwest::Client::new()
        .post(format!("{API_BASE}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query.code.as_deref().unwrap_or_default()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(body) => body,
                Err(err) => {
                    tracing::error!(%err, "SumUp token response was invalid");
                    return error(StatusCode::BAD_GATEWAY, "SumUp authorization could not be completed");
                }
            },
            Err(err) => {
                tracing::error!(%err, "SumUp rejected OAuth token exchange");
                return error(StatusCode::BAD_GATEWAY, "SumUp authorization could not be completed");
            }
        },
        Err(err) => {
            tracing::error!(%err, "SumUp OAuth token request failed");
            return error(StatusCode::BAD_GATEWAY, "SumUp could not be reached");
        }
    };
    let access_token = token_response["access_token"].as_str().unwrap_or_default();
    let refresh_token = token_response["refresh_token"].as_str().unwrap_or_default();
    if access_token.is_empty() || refresh_token.is_empty() {
        return error(StatusCode::BAD_GATEWAY, "SumUp did not issue the required OAuth tokens");
    }
    let access_enc = match integration_crypto::encrypt(access_token) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "integration encryption is not configured"),
    };
    let refresh_enc = match integration_crypto::encrypt(refresh_token) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "integration encryption is not configured"),
    };
    let memberships = match reqwest::Client::new()
        .get(format!("{API_BASE}/v0.1/memberships"))
        .query(&[("kind", "merchant"), ("status", "accepted"), ("limit", "100")])
        .bearer_auth(access_token)
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(body) => body["items"].as_array().cloned().unwrap_or_default(),
                Err(err) => {
                    tracing::error!(%err, "SumUp memberships response was invalid");
                    return error(StatusCode::BAD_GATEWAY, "SumUp merchant accounts could not be loaded");
                }
            },
            Err(err) => {
                tracing::error!(%err, "SumUp memberships request failed");
                return error(StatusCode::BAD_GATEWAY, "SumUp merchant accounts could not be loaded");
            }
        },
        Err(err) => {
            tracing::error!(%err, "SumUp memberships request failed");
            return error(StatusCode::BAD_GATEWAY, "SumUp could not be reached");
        }
    };
    let merchants: Vec<Value> = memberships
        .iter()
        .filter_map(|item| {
            let resource = &item["resource"];
            let id = resource["id"].as_str()?;
            let name = resource["name"].as_str().unwrap_or("SumUp business");
            Some(json!({ "merchant_code": id, "name": name }))
        })
        .collect();
    if merchants.is_empty() {
        return Redirect::to(&format!("{app_origin}/integrations?sumup=no_merchant")).into_response();
    }
    let merchant_code = if merchants.len() == 1 {
        merchants[0]["merchant_code"].as_str().map(str::to_string)
    } else {
        None
    };
    let scopes = token_response["scope"].as_str().unwrap_or_default();
    let expires_in = token_response["expires_in"].as_i64().unwrap_or(3600).clamp(60, 86_400);
    if sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be saved");
    }
    let saved = sqlx::query(
        "INSERT INTO sumup_business_accounts (tenant_id, business_id, merchant_code, access_token_enc, refresh_token_enc, token_expires_at, granted_scopes, available_merchants, connection_status, connected_at) \
         VALUES ($1,$2,$3,$4,$5,now() + ($6::text || ' seconds')::interval,$7,$8,CASE WHEN $3::text IS NULL THEN 'pending' ELSE 'connected' END,CASE WHEN $3::text IS NULL THEN NULL ELSE now() END) \
         ON CONFLICT (tenant_id,business_id) DO UPDATE SET merchant_code=EXCLUDED.merchant_code, access_token_enc=EXCLUDED.access_token_enc, refresh_token_enc=EXCLUDED.refresh_token_enc, token_expires_at=EXCLUDED.token_expires_at, granted_scopes=EXCLUDED.granted_scopes, available_merchants=EXCLUDED.available_merchants, connection_status=EXCLUDED.connection_status, connected_at=EXCLUDED.connected_at, updated_at=now()",
    )
    .bind(tenant_id)
    .bind(business_id)
    .bind(merchant_code.as_deref())
    .bind(access_enc)
    .bind(refresh_enc)
    .bind(expires_in)
    .bind(scopes)
    .bind(json!(merchants))
    .execute(&mut *tx)
    .await;
    if let Err(err) = saved {
        tracing::error!(%err, "SumUp account could not be saved");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be saved");
    }
    let _ = sqlx::query("UPDATE sumup_oauth_states SET consumed_at=now() WHERE state=$1")
        .bind(query.state)
        .execute(&mut *tx)
        .await;
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "SumUp OAuth callback commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp connection could not be saved");
    }
    let status = if merchant_code.is_some() { "connected" } else { "select_merchant" };
    Redirect::to(&format!("{app_origin}/integrations?sumup={status}")).into_response()
}

#[derive(Deserialize)]
pub struct SelectMerchantRequest {
    business_id: uuid::Uuid,
    merchant_code: String,
}

pub async fn select_merchant(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<SelectMerchantRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "SumUp merchant selection transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "merchant account could not be selected");
        }
    };
    let updated = sqlx::query(
        "UPDATE sumup_business_accounts SET merchant_code=$3, connection_status='connected', connected_at=now(), updated_at=now() \
         WHERE tenant_id=$1 AND business_id=$2 AND available_merchants @> jsonb_build_array(jsonb_build_object('merchant_code',$3))",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(request.merchant_code.trim())
    .execute(&mut *tx)
    .await;
    match updated {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => return error(StatusCode::BAD_REQUEST, "the selected SumUp merchant is not authorised"),
        Err(err) => {
            tracing::error!(%err, "SumUp merchant selection failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "merchant account could not be selected");
        }
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "SumUp merchant selection commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "merchant account could not be selected");
    }
    Json(json!({ "status": "connected" })).into_response()
}

async fn refreshed_token(
    state: &AuthState,
    context: &AuthContext,
    business_id: uuid::Uuid,
) -> Result<(String, String), Response> {
    let mut tx = begin_tenant_transaction(state, context)
        .await
        .map_err(|err| {
            tracing::error!(%err, "SumUp token lookup transaction failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp account could not be loaded")
        })?;
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT refresh_token_enc, merchant_code FROM sumup_business_accounts \
         WHERE tenant_id=$1 AND business_id=$2 AND connection_status='connected' AND merchant_code IS NOT NULL",
    )
    .bind(context.tenant_id)
    .bind(business_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(%err, "SumUp token lookup failed");
        error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp account could not be loaded")
    })?
    .ok_or_else(|| error(StatusCode::CONFLICT, "connect this business to SumUp first"))?;
    tx.commit().await.map_err(|err| {
        tracing::error!(%err, "SumUp token lookup commit failed");
        error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp account could not be loaded")
    })?;
    let refresh_token = integration_crypto::decrypt(&row.0)
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "SumUp credentials cannot be decrypted"))?;
    let (client_id, client_secret) = (
        config_value("SUMUP_CLIENT_ID").map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "SumUp OAuth is not configured"))?,
        config_value("SUMUP_CLIENT_SECRET").map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "SumUp OAuth is not configured"))?,
    );
    let response = reqwest::Client::new()
        .post(format!("{API_BASE}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
        .map_err(|err| {
            tracing::error!(%err, "SumUp token refresh request failed");
            error(StatusCode::BAD_GATEWAY, "SumUp could not be reached")
        })?
        .error_for_status()
        .map_err(|err| {
            tracing::error!(%err, "SumUp rejected token refresh");
            error(StatusCode::UNAUTHORIZED, "SumUp connection expired; reconnect this business")
        })?
        .json::<Value>()
        .await
        .map_err(|err| {
            tracing::error!(%err, "SumUp token refresh response was invalid");
            error(StatusCode::BAD_GATEWAY, "SumUp returned an invalid token response")
        })?;
    let access_token = response["access_token"].as_str().unwrap_or_default();
    if access_token.is_empty() {
        return Err(error(StatusCode::BAD_GATEWAY, "SumUp did not issue an access token"));
    }
    let new_refresh = response["refresh_token"].as_str().unwrap_or(&refresh_token);
    let access_enc = integration_crypto::encrypt(access_token)
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "integration encryption is not configured"))?;
    let refresh_enc = integration_crypto::encrypt(new_refresh)
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "integration encryption is not configured"))?;
    let expires = response["expires_in"].as_i64().unwrap_or(3600).clamp(60, 86_400);
    let mut tx = begin_tenant_transaction(state, context)
        .await
        .map_err(|err| {
            tracing::error!(%err, "SumUp token persistence transaction failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp credentials could not be refreshed")
        })?;
    sqlx::query(
        "UPDATE sumup_business_accounts SET access_token_enc=$3, refresh_token_enc=$4, token_expires_at=now() + ($5::text || ' seconds')::interval, updated_at=now() WHERE tenant_id=$1 AND business_id=$2",
    )
    .bind(context.tenant_id)
    .bind(business_id)
    .bind(access_enc)
    .bind(refresh_enc)
    .bind(expires)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(%err, "SumUp credentials could not be persisted");
        error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp credentials could not be refreshed")
    })?;
    tx.commit().await.map_err(|err| {
        tracing::error!(%err, "SumUp token persistence commit failed");
        error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp credentials could not be refreshed")
    })?;
    Ok((access_token.to_string(), row.1))
}

#[derive(Deserialize)]
pub struct BusinessQuery {
    business_id: uuid::Uuid,
}

pub async fn connection_status(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<BusinessQuery>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "SumUp status transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp status could not be loaded");
        }
    };
    match sqlx::query_as::<_, (String, Option<String>, Value)>(
        "SELECT connection_status,merchant_code,available_merchants FROM sumup_business_accounts WHERE tenant_id=$1 AND business_id=$2",
    )
    .bind(context.tenant_id)
    .bind(query.business_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some((status, merchant_code, merchants))) => Json(json!({
            "status": status, "merchant_code": merchant_code, "merchants": merchants
        })).into_response(),
        Ok(None) => Json(json!({ "status": "not_connected", "merchant_code": null, "merchants": [] })).into_response(),
        Err(err) => {
            tracing::error!(%err, "SumUp status lookup failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp status could not be loaded")
        }
    }
}

pub async fn list_readers(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<BusinessQuery>,
) -> Response {
    let (token, merchant) = match refreshed_token(&state, &context, query.business_id).await {
        Ok(values) => values,
        Err(response) => return response,
    };
    match reqwest::Client::new()
        .get(format!("{API_BASE}/v0.1/merchants/{merchant}/readers"))
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(body) => Json(body).into_response(),
                Err(err) => {
                    tracing::error!(%err, "SumUp readers response was invalid");
                    error(StatusCode::BAD_GATEWAY, "SumUp returned an invalid reader list")
                }
            },
            Err(err) => {
                tracing::error!(%err, "SumUp readers request failed");
                error(StatusCode::BAD_GATEWAY, "SumUp readers could not be loaded")
            }
        },
        Err(err) => {
            tracing::error!(%err, "SumUp readers request failed");
            error(StatusCode::BAD_GATEWAY, "SumUp could not be reached")
        }
    }
}

#[derive(Deserialize)]
pub struct ReaderCheckoutRequest {
    business_id: uuid::Uuid,
    reader_id: String,
}

#[derive(FromRow)]
struct SaleForReader {
    total_minor: i64,
    currency_code: String,
    sale_status: String,
    tender_id: uuid::Uuid,
    tender_status: String,
}

pub async fn start_reader_checkout(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(sale_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<ReaderCheckoutRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if request.reader_id.trim().is_empty() || request.reader_id.len() > 128 {
        return error(StatusCode::BAD_REQUEST, "SumUp reader ID is invalid");
    }
    let (token, merchant) = match refreshed_token(&state, &context, request.business_id).await {
        Ok(values) => values,
        Err(response) => return response,
    };
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "SumUp sale lookup transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp payment could not be started");
        }
    };
    let sale = sqlx::query_as::<_, SaleForReader>(
        "SELECT s.total_minor, s.currency_code, s.status AS sale_status, pt.id AS tender_id, pt.status AS tender_status \
         FROM sales s JOIN payment_tenders pt ON pt.tenant_id=s.tenant_id AND pt.sale_id=s.id \
         WHERE s.tenant_id=$1 AND s.business_id=$2 AND s.id=$3 AND pt.method='sumup_terminal' FOR UPDATE",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(sale_id)
    .fetch_optional(&mut *tx)
    .await;
    let sale = match sale {
        Ok(Some(sale)) if sale.sale_status == "awaiting_payment" && sale.tender_status == "pending" => sale,
        Ok(Some(_)) => return error(StatusCode::CONFLICT, "this sale is no longer awaiting SumUp payment"),
        Ok(None) => return error(StatusCode::NOT_FOUND, "pending SumUp sale was not found"),
        Err(err) => {
            tracing::error!(%err, "SumUp sale lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp payment could not be started");
        }
    };
    let affiliate_key = match config_value("SUMUP_AFFILIATE_KEY") {
        Ok(value) => value,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "SumUp Cloud API affiliate key is not configured"),
    };
    let webhook_base = match config_value("SUMUP_READER_WEBHOOK_URL") {
        Ok(value) if value.starts_with("https://") => value,
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "SumUp HTTPS webhook URL is not configured"),
    };
    let webhook_token = uuid::Uuid::new_v4().to_string();
    let webhook_hash = hex::encode(Sha256::digest(webhook_token.as_bytes()));
    let return_url = format!("{webhook_base}?token={webhook_token}");
    let body = json!({
        "total_amount": { "currency": sale.currency_code, "minor_unit": 2, "value": sale.total_minor },
        "affiliate": affiliate_key,
        "return_url": return_url,
    });
    let created = match reqwest::Client::new()
        .post(format!("{API_BASE}/v0.1/merchants/{merchant}/readers/{}/checkout", urlencoding::encode(&request.reader_id)))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(value) => value,
                Err(err) => {
                    tracing::error!(%err, "SumUp reader checkout response was invalid");
                    return error(StatusCode::BAD_GATEWAY, "SumUp returned an invalid checkout response");
                }
            },
            Err(err) => {
                tracing::error!(%err, "SumUp rejected reader checkout");
                return error(StatusCode::BAD_GATEWAY, "SumUp reader payment could not be started");
            }
        },
        Err(err) => {
            tracing::error!(%err, "SumUp reader checkout request failed");
            return error(StatusCode::BAD_GATEWAY, "SumUp could not be reached");
        }
    };
    let response_data = &created["data"];
    let transaction_id = response_data["client_transaction_id"].as_str().unwrap_or_default();
    if transaction_id.is_empty() {
        return error(StatusCode::BAD_GATEWAY, "SumUp did not return a transaction reference");
    }
    let checkout_id = response_data["checkout_id"].as_str();
    let inserted = sqlx::query(
        "INSERT INTO sumup_reader_payments (tenant_id,business_id,sale_id,tender_id,merchant_code,reader_id,checkout_id,client_transaction_id,webhook_token_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(sale_id)
    .bind(sale.tender_id)
    .bind(&merchant)
    .bind(&request.reader_id)
    .bind(checkout_id)
    .bind(transaction_id)
    .bind(&webhook_hash)
    .execute(&mut *tx)
    .await;
    if let Err(err) = inserted {
        tracing::error!(%err, "SumUp reader payment could not be saved");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp payment could not be recorded");
    }
    if let Err(err) = sqlx::query(
        "UPDATE payment_tenders SET provider_key='sumup', provider_reference=$3, terminal_reference=$4 WHERE tenant_id=$1 AND id=$2",
    )
    .bind(context.tenant_id)
    .bind(sale.tender_id)
    .bind(transaction_id)
    .bind(&request.reader_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "SumUp tender reference could not be saved");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp payment could not be recorded");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "SumUp reader checkout transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp payment could not be recorded");
    }
    Json(json!({
        "sale_id": sale_id,
        "client_transaction_id": transaction_id,
        "checkout_id": checkout_id,
        "reader_id": request.reader_id,
        "status": "pending",
        "message": "The SumUp reader has accepted the checkout request. The sale remains unpaid until the final reader event arrives."
    })).into_response()
}

pub async fn payment_status(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(client_transaction_id): Path<String>,
) -> Response {
    if client_transaction_id.len() > 100 {
        return error(StatusCode::BAD_REQUEST, "SumUp transaction reference is invalid");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "SumUp payment status transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp payment status could not be loaded");
        }
    };
    match sqlx::query_as::<_, (String, uuid::Uuid)>(
        "SELECT status,sale_id FROM sumup_reader_payments WHERE tenant_id=$1 AND client_transaction_id=$2",
    )
    .bind(context.tenant_id)
    .bind(client_transaction_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some((status, sale_id))) => Json(json!({ "status": status, "sale_id": sale_id })).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "SumUp transaction was not found"),
        Err(err) => {
            tracing::error!(%err, "SumUp payment status lookup failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "SumUp payment status could not be loaded")
        }
    }
}

#[derive(Deserialize)]
pub struct ReaderWebhookQuery {
    token: String,
}

pub async fn reader_webhook(
    State(state): State<AuthState>,
    Query(query): Query<ReaderWebhookQuery>,
    Json(event): Json<Value>,
) -> Response {
    if query.token.len() < 30 {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if event["event_type"] != "solo.transaction.updated" {
        return StatusCode::NO_CONTENT.into_response();
    }
    let transaction_id = event["payload"]["client_transaction_id"].as_str().unwrap_or_default();
    let merchant_code = event["payload"]["merchant_code"].as_str().unwrap_or_default();
    let status = event["payload"]["status"].as_str().unwrap_or_default();
    if transaction_id.is_empty() || merchant_code.is_empty() || !matches!(status, "successful" | "failed") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let hash = hex::encode(Sha256::digest(query.token.as_bytes()));
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "SumUp webhook transaction failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if sqlx::query("SELECT set_config('app.sumup_webhook_token_hash', $1, true)")
        .bind(&hash)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let row = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid, uuid::Uuid, String, String)>(
        "SELECT tenant_id, sale_id, tender_id, merchant_code, status FROM sumup_reader_payments WHERE webhook_token_hash=$1 AND client_transaction_id=$2",
    )
    .bind(&hash)
    .bind(transaction_id)
    .fetch_optional(&mut *tx)
    .await;
    let (tenant_id, sale_id, tender_id, expected_merchant, existing_status) = match row {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(%err, "SumUp webhook payment lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if expected_merchant != merchant_code {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if existing_status != "pending" {
        return StatusCode::NO_CONTENT.into_response();
    }
    if sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let (tender_status, sale_status) = if status == "successful" {
        ("captured", "completed")
    } else {
        ("failed", "cancelled")
    };
    let updated = sqlx::query(
        "UPDATE payment_tenders SET status=$3, captured_at=CASE WHEN $3='captured' THEN now() ELSE NULL END \
         WHERE tenant_id=$1 AND id=$2 AND method='sumup_terminal' AND status='pending'",
    )
    .bind(tenant_id)
    .bind(tender_id)
    .bind(tender_status)
    .execute(&mut *tx)
    .await;
    match updated {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => return StatusCode::CONFLICT.into_response(),
        Err(err) => {
            tracing::error!(%err, "SumUp tender update failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    if let Err(err) = sqlx::query(
        "UPDATE sales SET status=$3, completed_at=CASE WHEN $3='completed' THEN now() ELSE NULL END \
         WHERE tenant_id=$1 AND id=$2 AND status='awaiting_payment'",
    )
    .bind(tenant_id)
    .bind(sale_id)
    .bind(sale_status)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "SumUp sale update failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(err) = sqlx::query(
        "UPDATE sumup_reader_payments SET status=$2, failure_reason=$3, completed_at=now() WHERE tenant_id=$1 AND client_transaction_id=$4",
    )
    .bind(tenant_id)
    .bind(status)
    .bind(event["payload"]["failure_reason"].as_str())
    .bind(transaction_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "SumUp payment event update failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "SumUp webhook commit failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}
