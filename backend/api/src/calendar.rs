use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;
use url::Url;

use crate::{
    auth::{begin_tenant_transaction, AuthContext, AuthState},
    integration_crypto,
};

const GOOGLE_API: &str = "https://www.googleapis.com/calendar/v3";

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn origin_is_allowed(headers: &HeaderMap, state: &AuthState) -> bool {
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == state.allowed_origin)
}

fn required_env(key: &str) -> Result<String, &'static str> {
    std::env::var(key).map_err(|_| "Google Calendar integration is not configured")
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    business_id: uuid::Uuid,
}

pub async fn connect(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<ConnectRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    let (client_id, redirect_uri) = match (
        required_env("GOOGLE_CLIENT_ID"),
        required_env("GOOGLE_CALENDAR_REDIRECT_URI"),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "Google Calendar OAuth is not configured"),
    };
    let state_id = uuid::Uuid::new_v4();
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "Google Calendar connect transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be started");
        }
    };
    let exists: bool = match sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM businesses WHERE tenant_id=$1 AND id=$2)",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(%err, "Google Calendar business lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be started");
        }
    };
    if !exists {
        return error(StatusCode::NOT_FOUND, "business was not found");
    }
    if let Err(err) = sqlx::query(
        "INSERT INTO google_calendar_oauth_states (state,tenant_id,business_id) VALUES ($1,$2,$3)",
    )
    .bind(state_id)
    .bind(context.tenant_id)
    .bind(request.business_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%err, "Google Calendar OAuth state insert failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be started");
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "Google Calendar OAuth state commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be started");
    }
    let mut url = match Url::parse("https://accounts.google.com/o/oauth2/v2/auth") {
        Ok(url) => url,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Google authorization URL is invalid"),
    };
    url.query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "https://www.googleapis.com/auth/calendar.events")
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("include_granted_scopes", "true")
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
        return Redirect::to(&format!("{app_origin}/integrations?calendar=denied")).into_response();
    }
    let (client_id, client_secret, redirect_uri) = match (
        required_env("GOOGLE_CLIENT_ID"),
        required_env("GOOGLE_CLIENT_SECRET"),
        required_env("GOOGLE_CALENDAR_REDIRECT_URI"),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "Google Calendar OAuth is not configured"),
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "Google Calendar callback transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be completed");
        }
    };
    if sqlx::query("SELECT set_config('app.google_oauth_state',$1,true)")
        .bind(query.state.to_string())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be completed");
    }
    let row = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
        "SELECT tenant_id,business_id FROM google_calendar_oauth_states WHERE state=$1 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE",
    )
    .bind(query.state)
    .fetch_optional(&mut *tx)
    .await;
    let (tenant_id, business_id) = match row {
        Ok(Some(value)) => value,
        Ok(None) => return error(StatusCode::GONE, "Google Calendar authorization expired; reconnect the business"),
        Err(err) => {
            tracing::error!(%err, "Google Calendar state lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be completed");
        }
    };
    let token = match reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", query.code.as_deref().unwrap_or_default()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(value) => value,
                Err(err) => {
                    tracing::error!(%err, "Google token response was invalid");
                    return error(StatusCode::BAD_GATEWAY, "Google Calendar authorization failed");
                }
            },
            Err(err) => {
                tracing::error!(%err, "Google rejected OAuth code");
                return error(StatusCode::BAD_GATEWAY, "Google Calendar authorization failed");
            }
        },
        Err(err) => {
            tracing::error!(%err, "Google OAuth token request failed");
            return error(StatusCode::BAD_GATEWAY, "Google could not be reached");
        }
    };
    let refresh_token = token["refresh_token"].as_str().unwrap_or_default();
    if refresh_token.is_empty() {
        return error(StatusCode::BAD_GATEWAY, "Google did not issue an offline refresh token; reconnect with consent");
    }
    let refresh_enc = match integration_crypto::encrypt(refresh_token) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "integration encryption is not configured"),
    };
    if sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be saved");
    }
    let saved = sqlx::query(
        "INSERT INTO google_calendar_connections (tenant_id,business_id,calendar_id,refresh_token_enc,connection_status) VALUES ($1,$2,'primary',$3,'connected') \
         ON CONFLICT (tenant_id,business_id) DO UPDATE SET refresh_token_enc=EXCLUDED.refresh_token_enc,calendar_id='primary',sync_token=NULL,connection_status='connected',connected_at=now(),updated_at=now()",
    )
    .bind(tenant_id)
    .bind(business_id)
    .bind(refresh_enc)
    .execute(&mut *tx)
    .await;
    if let Err(err) = saved {
        tracing::error!(%err, "Google Calendar connection save failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be saved");
    }
    let _ = sqlx::query("UPDATE google_calendar_oauth_states SET consumed_at=now() WHERE state=$1")
        .bind(query.state)
        .execute(&mut *tx)
        .await;
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "Google Calendar callback commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be saved");
    }
    Redirect::to(&format!("{app_origin}/integrations?calendar=connected")).into_response()
}

async fn access_token(
    state: &AuthState,
    context: &AuthContext,
    business_id: uuid::Uuid,
) -> Result<(String, String), Response> {
    let mut tx = begin_tenant_transaction(state, context)
        .await
        .map_err(|err| {
            tracing::error!(%err, "Google Calendar token lookup transaction failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be loaded")
        })?;
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT refresh_token_enc,calendar_id FROM google_calendar_connections WHERE tenant_id=$1 AND business_id=$2 AND connection_status='connected'",
    )
    .bind(context.tenant_id)
    .bind(business_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(%err, "Google Calendar token lookup failed");
        error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be loaded")
    })?
    .ok_or_else(|| error(StatusCode::CONFLICT, "connect this business to Google Calendar first"))?;
    tx.commit().await.map_err(|err| {
        tracing::error!(%err, "Google Calendar token lookup commit failed");
        error(StatusCode::INTERNAL_SERVER_ERROR, "calendar connection could not be loaded")
    })?;
    let refresh_token = integration_crypto::decrypt(&row.0)
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Google Calendar credentials cannot be decrypted"))?;
    let (client_id, client_secret) = (
        required_env("GOOGLE_CLIENT_ID").map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Google Calendar OAuth is not configured"))?,
        required_env("GOOGLE_CLIENT_SECRET").map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Google Calendar OAuth is not configured"))?,
    );
    let token = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|err| {
            tracing::error!(%err, "Google Calendar token refresh failed");
            error(StatusCode::BAD_GATEWAY, "Google could not be reached")
        })?
        .error_for_status()
        .map_err(|err| {
            tracing::error!(%err, "Google Calendar refresh token was rejected");
            error(StatusCode::UNAUTHORIZED, "Google Calendar connection expired; reconnect this business")
        })?
        .json::<Value>()
        .await
        .map_err(|err| {
            tracing::error!(%err, "Google Calendar token response was invalid");
            error(StatusCode::BAD_GATEWAY, "Google returned an invalid token response")
        })?;
    let access = token["access_token"].as_str().unwrap_or_default();
    if access.is_empty() {
        return Err(error(StatusCode::BAD_GATEWAY, "Google did not issue an access token"));
    }
    Ok((access.to_string(), row.1))
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
            tracing::error!(%err, "calendar status transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar status could not be loaded");
        }
    };
    match sqlx::query_scalar::<_, String>(
        "SELECT connection_status FROM google_calendar_connections WHERE tenant_id=$1 AND business_id=$2",
    )
    .bind(context.tenant_id)
    .bind(query.business_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(status)) => Json(json!({ "status": status })).into_response(),
        Ok(None) => Json(json!({ "status": "not_connected" })).into_response(),
        Err(err) => {
            tracing::error!(%err, "calendar status lookup failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "calendar status could not be loaded")
        }
    }
}

#[derive(FromRow, serde::Serialize)]
struct AppointmentRow {
    id: uuid::Uuid,
    external_event_id: Option<String>,
    source: String,
    summary: String,
    description: Option<String>,
    location: Option<String>,
    customer_name: Option<String>,
    customer_email: Option<String>,
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    status: String,
}

pub async fn list_appointments(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<BusinessQuery>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "appointment list transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "appointments could not be loaded");
        }
    };
    match sqlx::query_as::<_, AppointmentRow>(
        "SELECT id,external_event_id,source,summary,description,location,customer_name,customer_email,start_at,end_at,status \
         FROM appointments WHERE tenant_id=$1 AND business_id=$2 AND start_at >= now()-interval '30 days' \
         ORDER BY start_at LIMIT 500",
    )
    .bind(context.tenant_id)
    .bind(query.business_id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => {
            tracing::error!(%err, "appointment list query failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "appointments could not be loaded")
        }
    }
}

#[derive(Deserialize)]
pub struct SyncRequest {
    business_id: uuid::Uuid,
    time_min: String,
    time_max: String,
}

fn event_time(event: &Value, key: &str) -> Option<String> {
    event[key]["dateTime"]
        .as_str()
        .map(str::to_string)
        .or_else(|| event[key]["date"].as_str().map(|date| format!("{date}T00:00:00Z")))
}

pub async fn sync(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<SyncRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if DateTime::parse_from_rfc3339(&request.time_min).is_err()
        || DateTime::parse_from_rfc3339(&request.time_max).is_err()
    {
        return error(StatusCode::BAD_REQUEST, "calendar sync range must use RFC3339 timestamps");
    }
    let (token, calendar_id) = match access_token(&state, &context, request.business_id).await {
        Ok(values) => values,
        Err(response) => return response,
    };
    let response = match reqwest::Client::new()
        .get(format!("{GOOGLE_API}/calendars/{}/events", urlencoding::encode(&calendar_id)))
        .bearer_auth(&token)
        .query(&[
            ("timeMin", request.time_min.as_str()),
            ("timeMax", request.time_max.as_str()),
            ("singleEvents", "true"),
            ("maxResults", "2500"),
            ("showDeleted", "true"),
        ])
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(body) => body,
                Err(err) => {
                    tracing::error!(%err, "Google Calendar events response was invalid");
                    return error(StatusCode::BAD_GATEWAY, "Google Calendar returned invalid events");
                }
            },
            Err(err) => {
                tracing::error!(%err, "Google Calendar events request failed");
                return error(StatusCode::BAD_GATEWAY, "Google Calendar events could not be loaded");
            }
        },
        Err(err) => {
            tracing::error!(%err, "Google Calendar request failed");
            return error(StatusCode::BAD_GATEWAY, "Google Calendar could not be reached");
        }
    };
    let events = response["items"].as_array().cloned().unwrap_or_default();
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "appointment sync transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar events could not be synchronised");
        }
    };
    let mut synced = 0_u32;
    for event in events {
        let Some(event_id) = event["id"].as_str() else { continue };
        if event["status"] == "cancelled" {
            if let Err(err) = sqlx::query(
                "UPDATE appointments SET status='cancelled',last_synced_at=now(),updated_at=now() WHERE tenant_id=$1 AND business_id=$2 AND external_event_id=$3",
            )
            .bind(context.tenant_id)
            .bind(request.business_id)
            .bind(event_id)
            .execute(&mut *tx)
            .await
            {
                tracing::error!(%err, "cancelled Google Calendar event update failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar events could not be synchronised");
            }
            synced += 1;
            continue;
        }
        let Some(start) = event_time(&event, "start") else { continue };
        let Some(end) = event_time(&event, "end") else { continue };
        let summary = event["summary"].as_str().unwrap_or("(No title)");
        let status = "confirmed";
        let result = sqlx::query(
            "INSERT INTO appointments (tenant_id,business_id,external_event_id,source,summary,description,location,start_at,end_at,status,last_synced_at) \
             VALUES ($1,$2,$3,'google',$4,$5,$6,$7::timestamptz,$8::timestamptz,$9,now()) \
             ON CONFLICT (tenant_id,business_id,external_event_id) DO UPDATE SET summary=EXCLUDED.summary,description=EXCLUDED.description,location=EXCLUDED.location,start_at=EXCLUDED.start_at,end_at=EXCLUDED.end_at,status=EXCLUDED.status,last_synced_at=now(),updated_at=now()",
        )
        .bind(context.tenant_id)
        .bind(request.business_id)
        .bind(event_id)
        .bind(summary)
        .bind(event["description"].as_str())
        .bind(event["location"].as_str())
        .bind(start)
        .bind(end)
        .bind(status)
        .execute(&mut *tx)
        .await;
        match result {
            Ok(_) => synced += 1,
            Err(err) => {
                tracing::error!(%err, "Google Calendar event upsert failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar events could not be synchronised");
            }
        }
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(%err, "appointment sync commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "calendar events could not be synchronised");
    }
    Json(json!({ "synced": synced, "status": "complete" })).into_response()
}

#[derive(Deserialize)]
pub struct SaveAppointmentRequest {
    business_id: uuid::Uuid,
    summary: String,
    description: Option<String>,
    location: Option<String>,
    customer_name: Option<String>,
    customer_email: Option<String>,
    start_at: String,
    end_at: String,
}

fn valid_appointment(request: &SaveAppointmentRequest) -> bool {
    request.summary.trim().len() > 0
        && request.summary.trim().len() <= 240
        && DateTime::parse_from_rfc3339(&request.start_at).is_ok()
        && DateTime::parse_from_rfc3339(&request.end_at).is_ok()
        && DateTime::parse_from_rfc3339(&request.end_at).unwrap()
            > DateTime::parse_from_rfc3339(&request.start_at).unwrap()
}

pub async fn create_appointment(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<SaveAppointmentRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if !valid_appointment(&request) {
        return error(StatusCode::BAD_REQUEST, "appointment details are invalid");
    }
    let (token, calendar_id) = match access_token(&state, &context, request.business_id).await {
        Ok(values) => values,
        Err(response) => return response,
    };
    let body = json!({
        "summary": request.summary.trim(),
        "description": request.description,
        "location": request.location,
        "start": { "dateTime": request.start_at },
        "end": { "dateTime": request.end_at },
        "extendedProperties": { "private": { "tomos_business_id": request.business_id.to_string() } }
    });
    let event = match reqwest::Client::new()
        .post(format!("{GOOGLE_API}/calendars/{}/events", urlencoding::encode(&calendar_id)))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<Value>().await {
                Ok(value) => value,
                Err(err) => {
                    tracing::error!(%err, "Google Calendar event response invalid");
                    return error(StatusCode::BAD_GATEWAY, "appointment could not be created in Google Calendar");
                }
            },
            Err(err) => {
                tracing::error!(%err, "Google Calendar rejected event create");
                return error(StatusCode::BAD_GATEWAY, "appointment could not be created in Google Calendar");
            }
        },
        Err(err) => {
            tracing::error!(%err, "Google Calendar event create failed");
            return error(StatusCode::BAD_GATEWAY, "Google Calendar could not be reached");
        }
    };
    let event_id = event["id"].as_str().unwrap_or_default();
    if event_id.is_empty() {
        return error(StatusCode::BAD_GATEWAY, "Google Calendar did not return an event ID");
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "appointment create transaction failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be saved");
        }
    };
    let saved = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO appointments (tenant_id,business_id,external_event_id,source,summary,description,location,customer_name,customer_email,start_at,end_at,last_synced_at) \
         VALUES ($1,$2,$3,'tomos',$4,$5,$6,$7,$8,$9::timestamptz,$10::timestamptz,now()) RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(event_id)
    .bind(request.summary.trim())
    .bind(request.description)
    .bind(request.location)
    .bind(request.customer_name)
    .bind(request.customer_email)
    .bind(request.start_at)
    .bind(request.end_at)
    .fetch_one(&mut *tx)
    .await;
    match saved {
        Ok(id) => {
            if let Err(err) = tx.commit().await {
                tracing::error!(%err, "appointment create commit failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be saved");
            }
            (StatusCode::CREATED, Json(json!({ "id": id, "external_event_id": event_id }))).into_response()
        }
        Err(err) => {
            tracing::error!(%err, "appointment insert failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be saved")
        }
    }
}

pub async fn update_appointment(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    Path(appointment_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<SaveAppointmentRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }
    if !valid_appointment(&request) {
        return error(StatusCode::BAD_REQUEST, "appointment details are invalid");
    }
    let (token, calendar_id) = match access_token(&state, &context, request.business_id).await {
        Ok(values) => values,
        Err(response) => return response,
    };
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "appointment update lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be updated");
        }
    };
    let event_id = sqlx::query_scalar::<_, Option<String>>(
        "SELECT external_event_id FROM appointments WHERE tenant_id=$1 AND business_id=$2 AND id=$3",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(appointment_id)
    .fetch_optional(&mut *tx)
    .await;
    let event_id = match event_id {
        Ok(Some(Some(id))) => id,
        Ok(_) => return error(StatusCode::NOT_FOUND, "appointment was not found"),
        Err(err) => {
            tracing::error!(%err, "appointment external event lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be updated");
        }
    };
    tx.commit().await.ok();
    let body = json!({
        "summary": request.summary.trim(),
        "description": request.description,
        "location": request.location,
        "start": { "dateTime": request.start_at },
        "end": { "dateTime": request.end_at }
    });
    let response = reqwest::Client::new()
        .patch(format!("{GOOGLE_API}/calendars/{}/events/{}", urlencoding::encode(&calendar_id), urlencoding::encode(&event_id)))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            tracing::warn!(status=%response.status(), "Google Calendar rejected appointment update");
            return error(StatusCode::BAD_GATEWAY, "Google Calendar could not update the appointment");
        }
        Err(err) => {
            tracing::error!(%err, "Google Calendar appointment update failed");
            return error(StatusCode::BAD_GATEWAY, "Google Calendar could not be reached");
        }
    }
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%err, "appointment update persistence failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be updated");
        }
    };
    let updated = sqlx::query(
        "UPDATE appointments SET summary=$4,description=$5,location=$6,customer_name=$7,customer_email=$8,start_at=$9::timestamptz,end_at=$10::timestamptz,last_synced_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND business_id=$2 AND id=$3",
    )
    .bind(context.tenant_id)
    .bind(request.business_id)
    .bind(appointment_id)
    .bind(request.summary.trim())
    .bind(request.description)
    .bind(request.location)
    .bind(request.customer_name)
    .bind(request.customer_email)
    .bind(request.start_at)
    .bind(request.end_at)
    .execute(&mut *tx)
    .await;
    match updated {
        Ok(result) if result.rows_affected() == 1 => {
            if let Err(err) = tx.commit().await {
                tracing::error!(%err, "appointment update commit failed");
                return error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be updated");
            }
            Json(json!({ "status": "updated" })).into_response()
        }
        Ok(_) => error(StatusCode::NOT_FOUND, "appointment was not found"),
        Err(err) => {
            tracing::error!(%err, "appointment update failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "appointment could not be updated")
        }
    }
}

