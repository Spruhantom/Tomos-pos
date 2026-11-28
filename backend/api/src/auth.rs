use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Extension, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};

const SESSION_COOKIE: &str = "tomos_pos_session";
const SESSION_SECONDS: i64 = 12 * 60 * 60;

#[derive(Clone)]
pub struct AuthState {
    pub db: PgPool,
    pub cookie_secure: bool,
    pub allowed_origin: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(FromRow)]
struct LoginRow {
    id: uuid::Uuid,
    email: String,
    display_name: String,
    password_hash: String,
    is_active: bool,
}

#[derive(FromRow)]
struct SessionUserRow {
    id: uuid::Uuid,
    email: String,
    display_name: String,
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorResponse { error: message })).into_response()
}

fn session_cookie(token: &str, secure: bool, max_age: i64) -> HeaderValue {
    let secure_attribute = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}{secure_attribute}"
    ))
    .expect("cookie value contains only safe characters")
}

fn token_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix("tomos_pos_session="))
        .filter(|token| !token.is_empty())
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn origin_matches(headers: &HeaderMap, allowed_origin: &str) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == allowed_origin)
}

fn origin_is_allowed(headers: &HeaderMap, state: &AuthState) -> bool {
    origin_matches(headers, &state.allowed_origin)
}

async fn login_is_rate_limited(state: &AuthState, email: &str) -> Result<bool, sqlx::Error> {
    let identifier_hash = hex::encode(Sha256::digest(email.as_bytes()));
    sqlx::query_scalar(
        "INSERT INTO auth_login_limits (identifier_hash, attempt_count) VALUES ($1, 1) \
         ON CONFLICT (identifier_hash) DO UPDATE SET \
           window_started_at = CASE \
             WHEN auth_login_limits.window_started_at <= now() - interval '15 minutes' \
             THEN now() ELSE auth_login_limits.window_started_at END, \
           attempt_count = CASE \
             WHEN auth_login_limits.window_started_at <= now() - interval '15 minutes' \
             THEN 1 ELSE auth_login_limits.attempt_count + 1 END, \
           blocked_until = CASE \
             WHEN auth_login_limits.blocked_until > now() THEN auth_login_limits.blocked_until \
             WHEN auth_login_limits.window_started_at <= now() - interval '15 minutes' THEN NULL \
             WHEN auth_login_limits.attempt_count + 1 >= 10 THEN now() + interval '15 minutes' \
             ELSE NULL END, \
           updated_at = now() \
         RETURNING blocked_until IS NOT NULL AND blocked_until > now()",
    )
    .bind(identifier_hash)
    .fetch_one(&state.db)
    .await
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}

fn verify_password(password: &str, encoded_hash: &str) -> bool {
    PasswordHash::new(encoded_hash).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

pub async fn login(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }

    if request.email.len() > 320 || request.password.len() > 1024 {
        return error(StatusCode::BAD_REQUEST, "invalid credentials");
    }

    let email_normalized = request.email.trim().to_lowercase();
    match login_is_rate_limited(&state, &email_normalized).await {
        Ok(true) => {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many login attempts; try again later",
            )
        }
        Ok(false) => {}
        Err(db_error) => {
            tracing::error!(%db_error, "login rate-limit check failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "login could not be completed",
            );
        }
    }

    let user = match sqlx::query_as::<_, LoginRow>(
        "SELECT id, email, display_name, password_hash, is_active \
         FROM users WHERE email_normalized = $1",
    )
    .bind(&email_normalized)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "email or password is incorrect"),
        Err(db_error) => {
            tracing::error!(%db_error, "login lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "login could not be completed",
            );
        }
    };

    if !user.is_active || !verify_password(&request.password, &user.password_hash) {
        return error(StatusCode::UNAUTHORIZED, "email or password is incorrect");
    }

    if let Err(db_error) = sqlx::query("DELETE FROM auth_login_limits WHERE identifier_hash = $1")
        .bind(hex::encode(Sha256::digest(email_normalized.as_bytes())))
        .execute(&state.db)
        .await
    {
        tracing::warn!(%db_error, "successful login rate-limit record cleanup failed");
    }

    let mut token_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);

    if let Err(db_error) = sqlx::query(
        "INSERT INTO user_sessions (user_id, token_hash, expires_at) \
         VALUES ($1, $2, now() + ($3 * interval '1 second'))",
    )
    .bind(user.id)
    .bind(token_hash(&token))
    .bind(SESSION_SECONDS as f64)
    .execute(&state.db)
    .await
    {
        tracing::error!(%db_error, "session creation failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "login could not be completed",
        );
    }

    let mut response = Json(UserResponse {
        id: user.id.to_string(),
        email: user.email,
        display_name: user.display_name,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&token, state.cookie_secure, SESSION_SECONDS),
    );
    response
}

pub async fn logout(State(state): State<AuthState>, headers: HeaderMap) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }

    if let Some(token) = token_from_headers(&headers) {
        if let Err(db_error) = sqlx::query(
            "UPDATE user_sessions SET revoked_at = now() \
             WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash(token))
        .execute(&state.db)
        .await
        {
            tracing::error!(%db_error, "session revocation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "logout could not be completed",
            );
        }
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie("", state.cookie_secure, 0),
    );
    response
}

pub async fn me(State(state): State<AuthState>, headers: HeaderMap) -> Response {
    let Some(token) = token_from_headers(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "authentication required");
    };

    let user = match sqlx::query_as::<_, SessionUserRow>(
        "SELECT u.id, u.email, u.display_name \
         FROM user_sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL \
           AND s.expires_at > now() AND u.is_active = TRUE",
    )
    .bind(token_hash(token))
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "session is invalid or expired"),
        Err(db_error) => {
            tracing::error!(%db_error, "session lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session could not be checked",
            );
        }
    };

    Json(UserResponse {
        id: user.id.to_string(),
        email: user.email,
        display_name: user.display_name,
    })
    .into_response()
}

#[derive(Clone)]
pub struct AuthContext {
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub membership_id: uuid::Uuid,
}

#[derive(Serialize)]
pub struct TenantContextResponse {
    pub user_id: String,
    pub tenant_id: String,
    pub membership_id: String,
}

pub async fn require_tenant(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = token_from_headers(request.headers()) else {
        return error(StatusCode::UNAUTHORIZED, "authentication required");
    };
    let Some(tenant_id) = request
        .headers()
        .get("x-tenant-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "a valid X-Tenant-ID header is required",
        );
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "tenant authentication transaction failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tenant access could not be checked",
            );
        }
    };

    let user_id: uuid::Uuid = match sqlx::query_scalar(
        "SELECT u.id FROM user_sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL \
           AND s.expires_at > now() AND u.is_active = TRUE",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(user_id)) => user_id,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "session is invalid or expired"),
        Err(db_error) => {
            tracing::error!(%db_error, "tenant session lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tenant access could not be checked",
            );
        }
    };

    if let Err(db_error) = sqlx::query("SELECT set_config('app.user_id', $1, true)")
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "tenant user context setup failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "tenant access could not be checked",
        );
    }

    let membership_id: uuid::Uuid = match sqlx::query_scalar(
        "SELECT id FROM tenant_memberships \
         WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(membership_id)) => membership_id,
        Ok(None) => {
            return error(
                StatusCode::FORBIDDEN,
                "user is not an active member of this tenant",
            )
        }
        Err(db_error) => {
            tracing::error!(%db_error, "tenant membership lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tenant access could not be checked",
            );
        }
    };

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "tenant authentication transaction commit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "tenant access could not be checked",
        );
    }

    request.extensions_mut().insert(AuthContext {
        user_id,
        tenant_id,
        membership_id,
    });

    next.run(request).await
}

pub async fn begin_tenant_transaction(
    state: &AuthState,
    context: &AuthContext,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, sqlx::Error> {
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT set_config('app.user_id', $1, true)")
        .bind(context.user_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(context.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

#[derive(Clone)]
pub struct PermissionState {
    pub auth: AuthState,
    pub permission_key: &'static str,
}

pub async fn require_permission(
    State(state): State<PermissionState>,
    Extension(context): Extension<AuthContext>,
    request: Request,
    next: Next,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state.auth, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "permission check transaction failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "permission could not be checked",
            );
        }
    };

    let permitted: bool = match sqlx::query_scalar(
        "SELECT EXISTS ( \
           SELECT 1 FROM membership_roles mr \
           JOIN tenant_memberships tm \
             ON tm.tenant_id = mr.tenant_id AND tm.id = mr.membership_id \
            AND tm.user_id = $4 AND tm.status = 'active' \
           JOIN role_permissions rp ON rp.tenant_id = mr.tenant_id AND rp.role_id = mr.role_id \
           JOIN permissions p ON p.id = rp.permission_id \
           WHERE mr.tenant_id = $1 AND mr.membership_id = $2 \
             AND p.permission_key = $3 \
         )",
    )
    .bind(context.tenant_id)
    .bind(context.membership_id)
    .bind(state.permission_key)
    .bind(context.user_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(permitted) => permitted,
        Err(db_error) => {
            tracing::error!(%db_error, "permission lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "permission could not be checked",
            );
        }
    };

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "permission check transaction commit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "permission could not be checked",
        );
    }

    if !permitted {
        return error(StatusCode::FORBIDDEN, "required permission is missing");
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::{hash_password, origin_matches, verify_password};
    use axum::http::{header, HeaderMap, HeaderValue};

    #[test]
    fn state_changing_requests_require_the_exact_configured_origin() {
        let mut headers = HeaderMap::new();
        assert!(!origin_matches(&headers, "https://pos.example.com"));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!origin_matches(&headers, "https://pos.example.com"));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://pos.example.com"),
        );
        assert!(origin_matches(&headers, "https://pos.example.com"));
    }

    #[test]
    fn password_hash_verifies_only_the_original_password() {
        let encoded = hash_password("correct horse battery staple")
            .expect("argon2 should generate a password hash");

        assert!(verify_password("correct horse battery staple", &encoded));
        assert!(!verify_password("incorrect password", &encoded));
        assert!(!encoded.contains("correct horse"));
    }
}

#[derive(Deserialize)]
pub struct InitialSetupRequest {
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub tenant_name: String,
    pub tenant_slug: String,
    pub legal_business_name: String,
}

pub async fn initial_setup(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Json(request): Json<InitialSetupRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }

    let email = request.email.trim();
    let email_normalized = email.to_lowercase();
    let tenant_slug = request.tenant_slug.trim().to_lowercase();

    if email.len() > 320
        || !email.contains('@')
        || request.password.len() < 12
        || request.password.len() > 1024
        || request.display_name.trim().is_empty()
        || request.display_name.len() > 120
        || request.tenant_name.trim().is_empty()
        || request.tenant_name.len() > 160
        || request.legal_business_name.trim().is_empty()
        || request.legal_business_name.len() > 200
        || tenant_slug.len() < 3
        || tenant_slug.len() > 48
        || !tenant_slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || tenant_slug.starts_with('-')
        || tenant_slug.ends_with('-')
    {
        return error(
            StatusCode::BAD_REQUEST,
            "setup details are invalid; use a 12-character password and a valid tenant slug",
        );
    }

    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(hash_error) => {
            tracing::error!(%hash_error, "initial password hashing failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "initial setup transaction could not start");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    // Serialise concurrent setup requests. Only the first installation owner can be created.
    if let Err(db_error) = sqlx::query("SELECT pg_advisory_xact_lock(741203)")
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "initial setup lock failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    let existing_users: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await
    {
        Ok(count) => count,
        Err(db_error) => {
            tracing::error!(%db_error, "initial setup user check failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    if existing_users > 0 {
        return error(
            StatusCode::CONFLICT,
            "initial setup has already been completed",
        );
    }

    let tenant_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO tenants (slug, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(&tenant_slug)
    .bind(request.tenant_name.trim())
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "initial tenant creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    if let Err(db_error) = sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "initial tenant context could not be established");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    let user_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO users (email, email_normalized, password_hash, display_name) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(email)
    .bind(&email_normalized)
    .bind(password_hash)
    .bind(request.display_name.trim())
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "initial owner creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    let business_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO businesses (tenant_id, legal_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(tenant_id)
    .bind(request.legal_business_name.trim())
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "initial business creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    let membership_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO tenant_memberships (tenant_id, user_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "initial owner membership creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    let role_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO roles (tenant_id, role_key, display_name, is_system) \
         VALUES ($1, 'owner', 'Owner', TRUE) RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "initial owner role creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    let staff_role_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO roles (tenant_id, role_key, display_name, is_system) \
         VALUES ($1, 'staff', 'Staff', FALSE) RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "initial staff role creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "initial setup could not be completed",
            );
        }
    };

    if let Err(db_error) = sqlx::query(
        "INSERT INTO role_permissions (tenant_id, role_id, permission_id) \
         SELECT $1, $2, id FROM permissions WHERE permission_key = 'business.read'",
    )
    .bind(tenant_id)
    .bind(staff_role_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "initial staff permissions could not be assigned");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    let role_grants = sqlx::query(
        "INSERT INTO role_permissions (tenant_id, role_id, permission_id) \
         SELECT $1, $2, id FROM permissions",
    )
    .bind(tenant_id)
    .bind(role_id)
    .execute(&mut *tx)
    .await;

    if let Err(db_error) = role_grants {
        tracing::error!(%db_error, "initial owner permissions could not be assigned");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    if let Err(db_error) = sqlx::query(
        "INSERT INTO membership_roles (tenant_id, membership_id, role_id) VALUES ($1, $2, $3)",
    )
    .bind(tenant_id)
    .bind(membership_id)
    .bind(role_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "initial owner role assignment failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    if let Err(db_error) = sqlx::query(
        "INSERT INTO business_locations (tenant_id, business_id, name, location_code) \
         VALUES ($1, $2, 'Main location', 'MAIN')",
    )
    .bind(tenant_id)
    .bind(business_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "initial business location creation failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    let audit_context = AuthContext {
        user_id,
        tenant_id,
        membership_id,
    };
    if let Err(db_error) = crate::audit::record_event(
        &mut tx,
        &audit_context,
        crate::audit::AuditEventType::BusinessCreated,
        crate::audit::AuditEntityType::Business,
        Some(business_id),
        serde_json::json!({ "source": "initial_setup" }),
    )
    .await
    {
        tracing::error!(%db_error, "initial setup audit event could not be recorded");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    let mut token_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);

    if let Err(db_error) = sqlx::query(
        "INSERT INTO user_sessions (user_id, token_hash, expires_at) \
         VALUES ($1, $2, now() + ($3 * interval '1 second'))",
    )
    .bind(user_id)
    .bind(token_hash(&token))
    .bind(SESSION_SECONDS as f64)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "initial owner session creation failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "initial setup transaction commit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "initial setup could not be completed",
        );
    }

    let mut response = Json(UserResponse {
        id: user_id.to_string(),
        email: email.to_string(),
        display_name: request.display_name.trim().to_string(),
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&token, state.cookie_secure, SESSION_SECONDS),
    );
    response
}

#[derive(Deserialize)]
pub struct CreateStaffInvitationRequest {
    pub email: String,
}

#[derive(Serialize)]
struct CreatedStaffInvitationResponse {
    id: String,
    email: String,
    token: String,
    expires_in_days: u8,
    delivery: &'static str,
}

#[derive(Deserialize)]
pub struct AcceptStaffInvitationRequest {
    pub token: String,
    pub password: String,
    pub display_name: String,
}

#[derive(FromRow)]
struct StaffInvitationRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    email_normalized: String,
    role_id: uuid::Uuid,
}

/// Create a seven-day, single-use invitation for the tenant's least-privileged
/// built-in Staff role. The raw token is returned once for secure delivery.
pub async fn create_staff_invitation(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    Json(request): Json<CreateStaffInvitationRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }

    let email_normalized = request.email.trim().to_lowercase();
    if email_normalized.len() > 320
        || !email_normalized.contains('@')
        || email_normalized.chars().any(char::is_whitespace)
    {
        return error(StatusCode::BAD_REQUEST, "a valid email address is required");
    }

    let mut token_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let digest = token_hash(&token);

    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "staff invitation transaction failed to start");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be created",
            );
        }
    };

    let lock_key = format!("{}:{}", context.tenant_id, email_normalized);
    if let Err(db_error) = sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&lock_key)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "staff invitation lock failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be created",
        );
    }

    let existing_user: bool =
        match sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email_normalized = $1)")
            .bind(&email_normalized)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(value) => value,
            Err(db_error) => {
                tracing::error!(%db_error, "staff invitation user check failed");
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invitation could not be created",
                );
            }
        };
    if existing_user {
        return error(
            StatusCode::CONFLICT,
            "this email already has an account; account linking is not available yet",
        );
    }

    let pending_invitation: bool = match sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM staff_invitations \
         WHERE tenant_id = $1 AND email_normalized = $2 \
           AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now())",
    )
    .bind(context.tenant_id)
    .bind(&email_normalized)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!(%db_error, "pending invitation lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be created",
            );
        }
    };
    if pending_invitation {
        return error(
            StatusCode::CONFLICT,
            "an active invitation already exists for this email",
        );
    }

    let role_id: uuid::Uuid = match sqlx::query_scalar(
        "SELECT id FROM roles WHERE tenant_id = $1 AND role_key = 'staff' AND is_system = FALSE",
    )
    .bind(context.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return error(
                StatusCode::CONFLICT,
                "the default staff role is not configured for this tenant",
            )
        }
        Err(db_error) => {
            tracing::error!(%db_error, "default staff role lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be created",
            );
        }
    };

    let invitation_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO staff_invitations \
         (tenant_id, email_normalized, role_id, invited_by, token_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5, now() + interval '7 days') RETURNING id",
    )
    .bind(context.tenant_id)
    .bind(&email_normalized)
    .bind(role_id)
    .bind(context.user_id)
    .bind(digest)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "staff invitation insert failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be created",
            );
        }
    };

    if let Err(db_error) = crate::audit::record_event(
        &mut tx,
        &context,
        crate::audit::AuditEventType::StaffInvited,
        crate::audit::AuditEntityType::Invitation,
        Some(invitation_id),
        serde_json::json!({ "email": email_normalized.clone(), "role": "staff" }),
    )
    .await
    {
        tracing::error!(%db_error, "staff invitation audit event failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be created",
        );
    }

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "staff invitation transaction commit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be created",
        );
    }

    Json(CreatedStaffInvitationResponse {
        id: invitation_id.to_string(),
        email: email_normalized,
        token,
        expires_in_days: 7,
        delivery: "manual_secure_delivery_required",
    })
    .into_response()
}

#[derive(Serialize)]
struct StaffInvitationListItem {
    id: String,
    email: String,
    created_at: String,
    expires_at: String,
    accepted_at: Option<String>,
    revoked_at: Option<String>,
    status: &'static str,
}

#[derive(FromRow)]
struct StaffInvitationListRow {
    id: uuid::Uuid,
    email_normalized: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn list_staff_invitations(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "staff invitation list transaction failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitations could not be listed",
            );
        }
    };

    let rows = match sqlx::query_as::<_, StaffInvitationListRow>(
        "SELECT id, email_normalized, created_at, expires_at, accepted_at, revoked_at \
         FROM staff_invitations WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(context.tenant_id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(db_error) => {
            tracing::error!(%db_error, "staff invitation list query failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitations could not be listed",
            );
        }
    };

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "staff invitation list transaction commit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitations could not be listed",
        );
    }

    let now = chrono::Utc::now();
    let invitations = rows
        .into_iter()
        .map(|row| {
            let status = if row.accepted_at.is_some() {
                "accepted"
            } else if row.revoked_at.is_some() {
                "revoked"
            } else if row.expires_at <= now {
                "expired"
            } else {
                "pending"
            };
            StaffInvitationListItem {
                id: row.id.to_string(),
                email: row.email_normalized,
                created_at: row.created_at.to_rfc3339(),
                expires_at: row.expires_at.to_rfc3339(),
                accepted_at: row.accepted_at.map(|value| value.to_rfc3339()),
                revoked_at: row.revoked_at.map(|value| value.to_rfc3339()),
                status,
            }
        })
        .collect::<Vec<_>>();

    Json(serde_json::json!({ "invitations": invitations, "limit": 200 })).into_response()
}

#[derive(FromRow)]
struct InvitationRevocationRow {
    email_normalized: String,
    accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn revoke_staff_invitation(
    State(state): State<AuthState>,
    Extension(context): Extension<AuthContext>,
    axum::extract::Path(invitation_id): axum::extract::Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }

    let mut tx = match begin_tenant_transaction(&state, &context).await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "staff invitation revocation transaction failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be revoked",
            );
        }
    };

    let invitation = match sqlx::query_as::<_, InvitationRevocationRow>(
        "SELECT email_normalized, accepted_at, revoked_at, expires_at \
         FROM staff_invitations WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(invitation_id)
    .bind(context.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(invitation)) => invitation,
        Ok(None) => return error(StatusCode::NOT_FOUND, "invitation was not found"),
        Err(db_error) => {
            tracing::error!(%db_error, "staff invitation revocation lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be revoked",
            );
        }
    };

    if invitation.accepted_at.is_some()
        || invitation.revoked_at.is_some()
        || invitation.expires_at <= chrono::Utc::now()
    {
        return error(
            StatusCode::CONFLICT,
            "only a pending invitation can be revoked",
        );
    }

    if let Err(db_error) = sqlx::query(
        "UPDATE staff_invitations SET revoked_at = now() \
         WHERE id = $1 AND tenant_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(invitation_id)
    .bind(context.tenant_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "staff invitation revocation update failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be revoked",
        );
    }

    if let Err(db_error) = crate::audit::record_event(
        &mut tx,
        &context,
        crate::audit::AuditEventType::StaffInvitationRevoked,
        crate::audit::AuditEntityType::Invitation,
        Some(invitation_id),
        serde_json::json!({ "email": invitation.email_normalized }),
    )
    .await
    {
        tracing::error!(%db_error, "staff invitation revocation audit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be revoked",
        );
    }

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "staff invitation revocation commit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be revoked",
        );
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Accept an invitation for a new account. Existing-account linking and email
/// delivery are intentionally separate follow-up work, not implicit here.
pub async fn accept_staff_invitation(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Json(request): Json<AcceptStaffInvitationRequest>,
) -> Response {
    if !origin_is_allowed(&headers, &state) {
        return error(StatusCode::FORBIDDEN, "request origin is not allowed");
    }

    let token = request.token.trim();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return error(StatusCode::BAD_REQUEST, "invitation token is invalid");
    }
    if request.password.len() < 12
        || request.password.len() > 1024
        || request.display_name.trim().is_empty()
        || request.display_name.len() > 120
    {
        return error(
            StatusCode::BAD_REQUEST,
            "a 12-character password and valid display name are required",
        );
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "invitation acceptance transaction failed to start");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be accepted",
            );
        }
    };

    let digest = token_hash(token);
    if let Err(db_error) = sqlx::query("SELECT set_config('app.invitation_token_hash', $1, true)")
        .bind(&digest)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "invitation token context could not be set");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    let invitation = match sqlx::query_as::<_, StaffInvitationRow>(
        "SELECT id, tenant_id, email_normalized, role_id FROM staff_invitations \
         WHERE token_hash = $1 AND expires_at > now() \
           AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE",
    )
    .bind(&digest)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(invitation)) => invitation,
        Ok(None) => {
            return error(
                StatusCode::GONE,
                "invitation is invalid, expired or already used",
            )
        }
        Err(db_error) => {
            tracing::error!(%db_error, "invitation token lookup failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be accepted",
            );
        }
    };

    // Do expensive password hashing only after the bearer token has been validated.
    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(hash_error) => {
            tracing::error!(%hash_error, "invited user password hashing failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be accepted",
            );
        }
    };

    if let Err(db_error) = sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(invitation.tenant_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "invitation tenant context could not be set");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    let existing_user: bool =
        match sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email_normalized = $1)")
            .bind(&invitation.email_normalized)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(value) => value,
            Err(db_error) => {
                tracing::error!(%db_error, "invitation account check failed");
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invitation could not be accepted",
                );
            }
        };
    if existing_user {
        return error(
            StatusCode::CONFLICT,
            "an account already exists for this email; sign-in invitation linking is not available yet",
        );
    }

    let user_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO users (email, email_normalized, password_hash, display_name) \
         VALUES ($1, $1, $2, $3) RETURNING id",
    )
    .bind(&invitation.email_normalized)
    .bind(password_hash)
    .bind(request.display_name.trim())
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "invited user account creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be accepted",
            );
        }
    };

    let membership_id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO tenant_memberships (tenant_id, user_id, status) \
         VALUES ($1, $2, 'active') RETURNING id",
    )
    .bind(invitation.tenant_id)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(db_error) => {
            tracing::error!(%db_error, "invited user membership creation failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation could not be accepted",
            );
        }
    };

    if let Err(db_error) = sqlx::query(
        "INSERT INTO membership_roles (tenant_id, membership_id, role_id) VALUES ($1, $2, $3)",
    )
    .bind(invitation.tenant_id)
    .bind(membership_id)
    .bind(invitation.role_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "invited user role assignment failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    if let Err(db_error) = sqlx::query(
        "UPDATE staff_invitations SET accepted_at = now(), membership_id = $2 WHERE id = $1",
    )
    .bind(invitation.id)
    .bind(membership_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "invitation could not be marked accepted");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    if let Err(db_error) = sqlx::query("SELECT set_config('app.user_id', $1, true)")
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "invited user context could not be set");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    let audit_context = AuthContext {
        user_id,
        tenant_id: invitation.tenant_id,
        membership_id,
    };
    if let Err(db_error) = crate::audit::record_event(
        &mut tx,
        &audit_context,
        crate::audit::AuditEventType::StaffInvitationAccepted,
        crate::audit::AuditEntityType::Membership,
        Some(membership_id),
        serde_json::json!({ "invitation_id": invitation.id }),
    )
    .await
    {
        tracing::error!(%db_error, "invitation acceptance audit event failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    let mut session_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut session_bytes);
    let session_token = hex::encode(session_bytes);
    if let Err(db_error) = sqlx::query(
        "INSERT INTO user_sessions (user_id, token_hash, expires_at) \
         VALUES ($1, $2, now() + ($3 * interval '1 second'))",
    )
    .bind(user_id)
    .bind(token_hash(&session_token))
    .bind(SESSION_SECONDS as f64)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "invited user session creation failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "invitation acceptance commit failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invitation could not be accepted",
        );
    }

    let mut response = Json(UserResponse {
        id: user_id.to_string(),
        email: invitation.email_normalized,
        display_name: request.display_name.trim().to_string(),
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&session_token, state.cookie_secure, SESSION_SECONDS),
    );
    response
}
