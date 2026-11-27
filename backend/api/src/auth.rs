use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
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

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}

fn verify_password(password: &str, encoded_hash: &str) -> bool {
    PasswordHash::new(encoded_hash)
        .ok()
        .is_some_and(|hash| Argon2::default().verify_password(password.as_bytes(), &hash).is_ok())
}

pub async fn login(
    State(state): State<AuthState>,
    Json(request): Json<LoginRequest>,
) -> Response {
    if request.email.len() > 320 || request.password.len() > 1024 {
        return error(StatusCode::BAD_REQUEST, "invalid credentials");
    }

    let email_normalized = request.email.trim().to_lowercase();
    let user = match sqlx::query_as::<_, LoginRow>(
        "SELECT id, email, display_name, password_hash, is_active \
         FROM users WHERE email_normalized = $1",
    )
    .bind(email_normalized)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "email or password is incorrect"),
        Err(db_error) => {
            tracing::error!(%db_error, "login lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "login could not be completed");
        }
    };

    if !user.is_active || !verify_password(&request.password, &user.password_hash) {
        return error(StatusCode::UNAUTHORIZED, "email or password is incorrect");
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
        return error(StatusCode::INTERNAL_SERVER_ERROR, "login could not be completed");
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

pub async fn logout(
    State(state): State<AuthState>,
    headers: HeaderMap,
) -> Response {
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
            return error(StatusCode::INTERNAL_SERVER_ERROR, "logout could not be completed");
        }
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie("", state.cookie_secure, 0),
    );
    response
}

pub async fn me(
    State(state): State<AuthState>,
    headers: HeaderMap,
) -> Response {
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
            return error(StatusCode::INTERNAL_SERVER_ERROR, "session could not be checked");
        }
    };

    Json(UserResponse {
        id: user.id.to_string(),
        email: user.email,
        display_name: user.display_name,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::{hash_password, verify_password};

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
    Json(request): Json<InitialSetupRequest>,
) -> Response {
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
        return error(StatusCode::BAD_REQUEST, "setup details are invalid; use a 12-character password and a valid tenant slug");
    }

    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(hash_error) => {
            tracing::error!(%hash_error, "initial password hashing failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
        }
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(db_error) => {
            tracing::error!(%db_error, "initial setup transaction could not start");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
        }
    };

    // Serialise concurrent setup requests. Only the first installation owner can be created.
    if let Err(db_error) = sqlx::query("SELECT pg_advisory_xact_lock(741203)")
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "initial setup lock failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
    }

    let existing_users: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await
    {
        Ok(count) => count,
        Err(db_error) => {
            tracing::error!(%db_error, "initial setup user check failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
        }
    };

    if existing_users > 0 {
        return error(StatusCode::CONFLICT, "initial setup has already been completed");
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
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
        }
    };

    if let Err(db_error) = sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::error!(%db_error, "initial tenant context could not be established");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
            return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
        }
    };

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
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
    }

    if let Err(db_error) = sqlx::query(
        "INSERT INTO audit_events (tenant_id, actor_user_id, event_type, entity_type, entity_id) \
         VALUES ($1, $2, 'installation.initialised', 'tenant', $1)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(%db_error, "initial setup audit event could not be recorded");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
    }

    if let Err(db_error) = tx.commit().await {
        tracing::error!(%db_error, "initial setup transaction commit failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "initial setup could not be completed");
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
