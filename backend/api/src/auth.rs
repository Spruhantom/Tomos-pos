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
