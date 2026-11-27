# Authentication API

Base path: `/api/v1/auth`

## Initial installation setup

`POST /setup` creates the first installation owner, tenant, legal business, main location and owner role. It is guarded by a transaction-scoped PostgreSQL advisory lock and refuses to run once any user exists. The first owner receives an authenticated session.

Example request:

```json
{
  "email": "owner@example.test",
  "password": "use-a-long-unique-password",
  "display_name": "Business Owner",
  "tenant_name": "Example Group",
  "tenant_slug": "example-group",
  "legal_business_name": "Example Trading Ltd"
}
```

Password length is currently limited to 12–1024 characters. Tenant slugs are lowercase letters, digits and hyphens, 3–48 characters. This is an initial-installation bootstrap, not an open registration endpoint.

## Login

`POST /login` accepts `email` and `password`. Password hashes use Argon2id. On success, the API creates a cryptographically random opaque session token, stores only its SHA-256 digest, and sends the token in an HttpOnly, SameSite=Lax cookie. The session expires after 12 hours.

## Current user

`GET /me` validates the cookie against the session table and returns the current user's public profile. Expired, revoked or inactive-user sessions are rejected.

## Logout

`POST /logout` revokes the current server-side session and expires the browser cookie.

## Cookie configuration

Set `COOKIE_SECURE=true` whenever the application is served over HTTPS. The sample development environment sets it to false for localhost HTTP only. Production deployments must use HTTPS and Secure cookies.

## Current limitations — not production ready

- Login rate limiting and account lockout are not implemented yet.
- CSRF/origin validation for cookie-authenticated state-changing routes is outstanding.
- MFA, password reset, email verification and session/device management are outstanding.
- Authentication is not yet connected to tenant-scoped authorisation middleware.
- Business registration/invitations after first-run setup are not implemented.
- The API currently has no web frontend.

Do not expose this API to the public internet or use it for live business data until the outstanding security controls and integration tests are complete.
