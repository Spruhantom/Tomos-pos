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

## Browser request protection

State-changing authentication requests (`POST /setup`, `/login` and `/logout`) must include an `Origin` header that exactly matches the configured `APP_ORIGIN`. Requests with missing or mismatched origins are rejected. Set `APP_ORIGIN` to the public web application's origin (scheme and host, with a port only when non-default). This is an additional CSRF defence alongside `SameSite=Lax`; it is not a replacement for a complete CSRF strategy for future API routes.

Login attempts are rate-limited per normalized email identity: the tenth attempt within a 15-minute window blocks further attempts for 15 minutes. The limiter stores a SHA-256 digest of the normalized email rather than the address itself.

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


## Tenant selection and authorisation

`GET /api/v1/tenant/context` requires the session cookie and an `X-Tenant-ID` header. The API validates that the session belongs to an active user and that the user has an active membership in the requested tenant. The tenant identifier is only a selector; it never grants access by itself.

The tenant middleware places a server-validated `AuthContext` into the request. Business handlers must use `begin_tenant_transaction` with that context so both `app.user_id` and `app.tenant_id` are set transaction-locally before querying RLS-protected tables. Do not use a plain pool query for tenant-owned records.

The reusable permission middleware checks the permission key against the authenticated membership's assigned roles. Apply it to each protected route with the exact permission required (for example `business.manage` or `reports.read`). No business-management routes are exposed yet; the middleware is the foundation for those routes. Route setup must put the tenant middleware outside the permission middleware so the latter receives the validated `AuthContext`. The permission key should be fixed in server route configuration, never supplied by the client.
