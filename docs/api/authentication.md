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

- Staff account administration and role-assignment endpoints are not implemented yet.
- CSRF/origin validation currently covers authentication state changes; all future cookie-authenticated mutation routes must apply the same origin validation or a stronger CSRF token strategy.
- MFA, password reset, email verification and session/device management are outstanding.
- Tenant-scoped authorisation middleware is implemented for the tenant context endpoint; all future business routes still need explicit permission middleware and tenant-scoped transactions.
- Business registration and staff invitations after first-run setup are not implemented.
- The API currently has no web frontend.

Do not expose this API to the public internet or use it for live business data until the outstanding security controls and integration tests are complete.


## Tenant selection and authorisation

`GET /api/v1/tenant/context` requires the session cookie and an `X-Tenant-ID` header. The API validates that the session belongs to an active user, that the user has an active membership in the requested tenant, and that the membership has the `business.read` permission. The tenant identifier is only a selector; it never grants access by itself.

The tenant middleware places a server-validated `AuthContext` into the request. Business handlers must use `begin_tenant_transaction` with that context so both `app.user_id` and `app.tenant_id` are set transaction-locally before querying RLS-protected tables. Do not use a plain pool query for tenant-owned records.

The reusable permission middleware checks the permission key against the authenticated membership's assigned roles. Apply it to each protected route with the exact permission required (for example `business.manage` or `reports.read`). No business-management routes are exposed yet; the middleware is the foundation for those routes. Route setup must put the tenant middleware outside the permission middleware so the latter receives the validated `AuthContext`. The permission key should be fixed in server route configuration, never supplied by the client.


## Audit event service

The append-only audit ledger is protected by database triggers that reject row updates, row deletes and table truncation. The API's `audit::record_event` helper accepts only server-defined event and entity enums and writes using the caller's tenant-scoped transaction. Business handlers should call it before committing the transaction so the business change and its audit record succeed or fail together. Event payloads must contain only necessary business metadata; never include passwords, session tokens, payment-card data or other secrets.


## Staff invitations

POST /api/v1/staff/invitations requires an authenticated tenant session and the roles.manage permission. It creates a seven-day, single-use invitation for the tenant's built-in least-privileged Staff role. The raw 256-bit bearer token is returned once because email delivery is not integrated yet; the caller must deliver it to the invited address through a secure channel. Only the token digest is stored. Do not log or persist the raw token in browser analytics or support logs.

POST /api/v1/staff/invitations/accept accepts a valid invitation for a new account, requires the exact configured Origin, a password of at least 12 characters and a display name, creates the account and active membership, assigns only the preselected Staff role, records an audit event and creates a session in one transaction. Expired, revoked, invalid and previously used tokens are rejected. Existing-account invitation linking is not implemented and returns a conflict.

The Staff role created during initial setup currently grants only business.read. Role administration, invitation listing/revocation, email delivery, email verification and existing-account linking remain outstanding. Treat invitation tokens like passwords: anyone holding one can claim the invitation.
