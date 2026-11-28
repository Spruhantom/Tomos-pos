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

- Staff invitation creation, listing and revocation are implemented. Tenant-scoped staff membership listing/removal and audited role assignment/removal are also available; membership reactivation remains outstanding.
- CSRF/origin validation currently covers authentication state changes; all future cookie-authenticated mutation routes must apply the same origin validation or a stronger CSRF token strategy.
- MFA, password reset, email verification and session/device management are outstanding.
- Tenant-scoped authorisation middleware is implemented for the tenant context and staff invitation endpoints; every future business route still needs explicit permission middleware and tenant-scoped transactions.
- Ongoing business registration and tenant provisioning are not implemented; staff invitations are available after first-run setup.
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

The Staff role created during initial setup currently grants only business.read. `GET /api/v1/staff/invitations` lists up to 200 newest invitations for the selected tenant and returns their status (`pending`, `expired`, `accepted` or `revoked`) without exposing token digests. `DELETE /api/v1/staff/invitations/{invitation_id}` revokes a pending invitation; accepted, expired or already-revoked invitations cannot be revoked. Both endpoints require `roles.manage`; revocation also requires the exact configured `Origin` and is recorded in the append-only audit ledger. Email delivery, email verification and existing-account linking remain outstanding. Treat invitation tokens like passwords: anyone holding one can claim the invitation.


## Staff membership management

`GET /api/v1/staff/memberships` requires the `staff.read` permission and returns up to 200 memberships for the selected tenant, including the account's public email/display name, membership status and assigned role keys. It does not expose password hashes, session data or other tenants' memberships.

`DELETE /api/v1/staff/memberships/{membership_id}` requires `staff.manage` and the exact configured `Origin`. It changes only the selected tenant membership to `removed`; it does not disable the user's global account or revoke sessions for other tenants. The acting user cannot remove their own membership, and owner memberships are protected from this endpoint. The change and the `staff.deactivated` audit event are committed in one transaction. Removed memberships cannot currently be reactivated through the API.


## Staff roles and assignments

`GET /api/v1/staff/roles` requires `roles.manage` and lists the selected tenant's roles with their permission keys. The built-in Owner role is marked non-assignable and cannot be granted through the staff API.

`POST /api/v1/staff/memberships/{membership_id}/roles` accepts a JSON `role_id` and assigns an existing role from the selected tenant. `DELETE /api/v1/staff/memberships/{membership_id}/roles/{role_id}` removes an existing assignment. Both operations require `roles.manage`, the exact configured `Origin`, an active non-owner target membership and an assignment to another member (self-role changes are rejected). A member's final role cannot be removed. Successful changes write a `staff.role_changed` audit event in the same transaction.

These endpoints assign existing roles only. Custom roles are managed separately:

- `GET /api/v1/staff/permissions` returns the server-owned permission catalogue and descriptions.
- `POST /api/v1/staff/roles` creates a tenant-scoped custom role using a lowercase kebab-case `role_key`, a display name and a list of permission keys from that catalogue.
- `PUT /api/v1/staff/roles/{role_id}/permissions` replaces the permission set for a custom role. An empty list creates a role with no permissions.

All three routes require `roles.manage`, tenant authentication and the exact configured `Origin` for mutations. Unknown or duplicate permission keys are rejected. The API does not accept arbitrary permission definitions. The built-in Owner and Staff roles cannot be created or edited through these endpoints. Role creation and permission replacement are transactionally audited in the append-only ledger. Custom role keys are unique within each tenant.
