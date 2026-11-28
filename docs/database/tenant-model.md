# Database and tenant model

## Identity model

A user is a platform-wide login identity. Access to a business tenant is granted through an active `tenant_memberships` row. This supports a person working with more than one independent business without duplicating their login identity.

A tenant represents an isolated customer/business account boundary. A tenant may contain one or more legal businesses and multiple trading locations. Each business belongs to exactly one tenant.

## Initial schema

- `tenants`: tenant lifecycle and unique URL-safe slug.
- `businesses`: legal/trading identity, country, currency and timezone.
- `business_locations`: tenant-owned operating locations.
- `users`: login identity and password hash.
- `tenant_memberships`: explicit user-to-tenant access and lifecycle.
- `roles`, `permissions`, `role_permissions`, `membership_roles`: tenant role-based access model.
- `user_sessions`: hashed opaque session token, expiry and revocation.
- `audit_events`: append-oriented business activity history.

## Tenant context and row-level security

The first migration enables PostgreSQL row-level security on businesses, locations, memberships and audit events. A request handler must authenticate the user, resolve an active membership, then set the tenant context inside the same database transaction:

```sql
SELECT set_config('app.tenant_id', $1, true);
```

The third argument makes the setting transaction-local. Do not set tenant context on a pooled connection outside a transaction; that can leak context to another request when the connection is reused.

All tenant-scoped queries must also include tenant predicates and validate parent-child relationships. RLS is defence in depth, not a replacement for application authorisation. The application database role must not be a superuser and must not have BYPASSRLS. Migration privileges should be separated from runtime privileges for production.

## Authentication implementation status

The initial migration defines password-hash and session storage only. Public registration, password hashing/verification, session issuance/revocation, MFA and tenant provisioning endpoints are not yet implemented. Do not expose the API as an authenticated production service until these controls and tests exist.

## Migration and test workflow

Migrations live in `database/migrations` and are embedded into the API binary through SQLx. The integration test applies migrations to a PostgreSQL 16 service and checks required tables and RLS metadata.

Migrations are forward-only once applied to shared environments. Use a new migration to evolve schema; do not edit an already-released migration.
