# Development roadmap

## M1 — Repository and development foundation
- [x] Monorepo conventions and documentation.
- [x] Rust workspace and Axum API bootstrap.
- [x] Local PostgreSQL Compose service.
- [x] CI for formatting, linting and tests.
- [x] Environment and secret-handling conventions.

## M2 — Persistence, identity and tenancy
- [x] SQLx PostgreSQL connection pool and migration runner.
- [x] Tenant, business, location, user and membership schema.
- [x] Initial roles and permissions schema.
- [x] Session storage schema.
- [x] Tenant row-level security policies for core tenant-owned tables.
- [x] PostgreSQL-backed readiness endpoint.
- [x] CI PostgreSQL service and migration smoke test.
- [x] Integration test proving tenant RLS isolation with a non-owner runtime role.
- [x] Initial installation tenant provisioning and owner assignment.
- [ ] Ongoing tenant provisioning service and owner invitations.
- [x] Single-use, seven-day staff invitations for new accounts, with tenant-scoped storage and token hashing.
- [x] Invitation acceptance creates an active membership, assigns the fixed least-privileged Staff role, creates a session and records an audit event transactionally.
- [x] Tenant-scoped invitation listing (newest 200, with pending/expired/accepted/revoked status) and audited revocation of pending invitations.
- [x] Tenant-scoped staff membership listing with public account details, statuses and role keys.
- [x] Audited staff membership removal scoped to one tenant; protect owner and self memberships.
- [x] Tenant-scoped role catalogue with permission keys and owner-role assignment protection.
- [x] Audited role assignment/removal for other active non-owner memberships; prevent self-role changes and removal of a member's final role.
- [x] Tenant-scoped custom role creation using a fixed permission catalogue; reject reserved Owner/Staff keys and unknown permissions.
- [x] Audited custom-role permission replacement; protect built-in Owner and Staff role definitions.
- [ ] Email delivery, existing-account invitation linking and membership reactivation.
- [x] Argon2id password hashing and verification.
- [x] One-time first-run owner, tenant and business provisioning.
- [x] Login, logout and current-user session endpoints with hashed opaque session tokens.
- [x] Per-account login throttling with persistent PostgreSQL counters.
- [x] Exact-origin checks for state-changing authentication requests.
- [ ] MFA and broader CSRF protections for future state-changing API routes.
- [x] Tenant membership validation middleware and tenant-context endpoint.
- [x] Reusable role/permission enforcement middleware (route adoption remains pending).
- [x] Transaction helper sets authenticated user and tenant context for RLS-protected queries.
- [ ] Apply tenant transactions to all business endpoints and add full cross-tenant endpoint tests.
- [x] Database-enforced append-only audit ledger (UPDATE, DELETE and TRUNCATE rejected; integration tests).
- [x] Typed transactional audit-writing service with server-defined event/entity vocabulary.
- [x] Initial business creation records its audit event in the provisioning transaction.
- [ ] Add audit event coverage to each subsequent business mutation as those routes are implemented.

## M2 — Business settings and locations
- [x] Tenant-scoped business listing and legal/trading settings update.
- [x] Tenant-scoped location listing, creation, update and deactivation.
- [x] Permission enforcement, exact-Origin mutation checks and transactional audit events.
- [x] Additional business creation within an existing tenant, with transactional audit event.
- [ ] Country-specific address validation, timezone database validation, new-tenant provisioning and owner invitations.

## M3 — Web shell and branding
- [x] Next.js/TypeScript management application foundation.
- [x] Login and authenticated tenant discovery/business selection.
- [x] Responsive management shell and TomOS dark theme.
- [x] Business settings, location management, staff invitations and membership removal screens.
- [x] Custom role creation and permission selection screen.
- [ ] End-to-end browser tests and accessibility review.
- [ ] POS checkout shell and tenant branding configuration.
- [ ] Installable PWA, service worker and offline application shell.

## M4 — Catalogue and inventory
- [x] Tenant-scoped product catalogue schema with SKU/barcode uniqueness and tax-rate metadata.
- [x] Product create/list API with name, SKU and barcode search, tenant permissions and audit events.
- [x] Product catalogue row-level security integration coverage.
- [ ] Product update/archive workflow.
- Products, services, categories, variants and barcodes.
- Stock locations and immutable stock movements.
- Suppliers, purchase orders and goods receiving.

## M5 — Sales and till operations
- [x] Server-calculated itemised basket API with immutable product, price and VAT snapshots.
- [x] VAT-inclusive line calculations using integer minor units and half-up tax rounding.
- [ ] Basket editing/held sales and checkout UI.
- [ ] Jurisdiction-specific tax rules and inclusive/exclusive pricing.
- Till sessions, cash movements and receipts.
- Refunds, reversals and held sales.

## M6 — Payment adapters
- Cash and bank transfer states.
- [x] SumUp Solo Cloud API bridge foundation and API webhook receiver with per-attempt callback tokens, tenant-scoped persistence, merchant/reference matching and idempotent final-state transitions.
- [x] Basic tenant-scoped sale amount records, authenticated Solo checkout initiation and sale-status lookup routes.
- [x] Successful webhook atomically settles unpaid sale and records payment audit event.
- [x] Ambiguous network/5xx checkout outcomes remain pending for reconciliation; definitive 4xx provider rejections are marked failed.
- [ ] Full basket-to-SumUp integration, receipts and provider reconciliation.
- Sandbox integration for selected card/payment-link providers.
- Signed webhook processing, idempotency and reconciliation.
- Provider and terminal capability matrix.

## M7 — Offline checkout
- PWA service worker and IndexedDB.
- Device identity and encrypted local outbox.
- Idempotent sync API and acknowledgements.
- Offline cash sale and reconnect/retry tests.
- Provider-approved terminal offline flow only, if supported.

## M8 — Reporting and accounting foundation
- Balanced journal entries and chart of accounts.
- Sales, cash, stock and expense reports.
- Reconciliation and accountant exports.

## M9 — UK tax
- Effective-dated UK VAT configuration and tested calculation fixtures.
- VAT record keeping and draft return calculations.
- HMRC sandbox authorisation and API integration.
- Separate MTD Income Tax assessment and scope.

## M10 — Industry modules
- Hospitality tables/orders and service charges.
- Repair jobs and serial/IMEI workflows.
- Appointment and booking management.
- Gift cards and loyalty.

## M11 — Production readiness
- Security assessment and dependency scanning.
- Load, resilience and backup/restore testing.
- Deployment guides, monitoring and upgrade/rollback process.
- Accessibility and usability review.

## M12 — Release
- Release candidate and acceptance testing.
- Document known limitations.
- Versioned release artifacts and upgrade notes.
- Production readiness approval.

## Delivery rule

Do not mark a milestone complete until code, tests, documentation and acceptance checks are present. A successful compile alone is not completion. Do not enable live payment processing or HMRC submissions before the relevant provider and compliance testing is complete.
