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
- [ ] Email delivery, existing-account invitation linking, invitation listing/revocation and full staff lifecycle management.
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

## M3 — Web shell and branding
- Next.js/TypeScript application.
- Login and business selection.
- Responsive admin shell and POS shell.
- TomOS default theme and tenant branding configuration.

## M4 — Catalogue and inventory
- Products, services, categories, variants and barcodes.
- Stock locations and immutable stock movements.
- Suppliers, purchase orders and goods receiving.

## M5 — Sales and till operations
- Basket and checkout workflow.
- Tax calculation snapshots.
- Till sessions, cash movements and receipts.
- Refunds, reversals and held sales.

## M6 — Payment adapters
- Cash and bank transfer states.
- [x] SumUp Solo Cloud API bridge foundation and API webhook receiver with per-attempt callback tokens, tenant-scoped persistence, merchant/reference matching and idempotent final-state transitions.
- [x] Basic tenant-scoped sale amount records, authenticated Solo checkout initiation and sale-status lookup routes.
- [x] Successful webhook atomically settles unpaid sale and records payment audit event.
- [x] Ambiguous network/5xx checkout outcomes remain pending for reconciliation; definitive 4xx provider rejections are marked failed.
- [ ] Full basket/tax/receipt integration and provider reconciliation.
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
