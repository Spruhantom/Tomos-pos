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
- [ ] Tenant provisioning service and owner invitation.
- [ ] Password hashing and secure login/session lifecycle.
- [ ] Role/permission enforcement middleware.
- [ ] Transaction-scoped tenant context and cross-tenant isolation tests.
- [ ] Append-only audit service and tests.

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
