# Architecture overview

## Architectural style

Start with a modular monolith. Keep domain modules and Rust crate boundaries explicit, but deploy one API initially. Extract services only when scale, isolation or operational requirements justify it.

## Logical components

1. **Web/POS client** — responsive management UI and installable PWA.
2. **API** — authentication, tenant context, authorisation, validation and orchestration.
3. **Domain modules** — businesses, catalogue, sales, payments, inventory, customers, suppliers, staff, accounting, tax, reporting and audit.
4. **Persistence** — PostgreSQL with SQLx migrations and tenant-scoped access.
5. **Offline subsystem** — IndexedDB outbox, device identity, idempotency keys and sync cursors.
6. **Adapters** — payment providers, HMRC APIs, accounting exports, receipt printers and barcode hardware.
7. **Operations** — Docker Compose, reverse proxy, backups, monitoring and restore procedures.

## Tenancy and authorisation

- Every tenant-owned row carries a non-null `tenant_id`.
- Resolve tenant membership from the authenticated session and server-side membership records.
- Never trust a tenant identifier supplied only by the client.
- Enforce tenant scope in repository methods and PostgreSQL row-level security where appropriate.
- Platform operators have no implicit right to inspect tenant financial or customer data.
- Test cross-tenant access attempts for every tenant-scoped API family.

## Financial correctness

- Store monetary amounts as integer minor units with an explicit ISO 4217 currency code.
- Use decimal arithmetic for rates and intermediate tax calculations; define and test rounding policy.
- Persist tax category, rate, jurisdiction and calculation snapshot on each transaction line.
- Keep sales, tenders, refunds, cash movements and ledger postings separately traceable.
- Completed sales are immutable. Corrections use compensating records.
- Introduce balanced journal entries and reconciliation invariants before production accounting reports.

## Offline model

- Cache only the minimum catalogue, pricing and configuration required by an authorised device.
- Store pending transactions in an encrypted local outbox where browser platform capabilities permit.
- Give each offline transaction a globally unique ID and idempotency key.
- Server synchronisation must be idempotent and return a durable acknowledgement.
- Define conflict policies per domain; never use last-write-wins for financial transactions or stock movements.
- Clearly distinguish locally queued, server accepted, payment pending and payment confirmed states.
- Cash may be accepted offline. Card acceptance offline depends on the terminal/provider's approved offline mode and risk controls; never assume a card payment succeeded because the POS is offline.

## Deployment

Self-hosted Docker Compose is the initial deployment target. Production deployments require TLS, secure secrets, persistent database volumes, encrypted off-host backups, monitoring, upgrade/rollback documentation and tested restores.

## Integration boundaries

External payment and tax integrations are adapters behind internal interfaces. Provider credentials are stored as secrets. Webhooks are authenticated, idempotent and auditable. Cardholder data is not stored by TomOS POS.
