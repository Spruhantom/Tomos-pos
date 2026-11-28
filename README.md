# TomOS POS

TomOS POS is a self-hosted, multi-business point-of-sale and business-management platform for retail, hospitality, repair and service businesses. It includes configurable TomOS branding, offline-capable checkout, inventory, reporting and UK accounting support.

## Project status

**Stage:** Early development / pre-alpha  
**Current milestone:** M2 — persistence, identity and tenancy  
**Default branch:** `main`  
**Integration branch:** `develop`

This repository is the canonical home of the project. See [docs/](docs/) for the architecture, product specification and roadmap.

## Product principles

- Multi-tenant isolation from the first database migration.
- Financial records are auditable; completed sales are corrected with reversals, refunds or adjustment records, never silent edits.
- Money is represented in integer minor units (pence for GBP), never floating-point values.
- Offline checkout uses unique transaction identifiers and idempotent synchronisation.
- Payment credentials and card data are handled by certified payment providers, not stored by this application.
- Tax rules are effective-dated and jurisdiction-aware.
- Self-hosted deployment is a first-class supported model.

## Planned architecture

- Web application: React, TypeScript and Next.js.
- API: Rust and Axum.
- Database: PostgreSQL, accessed through SQLx.
- Offline client: PWA, service worker and IndexedDB.
- Deployment: Docker Compose with a reverse proxy such as Caddy.

## Development

Requirements:

- Rust stable toolchain and Cargo
- Docker Engine and Docker Compose plugin

Copy `.env.example` to `.env`, then start the development database:

```sh
docker compose up -d db
```

Run the API from the repository root:

```sh
cargo run -p tomos-pos-api
```

The API exposes `GET /health/live`, database-backed `GET /health/ready`, and initial setup/login/logout/current-user routes under `/api/v1/auth`. See [authentication API](docs/api/authentication.md). Authentication and tenant authorization still need additional security controls before production use.

## Documentation

- [Architecture](docs/architecture/overview.md)
- [Product specification](docs/product/specification.md)
- [Development roadmap](docs/development/roadmap.md)
- [Security and data principles](docs/security/requirements.md)
- [Authentication API](docs/api/authentication.md)
- [Initial sales and SumUp payment API](docs/api/sales.md)
- [SumUp integration guide](docs/integrations/sumup.md)
- [Database and tenant model](docs/database/tenant-model.md)

## Important

This is an early development project. VAT reports, MTD submissions, payment processing, offline payment acceptance and production security are not yet implemented or certified. Do not use this foundation to process live payments or submit tax returns.
