# Product specification

**Product:** TomOS POS  
**Version:** 0.1 baseline  
**Deployment:** Self-hosted  
**Product model:** Single-business and multi-business installations

## Goals

Provide one configurable platform for point of sale and business operations across retail, hospitality, repairs and service businesses. The platform carries TomOS branding by default and allows each business to apply its own branding.

## User roles

- Platform operator: manages installation health and tenant provisioning; no automatic access to tenant business data.
- Business owner: full access to their business.
- Business administrator: business configuration and user administration.
- Manager: operational and reporting permissions.
- Supervisor: approved overrides and till controls.
- Cashier: checkout, permitted refunds and till operations.
- Accountant: read/export financial and tax records.
- Custom roles: granular permission sets.

## Functional modules

### 1. Point of sale
Product and service search, barcode input, categories, basket, quantity changes, discounts, customer assignment, tax calculation, held sales, split tender, receipts, exchanges, refunds, till sessions, cash movements and end-of-day reconciliation.

### 2. Catalogue
Products, services, SKUs, barcodes, categories, variants, bundles, cost and selling prices, tax categories, images, serial/IMEI tracking and effective-dated price lists.

### 3. Inventory and purchasing
Per-location stock, stock movements, counts, adjustments, transfers, reorder levels, suppliers, purchase orders, goods received, supplier invoices and valuation methods.

### 4. Payments
Cash, card terminal, bank transfer and payment links. A provider adapter interface isolates provider-specific APIs. Payment states include initiated, pending, authorised, captured, failed, cancelled, refunded and partially refunded. Do not store PAN or CVV. Webhook events require signature validation and idempotent processing.

### 5. Customers and loyalty
Customer profiles, contact preferences, order history, addresses, consent records, loyalty balances and account notes with access controls.

### 6. Staff and tills
Invitations, role assignments, shifts, clock-in/out, till sessions, opening float, paid-in/out, cash-up and manager approvals.

### 7. Business operations
Multiple locations, business settings, branded receipts/invoices, bookings, repair jobs, service records and optional industry-specific workflows.

### 8. Accounting and tax
Chart of accounts, balanced journal entries, sales and purchase records, expenses, VAT records, credit notes, tax periods, reconciliation and export. UK tax rules must be configurable and effective-dated. VAT and Making Tax Digital for Income Tax are separate scopes.

### 9. Reporting
Sales by date, location, product, category, staff and tender; gross margin; inventory valuation; refunds; cash reconciliation; expenses; profit and loss; VAT summaries; tax-year reports; PDF/CSV exports and saved report filters.

### 10. Branding and platform administration
TomOS default identity, per-business logo, colours, typography, receipt templates, business details, theme selection, tenant provisioning and installation health.

### 11. Offline operation
Installable PWA, cached authorised catalogue, local basket, queued cash sales, durable sync acknowledgements, retry handling, conflict reporting and device revocation. Offline card acceptance is allowed only where the selected provider and terminal explicitly support it.

### 12. Integrations and API
Versioned REST API, OpenAPI specification, signed webhooks, payment adapters, HMRC adapter, accounting exports and hardware adapters.

## Non-functional requirements

- Strong tenant isolation and least-privilege access.
- Accessible, responsive UI for desktop, tablet and mobile.
- Audit trail for security-sensitive and financial actions.
- Idempotent financial commands and webhook processing.
- Database migrations and tested backup/restore.
- Observable services with structured logs and health endpoints.
- GDPR-oriented data minimisation, retention and export/deletion workflows.
- No production compliance claims until independent validation is complete.

## Acceptance principles

A feature is complete only when its acceptance criteria, automated tests, failure handling, documentation and security review pass. A successful compile alone is not completion.
