# POS checkout and payment API

This is an early, tenant-scoped checkout foundation. All monetary amounts are integer minor units (pence for GBP). Product selling prices are treated as VAT-inclusive; each sale line snapshots its product name, SKU, unit price and tax rate so later catalogue edits cannot rewrite historical sale values.

## Catalogue

- `GET /api/v1/pos/catalogue?business_id={uuid}` — active products for the selected business; requires `pos.catalog.read`.
- `POST /api/v1/pos/products` — create a product; requires `pos.catalog.manage`.

Product fields include SKU, optional barcode, name, selling price in minor units, currency and tax rate in basis points. SKU and barcode uniqueness is scoped to the business.

## Till operations

- `GET /api/v1/pos/tills/current?location_id={uuid}` — current open till at a location.
- `POST /api/v1/pos/tills/open` — open one till per location with a counted opening float.
- `POST /api/v1/pos/tills/{till_id}/cash-movements` — record paid-in or paid-out cash with a reason.
- `POST /api/v1/pos/tills/{till_id}/close` — close the till and return expected cash, counted cash and variance.

Till operations require `pos.till.manage`. Cash expectations include the opening float, completed cash sales and recorded cash movements.

## Checkout

`POST /api/v1/pos/sales` accepts a business, location, open till, product/quantity basket, payment method and a client-generated UUID `idempotency_key`. Reusing the same key returns the original sale/tender rather than creating a second sale; the key is serialized with a transaction advisory lock and protected by a tenant-scoped unique constraint.

Cash requires `cash_received_minor` to cover the total. The API atomically creates the sale, line snapshots, captured cash tender and audit event, then returns the change due. The transaction cannot be partially committed.

Card terminal checkout creates an `awaiting_payment` sale and a `pending` card-terminal tender. It does not mark the sale paid, and the UI instructs staff not to release goods. A provider adapter, authenticated terminal response/webhook, signature validation, idempotent capture and reconciliation are still required before a card payment can be confirmed. No PAN or CVV is accepted or stored.

## Integrity and limitations

- Tenant RLS applies to catalogue, sale counters, tills, sales, sale lines, tenders and cash movements.
- Sale numbers are allocated transactionally per business.
- Checkout retries are idempotent per tenant, preventing accidental duplicate cash records or duplicate card intents.
- Sale totals use integer arithmetic; tax is extracted from the VAT-inclusive gross price with deterministic half-up rounding.
- Cash tenders and completed sales are protected against mutation. Refunds and reversals must use compensating records.
- Split tender, discounts, stock decrement, receipts, refunds, terminal-provider integration and offline checkout are not yet implemented.
- This is pre-alpha and must not be used to process live payments or hold live financial records.
