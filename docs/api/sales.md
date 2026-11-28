# Sales and SumUp API (initial payment slice)

All sales routes require the session cookie, an `X-Tenant-ID` header, and the tenant's `sales.manage` permission. Amounts are integer minor units.

## Create an unpaid sale

`POST /api/v1/sales`

```json
{
  "amount_minor": 1250,
  "currency": "GBP"
}
```

Returns `201 Created` with the sale ID, immutable amount, currency and `unpaid` status. This initial slice does not yet calculate baskets, VAT, discounts or stock movements.

## Start a Solo checkout

`POST /api/v1/sales/{sale_id}/payments/sumup`

```json
{
  "reader_id": "configured-reader-id"
}
```

Returns `202 Accepted` when SumUp accepts the asynchronous checkout request. This is not a payment confirmation. The sale remains unpaid until the Solo webhook arrives. Only the server-configured reader is accepted in this initial single-reader deployment.

A duplicate pending attempt for the same sale returns `409 Conflict`. A definitive provider 4xx rejection marks the attempt failed. A transport error or provider 5xx returns `202 Accepted` with `status: pending_reconciliation` and the payment-attempt ID. The client must not retry that sale; the attempt remains pending because the remote reader may already have accepted the request; an operator must reconcile it before retrying.

## Read sale status

`GET /api/v1/sales/{sale_id}`

Returns the current `unpaid`, `paid` or `void` state. A successful Solo callback atomically marks an unpaid sale paid and appends an audit event.

## Server configuration

Configure these values in the API deployment environment, never in browser code or committed files:

- `SUMUP_API_KEY`
- `SUMUP_AFFILIATE_KEY`
- `SUMUP_MERCHANT_CODE`
- `SUMUP_READER_ID`
- `SUMUP_PUBLIC_BASE_URL` — publicly reachable HTTPS origin for callbacks

Use sandbox credentials and Virtual Solo first. Live payments remain disabled until reconciliation, tenant-managed credential storage, refund handling, full sales/tax integration and physical reader acceptance tests are complete.
