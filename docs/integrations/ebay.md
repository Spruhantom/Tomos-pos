# eBay seller integration

## Scope

The eBay integration is a per-business seller connection. It uses eBay OAuth 2.0 and the official Sell APIs; it must not scrape Seller Hub or use private endpoints.

Initial target marketplace: Great Britain (`EBAY_GB`). Start in eBay Sandbox and require an explicit production configuration before live listings or order operations are enabled.

## Planned workflows

- Connect and revoke a seller account using OAuth authorization-code flow.
- Store access and refresh tokens encrypted at the application layer. Never return tokens to the browser or log them.
- Create and maintain inventory items using seller SKUs.
- Configure an eBay inventory location and seller business policies before publishing offers.
- Publish, revise, pause and end fixed-price offers through the Sell Inventory API.
- Import orders through the Sell Fulfillment API and deduplicate by the eBay order ID.
- Update fulfilment status and shipment tracking after dispatch.
- Synchronise stock from the TomOS product ledger to eBay using a durable retry queue.
- Keep a per-business audit trail and expose last-sync status and recoverable errors.

## Inventory and stock safety

TomOS is the source of truth for in-store stock. Reserve stock for paid/accepted marketplace orders before exposing the remaining quantity to other sales channels. Do not overwrite stock from a stale eBay response. Use idempotent jobs and re-fetch the current listing/order state before retrying ambiguous writes. A failed marketplace update must be visible as a sync error, not silently discarded.

The Inventory API requires a seller inventory location for each published offer and seller business policies for payment, fulfilment and returns. Sellers should enable eBay Out-of-Stock Control where appropriate. Listings created and managed through the Inventory API should continue to be edited through that API.

## Order and payment handling

An eBay order is an external marketplace order, not a new card payment at the physical till. Import the order and its payment/fulfilment state from eBay; do not attempt to charge the buyer again through SumUp or PayPal. Keep external order IDs unique per business and marketplace. Refunds, cancellations, partial fulfilments and returns require explicit state transitions and audit records.

## Configuration

Server-only settings (never expose in frontend bundles):

- `EBAY_CLIENT_ID`
- `EBAY_CLIENT_SECRET`
- `EBAY_RUNAME` (the registered eBay RuName redirect identifier)
- `EBAY_ENVIRONMENT` (`sandbox` or `production`)
- `EBAY_SCOPES` (least-privilege Sell API scopes)

Each business separately authorises its own seller account. Sandbox and production tokens, endpoints and OAuth state must not be mixed.

## Database foundation

Migration `0009_ebay_seller_integration.sql` adds tenant-isolated seller connections, OAuth state, product/listing mappings, imported order records and a durable sync-job queue. This is schema groundwork only; API routes, OAuth callbacks, workers, UI, and end-to-end tests are subsequent implementation steps.

## Official API references

- [eBay Sell Inventory API](https://developer.ebay.com/api-docs/sell/inventory/overview.html)
- [eBay Sell Fulfillment API](https://developer.ebay.com/api-docs/sell/fulfillment/overview.html)
- [eBay OAuth authorization](https://developer.ebay.com/api-docs/static/oauth-authorization-code-grant.html)
- [Inventory location requirements](https://developer.ebay.com/api-docs/sell/static/inventory/managing-inventory-locations.html)
- [Publishing offers and business policies](https://developer.ebay.com/api-docs/sell/static/inventory/publishing-offers.html)
