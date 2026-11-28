# PayPal multiparty integration

TomOS POS uses PayPal Complete Payments Platform (multiparty) so each business receives its own PayPal payments. The platform does not collect or pool seller proceeds.

## Seller connection

A business owner or user with `business.manage` starts connection with:

- `POST /api/v1/paypal/connect` with `business_id`.
- The API creates a Partner Referrals v2 onboarding link requesting payment and refund permissions.
- The business owner signs in to PayPal and grants consent.
- PayPal returns to `PAYPAL_ONBOARDING_RETURN_URL` with the opaque tracking ID, PayPal merchant ID, `permissionsGranted`, and `consentStatus`.
- The callback stores the merchant ID and marks the account connected only when PayPal confirms the seller granted permissions, consented, verified their email, and has a Business account.

The onboarding tracking ID is a random UUID, expires after 30 minutes, and is single-use. Merchant IDs are stored per tenant/business. TomOS does not store seller PayPal passwords or access tokens.

## Checkout

1. Create a POS sale with `payment_method: "paypal"`. It remains `awaiting_payment` with a pending tender.
2. Call `POST /api/v1/pos/sales/{sale_id}/paypal/order` with the business ID.
3. Redirect the customer to the returned `approval_url`.
4. PayPal returns the customer to `PAYPAL_CHECKOUT_RETURN_URL` with the sale ID.
5. Call `POST /api/v1/pos/sales/{sale_id}/paypal/capture`. The API captures the PayPal order on behalf of that business and completes the sale only when PayPal reports `COMPLETED`.

The Orders API uses the connected merchant's PayPal merchant ID as the payee, a PayPal-Auth-Assertion, and stable PayPal-Request-Id values. A browser redirect alone never marks a sale paid.

## Webhooks

Configure `POST /api/v1/paypal/webhook` on the PayPal REST app. Set `PAYPAL_WEBHOOK_ID` to the webhook ID issued by PayPal. The API calls PayPal's verify-webhook-signature endpoint before processing events. Subscribe to at least:

- `PAYMENT.CAPTURE.COMPLETED`
- `PAYMENT.CAPTURE.DENIED`
- `PAYMENT.CAPTURE.PENDING`

The completed event reconciles the tenant-scoped sale and tender; a denied capture marks the pending tender failed and cancels the awaiting sale. Pending and unrelated events are acknowledged without completing a sale. Checkout still captures and confirms the order server-side.

## Required environment

- `PAYPAL_ENVIRONMENT=sandbox` (set to `live` only after PayPal platform approval)
- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`
- `PAYPAL_ONBOARDING_RETURN_URL` — API callback URL ending in `/api/v1/paypal/onboarding/return`
- `PAYPAL_CHECKOUT_RETURN_URL` — frontend checkout return URL, normally ending in `/pos`
- `PAYPAL_CANCEL_URL` — frontend checkout cancellation URL
- `PAYPAL_WEBHOOK_ID`

Never commit credentials. Use sandbox credentials for development.

## Release requirements and limitations

PayPal Complete Payments Platform is sandbox-testable but live multiparty processing requires PayPal partner approval. The live rollout also requires PayPal to configure the production platform app and webhook. This code does not make a business eligible for live processing by itself.

Refund initiation, refund webhooks, dispute handling, seller disconnection/revocation handling, reconciliation dashboards, and end-to-end sandbox tests remain follow-up work. Do not enable live processing until those operational workflows and the PayPal partner review are complete.
