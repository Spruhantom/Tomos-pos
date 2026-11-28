# SumUp integration

TomOS POS connects each business to its own SumUp merchant account using SumUp OAuth 2.0. Solo reader payments use the SumUp Cloud API and remain pending until the `solo.transaction.updated` event reports a final successful result.

## Required configuration

Set these variables in the API service secret store. Do not commit credentials.

- `SUMUP_CLIENT_ID`
- `SUMUP_CLIENT_SECRET`
- `SUMUP_REDIRECT_URI` — exact registered OAuth callback, ending in `/api/v1/sumup/oauth/callback`
- `SUMUP_AFFILIATE_APP_ID` — app identifier from SumUp Affiliate Keys
- `SUMUP_AFFILIATE_KEY` — affiliate key from SumUp Affiliate Keys
- `SUMUP_READER_WEBHOOK_URL` — public HTTPS URL ending in `/api/v1/sumup/reader-webhook`
- `TOMOS_INTEGRATION_ENCRYPTION_KEY` — 32 random bytes represented as 64 hexadecimal characters

Generate the encryption key with `openssl rand -hex 32`. Keep it stable and back it up securely; changing it without re-encrypting stored credentials makes connected accounts unreadable.

## SumUp OAuth application

Register a confidential web OAuth application in the SumUp Developer Dashboard. Register the exact redirect URI and request:

- `user.profile_readonly` — enumerate merchant accounts the user can access
- `transactions.history` — transaction history access
- `readers.read` — list paired readers
- `readers.write` — start reader checkouts

TomOS requests only the scopes required for the current integration. If SumUp does not grant both reader scopes, the connection is not enabled for reader payments. Follow SumUp's approval process if the required scopes are unavailable to the application.

## Merchant connection

1. Open **Business integrations** in TomOS.
2. Select the business and choose **Connect SumUp business**.
3. Sign in to SumUp and grant the requested scopes.
4. If the SumUp user has several accepted merchant accounts, select the correct merchant for this business.
5. Pair the Solo reader with the same SumUp merchant account in SumUp.

TomOS encrypts access and refresh tokens with AES-256-GCM before storing them. OAuth state is single-use and expires after ten minutes. Refresh tokens are refreshed server-side and never returned to the browser.

## Reader checkout

1. Create a POS sale using `payment_method: "sumup_terminal"`.
2. Start `POST /api/v1/pos/sales/{sale_id}/sumup/reader-checkout` with the business ID and paired reader ID.
3. TomOS sends the amount, currency, affiliate metadata and a unique HTTPS callback URL to SumUp.
4. The Solo reader accepts the checkout asynchronously.
5. SumUp posts `solo.transaction.updated` with the returned `client_transaction_id`.
6. TomOS matches the event to the tenant-scoped pending tender using the transaction ID and a per-attempt high-entropy callback token. Only `successful` captures the tender and completes the sale. `failed` leaves the sale unpaid/cancelled.

An accepted reader checkout is not proof of payment. Do not hand over goods until the TomOS sale status is completed. The callback token is a shared secret in the HTTPS callback URL; do not log or disclose full callback URLs.

## Sandbox testing

Use a SumUp sandbox merchant and Virtual Solo to test pairing and reader payments without processing real funds. Test success, decline, duplicate callbacks, reader-offline behaviour, token refresh and revoked authorisation before enabling live payments.

The SumUp Affiliate Key is required for Cloud API card-present transactions. Reader checkouts require the appropriate reader scopes and an affiliate object containing both the app ID and key.

## Current scope

Implemented: OAuth connection per business, merchant selection, encrypted token storage, refresh, paired-reader listing, Solo checkout initiation, asynchronous callback reconciliation and POS tender completion.

Not yet implemented: reader pairing inside TomOS, device status dashboards, terminal termination, refunds, automatic webhook retries/repair tooling and production sandbox-to-live certification. Pair readers in SumUp for now.
