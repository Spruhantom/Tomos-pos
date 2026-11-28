# SumUp payment integration

## Scope

TomOS POS integrates SumUp through a provider adapter. The first implementation target is the Solo Cloud API, which supports a POS running on Linux, Windows, Android, iOS or the web using HTTPS. It does not require Bluetooth pairing between the PC and Solo.

The Rust client foundation lives in `backend/sumup-bridge`.

## Device integration matrix

| Device/path | Planned adapter | PC integration |
|---|---|---|
| Solo | Cloud API | Direct HTTPS from TomOS POS backend |
| Solo Lite | Reader SDK / supported mobile flow | Android companion bridge required |
| Air | Reader SDK / supported mobile flow | Android companion bridge required |
| Other supported readers | Select by official device compatibility | Capability-gated; not assumed |

Do not advertise every SumUp model as Cloud API compatible. Query the official device compatibility documentation and select the correct integration path per model and region.

## Solo pairing

1. Merchant configures SumUp API authorisation and the application affiliate key.
2. On a logged-out Solo, open Connections → API → Connect.
3. Enter the short-lived pairing code in the authorised TomOS POS device-management screen.
4. The backend calls the SumUp Create Reader endpoint and stores the returned reader identifier against the tenant and POS device.
5. Pairing codes expire after five minutes. Never log or persist the code.

## Checkout lifecycle

1. Create a local payment attempt with a unique transaction ID and immutable amount/currency snapshot.
2. Send the amount in integer minor units, reader ID, unique client transaction ID, HTTPS return URL and affiliate key to SumUp.
3. Treat the API response as checkout acceptance only. The sale remains unpaid.
4. Receive the `solo.transaction.updated` callback at a publicly reachable HTTPS endpoint.
5. Validate the event type, merchant code and exact client transaction ID against the pending attempt. The Solo Cloud API webhook example does not document a cryptographic signature header; protect each callback URL with HTTPS and a high-entropy, per-attempt unguessable token. Do not claim signature verification.
6. Only a matching final successful event may transition the payment attempt to successful. The POS sale must remain unpaid until this confirmation is durably stored; sale integration is still outstanding.
7. Failed, cancelled, timed-out or ambiguous attempts remain unpaid and are available for reconciliation. Never create a second charge automatically after an ambiguous network failure.

## Security and operational requirements

- Store API and affiliate keys in deployment secrets; never in the browser, repository, logs or tenant-readable configuration.
- Scope merchant credentials and paired reader records to a tenant.
- Keep cardholder data out of TomOS POS.
- Require HTTPS for callbacks and production API traffic.
- Do not invent an HMAC/signature check for Solo Cloud API: its documented callback contract shows no signature header. Use a per-attempt secret callback URL, HTTPS, merchant/reference matching, and provider reconciliation where available.
- Deduplicate webhook events and enforce uniqueness for provider transaction IDs and client transaction IDs.
- Record append-only audit events for pairing, checkout initiation, final result, termination and refund actions.
- Use provider transaction lookup/reconciliation to recover missed callbacks.
- Never assume card payments can be accepted offline.

## Current implementation status

- [x] Rust Cloud API client foundation: reader pairing, listing, status, checkout initiation and termination.
- [x] Integer minor-unit amount model and HTTPS callback validation.
- [x] Provider capability types for Cloud API, mobile SDK and Payment Switch paths.
- [ ] Tenant-scoped credential and reader persistence.
- [x] Solo webhook event parsing, merchant/reference matching and terminal-state/idempotency rules in the Rust bridge.
- [x] Axum callback endpoint with a 256-bit per-attempt token in the HTTPS return URL; only the SHA-256 token digest is persisted.\n- [x] Tenant-RLS-protected payment-attempt storage and conditional, idempotent final-state updates.\n- [ ] Connect attempt creation and checkout initiation to the sales workflow; add provider reconciliation.
- [ ] POS checkout and sale-state integration.
- [ ] Refund workflow and transaction reconciliation.
- [ ] Android companion adapter for supported Solo Lite/Air SDK workflows.
- [ ] Sandbox integration tests and physical-device acceptance tests.

## Current API implementation\n\nThe API exposes `POST /api/v1/payments/sumup/webhook/{token}` for the Solo callback. A trusted checkout service calls `sumup::create_attempt` before starting the remote checkout and uses the returned `return_url`. The plaintext callback token is returned once and must not be logged or persisted. The webhook handler resolves the token digest, restores the tenant RLS context, verifies the merchant and client transaction ID, and conditionally records the final state. This receiver is not yet connected to a sale checkout route; a successful attempt does not yet update a sale record.\n\n## Sandbox and release gate

Use a SumUp sandbox merchant account and Virtual Solo before connecting a physical Solo. Live payment processing must remain disabled until callback verification, tenant isolation, idempotency, reconciliation, refund handling and physical-device acceptance tests pass.

## Official references

- [SumUp Cloud API](https://developer.sumup.com/terminal-payments/cloud-api/)
- [SumUp terminal quickstart](https://developer.sumup.com/terminal-payments/quickstart/)
- [SumUp reader compatibility](https://developer.sumup.com/terminal-payments/readers/)
- [SumUp REST API](https://developer.sumup.com/api/)
