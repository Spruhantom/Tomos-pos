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
5. Authenticate/validate the callback according to SumUp's current webhook guidance, correlate it to the stored client transaction ID, and make processing idempotent.
6. Only a verified final successful transaction may transition the payment attempt to confirmed and the sale to paid.
7. Failed, cancelled, timed-out or ambiguous attempts remain unpaid and are available for reconciliation. Never create a second charge automatically after an ambiguous network failure.

## Security and operational requirements

- Store API and affiliate keys in deployment secrets; never in the browser, repository, logs or tenant-readable configuration.
- Scope merchant credentials and paired reader records to a tenant.
- Keep cardholder data out of TomOS POS.
- Require HTTPS for callbacks and production API traffic.
- Verify callback authenticity using the currently documented SumUp mechanism before accepting payment state changes.
- Deduplicate webhook events and enforce uniqueness for provider transaction IDs and client transaction IDs.
- Record append-only audit events for pairing, checkout initiation, final result, termination and refund actions.
- Use provider transaction lookup/reconciliation to recover missed callbacks.
- Never assume card payments can be accepted offline.

## Current implementation status

- [x] Rust Cloud API client foundation: reader pairing, listing, status, checkout initiation and termination.
- [x] Integer minor-unit amount model and HTTPS callback validation.
- [x] Provider capability types for Cloud API, mobile SDK and Payment Switch paths.
- [ ] Tenant-scoped credential and reader persistence.
- [ ] Authenticated webhook endpoint, signature/authenticity validation and idempotent event storage.
- [ ] POS checkout and sale-state integration.
- [ ] Refund workflow and transaction reconciliation.
- [ ] Android companion adapter for supported Solo Lite/Air SDK workflows.
- [ ] Sandbox integration tests and physical-device acceptance tests.

## Sandbox and release gate

Use a SumUp sandbox merchant account and Virtual Solo before connecting a physical Solo. Live payment processing must remain disabled until callback verification, tenant isolation, idempotency, reconciliation, refund handling and physical-device acceptance tests pass.

## Official references

- [SumUp Cloud API](https://developer.sumup.com/terminal-payments/cloud-api/)
- [SumUp terminal quickstart](https://developer.sumup.com/terminal-payments/quickstart/)
- [SumUp reader compatibility](https://developer.sumup.com/terminal-payments/readers/)
- [SumUp REST API](https://developer.sumup.com/api/)
