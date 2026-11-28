# Security and privacy requirements

## Identity and sessions
- Hash passwords using Argon2id with maintained parameters.
- Use secure, HttpOnly, SameSite cookies for browser sessions.
- Rotate session identifiers after authentication and privilege changes.
- Add rate limits, login throttling, recovery controls and administrator MFA.
- Revoke sessions and registered devices when access is removed.

## Tenant isolation
- Derive tenant membership from server-side identity context.
- Apply tenant filters to every tenant-owned query.
- Consider PostgreSQL row-level security as defence in depth.
- Include negative tests for cross-tenant reads and writes.
- Platform support access must be explicit, time-limited and audited.

## Financial integrity
- Use integer minor units for stored money and explicit currencies.
- Use database transactions for sale, tender and stock updates.
- Require idempotency keys for checkout, refunds, sync and webhooks.
- Preserve immutable audit and transaction history.
- Reconcile payment provider events against internal payment records.

## Payment data
- Use hosted checkout or certified terminal/provider SDKs.
- Never store card verification codes or raw card numbers.
- Keep provider secrets server-side and rotate them.
- Validate webhook signatures and reject replayed events.

## Application security
- Validate all inputs at API boundaries.
- Use parameterised SQL through SQLx.
- Apply CSRF protection where cookie-authenticated state-changing requests require it.
- Set secure HTTP headers and a restrictive Content Security Policy.
- Rate-limit authentication, public APIs and webhook endpoints.
- Scan dependencies and container images.

## Operations
- Do not commit secrets or production data.
- Encrypt backups and store a copy off-host.
- Test restoration and document recovery objectives.
- Keep structured logs free of passwords, tokens, payment secrets and unnecessary personal data.
- Define data retention, export and deletion policies with applicable legal requirements.
