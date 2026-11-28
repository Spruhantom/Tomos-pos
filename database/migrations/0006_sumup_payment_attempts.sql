-- Durable SumUp Solo payment attempts. The callback token is stored only as
-- a SHA-256 digest; the plaintext token is returned once when an attempt is made.
CREATE TABLE sumup_payment_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    sale_id UUID NOT NULL,
    reader_id TEXT NOT NULL,
    client_transaction_id TEXT NOT NULL UNIQUE,
    merchant_code TEXT NOT NULL,
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    currency CHAR(3) NOT NULL,
    callback_token_hash CHAR(64) NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'successful', 'failed')),
    provider_event_id TEXT UNIQUE,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sumup_payment_attempts_tenant_created_idx
    ON sumup_payment_attempts(tenant_id, created_at DESC);
CREATE INDEX sumup_payment_attempts_sale_idx
    ON sumup_payment_attempts(tenant_id, sale_id);
