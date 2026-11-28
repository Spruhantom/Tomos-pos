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
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'successful', 'failed')),
    provider_event_id TEXT UNIQUE,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE INDEX sumup_payment_attempts_tenant_created_idx
    ON sumup_payment_attempts(tenant_id, created_at DESC);
CREATE INDEX sumup_payment_attempts_sale_idx
    ON sumup_payment_attempts(tenant_id, sale_id);

ALTER TABLE sumup_payment_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sumup_payment_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY sumup_payment_attempts_tenant_isolation ON sumup_payment_attempts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

-- The callback receiver must resolve the tenant before it can set tenant RLS
-- context. This table therefore contains only a one-way token digest and the
-- scoped attempt reference; it contains no amount, sale or customer data.
CREATE TABLE sumup_webhook_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    attempt_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, attempt_id)
        REFERENCES sumup_payment_attempts(tenant_id, id) ON DELETE CASCADE
);
