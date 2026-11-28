-- Minimal immutable-amount sale record to anchor payment attempts.
-- Product lines, tax calculation and inventory are separate POS milestones.
CREATE TABLE pos_sales (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    status TEXT NOT NULL DEFAULT 'unpaid'
        CHECK (status IN ('unpaid', 'paid', 'void')),
    paid_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    CHECK ((status = 'paid') = (paid_at IS NOT NULL))
);

CREATE INDEX pos_sales_tenant_created_idx
    ON pos_sales(tenant_id, created_at DESC);

ALTER TABLE pos_sales ENABLE ROW LEVEL SECURITY;
ALTER TABLE pos_sales FORCE ROW LEVEL SECURITY;
CREATE POLICY pos_sales_tenant_isolation ON pos_sales
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

ALTER TABLE sumup_payment_attempts
    ADD CONSTRAINT sumup_attempt_sale_tenant_fk
    FOREIGN KEY (tenant_id, sale_id)
    REFERENCES pos_sales(tenant_id, id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX sumup_one_pending_attempt_per_sale_idx
    ON sumup_payment_attempts(tenant_id, sale_id)
    WHERE status = 'pending';

INSERT INTO permissions (permission_key, description)
VALUES ('sales.manage', 'Create sales and manage payment collection')
ON CONFLICT (permission_key) DO NOTHING;
