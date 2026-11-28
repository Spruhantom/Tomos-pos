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

-- Financial amount/currency snapshots cannot be silently edited after sale creation.
-- Paid and void sales are terminal; corrections require explicit reversal records.
CREATE FUNCTION protect_pos_sale_financial_fields() RETURNS trigger
LANGUAGE plpgsql AS $
BEGIN
    IF NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
       OR NEW.currency IS DISTINCT FROM OLD.currency THEN
        RAISE EXCEPTION 'sale amount and currency are immutable';
    END IF;
    IF OLD.status IN ('paid', 'void') AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION 'paid or void sales cannot be reopened';
    END IF;
    IF OLD.status = 'paid' AND NEW.paid_at IS DISTINCT FROM OLD.paid_at THEN
        RAISE EXCEPTION 'paid timestamp is immutable';
    END IF;
    RETURN NEW;
END;
$;

CREATE TRIGGER pos_sales_financial_fields_immutable
    BEFORE UPDATE ON pos_sales
    FOR EACH ROW EXECUTE FUNCTION protect_pos_sale_financial_fields();

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
