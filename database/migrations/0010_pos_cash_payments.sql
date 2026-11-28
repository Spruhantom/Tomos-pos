-- Cash tenders are immutable records linked to a single sale.
CREATE TABLE pos_cash_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    sale_id UUID NOT NULL,
    tendered_minor BIGINT NOT NULL CHECK (tendered_minor > 0),
    change_minor BIGINT NOT NULL CHECK (change_minor >= 0 AND change_minor <= tendered_minor),
    received_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, sale_id),
    FOREIGN KEY (tenant_id, sale_id)
        REFERENCES pos_sales(tenant_id, id) ON DELETE RESTRICT
);

ALTER TABLE pos_cash_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE pos_cash_payments FORCE ROW LEVEL SECURITY;
CREATE POLICY pos_cash_payments_tenant_isolation ON pos_cash_payments
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE FUNCTION reject_pos_cash_payment_mutation() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'cash payment records are immutable';
END;
$fn$;

CREATE TRIGGER pos_cash_payments_immutable
    BEFORE UPDATE OR DELETE ON pos_cash_payments
    FOR EACH ROW EXECUTE FUNCTION reject_pos_cash_payment_mutation();
