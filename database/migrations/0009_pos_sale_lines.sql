-- Immutable itemised sale-line snapshots. Prices in the catalogue are VAT-inclusive.
CREATE TABLE pos_sale_lines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    sale_id UUID NOT NULL,
    product_id UUID NOT NULL,
    product_name TEXT NOT NULL CHECK (length(trim(product_name)) BETWEEN 1 AND 160),
    product_sku TEXT,
    quantity INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 10000),
    unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor >= 0),
    tax_rate_bps INTEGER NOT NULL CHECK (tax_rate_bps BETWEEN 0 AND 10000),
    net_minor BIGINT NOT NULL CHECK (net_minor >= 0),
    tax_minor BIGINT NOT NULL CHECK (tax_minor >= 0),
    gross_minor BIGINT NOT NULL CHECK (gross_minor >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, sale_id)
        REFERENCES pos_sales(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, product_id)
        REFERENCES pos_products(tenant_id, id) ON DELETE RESTRICT,
    CHECK (net_minor + tax_minor = gross_minor),
    CHECK (unit_price_minor * quantity = gross_minor)
);

CREATE INDEX pos_sale_lines_tenant_sale_idx
    ON pos_sale_lines(tenant_id, sale_id);

ALTER TABLE pos_sale_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE pos_sale_lines FORCE ROW LEVEL SECURITY;
CREATE POLICY pos_sale_lines_tenant_isolation ON pos_sale_lines
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

-- Sale lines are accounting snapshots: corrections use reversals/refunds, not edits.
CREATE FUNCTION reject_pos_sale_line_mutation() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'sale line snapshots are immutable';
END;
$fn$;

CREATE TRIGGER pos_sale_lines_immutable
    BEFORE UPDATE OR DELETE ON pos_sale_lines
    FOR EACH ROW EXECUTE FUNCTION reject_pos_sale_line_mutation();
