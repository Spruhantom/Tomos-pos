-- M4/M5 foundation: catalogue, till sessions, immutable sales and tender records.
-- Money is stored in integer minor units (pence for GBP); no cardholder data is stored.

INSERT INTO permissions (permission_key, description) VALUES
    ('pos.catalog.read', 'View the product catalogue'),
    ('pos.catalog.manage', 'Create and manage products'),
    ('pos.checkout', 'Create sales and take payments'),
    ('pos.till.manage', 'Open, close and reconcile tills'),
    ('pos.refund', 'Refund completed sales')
ON CONFLICT (permission_key) DO NOTHING;

-- Existing owners receive the new POS permissions. Cashiers are assigned a
-- least-privileged custom role by an administrator using the role catalogue.
INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.permission_key IN
    ('pos.catalog.read', 'pos.catalog.manage', 'pos.checkout', 'pos.till.manage', 'pos.refund')
WHERE r.tenant_id IS NOT NULL AND r.role_key = 'owner'
ON CONFLICT DO NOTHING;

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    sku TEXT NOT NULL,
    barcode TEXT,
    name TEXT NOT NULL,
    description TEXT,
    unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor >= 0),
    cost_price_minor BIGINT CHECK (cost_price_minor IS NULL OR cost_price_minor >= 0),
    currency_code CHAR(3) NOT NULL DEFAULT 'GBP',
    tax_rate_bps INTEGER NOT NULL DEFAULT 0 CHECK (tax_rate_bps BETWEEN 0 AND 10000),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, business_id, sku)
);
CREATE UNIQUE INDEX products_business_barcode_idx
    ON products(tenant_id, business_id, barcode) WHERE barcode IS NOT NULL;
CREATE INDEX products_catalogue_name_idx
    ON products(tenant_id, business_id, name) WHERE is_active;

CREATE TABLE till_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    location_id UUID NOT NULL,
    opened_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    closed_by UUID REFERENCES users(id) ON DELETE RESTRICT,
    opening_float_minor BIGINT NOT NULL CHECK (opening_float_minor >= 0),
    closing_count_minor BIGINT CHECK (closing_count_minor IS NULL OR closing_count_minor >= 0),
    currency_code CHAR(3) NOT NULL DEFAULT 'GBP',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, business_id, location_id)
        REFERENCES business_locations(tenant_id, business_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id),
    CHECK ((status = 'open' AND closed_at IS NULL AND closed_by IS NULL)
        OR (status = 'closed' AND closed_at IS NOT NULL AND closed_by IS NOT NULL))
);
CREATE UNIQUE INDEX till_sessions_one_open_per_location
    ON till_sessions(tenant_id, location_id) WHERE status = 'open';
CREATE INDEX till_sessions_business_opened_idx
    ON till_sessions(tenant_id, business_id, opened_at DESC);

CREATE TABLE business_sale_counters (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    next_number BIGINT NOT NULL DEFAULT 1 CHECK (next_number > 0),
    PRIMARY KEY (tenant_id, business_id),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE sales (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    location_id UUID NOT NULL,
    till_session_id UUID NOT NULL,
    cashier_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    sale_number BIGINT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('awaiting_payment', 'completed', 'cancelled', 'refunded')),
    currency_code CHAR(3) NOT NULL,
    subtotal_minor BIGINT NOT NULL CHECK (subtotal_minor >= 0),
    tax_minor BIGINT NOT NULL CHECK (tax_minor >= 0),
    total_minor BIGINT NOT NULL CHECK (total_minor >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, business_id, location_id)
        REFERENCES business_locations(tenant_id, business_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, till_session_id) REFERENCES till_sessions(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, business_id, sale_number),
    CHECK (total_minor = subtotal_minor + tax_minor),
    CHECK ((status = 'completed' AND completed_at IS NOT NULL)
        OR (status <> 'completed' AND completed_at IS NULL))
);
CREATE INDEX sales_tenant_business_created_idx
    ON sales(tenant_id, business_id, created_at DESC);

CREATE TABLE sale_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    sale_id UUID NOT NULL,
    product_id UUID NOT NULL,
    product_name TEXT NOT NULL,
    sku TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 10000),
    unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor >= 0),
    tax_rate_bps INTEGER NOT NULL CHECK (tax_rate_bps BETWEEN 0 AND 10000),
    line_subtotal_minor BIGINT NOT NULL CHECK (line_subtotal_minor >= 0),
    line_tax_minor BIGINT NOT NULL CHECK (line_tax_minor >= 0),
    line_total_minor BIGINT NOT NULL CHECK (line_total_minor >= 0),
    FOREIGN KEY (tenant_id, sale_id) REFERENCES sales(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, product_id) REFERENCES products(tenant_id, id) ON DELETE RESTRICT,
    CHECK (line_total_minor = line_subtotal_minor + line_tax_minor)
);
CREATE INDEX sale_items_sale_idx ON sale_items(tenant_id, sale_id);

CREATE TABLE payment_tenders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    sale_id UUID NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('cash', 'card_terminal')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'captured', 'failed', 'cancelled', 'refunded')),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    amount_received_minor BIGINT CHECK (amount_received_minor IS NULL OR amount_received_minor >= 0),
    change_due_minor BIGINT NOT NULL DEFAULT 0 CHECK (change_due_minor >= 0),
    provider_key TEXT,
    provider_reference TEXT,
    terminal_reference TEXT,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    captured_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, sale_id) REFERENCES sales(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, id),
    CHECK (
        (method = 'cash' AND status = 'captured' AND amount_received_minor IS NOT NULL
            AND amount_received_minor >= amount_minor
            AND change_due_minor = amount_received_minor - amount_minor
            AND captured_at IS NOT NULL)
        OR
        (method = 'card_terminal' AND amount_received_minor IS NULL
            AND change_due_minor = 0
            AND (status <> 'captured' OR captured_at IS NOT NULL))
    )
);
CREATE INDEX payment_tenders_sale_idx ON payment_tenders(tenant_id, sale_id, created_at);

CREATE TABLE till_cash_movements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    till_session_id UUID NOT NULL,
    movement_type TEXT NOT NULL CHECK (movement_type IN ('paid_in', 'paid_out')),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 240),
    recorded_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, till_session_id) REFERENCES till_sessions(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX till_cash_movements_session_idx
    ON till_cash_movements(tenant_id, till_session_id, created_at);

-- Tenant isolation for every new operational table.
DO $$
DECLARE table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'products', 'till_sessions', 'sales', 'sale_items',
        'payment_tenders', 'till_cash_movements'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', TRUE), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', TRUE), '''')::uuid)',
            table_name || '_tenant_isolation', table_name
        );
    END LOOP;
END $$;

-- Completed financial records are immutable. Future refunds/reversals must be
-- separate compensating records rather than edits to a completed sale/tender.
CREATE FUNCTION prevent_completed_sale_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.status IN ('completed', 'refunded') THEN
        RAISE EXCEPTION 'completed sales are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sales_immutable_after_completion
    BEFORE UPDATE OR DELETE ON sales
    FOR EACH ROW EXECUTE FUNCTION prevent_completed_sale_mutation();

CREATE FUNCTION prevent_tender_mutation_after_capture() RETURNS trigger AS $$
BEGIN
    IF OLD.status IN ('captured', 'refunded') THEN
        RAISE EXCEPTION 'captured tenders are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenders_immutable_after_capture
    BEFORE UPDATE OR DELETE ON payment_tenders
    FOR EACH ROW EXECUTE FUNCTION prevent_tender_mutation_after_capture();
