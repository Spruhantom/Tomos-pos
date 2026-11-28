-- Tenant-scoped product catalogue foundation for itemised POS sales.
CREATE TABLE pos_products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    sku TEXT,
    barcode TEXT,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 160),
    description TEXT,
    unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor >= 0),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    tax_rate_bps INTEGER NOT NULL DEFAULT 0 CHECK (tax_rate_bps BETWEEN 0 AND 10000),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX pos_products_tenant_sku_unique
    ON pos_products(tenant_id, lower(sku)) WHERE sku IS NOT NULL;
CREATE UNIQUE INDEX pos_products_tenant_barcode_unique
    ON pos_products(tenant_id, barcode) WHERE barcode IS NOT NULL;
CREATE INDEX pos_products_tenant_name_idx
    ON pos_products(tenant_id, lower(name));

ALTER TABLE pos_products ENABLE ROW LEVEL SECURITY;
ALTER TABLE pos_products FORCE ROW LEVEL SECURITY;
CREATE POLICY pos_products_tenant_isolation ON pos_products
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

INSERT INTO permissions (permission_key, description) VALUES
    ('catalogue.read', 'View the product catalogue'),
    ('catalogue.manage', 'Create and manage catalogue products')
ON CONFLICT (permission_key) DO NOTHING;

-- Staff can operate the POS and read products; catalogue changes remain owner-managed.
INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.permission_key IN ('sales.manage', 'catalogue.read')
WHERE r.role_key = 'staff'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.permission_key IN ('catalogue.read', 'catalogue.manage')
WHERE r.role_key = 'owner'
ON CONFLICT DO NOTHING;
