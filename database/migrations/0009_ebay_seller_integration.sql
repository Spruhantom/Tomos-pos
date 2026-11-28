-- eBay seller connections, listing mappings, order imports and durable sync queue.
-- OAuth tokens must be encrypted by the API before persistence.

INSERT INTO permissions (permission_key, description) VALUES
    ('ebay.read', 'View eBay marketplace connections, listings and orders'),
    ('ebay.manage', 'Connect eBay seller accounts and manage marketplace synchronisation')
ON CONFLICT (permission_key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.permission_key IN ('ebay.read', 'ebay.manage')
WHERE r.tenant_id IS NOT NULL AND r.role_key = 'owner'
ON CONFLICT DO NOTHING;

CREATE TABLE ebay_business_accounts (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    ebay_user_id TEXT,
    marketplace_id TEXT NOT NULL DEFAULT 'EBAY_GB',
    environment TEXT NOT NULL DEFAULT 'sandbox'
        CHECK (environment IN ('sandbox', 'production')),
    access_token_enc TEXT,
    refresh_token_enc TEXT,
    access_token_expires_at TIMESTAMPTZ,
    granted_scopes TEXT NOT NULL DEFAULT '',
    connection_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (connection_status IN ('pending', 'connected', 'reauthorize', 'revoked')),
    connected_at TIMESTAMPTZ,
    last_sync_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, business_id),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    CHECK (connection_status <> 'connected' OR
        (ebay_user_id IS NOT NULL AND access_token_enc IS NOT NULL AND refresh_token_enc IS NOT NULL))
);
ALTER TABLE ebay_business_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ebay_business_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY ebay_business_accounts_tenant_isolation ON ebay_business_accounts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE ebay_oauth_states (
    state UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    business_id UUID NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes',
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE ebay_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE ebay_oauth_states FORCE ROW LEVEL SECURITY;
CREATE POLICY ebay_oauth_states_access ON ebay_oauth_states
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
        OR state::text = current_setting('app.ebay_oauth_state', TRUE))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

ALTER TABLE products ADD CONSTRAINT products_tenant_business_id_unique UNIQUE (tenant_id, business_id, id);

CREATE TABLE ebay_inventory_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    product_id UUID NOT NULL,
    sku TEXT NOT NULL,
    marketplace_id TEXT NOT NULL DEFAULT 'EBAY_GB',
    merchant_location_key TEXT,
    offer_id TEXT,
    listing_id TEXT,
    listing_status TEXT NOT NULL DEFAULT 'not_listed'
        CHECK (listing_status IN ('not_listed', 'draft', 'published', 'out_of_stock', 'ended', 'error')),
    last_published_quantity INTEGER CHECK (last_published_quantity IS NULL OR last_published_quantity >= 0),
    last_published_price_minor BIGINT CHECK (last_published_price_minor IS NULL OR last_published_price_minor >= 0),
    last_synced_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, business_id, product_id)
        REFERENCES products(tenant_id, business_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, business_id, product_id, marketplace_id),
    UNIQUE (tenant_id, business_id, sku, marketplace_id)
);
ALTER TABLE ebay_inventory_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ebay_inventory_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY ebay_inventory_mappings_tenant_isolation ON ebay_inventory_mappings
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE ebay_orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    ebay_order_id TEXT NOT NULL,
    marketplace_id TEXT NOT NULL DEFAULT 'EBAY_GB',
    order_status TEXT NOT NULL,
    fulfillment_status TEXT NOT NULL DEFAULT 'unfulfilled',
    currency CHAR(3) NOT NULL,
    total_minor BIGINT NOT NULL CHECK (total_minor >= 0),
    buyer_username TEXT,
    ordered_at TIMESTAMPTZ,
    raw_order JSONB NOT NULL,
    sale_id UUID,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, sale_id) REFERENCES sales(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, business_id, ebay_order_id)
);
ALTER TABLE ebay_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE ebay_orders FORCE ROW LEVEL SECURITY;
CREATE POLICY ebay_orders_tenant_isolation ON ebay_orders
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);
CREATE INDEX ebay_orders_recent_idx ON ebay_orders(tenant_id, business_id, ordered_at DESC);

CREATE TABLE ebay_sync_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    job_type TEXT NOT NULL CHECK (job_type IN (
        'inventory_publish', 'inventory_update', 'inventory_quantity',
        'orders_import', 'fulfillment_update', 'return_import'
    )),
    aggregate_key TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'succeeded', 'retry', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT
);
ALTER TABLE ebay_sync_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ebay_sync_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY ebay_sync_jobs_tenant_isolation ON ebay_sync_jobs
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);
CREATE INDEX ebay_sync_jobs_ready_idx ON ebay_sync_jobs(status, available_at)
    WHERE status IN ('pending', 'retry');
