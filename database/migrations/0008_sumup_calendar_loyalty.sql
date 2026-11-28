-- SumUp merchant connections, Google Calendar bridge, appointments and TomOS loyalty.
-- OAuth refresh tokens are encrypted by the API before being written to these tables.

INSERT INTO permissions (permission_key, description) VALUES
    ('integrations.manage', 'Connect and manage external business integrations'),
    ('calendar.read', 'View business appointments'),
    ('calendar.manage', 'Create and synchronise business appointments'),
    ('loyalty.read', 'View customers and loyalty balances'),
    ('loyalty.manage', 'Manage loyalty programmes and rewards')
ON CONFLICT (permission_key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.permission_key IN
    ('integrations.manage', 'calendar.read', 'calendar.manage', 'loyalty.read', 'loyalty.manage')
WHERE r.tenant_id IS NOT NULL AND r.role_key = 'owner'
ON CONFLICT DO NOTHING;

ALTER TABLE payment_tenders DROP CONSTRAINT IF EXISTS payment_tenders_method_check;
ALTER TABLE payment_tenders ADD CONSTRAINT payment_tenders_method_check
    CHECK (method IN ('cash', 'card_terminal', 'paypal', 'sumup_terminal'));
ALTER TABLE payment_tenders DROP CONSTRAINT IF EXISTS payment_tenders_check;
ALTER TABLE payment_tenders ADD CONSTRAINT payment_tenders_check CHECK (
    (method = 'cash' AND status = 'captured' AND amount_received_minor IS NOT NULL
        AND amount_received_minor >= amount_minor
        AND change_due_minor = amount_received_minor - amount_minor
        AND captured_at IS NOT NULL)
    OR
    (method IN ('card_terminal', 'paypal', 'sumup_terminal') AND amount_received_minor IS NULL
        AND change_due_minor = 0
        AND (status <> 'captured' OR captured_at IS NOT NULL))
);

CREATE TABLE sumup_business_accounts (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    merchant_code TEXT,
    access_token_enc TEXT,
    refresh_token_enc TEXT,
    token_expires_at TIMESTAMPTZ,
    granted_scopes TEXT NOT NULL DEFAULT '',
    available_merchants JSONB NOT NULL DEFAULT '[]'::jsonb,
    connection_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (connection_status IN ('pending', 'connected', 'reauthorize', 'revoked')),
    connected_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, business_id),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    CHECK (connection_status <> 'connected' OR
        (merchant_code IS NOT NULL AND access_token_enc IS NOT NULL AND refresh_token_enc IS NOT NULL))
);
ALTER TABLE sumup_business_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sumup_business_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY sumup_business_accounts_tenant_isolation ON sumup_business_accounts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE sumup_oauth_states (
    state UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    business_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes',
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE sumup_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE sumup_oauth_states FORCE ROW LEVEL SECURITY;
CREATE POLICY sumup_oauth_states_access ON sumup_oauth_states
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
        OR state::text = current_setting('app.sumup_oauth_state', TRUE))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE sumup_reader_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    sale_id UUID NOT NULL,
    tender_id UUID NOT NULL,
    merchant_code TEXT NOT NULL,
    reader_id TEXT NOT NULL,
    checkout_id TEXT,
    client_transaction_id TEXT NOT NULL UNIQUE,
    webhook_token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'successful', 'failed')),
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, sale_id) REFERENCES sales(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, tender_id) REFERENCES payment_tenders(tenant_id, id) ON DELETE RESTRICT
);
ALTER TABLE sumup_reader_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE sumup_reader_payments FORCE ROW LEVEL SECURITY;
CREATE POLICY sumup_reader_payments_access ON sumup_reader_payments
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
        OR webhook_token_hash = current_setting('app.sumup_webhook_token_hash', TRUE))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE google_calendar_connections (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    calendar_id TEXT NOT NULL DEFAULT 'primary',
    refresh_token_enc TEXT NOT NULL,
    access_token_enc TEXT,
    token_expires_at TIMESTAMPTZ,
    sync_token TEXT,
    connection_status TEXT NOT NULL DEFAULT 'connected'
        CHECK (connection_status IN ('connected', 'reauthorize', 'revoked')),
    connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, business_id),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT
);
ALTER TABLE google_calendar_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE google_calendar_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY google_calendar_connections_tenant_isolation ON google_calendar_connections
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE google_calendar_oauth_states (
    state UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    business_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes',
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE google_calendar_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE google_calendar_oauth_states FORCE ROW LEVEL SECURITY;
CREATE POLICY google_calendar_oauth_states_access ON google_calendar_oauth_states
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
        OR state::text = current_setting('app.google_oauth_state', TRUE))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE appointments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    external_event_id TEXT,
    source TEXT NOT NULL DEFAULT 'tomos' CHECK (source IN ('tomos', 'google')),
    summary TEXT NOT NULL CHECK (length(trim(summary)) BETWEEN 1 AND 240),
    description TEXT,
    location TEXT,
    customer_name TEXT,
    customer_email TEXT,
    start_at TIMESTAMPTZ NOT NULL,
    end_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed', 'cancelled')),
    last_synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    CHECK (end_at > start_at),
    UNIQUE (tenant_id, business_id, external_event_id)
);
CREATE INDEX appointments_calendar_idx ON appointments(tenant_id, business_id, start_at);
ALTER TABLE appointments ENABLE ROW LEVEL SECURITY;
ALTER TABLE appointments FORCE ROW LEVEL SECURITY;
CREATE POLICY appointments_tenant_isolation ON appointments
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE pos_customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    customer_number BIGINT GENERATED BY DEFAULT AS IDENTITY,
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 160),
    email TEXT,
    phone TEXT,
    sumup_customer_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, business_id, id)
);
CREATE INDEX pos_customers_search_idx ON pos_customers(tenant_id, business_id, lower(display_name));
ALTER TABLE pos_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE pos_customers FORCE ROW LEVEL SECURITY;
CREATE POLICY pos_customers_tenant_isolation ON pos_customers
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

ALTER TABLE sales ADD COLUMN customer_id UUID;
ALTER TABLE sales ADD CONSTRAINT sales_customer_business_fk
    FOREIGN KEY (tenant_id, business_id, customer_id)
    REFERENCES pos_customers(tenant_id, business_id, id) ON DELETE RESTRICT;

CREATE TABLE loyalty_programs (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    points_per_major_unit INTEGER NOT NULL DEFAULT 1 CHECK (points_per_major_unit BETWEEN 0 AND 10000),
    redemption_points_per_major_unit INTEGER NOT NULL DEFAULT 100 CHECK (redemption_points_per_major_unit BETWEEN 1 AND 100000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, business_id),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT
);
ALTER TABLE loyalty_programs ENABLE ROW LEVEL SECURITY;
ALTER TABLE loyalty_programs FORCE ROW LEVEL SECURITY;
CREATE POLICY loyalty_programs_tenant_isolation ON loyalty_programs
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE loyalty_accounts (
    tenant_id UUID NOT NULL,
    business_id UUID NOT NULL,
    customer_id UUID NOT NULL,
    balance_points BIGINT NOT NULL DEFAULT 0 CHECK (balance_points >= 0),
    lifetime_earned BIGINT NOT NULL DEFAULT 0 CHECK (lifetime_earned >= 0),
    lifetime_redeemed BIGINT NOT NULL DEFAULT 0 CHECK (lifetime_redeemed >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, business_id, customer_id),
    FOREIGN KEY (tenant_id, business_id, customer_id)
        REFERENCES pos_customers(tenant_id, business_id, id) ON DELETE RESTRICT
);
ALTER TABLE loyalty_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE loyalty_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY loyalty_accounts_tenant_isolation ON loyalty_accounts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE loyalty_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    business_id UUID NOT NULL,
    customer_id UUID NOT NULL,
    sale_id UUID,
    entry_type TEXT NOT NULL CHECK (entry_type IN ('earned', 'redeemed', 'adjusted')),
    points_delta BIGINT NOT NULL CHECK (points_delta <> 0),
    note TEXT,
    created_by UUID REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, business_id, customer_id)
        REFERENCES pos_customers(tenant_id, business_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, sale_id) REFERENCES sales(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, sale_id, entry_type)
);
CREATE INDEX loyalty_ledger_customer_idx ON loyalty_ledger(tenant_id, business_id, customer_id, created_at DESC);
ALTER TABLE loyalty_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE loyalty_ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY loyalty_ledger_tenant_isolation ON loyalty_ledger
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE TABLE loyalty_redemptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    business_id UUID NOT NULL,
    customer_id UUID NOT NULL,
    reward_code TEXT NOT NULL UNIQUE,
    points_redeemed BIGINT NOT NULL CHECK (points_redeemed > 0),
    reward_value_minor BIGINT NOT NULL CHECK (reward_value_minor > 0),
    status TEXT NOT NULL DEFAULT 'issued' CHECK (status IN ('issued', 'reserved', 'redeemed', 'expired')),
    reserved_sale_id UUID,
    redeemed_sale_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    redeemed_at TIMESTAMPTZ,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, business_id, customer_id)
        REFERENCES pos_customers(tenant_id, business_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, reserved_sale_id) REFERENCES sales(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, redeemed_sale_id) REFERENCES sales(tenant_id, id) ON DELETE RESTRICT,
    CHECK ((status = 'reserved' AND reserved_sale_id IS NOT NULL AND redeemed_sale_id IS NULL)
        OR (status = 'redeemed' AND reserved_sale_id IS NULL AND redeemed_sale_id IS NOT NULL)
        OR (status IN ('issued', 'expired') AND reserved_sale_id IS NULL AND redeemed_sale_id IS NULL))
);
ALTER TABLE sales
    ADD COLUMN discount_minor BIGINT NOT NULL DEFAULT 0 CHECK (discount_minor >= 0),
    ADD COLUMN discount_tax_minor BIGINT NOT NULL DEFAULT 0 CHECK (discount_tax_minor >= 0 AND discount_tax_minor <= discount_minor),
    ADD COLUMN loyalty_redemption_id UUID;
ALTER TABLE sales ADD CONSTRAINT sales_loyalty_redemption_fk
    FOREIGN KEY (tenant_id, loyalty_redemption_id)
    REFERENCES loyalty_redemptions(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE loyalty_redemptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE loyalty_redemptions FORCE ROW LEVEL SECURITY;
CREATE POLICY loyalty_redemptions_tenant_isolation ON loyalty_redemptions
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

CREATE OR REPLACE FUNCTION award_loyalty_points_for_sale() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    earn_rate INTEGER;
    earned BIGINT;
BEGIN
    IF NEW.status <> 'completed' OR NEW.customer_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'completed' THEN
        RETURN NEW;
    END IF;
    SELECT points_per_major_unit INTO earn_rate
      FROM loyalty_programs
     WHERE tenant_id = NEW.tenant_id AND business_id = NEW.business_id AND enabled = TRUE;
    IF NOT FOUND OR earn_rate <= 0 THEN
        RETURN NEW;
    END IF;
    earned := floor(NEW.total_minor::numeric * earn_rate / 100)::bigint;
    IF earned <= 0 THEN
        RETURN NEW;
    END IF;
    INSERT INTO loyalty_accounts (tenant_id, business_id, customer_id, balance_points, lifetime_earned)
    VALUES (NEW.tenant_id, NEW.business_id, NEW.customer_id, earned, earned)
    ON CONFLICT (tenant_id, business_id, customer_id) DO UPDATE
       SET balance_points = loyalty_accounts.balance_points + EXCLUDED.balance_points,
           lifetime_earned = loyalty_accounts.lifetime_earned + EXCLUDED.lifetime_earned,
           updated_at = now();
    INSERT INTO loyalty_ledger (tenant_id, business_id, customer_id, sale_id, entry_type, points_delta, note)
    VALUES (NEW.tenant_id, NEW.business_id, NEW.customer_id, NEW.id, 'earned', earned, 'Points earned from completed sale')
    ON CONFLICT (tenant_id, sale_id, entry_type) DO NOTHING;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sales_award_loyalty_points
AFTER INSERT OR UPDATE OF status ON sales
FOR EACH ROW EXECUTE FUNCTION award_loyalty_points_for_sale();
