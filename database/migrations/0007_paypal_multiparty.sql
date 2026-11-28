-- PayPal multiparty onboarding and checkout.
-- Each POS business connects its own PayPal Business account.

CREATE TABLE business_paypal_accounts (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    business_id UUID NOT NULL,
    merchant_id TEXT,
    onboarding_status TEXT NOT NULL DEFAULT 'not_connected'
        CHECK (onboarding_status IN ('not_connected', 'pending', 'connected', 'revoked')),
    permissions_granted BOOLEAN NOT NULL DEFAULT FALSE,
    consent_status BOOLEAN NOT NULL DEFAULT FALSE,
    connected_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, business_id),
    FOREIGN KEY (tenant_id, business_id) REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT,
    CHECK ((onboarding_status = 'connected' AND merchant_id IS NOT NULL
            AND permissions_granted AND consent_status AND connected_at IS NOT NULL)
        OR onboarding_status <> 'connected')
);

ALTER TABLE business_paypal_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE business_paypal_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY business_paypal_accounts_tenant_isolation ON business_paypal_accounts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid);

-- Opaque, short-lived correlation IDs let PayPal return the seller to the correct
-- tenant without exposing tenant IDs or requiring a logged-in browser callback.
-- This table intentionally has no tenant RLS; the random tracking_id is the
-- only lookup key and is generated server-side with UUID v4.
CREATE TABLE paypal_onboarding_sessions (
    tracking_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    business_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '30 minutes'),
    completed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, business_id)
        REFERENCES businesses(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX paypal_onboarding_sessions_expiry_idx
    ON paypal_onboarding_sessions(expires_at) WHERE completed_at IS NULL;

ALTER TABLE payment_tenders DROP CONSTRAINT payment_tenders_method_check;
ALTER TABLE payment_tenders ADD CONSTRAINT payment_tenders_method_check
    CHECK (method IN ('cash', 'card_terminal', 'paypal'));

ALTER TABLE payment_tenders DROP CONSTRAINT payment_tenders_check;
ALTER TABLE payment_tenders ADD CONSTRAINT payment_tenders_check CHECK (
    (method = 'cash' AND status = 'captured' AND amount_received_minor IS NOT NULL
        AND amount_received_minor >= amount_minor
        AND change_due_minor = amount_received_minor - amount_minor
        AND captured_at IS NOT NULL)
    OR
    (method IN ('card_terminal', 'paypal') AND amount_received_minor IS NULL
        AND change_due_minor = 0
        AND (status <> 'captured' OR captured_at IS NOT NULL))
);
