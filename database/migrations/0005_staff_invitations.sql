-- Single-use, time-limited staff invitations. The raw bearer token is never stored.
CREATE TABLE staff_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    email_normalized TEXT NOT NULL,
    role_id UUID NOT NULL,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    membership_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, membership_id)
        REFERENCES tenant_memberships(tenant_id, id) ON DELETE RESTRICT,
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX staff_invitations_tenant_email_idx
    ON staff_invitations(tenant_id, email_normalized, expires_at DESC);

ALTER TABLE staff_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff_invitations FORCE ROW LEVEL SECURITY;

-- Acceptance can locate exactly one invitation by its presented token digest
-- before tenant context is known. All subsequent access is tenant-scoped.
CREATE POLICY staff_invitations_tenant_isolation ON staff_invitations
    USING (
        tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
        OR token_hash = NULLIF(current_setting('app.invitation_token_hash', TRUE), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
    );
