-- Permit an authenticated user to discover only their own active tenant memberships.
-- Middleware sets app.user_id after validating the session, then resolves the requested tenant.
DROP POLICY memberships_tenant_isolation ON tenant_memberships;
CREATE POLICY memberships_tenant_isolation ON tenant_memberships
    USING (
        tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
        OR user_id = NULLIF(current_setting('app.user_id', TRUE), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::uuid
    );
