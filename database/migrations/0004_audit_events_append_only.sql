-- M2 security hardening: audit records are append-only.
-- Corrections must be represented by a new event, never by rewriting history.

CREATE OR REPLACE FUNCTION prevent_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only; % is not permitted', TG_OP
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_no_row_mutation
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_event_mutation();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION prevent_audit_event_mutation();

COMMENT ON FUNCTION prevent_audit_event_mutation() IS
    'Rejects UPDATE, DELETE and TRUNCATE operations on the audit event ledger.';
COMMENT ON TABLE audit_events IS
    'Tenant-scoped append-only audit ledger. Corrections are recorded as new events.';
