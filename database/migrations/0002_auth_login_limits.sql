-- M2 security hardening: persistent per-account login throttling.
CREATE TABLE auth_login_limits (
    identifier_hash TEXT PRIMARY KEY,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    blocked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_login_limits_updated_idx ON auth_login_limits(updated_at);
