-- 0001 foundations (F-001 T-02, AC-27, ADR-007)
-- Runs as app_migrator with SET ROLE fair_owner already applied by the runner.

-- Identity data (F-001 design §3). Tables arrive in Phase 1+.
CREATE SCHEMA iam AUTHORIZATION fair_owner;
REVOKE ALL ON SCHEMA iam FROM PUBLIC;
GRANT USAGE ON SCHEMA iam TO app_rw, app_engine;

-- Authorization internals (ADR-007): owned by authz_definer, not fair_owner,
-- so even the table owner role cannot read the HMAC key.
SET LOCAL ROLE authz_definer;

CREATE SCHEMA authz AUTHORIZATION authz_definer;
REVOKE ALL ON SCHEMA authz FROM PUBLIC;
-- Apps need USAGE to call authz.visible_bus() (T-09); they get no table grants.
GRANT USAGE ON SCHEMA authz TO app_rw, app_engine;

-- HMAC keys for the signed DB context. Two keys are valid during rotation;
-- tokens carry key_id. Readable only by authz_definer (and therefore only by
-- SECURITY DEFINER functions it owns). Populated at install from KMS/Vault.
CREATE TABLE authz.ctx_key (
    key_id      text        PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    secret      bytea       NOT NULL CHECK (octet_length(secret) >= 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz
);
REVOKE ALL ON TABLE authz.ctx_key FROM PUBLIC;

-- Functions created in authz default to no EXECUTE for PUBLIC; each one is
-- granted explicitly.
ALTER DEFAULT PRIVILEGES FOR ROLE authz_definer REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

SET LOCAL ROLE fair_owner;
ALTER DEFAULT PRIVILEGES FOR ROLE fair_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
