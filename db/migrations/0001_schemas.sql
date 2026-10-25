-- F-001 T-02: base schemas and the protected authorization key store.
-- Applied by scripts/db-migrate.sh as app_migrator under SET ROLE fair_owner.

CREATE SCHEMA IF NOT EXISTS iam   AUTHORIZATION fair_owner;
CREATE SCHEMA IF NOT EXISTS authz AUTHORIZATION fair_owner;

REVOKE ALL ON SCHEMA iam   FROM PUBLIC;
REVOKE ALL ON SCHEMA authz FROM PUBLIC;

-- Application roles may use the schemas but never create objects in them.
GRANT USAGE ON SCHEMA iam   TO app_rw, app_engine;
GRANT USAGE ON SCHEMA authz TO app_rw, app_engine, authz_definer;

-- ADR-007: HMAC keys for the signed database context. Application roles have
-- NO privileges on this table; only SECURITY DEFINER functions owned by
-- authz_definer (F-001 T-09) may read it.
CREATE TABLE IF NOT EXISTS authz.ctx_key (
  key_id      text        PRIMARY KEY,
  secret      bytea       NOT NULL CHECK (octet_length(secret) >= 32),
  created_at  timestamptz NOT NULL DEFAULT now(),
  retired_at  timestamptz
);
REVOKE ALL ON authz.ctx_key FROM PUBLIC;
GRANT SELECT ON authz.ctx_key TO authz_definer;

-- Default privileges for future objects created by fair_owner in iam:
-- nothing is granted automatically. Each migration grants explicitly.
ALTER DEFAULT PRIVILEGES FOR ROLE fair_owner IN SCHEMA iam   REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE fair_owner IN SCHEMA authz REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE fair_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
