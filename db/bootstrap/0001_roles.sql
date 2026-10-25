-- F-001 T-02 / ADR-007: database roles.
--
-- Run ONCE per database by the installer or platform DBA with a privileged
-- account, never by the application. Idempotent. Passwords are supplied as psql
-- variables read from secret files by scripts/db-bootstrap.sh, never committed.
--
-- Roles:
--   fair_owner     NOLOGIN  owns all schemas and tables; cannot log in
--   authz_definer  NOLOGIN  owns SECURITY DEFINER authorization functions (Phase 1)
--   app_migrator   LOGIN    runs migrations by explicitly SET ROLE fair_owner
--   app_rw         LOGIN    application services; NOBYPASSRLS; owns nothing
--   app_engine     LOGIN    Python simulation engine; NOBYPASSRLS; narrower grants
--
-- Required psql variables: dbname, migrator_password, rw_password, engine_password

\set ON_ERROR_STOP on

DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['fair_owner', 'authz_definer'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
    END IF;
    EXECUTE format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;

  FOREACH r IN ARRAY ARRAY['app_migrator', 'app_rw', 'app_engine'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
    END IF;
    -- Re-assert attributes every run so drift (e.g. someone granting BYPASSRLS) is corrected.
    EXECUTE format('ALTER ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;
END
$$;

ALTER ROLE app_migrator PASSWORD :'migrator_password';
ALTER ROLE app_rw       PASSWORD :'rw_password';
ALTER ROLE app_engine   PASSWORD :'engine_password';

ALTER ROLE app_rw     CONNECTION LIMIT 200;
ALTER ROLE app_engine CONNECTION LIMIT 100;

-- The migrator may become fair_owner only by an explicit SET ROLE (no inherited privileges).
GRANT fair_owner TO app_migrator WITH INHERIT FALSE, SET TRUE;

-- Lock down the database: nobody connects unless granted.
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO app_migrator, app_rw, app_engine;
GRANT CREATE ON DATABASE :"dbname" TO fair_owner;

-- No objects in the public schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Row-level security must never be silently disabled for application roles.
ALTER ROLE app_rw     SET row_security = on;
ALTER ROLE app_engine SET row_security = on;
