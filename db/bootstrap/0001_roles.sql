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
--   posture_definer NOLOGIN owns the SECURITY DEFINER posture functions (F-015)
--   app_posture    LOGIN    the posture service (F-015); NOBYPASSRLS; owns nothing
--   rollup_definer NOLOGIN  owns the features' roll-up functions (F-001 T-30): the
--                           only role that reads aggregate-only restricted BU rows
--   bu_guard_definer NOLOGIN owns the archive guard's count (F-001 T-31): counts
--                           a BU's rows in every BU-owned table, never returns them
--   app_gateway    LOGIN    the gateway (F-001 T-13): sessions and DB contexts
--                           only, through SECURITY DEFINER functions; NOBYPASSRLS
--   audit_definer  NOLOGIN  owns the audit trail's tables and SECURITY DEFINER
--                           functions (F-002 T-02); append-only by trigger
--   app_audit      LOGIN    the audit service (F-002 T-05): the trail only
--                           through audit_definer's functions; NOBYPASSRLS
--   risk_definer   NOLOGIN  owns the risk schema's trigger functions (F-003 T-03):
--                           version checks, head advances, pins; subject to RLS
--   estimate_definer NOLOGIN owns the estimate schema's functions (F-004 T-04):
--                           estimators' and jobs' access to requests, answers,
--                           calibration; RLS admits it only where a table
--                           allows it (ADR-007 amendment 3)
--   analysis_definer NOLOGIN owns the analysis schema's functions (F-005 T-02):
--                           requests' checks, the worker's state changes,
--                           cancellation; RLS admits it only where a table
--                           allows it (ADR-007 amendment 3)
--
-- Required psql variables: dbname, migrator_password, rw_password,
-- engine_password, posture_password, gateway_password, audit_password

\set ON_ERROR_STOP on

DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['fair_owner', 'authz_definer', 'posture_definer', 'rollup_definer', 'bu_guard_definer', 'audit_definer', 'risk_definer', 'estimate_definer', 'analysis_definer'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
    END IF;
    EXECUTE format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r);
  END LOOP;

  FOREACH r IN ARRAY ARRAY['app_migrator', 'app_rw', 'app_engine', 'app_posture', 'app_gateway', 'app_audit'] LOOP
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
ALTER ROLE app_posture  PASSWORD :'posture_password';
ALTER ROLE app_gateway  PASSWORD :'gateway_password';
ALTER ROLE app_audit    PASSWORD :'audit_password';

ALTER ROLE app_rw      CONNECTION LIMIT 200;
ALTER ROLE app_engine  CONNECTION LIMIT 100;
ALTER ROLE app_posture CONNECTION LIMIT 50;
ALTER ROLE app_gateway CONNECTION LIMIT 100;
ALTER ROLE app_audit   CONNECTION LIMIT 50;

-- The migrator may become fair_owner only by an explicit SET ROLE (no inherited privileges).
GRANT fair_owner TO app_migrator WITH INHERIT FALSE, SET TRUE;

-- Migrations (as fair_owner) hand the signed-context functions to
-- authz_definer (F-001 T-09), which needs SET on that role. fair_owner already
-- owns everything authz_definer can read, so this widens nothing.
GRANT authz_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;
-- Likewise for the posture functions (F-015 T-08; design §5 access model).
GRANT posture_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;
-- Likewise for roll-up functions (F-001 T-30).
GRANT rollup_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;
-- And for the archive guard (F-001 T-31).
GRANT bu_guard_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;
-- And for the audit trail (F-002 T-02).
GRANT audit_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;
-- And for the risk data model (F-003 T-03).
GRANT risk_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;
-- And for estimate capture (F-004 T-04).
GRANT estimate_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;
-- And for simulation (F-005 T-02).
GRANT analysis_definer TO fair_owner WITH INHERIT FALSE, SET TRUE;

-- Lock down the database: nobody connects unless granted.
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO app_migrator, app_rw, app_engine, app_posture, app_gateway, app_audit;
GRANT CREATE ON DATABASE :"dbname" TO fair_owner;

-- No objects in the public schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Row-level security must never be silently disabled for application roles.
ALTER ROLE app_rw     SET row_security = on;
ALTER ROLE app_engine SET row_security = on;
ALTER ROLE app_posture SET row_security = on;
ALTER ROLE app_gateway SET row_security = on;
ALTER ROLE app_audit   SET row_security = on;
