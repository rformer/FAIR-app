-- F-011 T-15 (design §2): the integrate service's database role, as the
-- notify service's (migration 0125).
--
-- app_integrate (bootstrap: FAIR_INTEGRATE_PASSWORD_FILE) records its own
-- events with audit.submit, registers and reads F-011's settings as every
-- service does (settings.Client), and loads callers' grants for the
-- integrations API (authz.grant_snapshot, T-16). The integration functions
-- it calls were granted with their tasks (migrations 0147, 0148); it reads
-- no table itself.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_integrate') THEN
    RAISE EXCEPTION 'role app_integrate is missing: re-run scripts/db-bootstrap.sh with FAIR_INTEGRATE_PASSWORD_FILE (F-011 T-03)';
  END IF;
END $$;

GRANT USAGE ON SCHEMA audit, posture, authz TO app_integrate;

SET ROLE audit_definer; -- the owner of audit.submit
GRANT EXECUTE ON FUNCTION audit.submit(jsonb) TO app_integrate;
RESET ROLE;
SET LOCAL ROLE fair_owner;

SET ROLE posture_definer; -- the owner of the settings functions
GRANT EXECUTE ON FUNCTION posture.effective_settings(), posture.settings_version(), posture.register_settings(text, text, jsonb) TO app_integrate;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT EXECUTE ON FUNCTION authz.grant_snapshot() TO app_integrate;
