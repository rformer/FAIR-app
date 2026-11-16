-- F-009 T-03 (design §2): the notify service's database role, as the audit
-- service's (migration 0069).
--
-- app_notify (bootstrap: FAIR_NOTIFY_PASSWORD_FILE) records its own events
-- with audit.submit, registers and reads F-009's settings as every service
-- does (settings.Client), and loads callers' grants for the notifications
-- API (authz.grant_snapshot, T-06). The notify functions are granted to it
-- with the tasks that add them (T-04 onward); it reads no table itself.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_notify') THEN
    RAISE EXCEPTION 'role app_notify is missing: re-run scripts/db-bootstrap.sh with FAIR_NOTIFY_PASSWORD_FILE (F-009 T-02)';
  END IF;
END $$;

GRANT USAGE ON SCHEMA audit, posture, authz TO app_notify;

SET ROLE audit_definer; -- the owner of audit.submit
GRANT EXECUTE ON FUNCTION audit.submit(jsonb) TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;

SET ROLE posture_definer; -- the owner of the settings functions
GRANT EXECUTE ON FUNCTION posture.effective_settings(), posture.settings_version(), posture.register_settings(text, text, jsonb) TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT EXECUTE ON FUNCTION authz.grant_snapshot() TO app_notify;
