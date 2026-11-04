-- F-002 T-05 (design §2, §4.3): the audit service's database role.
--
-- app_audit (bootstrap: FAIR_AUDIT_PASSWORD_FILE) reaches the trail only
-- through audit_definer's functions, as the other services do. It records
-- its own events with audit.submit; the sequencer, checkpoint, verification,
-- retention and read functions are granted to it with the tasks that add
-- them (T-07 onward).

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_audit') THEN
    RAISE EXCEPTION 'role app_audit is missing: re-run scripts/db-bootstrap.sh with FAIR_AUDIT_PASSWORD_FILE (F-002 T-05)';
  END IF;
END $$;

GRANT USAGE ON SCHEMA audit TO app_audit;

-- audit_definer owns audit.submit, so it grants it.
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.submit(jsonb) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
