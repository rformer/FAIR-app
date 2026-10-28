-- F-015 T-37 (design §11 deployment modes): air-gapped becomes a deployment
-- mode of its own (approved by Robert Former, 2026-10-28; ADR-005 amended).
-- In the database it behaves as self-hosted: every posture rule that
-- differs by mode tests for 'saas'. The services add what is specific to
-- air-gapped installs (no outbound integrations, in-cluster TLS probing).
--
-- Also: posture.mac_key_active(), so the posture service can refuse to
-- start in production without an active row-MAC key (the per-mode key
-- checks, T-37).

ALTER TABLE posture.state DROP CONSTRAINT state_deployment_mode_check;
ALTER TABLE posture.state ADD CONSTRAINT state_deployment_mode_check
  CHECK (deployment_mode IN ('saas', 'self-hosted', 'air-gapped'));

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

CREATE OR REPLACE FUNCTION posture.set_deployment_mode(mode text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF mode IS NULL OR mode NOT IN ('saas', 'self-hosted', 'air-gapped') THEN
    RAISE EXCEPTION 'deployment mode must be saas, self-hosted or air-gapped' USING ERRCODE = 'PF004';
  END IF;
  UPDATE posture.state SET deployment_mode = mode;
END $$;

-- The key that signs new rows (NULL when none is active). Key material
-- never leaves the database.
CREATE FUNCTION posture.mac_key_active() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT key_id FROM posture.mac_key WHERE retired_at IS NULL ORDER BY created_at DESC, key_id LIMIT 1;
$$;

REVOKE ALL ON FUNCTION posture.mac_key_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.mac_key_active() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
