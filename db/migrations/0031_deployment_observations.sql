-- F-015 T-29 (AC-41, design D-OQ2): how passing deployment subjects were
-- assessed, from scanner reports. For node FIPS mode: "verified" (the
-- node's fips-probe confirmed the kernel flag) or "attested" (declared at
-- install; OSCAL exports, T-33, say "attested, not verified"). Each report
-- replaces the observations of the checks it ran.

CREATE TABLE posture.deployment_observation (
  check_id     text        NOT NULL CHECK (check_id ~ '^[a-z][a-z0-9_]*$'),
  subject      text        NOT NULL CHECK (subject ~ '^deployment:' AND length(subject) <= 600),
  method       text        NOT NULL CHECK (method IN ('verified', 'attested')),
  detail       jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object'),
  observed_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (check_id, subject)
);
REVOKE ALL ON posture.deployment_observation FROM PUBLIC;
ALTER TABLE posture.deployment_observation ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.deployment_observation FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.deployment_observation TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, DELETE ON posture.deployment_observation TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Replaces the observations of the given checks (called in the same
-- transaction as the scan's findings). observations: [{check_id, subject,
-- method, detail}], each for one of checks.
CREATE FUNCTION posture.record_deployment_observations(checks text[], observations jsonb) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  n integer;
BEGIN
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(observations, '[]')) o WHERE NOT (o ->> 'check_id') = ANY (checks)) THEN
    RAISE EXCEPTION 'observation for a check outside this scan' USING ERRCODE = 'PF004';
  END IF;
  DELETE FROM posture.deployment_observation d WHERE d.check_id = ANY (checks);
  INSERT INTO posture.deployment_observation (check_id, subject, method, detail)
  SELECT o ->> 'check_id', o ->> 'subject', o ->> 'method', coalesce(o -> 'detail', '{}')
  FROM jsonb_array_elements(coalesce(observations, '[]')) o;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

-- Observations for the Posture page and the OSCAL export.
CREATE FUNCTION posture.deployment_observations()
RETURNS TABLE (check_id text, subject text, method text, detail jsonb, observed_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT d.check_id, d.subject, d.method, d.detail, d.observed_at
  FROM posture.deployment_observation d ORDER BY d.check_id, d.subject;
$$;

REVOKE ALL ON FUNCTION posture.record_deployment_observations(text[], jsonb), posture.deployment_observations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.record_deployment_observations(text[], jsonb), posture.deployment_observations() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
