-- F-015 T-36 (design §8, "Tampering: exception expiry extended by editing
-- the DB"): row MACs on exceptions.
--
-- §8 lists a MAC on exception rows among the mitigations; until now only
-- setting_value and overlay_value carried one, so an expiry extended with a
-- direct UPDATE went unnoticed. Every exception row now carries
-- HMAC-SHA-256 (the current posture MAC key) over its identity, value,
-- justification, people, times, lineage and state.
--
-- The MAC is computed by a trigger, but only when the writer is
-- posture_definer, i.e. inside the posture functions. A direct edit by any
-- other role (a DBA, superuser or not) leaves the old MAC, and drift check 1
-- reports row_mac_mismatch on "exception:<id>" (critical). Later posture
-- updates (supersede, revert) never re-sign a row whose MAC is wrong, so the
-- finding stays until people review it (acknowledge). As for the other
-- MACs, an attacker who is a superuser and reads the key, or who assumes
-- posture_definer, can forge one: that is the documented residual risk of
-- an in-database key (KMS custody is D-OQ5).
--
-- Times are hashed as epoch seconds, so the MAC does not depend on the
-- session's TimeZone.

ALTER TABLE posture.exception
  ADD COLUMN mac_key_id text REFERENCES posture.mac_key (key_id),
  ADD COLUMN row_mac    bytea;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

CREATE FUNCTION posture.exception_mac_input(e posture.exception) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT convert_to(jsonb_build_array('exception', e.id, e.key, e.bu_id, e.overlay, e.value, e.bound_at_creation,
    e.justification, e.owner_id, e.approved_by, extract(epoch FROM e.created_at), extract(epoch FROM e.expires_at),
    e.renewed_from, e.state)::text, 'UTF8');
$$;

CREATE FUNCTION posture.exception_set_mac() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  k posture.mac_key;
BEGIN
  IF current_user <> 'posture_definer' THEN
    RETURN NEW; -- not a posture function: keep the old MAC, so drift sees the edit
  END IF;
  -- Never launder: a row whose MAC is wrong (edited outside posture) keeps
  -- it through later posture updates, so the evidence stays until reviewed.
  -- A row left unsigned while no key was active (NULL) is signed again.
  IF TG_OP = 'UPDATE' AND OLD.row_mac IS NOT NULL THEN
    SELECT * INTO k FROM posture.mac_key WHERE key_id = OLD.mac_key_id;
    IF NOT FOUND OR OLD.row_mac <> authz.hmac(posture.exception_mac_input(OLD), k.secret, 'sha256') THEN
      NEW.mac_key_id := OLD.mac_key_id;
      NEW.row_mac := OLD.row_mac;
      RETURN NEW;
    END IF;
  END IF;
  SELECT * INTO k FROM posture.mac_key WHERE retired_at IS NULL ORDER BY created_at DESC, key_id LIMIT 1;
  IF NOT FOUND THEN
    -- No new exception without a key. An update (the revert loop recording
    -- a failure, which may be this very fault) still goes through, unsigned:
    -- drift reports the row until the next update with a key re-signs it.
    IF TG_OP = 'INSERT' THEN
      RAISE EXCEPTION 'no active posture MAC key (install one with posture.add_mac_key)' USING ERRCODE = 'PF006';
    END IF;
    NEW.mac_key_id := NULL;
    NEW.row_mac := NULL;
    RETURN NEW;
  END IF;
  NEW.mac_key_id := k.key_id;
  NEW.row_mac := authz.hmac(posture.exception_mac_input(NEW), k.secret, 'sha256');
  RETURN NEW;
END $$;

-- The table's owner creates the trigger; posture_definer owns its function.
RESET ROLE;
SET LOCAL ROLE fair_owner;
CREATE TRIGGER exception_mac BEFORE INSERT OR UPDATE ON posture.exception
  FOR EACH ROW EXECUTE FUNCTION posture.exception_set_mac();
SET ROLE posture_definer;

-- Existing rows, signed once as posture_definer (no-op UPDATE fires the
-- trigger).
UPDATE posture.exception SET state = state;

-- Exception rows join check 1, as "exception:<id>".
CREATE OR REPLACE FUNCTION posture.mac_mismatches() RETURNS TABLE (key text, bu_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT x.key, x.bu_id FROM (
    SELECT s.key, s.bu_id FROM posture.setting_value s
    LEFT JOIN posture.mac_key m ON m.key_id = s.mac_key_id
    WHERE m.key_id IS NULL
       OR s.row_mac <> authz.hmac(convert_to(jsonb_build_array(s.key, s.bu_id, s.value, s.source, s.change_id, s.exception_id)::text, 'UTF8'), m.secret, 'sha256')
    UNION ALL
    SELECT 'overlay:' || o.key, NULL::uuid FROM posture.overlay_value o
    LEFT JOIN posture.mac_key m ON m.key_id = o.mac_key_id
    WHERE m.key_id IS NULL
       OR o.row_mac <> authz.hmac(convert_to(jsonb_build_array('overlay:' || o.key, NULL::uuid, o.value, o.source, o.change_id, o.exception_id)::text, 'UTF8'), m.secret, 'sha256')
    UNION ALL
    SELECT 'exception:' || e.id, e.bu_id FROM posture.exception e
    LEFT JOIN posture.mac_key m ON m.key_id = e.mac_key_id
    WHERE m.key_id IS NULL OR e.row_mac IS NULL
       OR e.row_mac <> authz.hmac(posture.exception_mac_input(e), m.secret, 'sha256')
  ) x
  ORDER BY x.key, x.bu_id NULLS FIRST;
$$;

-- Checks 1-3 (0028), with exception rows reported under their own subject
-- and remediation.
CREATE OR REPLACE FUNCTION posture.drift_scan(revert_grace interval DEFAULT interval '1 minute')
RETURNS TABLE (check_id text, severity text, controls text[], subject text, detail jsonb, remediation text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH ap AS (
    SELECT a.profile_id, a.version, p.family FROM posture.active_profile a
    JOIN posture.profile p ON p.id = a.profile_id AND p.version = a.version),
  vals AS (
    SELECT s.key, s.bu_id, s.value, s.source, pv.bound, ap.family,
           posture.below_floor(d, ap.family, s.value) AS below_floor,
           posture.compare(d, s.value, pv.bound) < 0 AS weaker,
           s.source = 'exception' AND EXISTS (
             SELECT 1 FROM posture.exception e
             WHERE e.id = s.exception_id AND e.key = s.key AND e.bu_id IS NOT DISTINCT FROM s.bu_id AND NOT e.overlay
               AND e.state IN ('active', 'revert_failed') AND e.value = s.value) AS covered
    FROM posture.setting_value s
    JOIN posture.setting_def d ON d.key = s.key
    CROSS JOIN ap
    JOIN posture.profile_value pv ON pv.profile_id = ap.profile_id AND pv.version = ap.version AND pv.key = s.key),
  ovals AS (
    SELECT o.key, o.value, posture.overlay_defaults() -> o.key AS bound, ap.family,
           posture.below_floor(d, ap.family, o.value) AS below_floor,
           posture.compare(d, o.value, posture.overlay_defaults() -> o.key) < 0 AS weaker,
           o.source = 'exception' AND EXISTS (
             SELECT 1 FROM posture.exception e
             WHERE e.id = o.exception_id AND e.key = o.key AND e.overlay
               AND e.state IN ('active', 'revert_failed') AND e.value = o.value) AS covered
    FROM posture.overlay_value o
    JOIN posture.setting_def d ON d.key = o.key
    CROSS JOIN ap)
  SELECT 'row_mac_mismatch', 'critical', ARRAY['CM-5', 'CM-6', 'SI-7'],
         CASE WHEN m.key LIKE 'overlay:%' OR m.key LIKE 'exception:%' THEN m.key ELSE posture.setting_subject(m.key, m.bu_id) END,
         jsonb_build_object('key', m.key, 'bu_id', m.bu_id),
         CASE WHEN m.key LIKE 'exception:%'
           THEN 'An exception record (its expiry, value, approver or state) was changed outside the posture service. Review the database audit log; treat the exception as untrusted and have it re-approved or revoked.'
           ELSE 'The stored value was changed outside the posture service. Review the database audit log, then set the value again through the Posture page or API.' END
  FROM posture.mac_mismatches() m
  UNION ALL
  SELECT 'hard_floor_violation', 'critical', ARRAY['CM-6', 'CM-7'], posture.setting_subject(v.key, v.bu_id),
         jsonb_build_object('key', v.key, 'bu_id', v.bu_id, 'value', v.value, 'source', v.source, 'profile_family', v.family),
         'A value below the hard floor is in force. Set it back to at least the floor at once; no exception can cover it.'
  FROM vals v WHERE v.below_floor
  UNION ALL
  SELECT 'unapproved_deviation', 'high', ARRAY['CM-3', 'CM-6'], posture.setting_subject(v.key, v.bu_id),
         jsonb_build_object('key', v.key, 'bu_id', v.bu_id, 'value', v.value, 'bound', v.bound, 'source', v.source),
         'The value is weaker than the active profile allows and no approved exception covers it. Tighten it, or request an exception.'
  FROM vals v WHERE NOT v.below_floor AND v.weaker AND NOT v.covered
  UNION ALL
  SELECT 'hard_floor_violation', 'critical', ARRAY['CM-6', 'CM-7'], 'overlay:' || o.key,
         jsonb_build_object('key', o.key, 'overlay', true, 'value', o.value, 'profile_family', o.family),
         'A Restricted BU overlay value below the hard floor is in force. Set it back to at least the floor at once.'
  FROM ovals o WHERE o.below_floor
  UNION ALL
  SELECT 'unapproved_deviation', 'high', ARRAY['CM-3', 'CM-6'], 'overlay:' || o.key,
         jsonb_build_object('key', o.key, 'overlay', true, 'value', o.value, 'bound', o.bound),
         'The Restricted BU overlay value is weaker than its default and no approved exception covers it. Tighten it, or request an exception.'
  FROM ovals o WHERE NOT o.below_floor AND o.weaker AND NOT o.covered
  UNION ALL
  SELECT 'missed_revert', 'high', ARRAY['CA-5', 'CM-6'], 'exception:' || e.id,
         jsonb_build_object('exception_id', e.id, 'key', e.key, 'bu_id', e.bu_id, 'overlay', e.overlay, 'value', e.value, 'expired_at', e.expires_at),
         'An expired exception has not been reverted. Check that the posture service is running; the revert runs automatically.'
  FROM posture.exception e WHERE e.state = 'active' AND e.expires_at < now() - revert_grace;
$$;

REVOKE ALL ON FUNCTION posture.exception_mac_input(posture.exception), posture.exception_set_mac() FROM PUBLIC;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
