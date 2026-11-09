-- F-003 T-09 (F-003-AC-19, AC-20, AC-22; design §6.4, §6.7): moving
-- scenarios, archiving and restoring.
--
--   * risk.move_scenario(id, to_bu): the head, its versions and pins take
--     the new BU in one statement each, under the caller's RLS context: the
--     caller needs write scope at both BUs (USING the old, WITH CHECK the
--     new). A scenario inside a restricted subtree never leaves it (PF020).
--     Archived scenarios do not move (PF017). Documents and digests are
--     untouched (they do not hold the BU).
--   * risk.set_archived(kind, id, archived): archives or restores a
--     scenario, library entry or control: the head and, in step, its
--     versions and pins (archived_at), so archived data does not hold its
--     BU open (F-001 T-31: the version and pin tables are re-registered with
--     archived_at as their inactive column). Archived heads refuse new
--     versions (the version trigger, PF017). app_rw no longer updates
--     archived_at directly: every archive and restore goes through here and
--     is recorded with its reason by the service.
--   * Only risk_definer changes bu_id or archived_at of versions and pins,
--     and nothing else of them (PF018 for every other change, the owner's
--     included).
--   * Pins record the pinned entry's BU (to_bu_id; entries never move), and
--     risk.pin_reachable says, for a scenario version, which pins its BU
--     still reads by inheritance after a move (AC-20). It answers only for
--     pins the caller can see, and only whether each is reachable.

ALTER TABLE risk.scenario_version ADD COLUMN archived_at timestamptz;
ALTER TABLE risk.library_version ADD COLUMN archived_at timestamptz;
ALTER TABLE risk.control_version ADD COLUMN archived_at timestamptz;
ALTER TABLE risk.scenario_pin ADD COLUMN archived_at timestamptz, ADD COLUMN to_bu_id uuid;
ALTER TABLE risk.library_pin ADD COLUMN archived_at timestamptz, ADD COLUMN to_bu_id uuid;

SELECT authz.apply_bu_rls('risk.scenario_version', 'scenario', 'archived_at');
SELECT authz.apply_bu_rls('risk.scenario_pin', 'scenario', 'archived_at');
SELECT authz.apply_bu_rls('risk.library_version', 'library', 'archived_at', shared_down => true);
SELECT authz.apply_bu_rls('risk.library_pin', 'library', 'archived_at', shared_down => true);
SELECT authz.apply_bu_rls('risk.control_version', 'control', 'archived_at', shared_down => true);

REVOKE UPDATE (archived_at) ON risk.scenario, risk.library_entry, risk.control FROM app_rw;
GRANT UPDATE (bu_id, archived_at) ON risk.scenario, risk.scenario_version, risk.scenario_pin TO risk_definer;
GRANT UPDATE (archived_at) ON risk.library_entry, risk.library_version, risk.library_pin, risk.control, risk.control_version TO risk_definer;
GRANT EXECUTE ON FUNCTION iam.restricted_root(uuid) TO risk_definer;
GRANT SELECT ON iam.bu_closure TO risk_definer;

-- Heads: as in 0087, and risk_definer may move a head (bu_id) or archive it.
CREATE OR REPLACE FUNCTION risk.head_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  summary text[] := ARRAY['name', 'owner', 'asset_id', 'threat_community_id'];
  managed text[] := ARRAY['archived_at', 'current_version'] || CASE WHEN current_user = 'risk_definer' THEN ARRAY['bu_id'] ELSE '{}'::text[] END;
BEGIN
  IF (to_jsonb(NEW) - managed - summary) IS DISTINCT FROM (to_jsonb(OLD) - managed - summary)
     OR (NEW.current_version IS DISTINCT FROM OLD.current_version AND NEW.current_version IS DISTINCT FROM OLD.current_version + 1)
     OR ((to_jsonb(NEW) -> 'name', to_jsonb(NEW) -> 'owner', to_jsonb(NEW) -> 'asset_id', to_jsonb(NEW) -> 'threat_community_id')
         IS DISTINCT FROM (to_jsonb(OLD) -> 'name', to_jsonb(OLD) -> 'owner', to_jsonb(OLD) -> 'asset_id', to_jsonb(OLD) -> 'threat_community_id')
         AND NEW.current_version IS NOT DISTINCT FROM OLD.current_version) THEN
    RAISE EXCEPTION 'risk.%: only archived_at changes, and current_version and the summary only by a new version', TG_TABLE_NAME USING ERRCODE = 'PF018';
  END IF;
  RETURN NEW;
END $$;

GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;

-- Versions and pins never change, but for risk_definer moving or
-- archiving them (bu_id, archived_at); heads are never deleted (PF018).
CREATE OR REPLACE FUNCTION risk.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND current_user = 'risk_definer'
     AND (to_jsonb(NEW) - 'bu_id' - 'archived_at') IS NOT DISTINCT FROM (to_jsonb(OLD) - 'bu_id' - 'archived_at') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'risk.%: % refused; risk data versions are append-only and heads are archived, never deleted', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'PF018';
END $$;

-- As in 0088, and pins record the pinned entry's BU.
CREATE OR REPLACE FUNCTION risk.version_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  pin record;
  kind text;
  d jsonb := convert_from(NEW.document, 'UTF8')::jsonb;
  v record;
  members integer;
BEGIN
  kind := d ->> 'kind';
  FOR pin IN SELECT * FROM risk.document_pins(kind, d) LOOP
    IF pin.to_kind = 'control' THEN
      SELECT cv.digest, cv.document, c.bu_id INTO v FROM risk.control_version cv JOIN risk.control c ON c.id = cv.control_id
      WHERE cv.control_id = pin.to_id AND cv.version = pin.to_version;
    ELSE
      SELECT lv.digest, lv.document, e.bu_id INTO v FROM risk.library_version lv JOIN risk.library_entry e ON e.id = lv.entry_id
      WHERE lv.entry_id = pin.to_id AND lv.version = pin.to_version AND e.kind = pin.to_kind;
    END IF;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'risk.%: % pins %s % version %, which does not exist or is not visible', TG_TABLE_NAME, pin.pointer,
        pin.to_kind, pin.to_id, pin.to_version USING ERRCODE = 'PF016';
    END IF;
    IF TG_TABLE_NAME = 'scenario_version' THEN
      INSERT INTO risk.scenario_pin (scenario_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document, to_bu_id)
      VALUES (NEW.scenario_id, NEW.version, NEW.bu_id, pin.pointer, pin.to_kind, pin.to_id, pin.to_version, v.digest, v.document, v.bu_id);
      IF pin.to_kind = 'asset_group' THEN
        INSERT INTO risk.scenario_pin (scenario_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document, member_of, to_bu_id)
        SELECT NEW.scenario_id, NEW.version, NEW.bu_id, pin.pointer || lp.pointer, lp.to_kind, lp.to_id, lp.to_version, lp.to_digest, lp.to_document,
               pin.pointer, lp.to_bu_id
        FROM risk.library_pin lp WHERE lp.entry_id = pin.to_id AND lp.version = pin.to_version;
        GET DIAGNOSTICS members = ROW_COUNT;
        IF members = 0 THEN
          RAISE EXCEPTION 'risk.%: the members of asset group % version % are not visible', TG_TABLE_NAME, pin.to_id, pin.to_version
            USING ERRCODE = 'PF016';
        END IF;
      END IF;
    ELSE
      INSERT INTO risk.library_pin (entry_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document, to_bu_id)
      VALUES (NEW.entry_id, NEW.version, NEW.bu_id, pin.pointer, pin.to_kind, pin.to_id, pin.to_version, v.digest, v.document, v.bu_id);
    END IF;
  END LOOP;
  RETURN NULL;
END $$;

-- Moves a scenario to another BU (AC-19) and returns the BU it left.
CREATE FUNCTION risk.move_scenario(id uuid, to_bu uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h record;
  r_from uuid;
BEGIN
  PERFORM risk.actor();
  SELECT s.bu_id, s.archived_at INTO h FROM risk.scenario s WHERE s.id = move_scenario.id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'risk: no such scenario %', id USING ERRCODE = 'PF017';
  END IF;
  IF h.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'risk: scenario % is archived; restore it before moving it', id USING ERRCODE = 'PF017';
  END IF;
  IF h.bu_id = to_bu THEN
    RAISE EXCEPTION 'risk: scenario % is in that BU already', id USING ERRCODE = 'PF017';
  END IF;
  r_from := iam.restricted_root(h.bu_id);
  IF r_from IS NOT NULL AND r_from IS DISTINCT FROM iam.restricted_root(to_bu) THEN
    RAISE EXCEPTION 'risk: scenario % is inside a restricted BU and cannot leave its subtree', id USING ERRCODE = 'PF020';
  END IF;
  UPDATE risk.scenario s SET bu_id = to_bu WHERE s.id = move_scenario.id;
  UPDATE risk.scenario_version v SET bu_id = to_bu WHERE v.scenario_id = move_scenario.id;
  UPDATE risk.scenario_pin p SET bu_id = to_bu WHERE p.scenario_id = move_scenario.id;
  RETURN h.bu_id;
END $$;

-- Archives (archived = true) or restores a scenario, library entry or
-- control, with its versions and pins (AC-22). Returns the head's BU.
CREATE FUNCTION risk.set_archived(kind text, id uuid, archived boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  bu uuid;
  was timestamptz;
  stamp timestamptz := CASE WHEN archived THEN now() END;
BEGIN
  PERFORM risk.actor();
  IF archived IS NULL THEN
    RAISE EXCEPTION 'risk: archived must be true or false' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  CASE kind
  WHEN 'scenario' THEN
    SELECT s.bu_id, s.archived_at INTO bu, was FROM risk.scenario s WHERE s.id = set_archived.id FOR UPDATE;
  WHEN 'library' THEN
    SELECT e.bu_id, e.archived_at INTO bu, was FROM risk.library_entry e WHERE e.id = set_archived.id FOR UPDATE;
  WHEN 'control' THEN
    SELECT c.bu_id, c.archived_at INTO bu, was FROM risk.control c WHERE c.id = set_archived.id FOR UPDATE;
  ELSE
    RAISE EXCEPTION 'risk: unknown kind %', kind USING ERRCODE = 'invalid_parameter_value';
  END CASE;
  IF bu IS NULL THEN
    RAISE EXCEPTION 'risk: no such % %', kind, id USING ERRCODE = 'PF017';
  END IF;
  IF (was IS NOT NULL) = archived THEN
    RAISE EXCEPTION 'risk: the % is % already', kind, CASE WHEN archived THEN 'archived' ELSE 'active' END USING ERRCODE = 'PF017';
  END IF;
  CASE kind
  WHEN 'scenario' THEN
    UPDATE risk.scenario s SET archived_at = stamp WHERE s.id = set_archived.id;
    UPDATE risk.scenario_version v SET archived_at = stamp WHERE v.scenario_id = set_archived.id;
    UPDATE risk.scenario_pin p SET archived_at = stamp WHERE p.scenario_id = set_archived.id;
  WHEN 'library' THEN
    UPDATE risk.library_entry e SET archived_at = stamp WHERE e.id = set_archived.id;
    UPDATE risk.library_version v SET archived_at = stamp WHERE v.entry_id = set_archived.id;
    UPDATE risk.library_pin p SET archived_at = stamp WHERE p.entry_id = set_archived.id;
  WHEN 'control' THEN
    UPDATE risk.control c SET archived_at = stamp WHERE c.id = set_archived.id;
    UPDATE risk.control_version v SET archived_at = stamp WHERE v.control_id = set_archived.id;
  END CASE;
  RETURN bu;
END $$;

-- For each pin of a scenario version the caller sees: whether the
-- scenario's BU reads the pinned entry's BU (itself, or an ancestor on a
-- path without a restricted BU: inherited read). After a move a pin may
-- not be (AC-20); the scenario keeps its copy.
CREATE FUNCTION risk.pin_reachable(scenario uuid, version integer) RETURNS TABLE (pointer text, reachable boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT p.pointer,
         p.to_bu_id IS NOT NULL AND (p.to_bu_id = p.bu_id OR EXISTS (
           SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = p.to_bu_id AND c.descendant_id = p.bu_id AND c.depth > 0 AND NOT c.blocked))
  FROM risk.scenario_pin p WHERE p.scenario_id = pin_reachable.scenario AND p.version = pin_reachable.version;
$$;

REVOKE ALL ON FUNCTION risk.move_scenario(uuid, uuid), risk.set_archived(text, uuid, boolean), risk.pin_reachable(uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.move_scenario(uuid, uuid), risk.set_archived(text, uuid, boolean), risk.pin_reachable(uuid, integer) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;
