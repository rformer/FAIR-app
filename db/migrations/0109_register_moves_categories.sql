-- F-007 T-04 (F-007-AC-01, AC-05; design §3.1, §3.5, §6): moving risks and
-- managing categories.
--
--   * register.move_risk(risk, to_bu): the head, its versions, its links and
--     its treatment move together (AC-05). Refused (PF026) when a linked
--     scenario would be outside the new BU's subtree (hint
--     scenario_outside), and (PF020, as F-003's moves) when the risk would
--     leave a restricted subtree. The caller's write scope at both BUs is
--     the service's check (register.edit at both) and RLS's: versions and
--     links are updated under the caller's context.
--   * Only register_definer changes a version's bu_id (moves); versions are
--     otherwise append-only, as before (PF025).
--   * register.subtree(bu): the BUs of bu's subtree where the caller reads
--     the register, for the list's BU filter (app_rw does not read the BU
--     tree itself).
--   * Categories: register.category_add, category_rename, category_archive
--     (archive or restore), for holders of register write scope at the root
--     BU (register.edit there); names unique among those in use.

GRANT UPDATE (bu_id) ON register.risk, register.treatment, register.risk_version, register.treatment_version TO register_definer;
GRANT INSERT (name), UPDATE (name, archived_at) ON register.category TO register_definer;
GRANT EXECUTE ON FUNCTION iam.restricted_root(uuid) TO register_definer;
GRANT SELECT ON iam.bu TO register_definer;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

-- Versions never change, but for register_definer moving them (bu_id).
CREATE FUNCTION register.version_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND current_user = 'register_definer' AND (to_jsonb(NEW) - 'bu_id') = (to_jsonb(OLD) - 'bu_id') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'register.%: % refused; register versions are append-only', TG_TABLE_NAME, TG_OP USING ERRCODE = 'PF025';
END $$;

-- Moves a risk with its versions, links and treatment; returns the BU it
-- left.
CREATE FUNCTION register.move_risk(risk uuid, to_bu uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.risk;
  r_from uuid;
  outside uuid;
BEGIN
  PERFORM register.actor();
  SELECT * INTO h FROM register.risk x WHERE x.id = move_risk.risk FOR UPDATE;
  IF NOT FOUND OR NOT h.bu_id = ANY (authz.visible_bus('register', 'write')) THEN
    RAISE EXCEPTION 'register: no such risk %', risk USING ERRCODE = 'P0002';
  END IF;
  IF NOT to_bu = ANY (authz.visible_bus('register', 'write')) THEN
    RAISE EXCEPTION 'register: you cannot write at the business unit %', to_bu USING ERRCODE = '42501';
  END IF;
  IF h.bu_id = to_bu THEN
    RAISE EXCEPTION 'register: risk % is in that business unit already', risk USING ERRCODE = 'PF026', HINT = 'same_bu';
  END IF;
  r_from := iam.restricted_root(h.bu_id);
  IF r_from IS NOT NULL AND r_from IS DISTINCT FROM iam.restricted_root(to_bu) THEN
    RAISE EXCEPTION 'register: risk % is inside a restricted business unit and cannot leave its subtree', risk USING ERRCODE = 'PF020';
  END IF;
  SELECT l.scenario_id INTO outside FROM register.risk_scenario l JOIN risk.scenario s ON s.id = l.scenario_id
  WHERE l.risk_id = h.id AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = to_bu AND c.descendant_id = s.bu_id)
  LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION 'register: a linked scenario would be outside the business unit''s subtree' USING ERRCODE = 'PF026',
      DETAIL = '/scenarios: ' || outside || ' is outside the new business unit', HINT = 'scenario_outside';
  END IF;
  UPDATE register.risk x SET bu_id = to_bu WHERE x.id = h.id;
  UPDATE register.risk_version v SET bu_id = to_bu WHERE v.risk_id = h.id;
  UPDATE register.risk_scenario l SET bu_id = to_bu WHERE l.risk_id = h.id;
  UPDATE register.treatment t SET bu_id = to_bu WHERE t.risk_id = h.id;
  UPDATE register.treatment_version v SET bu_id = to_bu WHERE v.risk_id = h.id;
  RETURN h.bu_id;
END $$;

-- The BUs of bu's subtree where the caller reads the register.
CREATE FUNCTION register.subtree(bu uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.descendant_id FROM iam.bu_closure c
  WHERE c.ancestor_id = subtree.bu AND c.descendant_id = ANY (authz.visible_bus('register', 'read'))
$$;

-- The root BU, if the caller may write the register there (register.edit).
CREATE FUNCTION register.root_writer() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE root uuid := (SELECT b.id FROM iam.bu b WHERE b.parent_id IS NULL);
BEGIN
  PERFORM register.actor();
  IF NOT root = ANY (authz.visible_bus('register', 'write')) THEN
    RAISE EXCEPTION 'register: categories are managed with register.edit at the root business unit' USING ERRCODE = '42501';
  END IF;
  RETURN root;
END $$;

CREATE FUNCTION register.category_name(name text) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF name IS NULL OR char_length(btrim(name)) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'register: a category name is 1 to 100 characters' USING ERRCODE = 'PF026', DETAIL = '/name: is 1 to 100 characters';
  END IF;
  RETURN btrim(name);
END $$;

CREATE FUNCTION register.category_add(name text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE id uuid;
BEGIN
  PERFORM register.root_writer();
  INSERT INTO register.category (name) VALUES (register.category_name(name)) RETURNING category.id INTO id;
  RETURN id;
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION 'register: a category of that name is in use' USING ERRCODE = 'PF026', DETAIL = '/name: is the name of a category in use', HINT = 'duplicate';
END $$;

CREATE FUNCTION register.category_rename(id uuid, name text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM register.root_writer();
  UPDATE register.category c SET name = register.category_name(category_rename.name) WHERE c.id = category_rename.id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'register: no such category %', id USING ERRCODE = 'P0002';
  END IF;
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION 'register: a category of that name is in use' USING ERRCODE = 'PF026', DETAIL = '/name: is the name of a category in use', HINT = 'duplicate';
END $$;

CREATE FUNCTION register.category_archive(id uuid, archived boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM register.root_writer();
  UPDATE register.category c SET archived_at = CASE WHEN archived THEN now() END WHERE c.id = category_archive.id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'register: no such category %', id USING ERRCODE = 'P0002';
  END IF;
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION 'register: a category of that name is in use' USING ERRCODE = 'PF026', DETAIL = '/name: is the name of a category in use', HINT = 'duplicate';
END $$;

REVOKE ALL ON FUNCTION register.version_before_update(), register.move_risk(uuid, uuid), register.subtree(uuid), register.root_writer(), register.category_name(text),
  register.category_add(text), register.category_rename(uuid, text), register.category_archive(uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register.move_risk(uuid, uuid), register.subtree(uuid), register.root_writer(), register.category_add(text), register.category_rename(uuid, text),
  register.category_archive(uuid, boolean) TO app_rw;
GRANT EXECUTE ON FUNCTION register.version_before_update() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;

-- Versions: append-only, but for the definer's moves.
DROP TRIGGER append_only ON register.risk_version;
DROP TRIGGER append_only ON register.treatment_version;
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON register.risk_version FOR EACH ROW EXECUTE FUNCTION register.version_before_update();
CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON register.treatment_version FOR EACH ROW EXECUTE FUNCTION register.version_before_update();
