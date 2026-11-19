-- F-013 T-02 (F-013-AC-01 to AC-11, AC-20; design §2, §5): the framework
-- schema.
--
--   * Owned through framework_definer (bootstrap role; re-run
--     scripts/db-bootstrap.sh). Frameworks are installation-wide reference
--     data: every table but control_mapping is the definer's alone, read and
--     written through its functions (T-04 on).
--   * framework.family: a framework's stable key (nist-800-53), title and
--     publisher.
--   * framework.version: one imported catalog of a family; append-only but
--     its state (active, retired) and diff summary.
--   * framework.requirement: a control or enhancement of a version, as
--     published; immutable.
--   * framework.baseline: an OSCAL profile resolved to a version's
--     requirements (selected identifiers, parameters); append-only but its
--     state.
--   * framework.crosswalk / relationship: relationships between two
--     versions' requirements (NIST IR 8278: equal, subset_of, superset_of,
--     intersects); immutable but the crosswalk's state.
--   * framework.import: an upload's job and outcome (problems at most
--     1,000).
--   * framework.control_mapping: the latest-version projection of controls'
--     mappings (T-06 fills it): BU-owned, RLS type control, shared down as
--     controls are; inserted and updated only by framework_definer (ADR-007
--     amendments 3 and 5), never deleted.
--   * PF033: refusals of the state rules (the hint names the rule); PF034:
--     limits (OQ6): 100 framework versions, 20,000 requirements a version,
--     200,000 relationships, 500 mappings a control version.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'framework_definer') THEN
    RAISE EXCEPTION 'role framework_definer is missing: re-run scripts/db-bootstrap.sh (F-013 T-02)';
  END IF;
END $$;

CREATE SCHEMA framework;
REVOKE ALL ON SCHEMA framework FROM PUBLIC;
GRANT USAGE ON SCHEMA framework TO framework_definer, app_rw;

CREATE TABLE framework.family (
  key        text        PRIMARY KEY CHECK (key ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  title      text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 300),
  publisher  text        CHECK (char_length(publisher) <= 300),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE framework.version (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  family        text        NOT NULL REFERENCES framework.family (key),
  label         text        NOT NULL CHECK (char_length(label) BETWEEN 1 AND 100),
  title         text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 300),
  published     date,
  source        text        NOT NULL CHECK (source IN ('shipped', 'upload')),
  format        text        NOT NULL CHECK (format IN ('oscal', 'simple')),
  sha256        text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  state         text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired')),
  diff          jsonb       CHECK (diff IS NULL OR jsonb_typeof(diff) = 'object'),
  imported_by   uuid        REFERENCES iam.app_user (id),
  imported_at   timestamptz NOT NULL DEFAULT now(),
  retired_by    uuid        REFERENCES iam.app_user (id),
  retired_at    timestamptz,
  UNIQUE (family, label),
  CHECK ((state = 'retired') = (retired_at IS NOT NULL)),
  CHECK (source = 'shipped' OR imported_by IS NOT NULL)
);

CREATE TABLE framework.requirement (
  id                uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
  version_id        uuid    NOT NULL REFERENCES framework.version (id),
  identifier        text    NOT NULL CHECK (identifier ~ '^[A-Za-z0-9][A-Za-z0-9._:()-]{0,99}$'),
  label             text    CHECK (char_length(label) <= 100),
  title             text    NOT NULL CHECK (char_length(title) BETWEEN 1 AND 500),
  statement         text    CHECK (char_length(statement) <= 20000),
  parent            text,
  ord               integer NOT NULL CHECK (ord >= 0),
  withdrawn         boolean NOT NULL DEFAULT false,
  incorporated_into text[]  NOT NULL DEFAULT '{}' CHECK (cardinality(incorporated_into) <= 50),
  UNIQUE (version_id, identifier)
);
CREATE INDEX requirement_version_ord ON framework.requirement (version_id, ord);

CREATE TABLE framework.baseline (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  version_id  uuid        NOT NULL REFERENCES framework.version (id),
  key         text        NOT NULL CHECK (key ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  title       text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 300),
  source      text        NOT NULL CHECK (source IN ('shipped', 'upload')),
  sha256      text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  selected    text[]      NOT NULL CHECK (cardinality(selected) BETWEEN 1 AND 20000),
  parameters  jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(parameters) = 'object'),
  notes       text[]      NOT NULL DEFAULT '{}',
  state       text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired')),
  imported_by uuid        REFERENCES iam.app_user (id),
  imported_at timestamptz NOT NULL DEFAULT now(),
  retired_at  timestamptz,
  UNIQUE (version_id, key),
  CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);

CREATE TABLE framework.crosswalk (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  title          text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 300),
  publisher      text        CHECK (char_length(publisher) <= 300),
  label          text        NOT NULL CHECK (char_length(label) BETWEEN 1 AND 100),
  source_version uuid        NOT NULL REFERENCES framework.version (id),
  target_version uuid        NOT NULL REFERENCES framework.version (id),
  source         text        NOT NULL CHECK (source IN ('shipped', 'upload')),
  sha256         text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  state          text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired')),
  imported_by    uuid        REFERENCES iam.app_user (id),
  imported_at    timestamptz NOT NULL DEFAULT now(),
  retired_at     timestamptz,
  CHECK (source_version <> target_version),
  CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);

CREATE TABLE framework.relationship (
  crosswalk_id uuid NOT NULL REFERENCES framework.crosswalk (id),
  source_id    uuid NOT NULL REFERENCES framework.requirement (id),
  target_id    uuid NOT NULL REFERENCES framework.requirement (id),
  relationship text NOT NULL CHECK (relationship IN ('equal', 'subset_of', 'superset_of', 'intersects')),
  PRIMARY KEY (crosswalk_id, source_id, target_id)
);
CREATE INDEX relationship_source ON framework.relationship (source_id);
CREATE INDEX relationship_target ON framework.relationship (target_id);

CREATE TABLE framework.import (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind         text        NOT NULL CHECK (kind IN ('catalog', 'profile', 'simple', 'crosswalk')),
  dry_run      boolean     NOT NULL DEFAULT false,
  requested_by uuid        NOT NULL REFERENCES iam.app_user (id),
  requested_at timestamptz NOT NULL DEFAULT now(),
  sha256       text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  state        text        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'refused', 'failed')),
  problems     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(problems) = 'array' AND jsonb_array_length(problems) <= 1000),
  result       jsonb       CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
  finished_at  timestamptz,
  CHECK ((state IN ('succeeded', 'refused', 'failed')) = (finished_at IS NOT NULL))
);

-- The projection of controls' mappings (design §3.4): BU-owned, under RLS.
CREATE TABLE framework.control_mapping (
  control_id      uuid        NOT NULL REFERENCES risk.control (id),
  control_version integer     NOT NULL CHECK (control_version >= 1),
  bu_id           uuid        NOT NULL,
  requirement_id  uuid        NOT NULL REFERENCES framework.requirement (id),
  strength        text        NOT NULL CHECK (strength IN ('full', 'partial', 'supports')),
  implementation  text        CHECK (implementation IN ('in_place', 'partial', 'planned', 'not_in_place')),
  current         boolean     NOT NULL DEFAULT true,
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (control_id, control_version, requirement_id)
);
CREATE INDEX control_mapping_requirement ON framework.control_mapping (requirement_id) WHERE current AND archived_at IS NULL;
CREATE INDEX control_mapping_bu ON framework.control_mapping (bu_id) WHERE current AND archived_at IS NULL;

SELECT authz.apply_bu_rls('framework.control_mapping', 'control', 'archived_at', shared_down => true);
SELECT authz.allow_definer('framework.control_mapping', 'framework_definer');
SELECT authz.allow_definer_insert('framework.control_mapping', 'framework_definer');

REVOKE ALL ON framework.family, framework.version, framework.requirement, framework.baseline, framework.crosswalk, framework.relationship,
  framework.import, framework.control_mapping FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON framework.family, framework.version, framework.baseline, framework.crosswalk, framework.import TO framework_definer;
GRANT SELECT, INSERT ON framework.requirement, framework.relationship TO framework_definer;
GRANT SELECT, INSERT, UPDATE ON framework.control_mapping TO framework_definer;
GRANT SELECT ON framework.control_mapping TO app_rw;

-- State rules (PF033), for every role.
CREATE FUNCTION framework.no_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'framework: % rows do not change', TG_TABLE_NAME USING ERRCODE = 'PF033', HINT = 'immutable';
END $$;

CREATE FUNCTION framework.refuse_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'framework: % is not truncated', TG_TABLE_NAME USING ERRCODE = 'PF033', HINT = 'immutable';
END $$;

-- A version, baseline or crosswalk changes only its state (active to
-- retired, once) and, for a version, its diff summary.
CREATE FUNCTION framework.state_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['state', 'retired_at', 'retired_by', 'diff']) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state', 'retired_at', 'retired_by', 'diff']) THEN
    RAISE EXCEPTION 'framework: a % keeps what was imported; only its state changes', TG_TABLE_NAME USING ERRCODE = 'PF033', HINT = 'immutable';
  END IF;
  IF OLD.state = 'retired' AND (NEW.state <> 'retired' OR NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
    RAISE EXCEPTION 'framework: a retired % stays retired', TG_TABLE_NAME USING ERRCODE = 'PF033', HINT = 'retired';
  END IF;
  IF TG_TABLE_NAME = 'version' AND OLD.diff IS NOT NULL AND NEW.diff IS DISTINCT FROM OLD.diff THEN
    RAISE EXCEPTION 'framework: a version''s diff is recorded once' USING ERRCODE = 'PF033', HINT = 'immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER state_only BEFORE UPDATE ON framework.version FOR EACH ROW EXECUTE FUNCTION framework.state_only();
CREATE TRIGGER state_only BEFORE UPDATE ON framework.baseline FOR EACH ROW EXECUTE FUNCTION framework.state_only();
CREATE TRIGGER state_only BEFORE UPDATE ON framework.crosswalk FOR EACH ROW EXECUTE FUNCTION framework.state_only();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON framework.requirement FOR EACH ROW EXECUTE FUNCTION framework.no_change();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON framework.relationship FOR EACH ROW EXECUTE FUNCTION framework.no_change();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON framework.family FOR EACH ROW EXECUTE FUNCTION framework.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON framework.version FOR EACH ROW EXECUTE FUNCTION framework.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON framework.baseline FOR EACH ROW EXECUTE FUNCTION framework.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON framework.crosswalk FOR EACH ROW EXECUTE FUNCTION framework.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON framework.import FOR EACH ROW EXECUTE FUNCTION framework.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON framework.control_mapping FOR EACH ROW EXECUTE FUNCTION framework.no_change();

-- A finished import is final.
CREATE FUNCTION framework.import_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.state IN ('succeeded', 'refused', 'failed') THEN
    RAISE EXCEPTION 'framework: a finished import does not change' USING ERRCODE = 'PF033', HINT = 'import_finished';
  END IF;
  IF (NEW.id, NEW.kind, NEW.dry_run, NEW.requested_by, NEW.requested_at, NEW.sha256) IS DISTINCT FROM
     (OLD.id, OLD.kind, OLD.dry_run, OLD.requested_by, OLD.requested_at, OLD.sha256) THEN
    RAISE EXCEPTION 'framework: an import keeps its request' USING ERRCODE = 'PF033', HINT = 'immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER state BEFORE UPDATE ON framework.import FOR EACH ROW EXECUTE FUNCTION framework.import_before_update();

-- A mapping row keeps what it projects; only current, archived_at and
-- bu_id (a control moved) change.
CREATE FUNCTION framework.mapping_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.control_id, NEW.control_version, NEW.requirement_id, NEW.strength, NEW.implementation, NEW.created_at) IS DISTINCT FROM
     (OLD.control_id, OLD.control_version, OLD.requirement_id, OLD.strength, OLD.implementation, OLD.created_at) THEN
    RAISE EXCEPTION 'framework: a mapping row keeps what it projects' USING ERRCODE = 'PF033', HINT = 'immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER fixed BEFORE UPDATE ON framework.control_mapping FOR EACH ROW EXECUTE FUNCTION framework.mapping_before_update();

CREATE TRIGGER no_truncate BEFORE TRUNCATE ON framework.version FOR EACH STATEMENT EXECUTE FUNCTION framework.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON framework.requirement FOR EACH STATEMENT EXECUTE FUNCTION framework.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON framework.relationship FOR EACH STATEMENT EXECUTE FUNCTION framework.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON framework.control_mapping FOR EACH STATEMENT EXECUTE FUNCTION framework.refuse_truncate();

-- Limits (PF034), checked once per statement (an import inserts a
-- version's requirements in one statement).
CREATE FUNCTION framework.version_limit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (SELECT count(*) FROM framework.version) >= 100 THEN
    RAISE EXCEPTION 'framework: at most 100 framework versions' USING ERRCODE = 'PF034', HINT = 'too_many_versions';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER limits BEFORE INSERT ON framework.version FOR EACH ROW EXECUTE FUNCTION framework.version_limit();

CREATE FUNCTION framework.requirement_limit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM framework.requirement r WHERE r.version_id IN (SELECT DISTINCT n.version_id FROM inserted n)
             GROUP BY r.version_id HAVING count(*) > 20000) THEN
    RAISE EXCEPTION 'framework: at most 20,000 requirements a version' USING ERRCODE = 'PF034', HINT = 'too_many_requirements';
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER limits AFTER INSERT ON framework.requirement REFERENCING NEW TABLE AS inserted
  FOR EACH STATEMENT EXECUTE FUNCTION framework.requirement_limit();

CREATE FUNCTION framework.relationship_limit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (SELECT count(*) FROM framework.relationship) > 200000 THEN
    RAISE EXCEPTION 'framework: at most 200,000 crosswalk relationships' USING ERRCODE = 'PF034', HINT = 'too_many_relationships';
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER limits AFTER INSERT ON framework.relationship FOR EACH STATEMENT EXECUTE FUNCTION framework.relationship_limit();

CREATE FUNCTION framework.mapping_limit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM framework.control_mapping m JOIN (SELECT DISTINCT n.control_id, n.control_version FROM inserted n) n
             ON n.control_id = m.control_id AND n.control_version = m.control_version
             GROUP BY m.control_id, m.control_version HAVING count(*) > 500) THEN
    RAISE EXCEPTION 'framework: at most 500 mappings a control' USING ERRCODE = 'PF034', HINT = 'too_many_mappings';
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER limits AFTER INSERT ON framework.control_mapping REFERENCING NEW TABLE AS inserted
  FOR EACH STATEMENT EXECUTE FUNCTION framework.mapping_limit();
