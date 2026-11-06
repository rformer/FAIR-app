-- F-003 T-03 (F-003-AC-05, AC-06, AC-15, AC-18, AC-23; design §4): the risk
-- schema. Scenarios, library entries and controls are heads with
-- append-only versions; each version holds one canonical JSON document
-- (internal/risk/canon) with its SHA-256 digest. The service validates
-- documents (internal/risk/model); these triggers re-check every rule in the
-- database, so a document that bypasses the service is refused too
-- (TestRiskValidationParity holds the two equal over the shared corpus).
--
--   * Heads (scenario, library_entry, control): app_rw inserts (id, bu_id,
--     and kind for library entries) and may update archived_at only. The
--     creator comes from the signed DB context. current_version is advanced
--     only by the version trigger.
--   * Versions: app_rw inserts (head id, version, document, digest,
--     change_note). The trigger takes bu_id from the head, the author from
--     the context, requires version = current + 1 of an unarchived head
--     (PF017), the digest to match and the document to pass
--     risk.check_document (PF016), and advances the head.
--   * Pins: written by the version trigger from the document; every pinned
--     version must exist and be visible to the writer, inherited read
--     included, with the kind the pin names (PF016).
--   * Versions and pins are append-only, for every role (PF018). Heads are
--     never deleted.
--   * BU scoping: every table is BU-owned (apply_bu_rls); library and
--     control tables are shared down (ADR-007 amendment 2).
--
-- The trigger functions are SECURITY DEFINER, owned by risk_definer (a
-- bootstrap role): they write what app_rw cannot (head versions, pins), and
-- RLS still applies to them under the caller's context.

CREATE SCHEMA risk;
REVOKE ALL ON SCHEMA risk FROM PUBLIC;
GRANT USAGE ON SCHEMA risk TO app_rw, risk_definer;

-- The installation currency (design §3.4): set by `risk currency set` (T-04).
CREATE TABLE risk.instance (
  singleton boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  currency  text        NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  set_at    timestamptz NOT NULL DEFAULT now(),
  set_by    text        NOT NULL
);
GRANT SELECT ON risk.instance TO app_rw;

-- Heads ---------------------------------------------------------------------

CREATE TABLE risk.scenario (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id           uuid        NOT NULL,
  current_version integer     NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  created_by      uuid        NOT NULL
);
CREATE TABLE risk.library_entry (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id           uuid        NOT NULL,
  kind            text        NOT NULL CHECK (kind IN ('asset', 'asset_group', 'threat_community', 'loss_profile')),
  current_version integer     NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  origin          text        CHECK (char_length(origin) BETWEEN 1 AND 200), -- starter library key and release, if copied (T-10)
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  created_by      uuid        NOT NULL
);
CREATE TABLE risk.control (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id           uuid        NOT NULL,
  current_version integer     NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  created_by      uuid        NOT NULL
);

-- Versions ------------------------------------------------------------------

CREATE TABLE risk.scenario_version (
  scenario_id uuid        NOT NULL REFERENCES risk.scenario (id),
  version     integer     NOT NULL CHECK (version >= 1),
  bu_id       uuid        NOT NULL,
  document    bytea       NOT NULL,
  digest      text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  author      uuid        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  change_note text        NOT NULL CHECK (char_length(btrim(change_note)) BETWEEN 1 AND 1000),
  PRIMARY KEY (scenario_id, version)
);
CREATE TABLE risk.library_version (
  entry_id    uuid        NOT NULL REFERENCES risk.library_entry (id),
  version     integer     NOT NULL CHECK (version >= 1),
  bu_id       uuid        NOT NULL,
  document    bytea       NOT NULL,
  digest      text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  author      uuid        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  change_note text        NOT NULL CHECK (char_length(btrim(change_note)) BETWEEN 1 AND 1000),
  PRIMARY KEY (entry_id, version)
);
CREATE TABLE risk.control_version (
  control_id  uuid        NOT NULL REFERENCES risk.control (id),
  version     integer     NOT NULL CHECK (version >= 1),
  bu_id       uuid        NOT NULL,
  document    bytea       NOT NULL,
  digest      text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  author      uuid        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  change_note text        NOT NULL CHECK (char_length(btrim(change_note)) BETWEEN 1 AND 1000),
  PRIMARY KEY (control_id, version)
);

-- Pins: what a version uses. Scenario pins (asset or asset group, threat
-- community, controls) are scenario data; asset group pins (member assets)
-- are library data, shared down with the group. Each pin holds a copy of
-- the pinned version (digest and document; versions never change), so a
-- reader of the scenario sees exactly what it uses under the scenario's own
-- policy, without library.view and after a move (design §4.4, AC-20).
CREATE TABLE risk.scenario_pin (
  scenario_id uuid    NOT NULL,
  version     integer NOT NULL,
  bu_id       uuid    NOT NULL,
  pointer     text    NOT NULL,
  to_kind     text    NOT NULL CHECK (to_kind IN ('asset', 'asset_group', 'threat_community', 'control')),
  to_id       uuid    NOT NULL,
  to_version  integer NOT NULL CHECK (to_version >= 1),
  to_digest   text    NOT NULL,
  to_document bytea   NOT NULL,
  PRIMARY KEY (scenario_id, version, pointer),
  FOREIGN KEY (scenario_id, version) REFERENCES risk.scenario_version (scenario_id, version)
);
CREATE INDEX scenario_pin_to ON risk.scenario_pin (to_id, to_version);
CREATE TABLE risk.library_pin (
  entry_id    uuid    NOT NULL,
  version     integer NOT NULL,
  bu_id       uuid    NOT NULL,
  pointer     text    NOT NULL,
  to_kind     text    NOT NULL CHECK (to_kind = 'asset'),
  to_id       uuid    NOT NULL,
  to_version  integer NOT NULL CHECK (to_version >= 1),
  to_digest   text    NOT NULL,
  to_document bytea   NOT NULL,
  PRIMARY KEY (entry_id, version, pointer),
  FOREIGN KEY (entry_id, version) REFERENCES risk.library_version (entry_id, version)
);
CREATE INDEX library_pin_to ON risk.library_pin (to_id, to_version);

-- apply_bu_rls checks the resource type against the permission catalog.
-- On a fresh install (and for a type new in a release) the catalog is
-- recorded only after the migrations (iam.sync_release), so it also accepts
-- the release's types, which iam migrate passes in the transaction setting
-- fair.release_resource_types. Otherwise as in 0084.
CREATE OR REPLACE FUNCTION authz.apply_bu_rls(tbl regclass, resource_type text, inactive_column text DEFAULT NULL, shared_down boolean DEFAULT false) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rel text := (SELECT c.relname FROM pg_class c WHERE c.oid = tbl);
  rt text := quote_literal(resource_type);
  sch text := (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = tbl);
  r text := CASE WHEN shared_down THEN authz.bu_inherited_expr(resource_type) ELSE authz.bu_scope_expr(resource_type, 'read') END;
  w text := authz.bu_scope_expr(resource_type, 'write');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.resource_type = apply_bu_rls.resource_type)
     AND NOT apply_bu_rls.resource_type = ANY (string_to_array(coalesce(current_setting('fair.release_resource_types', true), ''), ',')) THEN
    RAISE EXCEPTION 'apply_bu_rls: unknown resource type %', resource_type USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF shared_down IS NULL THEN
    RAISE EXCEPTION 'apply_bu_rls: shared_down must be true or false' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = 'bu_id'
                 AND a.atttypid = 'uuid'::regtype AND a.attnotnull AND NOT a.attisdropped) THEN
    RAISE EXCEPTION 'apply_bu_rls: % needs a NOT NULL uuid column bu_id (AC-24)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF inactive_column IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = inactive_column
                 AND a.atttypid IN ('timestamptz'::regtype, 'timestamp'::regtype, 'date'::regtype) AND NOT a.attisdropped) THEN
    RAISE EXCEPTION 'apply_bu_rls: the inactive column of % must be a timestamp or date column (AC-18)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = tbl
             AND p.polname NOT IN ('bu_select', 'bu_insert', 'bu_update', 'bu_delete', 'bu_rollup', 'bu_guard')) THEN
    RAISE EXCEPTION 'apply_bu_rls: % has other policies; BU tables carry only the BU policies', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid = tbl AND c.contype = 'f' AND c.confrelid = 'iam.bu'::regclass) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (bu_id) REFERENCES iam.bu (id)', tbl, rel || '_bu_fk');
  END IF;
  EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s (bu_id)', rel || '_bu_id', tbl);
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);

  EXECUTE format('DROP POLICY IF EXISTS bu_select ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_insert ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_update ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_delete ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_rollup ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_guard ON %s', tbl);
  EXECUTE format('CREATE POLICY bu_select ON %s FOR SELECT USING (%s)', tbl, r);
  EXECUTE format('CREATE POLICY bu_insert ON %s FOR INSERT WITH CHECK (%s)', tbl, w);
  EXECUTE format('CREATE POLICY bu_update ON %s FOR UPDATE USING (%s) WITH CHECK (%s)', tbl, w, w);
  EXECUTE format('CREATE POLICY bu_delete ON %s FOR DELETE USING (%s)', tbl, w);
  EXECUTE format('CREATE POLICY bu_rollup ON %s FOR SELECT TO rollup_definer'
                 ' USING (bu_id = ANY ((SELECT ARRAY(SELECT r.bu_id FROM authz.rollup_bus(%s) r WHERE r.mode = %L))::uuid[]))',
                 tbl, rt, 'aggregate');
  EXECUTE format('CREATE POLICY bu_guard ON %s FOR SELECT TO bu_guard_definer USING (true)', tbl);
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO rollup_definer, bu_guard_definer', sch);
  EXECUTE format('GRANT SELECT ON %s TO rollup_definer, bu_guard_definer', tbl);

  INSERT INTO iam.bu_owned_tables (table_name, resource_type, inactive_column, shared_down) VALUES (tbl, resource_type, inactive_column, shared_down)
  ON CONFLICT (table_name) DO UPDATE SET resource_type = EXCLUDED.resource_type, inactive_column = EXCLUDED.inactive_column,
    shared_down = EXCLUDED.shared_down;
END $$;

SELECT authz.apply_bu_rls('risk.scenario', 'scenario', 'archived_at');
SELECT authz.apply_bu_rls('risk.scenario_version', 'scenario');
SELECT authz.apply_bu_rls('risk.scenario_pin', 'scenario');
SELECT authz.apply_bu_rls('risk.library_entry', 'library', 'archived_at', shared_down => true);
SELECT authz.apply_bu_rls('risk.library_version', 'library', shared_down => true);
SELECT authz.apply_bu_rls('risk.library_pin', 'library', shared_down => true);
SELECT authz.apply_bu_rls('risk.control', 'control', 'archived_at', shared_down => true);
SELECT authz.apply_bu_rls('risk.control_version', 'control', shared_down => true);

-- Privileges ----------------------------------------------------------------

GRANT SELECT ON risk.scenario, risk.library_entry, risk.control,
  risk.scenario_version, risk.library_version, risk.control_version,
  risk.scenario_pin, risk.library_pin TO app_rw, risk_definer;
GRANT INSERT (id, bu_id) ON risk.scenario, risk.control TO app_rw;
GRANT INSERT (id, bu_id, kind) ON risk.library_entry TO app_rw;
GRANT UPDATE (archived_at) ON risk.scenario, risk.library_entry, risk.control TO app_rw;
GRANT INSERT (scenario_id, version, document, digest, change_note) ON risk.scenario_version TO app_rw;
GRANT INSERT (entry_id, version, document, digest, change_note) ON risk.library_version TO app_rw;
GRANT INSERT (control_id, version, document, digest, change_note) ON risk.control_version TO app_rw;
GRANT UPDATE (current_version) ON risk.scenario, risk.library_entry, risk.control TO risk_definer;
GRANT INSERT ON risk.scenario_pin, risk.library_pin TO risk_definer;

-- risk_definer runs under RLS with the caller's context: it needs the
-- policies' functions, the context, and the secrets check.
GRANT USAGE ON SCHEMA authz, iam TO risk_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope(), authz.visible_bus(text, text), authz.scope_excludes(text, text),
  authz.scope_hides(text, text), authz.inherited_bus(text) TO risk_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.looks_secret(text) TO risk_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT USAGE ON SCHEMA audit TO risk_definer;

-- Canonical form and the document check -------------------------------------

-- The canonical text of a JSON value (internal/risk/canon): members sorted
-- (every member name a valid document has is ASCII, where byte order and
-- RFC 8785's UTF-16 order agree), no whitespace, strings as JSON escapes
-- them (quote, backslash, \b \f \n \r \t, \u00xx for other controls).
CREATE FUNCTION risk.canonical(j jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE jsonb_typeof(j)
    WHEN 'object' THEN '{' || coalesce((SELECT string_agg(to_json(e.k)::text || ':' || risk.canonical(e.v), ',' ORDER BY e.k COLLATE "C")
                                        FROM jsonb_each(j) e(k, v)), '') || '}'
    WHEN 'array' THEN '[' || coalesce((SELECT string_agg(risk.canonical(a.v), ',' ORDER BY a.o)
                                       FROM jsonb_array_elements(j) WITH ORDINALITY a(v, o)), '') || ']'
    ELSE j::text END;
$$;

-- Helpers return problems as 'pointer: message' (empty when fine).
CREATE FUNCTION risk.p(ptr text, msg text) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT ARRAY[ptr || ': ' || msg] $$;

-- Members of an object outside the allowed set.
CREATE FUNCTION risk.unknown(o jsonb, ptr text, allowed text[]) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(array_agg(ptr || '/' || replace(replace(k, '~', '~0'), '/', '~1') || ': is not a field of this document' ORDER BY k), '{}')
  FROM jsonb_object_keys(CASE WHEN jsonb_typeof(o) = 'object' THEN o ELSE '{}' END) k WHERE NOT k = ANY (allowed);
$$;

CREATE FUNCTION risk.text(v jsonb, ptr text, max integer, required boolean, multiline boolean) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE s text;
BEGIN
  IF v IS NULL OR jsonb_typeof(v) = 'null' THEN
    RETURN CASE WHEN required THEN risk.p(ptr, 'is required') ELSE '{}' END;
  END IF;
  IF jsonb_typeof(v) <> 'string' THEN
    RETURN risk.p(ptr, 'must be a string');
  END IF;
  s := v #>> '{}';
  IF required AND btrim(s, E' \t\n\r') = '' THEN RETURN risk.p(ptr, 'is required'); END IF;
  IF char_length(s) > max THEN RETURN risk.p(ptr, format('is longer than %s characters', max)); END IF;
  IF NOT multiline AND s ~ E'[\\n\\r]' THEN RETURN risk.p(ptr, 'must be a single line'); END IF;
  IF s ~ E'[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]' THEN RETURN risk.p(ptr, 'contains a control character'); END IF;
  IF audit.looks_secret(s) THEN RETURN risk.p(ptr, 'looks like a secret; secrets do not belong in risk data'); END IF;
  RETURN '{}';
END $$;

CREATE FUNCTION risk.is_uuid(v jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_typeof(v) = 'string' AND (v #>> '{}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
$$;

-- An integer of at least lo (and at most 2^53-1).
CREATE FUNCTION risk.int(v jsonb, ptr text, lo bigint) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN v IS NULL THEN risk.p(ptr, 'is required')
    WHEN jsonb_typeof(v) <> 'number' OR (v::text) !~ '^-?[0-9]{1,16}$' THEN risk.p(ptr, 'must be an integer')
    WHEN (v::text)::numeric < lo THEN risk.p(ptr, format('must be %s or more', lo))
    WHEN abs((v::text)::numeric) > 9007199254740991 THEN risk.p(ptr, 'must be an integer')
    ELSE '{}' END;
$$;

-- A canonical decimal string (canon.Decimal), or NULL.
CREATE FUNCTION risk.decimal(v jsonb) RETURNS numeric
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN jsonb_typeof(v) = 'string'
               AND (v #>> '{}') ~ '^-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$' AND (v #>> '{}') <> '-0'
               AND char_length(v #>> '{}') <= 64
               AND char_length(ltrim(replace(replace(v #>> '{}', '-', ''), '.', ''), '0')) <= 34
              THEN (v #>> '{}')::numeric END;
$$;

CREATE FUNCTION risk.oneof(v jsonb, ptr text, allowed text[]) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN v IS NULL OR jsonb_typeof(v) <> 'string' OR NOT (v #>> '{}') = ANY (allowed)
    THEN risk.p(ptr, format('is %s, want one of %s', coalesce(v::text, 'missing'), array_to_string(allowed, ', '))) ELSE '{}' END;
$$;

CREATE FUNCTION risk.array_len(v jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN jsonb_typeof(v) = 'array' THEN jsonb_array_length(v) END;
$$;

-- An estimate in the unit its factor needs (design §3.2; AC-05, AC-06).
CREATE FUNCTION risk.estimate(e jsonb, ptr text, unit text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p text[] := '{}';
  f text;
  n numeric;
  lo numeric; ml numeric; hi numeric;
  i integer;
  s jsonb;
BEGIN
  IF e IS NULL THEN RETURN risk.p(ptr, 'is required'); END IF;
  IF jsonb_typeof(e) <> 'object' THEN RETURN risk.p(ptr, 'must be an object'); END IF;
  p := p || risk.unknown(e, ptr, ARRAY['min', 'ml', 'max', 'unit', 'confidence', 'rationale', 'sources']);
  IF (e ->> 'unit') IS DISTINCT FROM unit THEN
    p := p || risk.p(ptr || '/unit', format('is %s; this factor is estimated in "%s"', coalesce((e -> 'unit')::text, 'missing'), unit));
  END IF;
  FOREACH f IN ARRAY ARRAY['min', 'ml', 'max'] LOOP
    n := risk.decimal(e -> f);
    IF n IS NULL THEN
      p := p || risk.p(ptr || '/' || f, CASE WHEN e ? f THEN 'is not a canonical decimal' ELSE 'is required' END);
    ELSIF n < 0 THEN
      p := p || risk.p(ptr || '/' || f, 'must not be negative');
    ELSIF unit IN ('probability', 'fraction') AND n > 1 THEN
      p := p || risk.p(ptr || '/' || f, 'must be between 0 and 1');
    ELSIF unit = 'percentile' AND n > 100 THEN
      p := p || risk.p(ptr || '/' || f, 'must be between 0 and 100');
    END IF;
  END LOOP;
  lo := risk.decimal(e -> 'min'); ml := risk.decimal(e -> 'ml'); hi := risk.decimal(e -> 'max');
  IF lo > ml OR ml > hi THEN
    p := p || risk.p(ptr, 'must be ordered: min ≤ ml ≤ max');
  END IF;
  n := risk.decimal(e -> 'confidence');
  IF n IS NULL THEN
    p := p || risk.p(ptr || '/confidence', CASE WHEN e ? 'confidence' THEN 'is not a canonical decimal' ELSE 'is required' END);
  ELSIF n <= 0 OR n >= 1 THEN
    p := p || risk.p(ptr || '/confidence', 'must be between 0 and 1, exclusive');
  END IF;
  p := p || risk.text(e -> 'rationale', ptr || '/rationale', 10000, true, true);
  i := risk.array_len(e -> 'sources');
  IF i IS NULL OR i = 0 THEN
    p := p || risk.p(ptr || '/sources', 'at least one source is required');
  ELSIF i > 20 THEN
    p := p || risk.p(ptr || '/sources', 'at most 20 sources');
  ELSE
    FOR i IN 0 .. jsonb_array_length(e -> 'sources') - 1 LOOP
      s := e -> 'sources' -> i;
      IF jsonb_typeof(s) <> 'object' THEN
        p := p || risk.p(format('%s/sources/%s', ptr, i), 'must be an object');
        CONTINUE;
      END IF;
      p := p || risk.unknown(s, format('%s/sources/%s', ptr, i), ARRAY['type', 'ref', 'note'])
             || risk.oneof(s -> 'type', format('%s/sources/%s/type', ptr, i), ARRAY['person', 'document', 'dataset', 'integration'])
             || risk.text(s -> 'ref', format('%s/sources/%s/ref', ptr, i), 1000, true, false)
             || risk.text(s -> 'note', format('%s/sources/%s/note', ptr, i), 1000, false, false);
    END LOOP;
  END IF;
  RETURN p;
END $$;

CREATE FUNCTION risk.forms() RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY['productivity', 'response', 'replacement', 'fines_judgments', 'competitive_advantage', 'reputation'];
$$;

CREATE FUNCTION risk.loss_map(m jsonb, ptr text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; k text;
BEGIN
  IF m IS NULL OR jsonb_typeof(m) <> 'object' OR m = '{}' THEN
    RETURN risk.p(ptr, 'at least one form of loss is required');
  END IF;
  FOR k IN SELECT x FROM jsonb_object_keys(m) x ORDER BY x COLLATE "C" LOOP
    IF NOT k = ANY (risk.forms()) THEN
      p := p || risk.p(ptr || '/' || replace(replace(k, '~', '~0'), '/', '~1'), 'is not an Open FAIR form of loss');
    ELSE
      p := p || risk.estimate(m -> k, ptr || '/' || k, 'currency');
    END IF;
  END LOOP;
  RETURN p;
END $$;

CREATE FUNCTION risk.pin(v jsonb, ptr text) RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN v IS NULL THEN risk.p(ptr, 'is required')
              WHEN jsonb_typeof(v) <> 'object' THEN risk.p(ptr, 'must be an object')
              ELSE CASE WHEN risk.is_uuid(v -> 'id') THEN '{}'::text[] ELSE risk.p(ptr || '/id', 'must be a UUID') END
                   || risk.int(v -> 'version', ptr || '/version', 1) END;
$$;

-- A control's effects (design §3.5).
CREATE FUNCTION risk.effects(a jsonb, ptr text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; i integer; e jsonb; f text; seen text[] := '{}';
BEGIN
  IF risk.array_len(a) IS NULL OR risk.array_len(a) = 0 THEN RETURN risk.p(ptr, 'at least one effect is required'); END IF;
  IF jsonb_array_length(a) > 20 THEN p := p || risk.p(ptr, 'at most 20 effects'); END IF;
  FOR i IN 0 .. jsonb_array_length(a) - 1 LOOP
    e := a -> i;
    IF jsonb_typeof(e) <> 'object' THEN p := p || risk.p(format('%s/%s', ptr, i), 'must be an object'); CONTINUE; END IF;
    p := p || risk.unknown(e, format('%s/%s', ptr, i), ARRAY['factor', 'estimate']);
    f := e ->> 'factor';
    IF f IS NULL OR NOT (f IN ('contact_frequency', 'probability_of_action', 'threat_capability', 'resistance_strength')
                         OR (f LIKE 'loss.%' AND substr(f, 6) = ANY (risk.forms()))) THEN
      p := p || risk.p(format('%s/%s/factor', ptr, i), 'is not a factor a control affects');
      CONTINUE;
    END IF;
    IF f = ANY (seen) THEN p := p || risk.p(format('%s/%s/factor', ptr, i), 'is listed twice'); END IF;
    seen := seen || f;
    p := p || risk.estimate(e -> 'estimate', format('%s/%s/estimate', ptr, i),
                            CASE WHEN f = 'resistance_strength' THEN 'percentile' ELSE 'fraction' END);
  END LOOP;
  RETURN p;
END $$;

-- The LEF branch at its chosen levels (design §3.1; AC-03, AC-29).
CREATE FUNCTION risk.lef(l jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; t jsonb; v jsonb; tc jsonb;
BEGIN
  IF l IS NULL OR jsonb_typeof(l) <> 'object' THEN RETURN risk.p('/lef', 'is required'); END IF;
  p := p || risk.unknown(l, '/lef', ARRAY['level', 'estimate', 'tef', 'vulnerability']);
  CASE l ->> 'level'
  WHEN 'lef' THEN
    p := p || risk.estimate(l -> 'estimate', '/lef/estimate', 'events_per_year');
    IF l ? 'tef' THEN p := p || risk.p('/lef/tef', 'is not used at level "lef"'); END IF;
    IF l ? 'vulnerability' THEN p := p || risk.p('/lef/vulnerability', 'is not used at level "lef"'); END IF;
  WHEN 'tef_vuln' THEN
    IF l ? 'estimate' THEN p := p || risk.p('/lef/estimate', 'is not used at level "tef_vuln"'); END IF;
    t := l -> 'tef';
    IF t IS NULL OR jsonb_typeof(t) <> 'object' THEN
      p := p || risk.p('/lef/tef', 'is required at this level');
    ELSE
      p := p || risk.unknown(t, '/lef/tef', ARRAY['level', 'estimate', 'contact_frequency', 'probability_of_action']);
      CASE t ->> 'level'
      WHEN 'tef' THEN
        p := p || risk.estimate(t -> 'estimate', '/lef/tef/estimate', 'events_per_year');
        IF t ? 'contact_frequency' THEN p := p || risk.p('/lef/tef/contact_frequency', 'is not used at level "tef"'); END IF;
        IF t ? 'probability_of_action' THEN p := p || risk.p('/lef/tef/probability_of_action', 'is not used at level "tef"'); END IF;
      WHEN 'cf_poa' THEN
        IF t ? 'estimate' THEN p := p || risk.p('/lef/tef/estimate', 'is not used at level "cf_poa"'); END IF;
        p := p || risk.estimate(t -> 'contact_frequency', '/lef/tef/contact_frequency', 'events_per_year')
               || risk.estimate(t -> 'probability_of_action', '/lef/tef/probability_of_action', 'probability');
      ELSE
        p := p || risk.p('/lef/tef/level', 'is not "tef" or "cf_poa"');
      END CASE;
    END IF;
    v := l -> 'vulnerability';
    IF v IS NULL OR jsonb_typeof(v) <> 'object' THEN
      p := p || risk.p('/lef/vulnerability', 'is required at this level');
    ELSE
      p := p || risk.unknown(v, '/lef/vulnerability', ARRAY['level', 'estimate', 'threat_capability', 'resistance_strength']);
      CASE v ->> 'level'
      WHEN 'direct' THEN
        p := p || risk.estimate(v -> 'estimate', '/lef/vulnerability/estimate', 'probability');
        IF v ? 'threat_capability' THEN p := p || risk.p('/lef/vulnerability/threat_capability', 'is not used at level "direct"'); END IF;
        IF v ? 'resistance_strength' THEN p := p || risk.p('/lef/vulnerability/resistance_strength', 'is not used at level "direct"'); END IF;
      WHEN 'derived' THEN
        IF v ? 'estimate' THEN p := p || risk.p('/lef/vulnerability/estimate', 'is not used at level "derived"'); END IF;
        tc := v -> 'threat_capability';
        IF tc IS NULL OR jsonb_typeof(tc) <> 'object' THEN
          p := p || risk.p('/lef/vulnerability/threat_capability', 'is required at this level');
        ELSE
          p := p || risk.unknown(tc, '/lef/vulnerability/threat_capability', ARRAY['source', 'estimate']);
          CASE tc ->> 'source'
          WHEN 'threat_community' THEN
            IF tc ? 'estimate' THEN
              p := p || risk.p('/lef/vulnerability/threat_capability/estimate', 'is not used when threat capability comes from the threat community');
            END IF;
          WHEN 'scenario' THEN
            p := p || risk.estimate(tc -> 'estimate', '/lef/vulnerability/threat_capability/estimate', 'percentile');
          ELSE
            p := p || risk.p('/lef/vulnerability/threat_capability/source', 'is not "threat_community" or "scenario"');
          END CASE;
        END IF;
        p := p || risk.estimate(v -> 'resistance_strength', '/lef/vulnerability/resistance_strength', 'percentile');
      ELSE
        p := p || risk.p('/lef/vulnerability/level', 'is not "direct" or "derived"');
      END CASE;
    END IF;
  ELSE
    p := p || risk.p('/lef/level', 'is not "lef" or "tef_vuln"');
  END CASE;
  RETURN p;
END $$;

CREATE FUNCTION risk.check_scenario(d jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  p text[] := '{}';
  i integer; j integer; n integer;
  x jsonb; cs jsonb; c jsonb;
  seen text[]; names text[] := '{}'; current integer := 0;
  s date; e date;
BEGIN
  p := p || risk.unknown(d, '', ARRAY['kind', 'schema_version', 'name', 'description', 'scope', 'analysis_period', 'owner', 'asset',
    'threat_community', 'threat_effects', 'loss_event', 'lef', 'primary_loss', 'secondary_risk', 'control_sets'])
    || risk.text(d -> 'name', '/name', 200, true, false)
    || risk.text(d -> 'description', '/description', 10000, false, true);
  IF jsonb_typeof(d -> 'scope') <> 'object' THEN
    p := p || risk.p('/scope/in', 'is required');
  ELSE
    p := p || risk.unknown(d -> 'scope', '/scope', ARRAY['in', 'out'])
           || risk.text(d #> '{scope,in}', '/scope/in', 10000, true, true)
           || risk.text(d #> '{scope,out}', '/scope/out', 10000, false, true);
  END IF;
  -- The analysis period: dates, ending after it starts.
  p := p || risk.unknown(d -> 'analysis_period', '/analysis_period', ARRAY['start', 'end']);
  BEGIN
    s := CASE WHEN (d #>> '{analysis_period,start}') ~ '^\d{4}-\d{2}-\d{2}$' THEN (d #>> '{analysis_period,start}')::date END;
  EXCEPTION WHEN others THEN s := NULL;
  END;
  BEGIN
    e := CASE WHEN (d #>> '{analysis_period,end}') ~ '^\d{4}-\d{2}-\d{2}$' THEN (d #>> '{analysis_period,end}')::date END;
  EXCEPTION WHEN others THEN e := NULL;
  END;
  IF s IS NULL THEN p := p || risk.p('/analysis_period/start', 'must be a date (YYYY-MM-DD)'); END IF;
  IF e IS NULL THEN p := p || risk.p('/analysis_period/end', 'must be a date (YYYY-MM-DD)'); END IF;
  IF e <= s THEN p := p || risk.p('/analysis_period', 'must end after it starts'); END IF;
  IF NOT coalesce(risk.is_uuid(d -> 'owner'), false) THEN p := p || risk.p('/owner', 'must be a UUID'); END IF;

  -- The asset (or asset group) and the threat community.
  IF NOT coalesce((d #>> '{asset,kind}') IN ('asset', 'asset_group'), false) THEN
    p := p || risk.p('/asset/kind', 'is not "asset" or "asset_group"');
  END IF;
  p := p || risk.unknown(d -> 'asset', '/asset', ARRAY['kind', 'id', 'version'])
         || risk.pin((d -> 'asset') - 'kind', '/asset')
         || risk.unknown(d -> 'threat_community', '/threat_community', ARRAY['id', 'version'])
         || risk.pin(d -> 'threat_community', '/threat_community');

  -- Threat effects: one or more, distinct, sorted (canonical).
  n := risk.array_len(d -> 'threat_effects');
  IF n IS NULL OR n = 0 THEN
    p := p || risk.p('/threat_effects', 'at least one threat effect is required');
  ELSE
    seen := '{}';
    FOR i IN 0 .. n - 1 LOOP
      x := d -> 'threat_effects' -> i;
      IF NOT coalesce((x #>> '{}') IN ('confidentiality', 'integrity', 'availability') AND jsonb_typeof(x) = 'string', false) THEN
        p := p || risk.p(format('/threat_effects/%s', i), 'is not a threat effect');
      ELSIF (x #>> '{}') = ANY (seen) THEN
        p := p || risk.p(format('/threat_effects/%s', i), 'is listed twice');
      END IF;
      seen := seen || (x #>> '{}');
    END LOOP;
    IF seen IS DISTINCT FROM (SELECT array_agg(t ORDER BY t COLLATE "C") FROM unnest(seen) t) THEN
      p := p || risk.p('/threat_effects', 'must be sorted (canonical form)');
    END IF;
  END IF;
  p := p || risk.text(d -> 'loss_event', '/loss_event', 10000, true, true)
         || risk.lef(d -> 'lef')
         || risk.loss_map(d -> 'primary_loss', '/primary_loss');

  -- Secondary risk per stakeholder group.
  IF d ? 'secondary_risk' THEN
    n := risk.array_len(d -> 'secondary_risk');
    IF n IS NULL THEN
      p := p || risk.p('/secondary_risk', 'must be an array');
    ELSE
      IF n > 20 THEN p := p || risk.p('/secondary_risk', 'at most 20 secondary stakeholder groups'); END IF;
      seen := '{}';
      FOR i IN 0 .. n - 1 LOOP
        x := d -> 'secondary_risk' -> i;
        p := p || risk.unknown(x, format('/secondary_risk/%s', i), ARRAY['stakeholder', 'slef', 'loss'])
               || risk.text(x -> 'stakeholder', format('/secondary_risk/%s/stakeholder', i), 200, true, false);
        IF (x ->> 'stakeholder') = ANY (seen) THEN
          p := p || risk.p(format('/secondary_risk/%s/stakeholder', i), 'is listed twice');
        END IF;
        seen := seen || (x ->> 'stakeholder');
        p := p || risk.estimate(x -> 'slef', format('/secondary_risk/%s/slef', i), 'probability')
               || risk.loss_map(x -> 'loss', format('/secondary_risk/%s/loss', i));
      END LOOP;
    END IF;
  END IF;

  -- Control sets: exactly one current (AC-13).
  n := risk.array_len(d -> 'control_sets');
  IF n IS NULL OR n = 0 THEN
    p := p || risk.p('/control_sets', 'the current control set is required');
  ELSE
    IF n > 20 THEN p := p || risk.p('/control_sets', 'at most 20 control sets'); END IF;
    FOR i IN 0 .. n - 1 LOOP
      cs := d -> 'control_sets' -> i;
      p := p || risk.unknown(cs, format('/control_sets/%s', i), ARRAY['name', 'current', 'controls'])
             || risk.text(cs -> 'name', format('/control_sets/%s/name', i), 200, true, false);
      IF (cs ->> 'name') = ANY (names) THEN p := p || risk.p(format('/control_sets/%s/name', i), 'is used twice'); END IF;
      names := names || (cs ->> 'name');
      IF jsonb_typeof(cs -> 'current') IS DISTINCT FROM 'boolean' THEN
        p := p || risk.p(format('/control_sets/%s/current', i), 'must be true or false');
      ELSIF (cs -> 'current')::boolean THEN
        current := current + 1;
      END IF;
      IF risk.array_len(cs -> 'controls') IS NULL THEN
        p := p || risk.p(format('/control_sets/%s/controls', i), 'must be an array');
        CONTINUE;
      END IF;
      IF jsonb_array_length(cs -> 'controls') > 200 THEN
        p := p || risk.p(format('/control_sets/%s/controls', i), 'at most 200 controls in a set');
      END IF;
      seen := '{}';
      FOR j IN 0 .. jsonb_array_length(cs -> 'controls') - 1 LOOP
        c := cs -> 'controls' -> j;
        p := p || risk.unknown(c, format('/control_sets/%s/controls/%s', i, j), ARRAY['id', 'version', 'status', 'effects'])
               || risk.pin(c - 'status' - 'effects', format('/control_sets/%s/controls/%s', i, j));
        IF (c ->> 'id') = ANY (seen) THEN
          p := p || risk.p(format('/control_sets/%s/controls/%s/id', i, j), 'the control is in this set twice');
        END IF;
        seen := seen || (c ->> 'id');
        IF NOT coalesce((c ->> 'status') IN ('in_place', 'proposed'), false) THEN
          p := p || risk.p(format('/control_sets/%s/controls/%s/status', i, j), 'is not "in_place" or "proposed"');
        END IF;
        IF c ? 'effects' THEN
          p := p || risk.effects(c -> 'effects', format('/control_sets/%s/controls/%s/effects', i, j));
        END IF;
      END LOOP;
    END LOOP;
    IF current <> 1 THEN
      p := p || risk.p('/control_sets', format('exactly one control set must be current; %s are', current));
    END IF;
  END IF;
  RETURN p;
END $$;

CREATE FUNCTION risk.check_library(kind text, d jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[] := '{}'; i integer; n integer; x jsonb; seen text[] := '{}';
BEGIN
  p := p || risk.text(d -> 'name', '/name', 200, true, false)
         || risk.text(d -> 'description', '/description', 10000, false, true);
  CASE kind
  WHEN 'asset' THEN
    p := p || risk.unknown(d, '', ARRAY['kind', 'schema_version', 'name', 'asset_type', 'description', 'value', 'value_basis'])
           || risk.text(d -> 'asset_type', '/asset_type', 200, true, false);
    IF d ? 'value' AND d ? 'value_basis' THEN
      p := p || risk.p('/value', 'give a value or a value basis, not both');
    ELSIF d ? 'value' THEN
      p := p || risk.estimate(d -> 'value', '/value', 'currency');
    ELSE
      p := p || risk.text(d -> 'value_basis', '/value_basis', 10000, true, true);
    END IF;
  WHEN 'asset_group' THEN
    p := p || risk.unknown(d, '', ARRAY['kind', 'schema_version', 'name', 'description', 'members', 'valuation', 'value']);
    n := risk.array_len(d -> 'members');
    IF n IS NULL OR n = 0 THEN
      p := p || risk.p('/members', 'at least one member asset is required');
    ELSE
      IF n > 1000 THEN p := p || risk.p('/members', 'at most 1000 members'); END IF;
      FOR i IN 0 .. n - 1 LOOP
        x := d -> 'members' -> i;
        p := p || risk.unknown(x, format('/members/%s', i), ARRAY['id', 'version']) || risk.pin(x, format('/members/%s', i));
        IF (x ->> 'id') = ANY (seen) THEN p := p || risk.p(format('/members/%s/id', i), 'the asset is a member twice'); END IF;
        seen := seen || (x ->> 'id');
      END LOOP;
    END IF;
    CASE d ->> 'valuation'
    WHEN 'whole' THEN p := p || risk.estimate(d -> 'value', '/value', 'currency');
    WHEN 'members' THEN
      IF d ? 'value' THEN p := p || risk.p('/value', 'is not used when the group is valued by its members'); END IF;
    ELSE p := p || risk.p('/valuation', 'is not "whole" or "members"');
    END CASE;
  WHEN 'threat_community' THEN
    p := p || risk.unknown(d, '', ARRAY['kind', 'schema_version', 'name', 'description', 'threat_capability'])
           || risk.estimate(d -> 'threat_capability', '/threat_capability', 'percentile');
  WHEN 'loss_profile' THEN
    p := p || risk.unknown(d, '', ARRAY['kind', 'schema_version', 'name', 'description', 'magnitudes'])
           || risk.loss_map(d -> 'magnitudes', '/magnitudes');
  WHEN 'control' THEN
    p := p || risk.unknown(d, '', ARRAY['kind', 'schema_version', 'name', 'description', 'references', 'effects']);
    IF d ? 'references' THEN
      n := risk.array_len(d -> 'references');
      IF n IS NULL THEN
        p := p || risk.p('/references', 'must be an array');
      ELSE
        IF n > 50 THEN p := p || risk.p('/references', 'at most 50 references'); END IF;
        FOR i IN 0 .. n - 1 LOOP
          x := d -> 'references' -> i;
          p := p || risk.unknown(x, format('/references/%s', i), ARRAY['framework', 'identifier'])
                 || risk.text(x -> 'framework', format('/references/%s/framework', i), 200, true, false)
                 || risk.text(x -> 'identifier', format('/references/%s/identifier', i), 200, true, false);
          IF x::text = ANY (seen) THEN p := p || risk.p(format('/references/%s', i), 'is listed twice'); END IF;
          seen := seen || x::text;
        END LOOP;
      END IF;
    END IF;
    p := p || risk.effects(d -> 'effects', '/effects');
  END CASE;
  RETURN p;
END $$;

-- Every problem with a stored document of the given kind, as
-- 'pointer: message' ('' is the whole document); empty when valid. A stored
-- document must be canonical, so the check starts there.
CREATE FUNCTION risk.check_document(kind text, doc bytea) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE t text; d jsonb;
BEGIN
  IF kind IS NULL OR NOT kind IN ('scenario', 'asset', 'asset_group', 'threat_community', 'loss_profile', 'control') THEN
    RETURN risk.p('/kind', 'unknown kind');
  END IF;
  IF doc IS NULL OR length(doc) > 1048576 THEN
    RETURN risk.p('', 'missing or larger than 1048576 bytes');
  END IF;
  BEGIN
    t := convert_from(doc, 'UTF8');
    d := t::jsonb;
  EXCEPTION WHEN others THEN
    RETURN risk.p('', 'not a JSON document');
  END;
  IF jsonb_typeof(d) <> 'object' THEN RETURN risk.p('', 'not a JSON object'); END IF;
  IF risk.canonical(d) <> t THEN RETURN risk.p('', 'not in canonical form'); END IF;
  IF (d ->> 'kind') IS DISTINCT FROM kind THEN RETURN risk.p('/kind', format('want "%s"', kind)); END IF;
  IF (d -> 'schema_version')::text IS DISTINCT FROM '1' THEN  -- jsonb holds 1.0 = 1; the text tells them apart
    RETURN risk.p('/schema_version', 'want 1');
  END IF;
  IF kind = 'scenario' THEN RETURN risk.check_scenario(d); END IF;
  RETURN risk.check_library(kind, d);
END $$;

-- The pins a stored document holds.
CREATE FUNCTION risk.document_pins(kind text, d jsonb)
RETURNS TABLE (pointer text, to_kind text, to_id uuid, to_version integer)
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT '/asset', d #>> '{asset,kind}', (d #>> '{asset,id}')::uuid, (d #>> '{asset,version}')::integer WHERE kind = 'scenario'
  UNION ALL
  SELECT '/threat_community', 'threat_community', (d #>> '{threat_community,id}')::uuid, (d #>> '{threat_community,version}')::integer WHERE kind = 'scenario'
  UNION ALL
  SELECT format('/control_sets/%s/controls/%s', s.i - 1, c.j - 1), 'control', (c.v ->> 'id')::uuid, (c.v ->> 'version')::integer
  FROM jsonb_array_elements(CASE WHEN kind = 'scenario' THEN d -> 'control_sets' ELSE '[]' END) WITH ORDINALITY s(v, i),
       jsonb_array_elements(s.v -> 'controls') WITH ORDINALITY c(v, j)
  UNION ALL
  SELECT format('/members/%s', m.i - 1), 'asset', (m.v ->> 'id')::uuid, (m.v ->> 'version')::integer
  FROM jsonb_array_elements(CASE WHEN kind = 'asset_group' THEN d -> 'members' ELSE '[]' END) WITH ORDINALITY m(v, i);
$$;

-- Ownership and privileges of the check functions: the triggers call them
-- as risk_definer; nothing else needs them.
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'risk' LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO risk_definer', f);
  END LOOP;
END $$;

-- Triggers ------------------------------------------------------------------

GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;

-- The signed context's user, or an error: every write is attributed.
CREATE FUNCTION risk.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'risk data needs a valid signed database context' USING ERRCODE = 'PF016';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION risk.head_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  NEW.created_by := risk.actor();
  NEW.created_at := now();
  NEW.current_version := 0;
  NEW.archived_at := NULL;
  RETURN NEW;
END $$;

-- A new version (TG_ARGV[0]: the document kind, or 'library').
CREATE FUNCTION risk.version_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  head_id uuid;
  h record;
  kind text := TG_ARGV[0];
  problems text[];
BEGIN
  NEW.author := risk.actor();
  NEW.created_at := now();
  CASE TG_TABLE_NAME
  WHEN 'scenario_version' THEN
    head_id := NEW.scenario_id;
    SELECT s.bu_id, s.current_version, s.archived_at, 'scenario' AS kind INTO h FROM risk.scenario s WHERE s.id = head_id FOR UPDATE;
  WHEN 'library_version' THEN
    head_id := NEW.entry_id;
    SELECT e.bu_id, e.current_version, e.archived_at, e.kind INTO h FROM risk.library_entry e WHERE e.id = head_id FOR UPDATE;
  WHEN 'control_version' THEN
    head_id := NEW.control_id;
    SELECT c.bu_id, c.current_version, c.archived_at, 'control' AS kind INTO h FROM risk.control c WHERE c.id = head_id FOR UPDATE;
  END CASE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'risk.%: no such head %', TG_TABLE_NAME, head_id USING ERRCODE = 'PF017';
  END IF;
  IF h.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'risk.%: % is archived; restore it before changing it', TG_TABLE_NAME, head_id USING ERRCODE = 'PF017';
  END IF;
  IF NEW.version IS DISTINCT FROM h.current_version + 1 THEN
    RAISE EXCEPTION 'risk.%: version % of % is stale; the current version is %', TG_TABLE_NAME, NEW.version, head_id, h.current_version
      USING ERRCODE = 'PF017';
  END IF;
  NEW.bu_id := h.bu_id;
  IF NEW.digest IS DISTINCT FROM encode(sha256(NEW.document), 'hex') THEN
    RAISE EXCEPTION 'risk.%: the digest does not match the document', TG_TABLE_NAME USING ERRCODE = 'PF016';
  END IF;
  problems := risk.check_document(h.kind, NEW.document);
  IF cardinality(problems) > 0 THEN
    RAISE EXCEPTION 'risk.%: invalid % document', TG_TABLE_NAME, h.kind
      USING ERRCODE = 'PF016', DETAIL = array_to_string(problems, E'\n');
  END IF;
  CASE TG_TABLE_NAME
  WHEN 'scenario_version' THEN UPDATE risk.scenario SET current_version = NEW.version WHERE id = head_id;
  WHEN 'library_version' THEN UPDATE risk.library_entry SET current_version = NEW.version WHERE id = head_id;
  WHEN 'control_version' THEN UPDATE risk.control SET current_version = NEW.version WHERE id = head_id;
  END CASE;
  RETURN NEW;
END $$;

-- Pins: every pinned version exists, is visible to the writer (inherited
-- read included) and has the pinned kind; the pin keeps its copy.
CREATE FUNCTION risk.version_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  pin record;
  kind text;
  d jsonb := convert_from(NEW.document, 'UTF8')::jsonb;
  v record;
BEGIN
  kind := d ->> 'kind';
  FOR pin IN SELECT * FROM risk.document_pins(kind, d) LOOP
    IF pin.to_kind = 'control' THEN
      SELECT cv.digest, cv.document INTO v FROM risk.control_version cv WHERE cv.control_id = pin.to_id AND cv.version = pin.to_version;
    ELSE
      SELECT lv.digest, lv.document INTO v FROM risk.library_version lv JOIN risk.library_entry e ON e.id = lv.entry_id
      WHERE lv.entry_id = pin.to_id AND lv.version = pin.to_version AND e.kind = pin.to_kind;
    END IF;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'risk.%: % pins %s % version %, which does not exist or is not visible', TG_TABLE_NAME, pin.pointer,
        pin.to_kind, pin.to_id, pin.to_version USING ERRCODE = 'PF016';
    END IF;
    IF TG_TABLE_NAME = 'scenario_version' THEN
      INSERT INTO risk.scenario_pin (scenario_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document)
      VALUES (NEW.scenario_id, NEW.version, NEW.bu_id, pin.pointer, pin.to_kind, pin.to_id, pin.to_version, v.digest, v.document);
    ELSE
      INSERT INTO risk.library_pin (entry_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document)
      VALUES (NEW.entry_id, NEW.version, NEW.bu_id, pin.pointer, pin.to_kind, pin.to_id, pin.to_version, v.digest, v.document);
    END IF;
  END LOOP;
  RETURN NULL;
END $$;

-- Versions and pins never change; heads are never deleted (PF018).
CREATE FUNCTION risk.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'risk.%: % refused; risk data versions are append-only and heads are archived, never deleted', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'PF018';
END $$;

REVOKE ALL ON FUNCTION risk.actor(), risk.head_before_insert(), risk.version_before_insert(), risk.version_after_insert(),
  risk.refuse_change() FROM PUBLIC;
-- Creating a trigger needs EXECUTE on its function.
GRANT EXECUTE ON FUNCTION risk.head_before_insert(), risk.version_before_insert(), risk.version_after_insert(),
  risk.refuse_change() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;

CREATE TRIGGER head_before_insert BEFORE INSERT ON risk.scenario FOR EACH ROW EXECUTE FUNCTION risk.head_before_insert();
CREATE TRIGGER head_before_insert BEFORE INSERT ON risk.library_entry FOR EACH ROW EXECUTE FUNCTION risk.head_before_insert();
CREATE TRIGGER head_before_insert BEFORE INSERT ON risk.control FOR EACH ROW EXECUTE FUNCTION risk.head_before_insert();
CREATE TRIGGER version_before_insert BEFORE INSERT ON risk.scenario_version FOR EACH ROW EXECUTE FUNCTION risk.version_before_insert();
CREATE TRIGGER version_before_insert BEFORE INSERT ON risk.library_version FOR EACH ROW EXECUTE FUNCTION risk.version_before_insert();
CREATE TRIGGER version_before_insert BEFORE INSERT ON risk.control_version FOR EACH ROW EXECUTE FUNCTION risk.version_before_insert();
CREATE TRIGGER version_after_insert AFTER INSERT ON risk.scenario_version FOR EACH ROW EXECUTE FUNCTION risk.version_after_insert();
CREATE TRIGGER version_after_insert AFTER INSERT ON risk.library_version FOR EACH ROW EXECUTE FUNCTION risk.version_after_insert();
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['scenario_version', 'library_version', 'control_version', 'scenario_pin', 'library_pin'] LOOP
    EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON risk.%I FOR EACH ROW EXECUTE FUNCTION risk.refuse_change()', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON risk.%I FOR EACH STATEMENT EXECUTE FUNCTION risk.refuse_change()', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['scenario', 'library_entry', 'control'] LOOP
    EXECUTE format('CREATE TRIGGER never_deleted BEFORE DELETE ON risk.%I FOR EACH ROW EXECUTE FUNCTION risk.refuse_change()', t);
    EXECUTE format('CREATE TRIGGER never_truncated BEFORE TRUNCATE ON risk.%I FOR EACH STATEMENT EXECUTE FUNCTION risk.refuse_change()', t);
  END LOOP;
END $$;
-- Heads: only archived_at changes outside the version trigger (column
-- grants), and the trigger may only advance current_version by one.
CREATE FUNCTION risk.head_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (to_jsonb(NEW) - 'archived_at' - 'current_version') IS DISTINCT FROM (to_jsonb(OLD) - 'archived_at' - 'current_version')
     OR (NEW.current_version IS DISTINCT FROM OLD.current_version AND NEW.current_version IS DISTINCT FROM OLD.current_version + 1) THEN
    RAISE EXCEPTION 'risk.%: only archived_at changes, and current_version only by a new version', TG_TABLE_NAME USING ERRCODE = 'PF018';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION risk.head_before_update() FROM PUBLIC;
CREATE TRIGGER head_before_update BEFORE UPDATE ON risk.scenario FOR EACH ROW EXECUTE FUNCTION risk.head_before_update();
CREATE TRIGGER head_before_update BEFORE UPDATE ON risk.library_entry FOR EACH ROW EXECUTE FUNCTION risk.head_before_update();
CREATE TRIGGER head_before_update BEFORE UPDATE ON risk.control FOR EACH ROW EXECUTE FUNCTION risk.head_before_update();
