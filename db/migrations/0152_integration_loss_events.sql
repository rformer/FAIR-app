-- F-011 T-12 (F-011-AC-17 to AC-19; design §3.5 and §5 as amended
-- 2026-11-18, §6.2): loss events and derivations.
--
--   * integration.loss_event gains digest (the record's): a run writes the
--     events that are new or changed (integration.put_loss_events, in the
--     pusher's transaction) and a complete run archives the events it no
--     longer holds; integration.loss_event_match lets the batch say which
--     are new, changed or unchanged. Events are read under RLS (library).
--   * Derivations: integration.set_derivation / get_derivation /
--     delete_derivation (library.view or library.edit at the reference
--     class's BU, read under the caller's RLS); integration.derive computes
--     a class's period and data from the events in a subtree of its BU,
--     within its restricted root only; integration.propose_derivation
--     proposes a new version when the data differs from the last computed.
--   * A proposal's origin is an integration and its run, or a derivation
--     (derivation_id), never both (design §3.5 as amended).

ALTER TABLE integration.loss_event ADD COLUMN digest text CHECK (digest ~ '^[0-9a-f]{64}$');

GRANT USAGE ON SCHEMA risk TO integration_definer;
GRANT SELECT ON risk.library_entry, risk.library_version TO integration_definer;
GRANT EXECUTE ON FUNCTION iam.restricted_root(uuid) TO integration_definer;
-- The library's RLS policies, evaluated for the caller's context when a
-- derivation reads its reference class (as register_definer reads risks).
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope(), authz.visible_bus(text, text), authz.scope_excludes(text, text),
  authz.scope_hides(text, text), authz.inherited_bus(text) TO integration_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT UPDATE (bu_id, occurred_on, event_type, description, amounts, digest, archived_at, updated_at) ON integration.loss_event TO integration_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON integration.derivation TO integration_definer;


ALTER TABLE integration.proposal ALTER COLUMN integration_id DROP NOT NULL, ALTER COLUMN run_id DROP NOT NULL;
ALTER TABLE integration.proposal ADD COLUMN derivation_id uuid REFERENCES risk.library_entry (id);
ALTER TABLE integration.proposal ADD CONSTRAINT proposal_origin CHECK (
  (integration_id IS NOT NULL AND run_id IS NOT NULL AND derivation_id IS NULL)
  OR (integration_id IS NULL AND run_id IS NULL AND derivation_id IS NOT NULL AND target_type = 'reference_class' AND action = 'update'
      AND external_id IS NULL AND target_id = derivation_id));
CREATE UNIQUE INDEX proposal_one_pending_derivation ON integration.proposal (derivation_id) WHERE state = 'pending' AND derivation_id IS NOT NULL;

CREATE OR REPLACE FUNCTION integration.proposal_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.integration_id, NEW.run_id, NEW.derivation_id, NEW.bu_id, NEW.target_type, NEW.target_id, NEW.external_id, NEW.action,
      NEW.base_version, NEW.document, NEW.digest, NEW.descriptive_only, NEW.created_at, NEW.seq)
     IS DISTINCT FROM (OLD.id, OLD.integration_id, OLD.run_id, OLD.derivation_id, OLD.bu_id, OLD.target_type, OLD.target_id, OLD.external_id,
      OLD.action, OLD.base_version, OLD.document, OLD.digest, OLD.descriptive_only, OLD.created_at, OLD.seq) THEN
    RAISE EXCEPTION 'integration: a proposal keeps what it proposes' USING ERRCODE = 'PF031', HINT = 'proposal_fixed';
  END IF;
  IF OLD.state <> 'pending' THEN
    RAISE EXCEPTION 'integration: a decided proposal does not change' USING ERRCODE = 'PF031', HINT = 'proposal_decided';
  END IF;
  RETURN NEW;
END $$;

GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

-- Proposals of either origin.
CREATE OR REPLACE FUNCTION integration.proposal_json(p integration.proposal) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', p.id, 'integration_id', p.integration_id, 'integration_name', i.name, 'run_id', p.run_id,
    'run_started_at', r.started_at, 'derivation_id', p.derivation_id, 'bu_id', p.bu_id, 'bu_name', b.name, 'target_type', p.target_type,
    'target_id', p.target_id, 'external_id', p.external_id, 'action', p.action, 'record', p.document, 'digest', p.digest,
    'descriptive_only', p.descriptive_only, 'state', p.state, 'decided_by', p.decided_by,
    'decided_by_name', (SELECT a.display_name FROM iam.app_user a WHERE a.id = p.decided_by),
    'decided_at', p.decided_at, 'reason', p.reason, 'created_at', p.created_at)
  FROM iam.bu b LEFT JOIN integration.integration i ON i.id = p.integration_id LEFT JOIN integration.run r ON r.id = p.run_id
  WHERE b.id = p.bu_id;
$$;

CREATE OR REPLACE FUNCTION integration.decision_event(type text, u uuid, p integration.proposal, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', 'low', 'actor', u::text, 'target', 'integration_proposal:' || p.id,
    'bu_id', p.bu_id, 'attributes', attrs || jsonb_build_object('proposal', p.id::text,
      'integration', coalesce(p.integration_id::text, 'derivation:' || p.derivation_id),
      'external_id', coalesce(p.external_id, ''), 'action', p.action, 'target_type', p.target_type)));
$$;

CREATE OR REPLACE FUNCTION integration.accepted(id uuid, target uuid, version integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); p integration.proposal := integration.decidable(id);
BEGIN
  IF target IS NULL OR (p.target_id IS NOT NULL AND target <> p.target_id) THEN
    RAISE EXCEPTION 'integration: the accepted target is not the proposal''s' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  UPDATE integration.proposal x SET state = 'accepted', decided_by = u, decided_at = now() WHERE x.id = p.id RETURNING * INTO p;
  IF p.action = 'archive' THEN
    DELETE FROM integration.link l WHERE l.integration_id = p.integration_id AND l.external_id = p.external_id;
  ELSE
    INSERT INTO integration.applied (proposal_id, target_type, target_id, version, accepted_by) VALUES (p.id, p.target_type, target, version, u);
    IF p.integration_id IS NOT NULL THEN
      INSERT INTO integration.link (integration_id, external_id, target_type, target_id, last_digest)
      VALUES (p.integration_id, p.external_id, p.target_type, target, p.digest)
      ON CONFLICT ON CONSTRAINT link_pkey DO UPDATE SET last_digest = EXCLUDED.last_digest, rejected_digest = NULL, updated_at = now();
    END IF;
  END IF;
  PERFORM integration.decision_event('integration.proposal_accepted', u, p, jsonb_build_object('target', target::text,
    'version', coalesce(version::text, '')));
  RETURN integration.proposal_json(p);
END $$;

CREATE OR REPLACE FUNCTION integration.provenance(target_type text, target_id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor();
BEGIN
  RETURN coalesce((SELECT jsonb_agg(jsonb_build_object('version', a.version, 'integration_id', i.id, 'integration_name', i.name, 'run_id', p.run_id,
      'derivation_id', p.derivation_id, 'external_id', p.external_id, 'received_at', coalesce(r.started_at, p.created_at), 'accepted_at', a.accepted_at,
      'accepted_by_name', (SELECT x.display_name FROM iam.app_user x WHERE x.id = a.accepted_by)) ORDER BY a.version)
    FROM integration.applied a JOIN integration.proposal p ON p.id = a.proposal_id
    LEFT JOIN integration.integration i ON i.id = p.integration_id LEFT JOIN integration.run r ON r.id = p.run_id
    WHERE a.target_type = provenance.target_type AND a.target_id = provenance.target_id
      AND iam.holds_permission(u, integration.view_permission(p.target_type), p.bu_id)), '[]');
END $$;

-- Loss events (AC-17).
CREATE FUNCTION integration.loss_event_match(id uuid, external_ids text[]) RETURNS TABLE (external_id text, digest text, archived boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i integration.integration := integration.pushable(id);
BEGIN
  RETURN QUERY SELECT e.external_id, e.digest, e.archived_at IS NOT NULL FROM integration.loss_event e
    WHERE e.integration_id = i.id AND e.external_id = ANY (external_ids);
END $$;

-- events: [{external_id, bu_id, occurred_on, event_type, description,
-- amounts, digest}] of the caller's running run.
CREATE FUNCTION integration.put_loss_events(run uuid, events jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r        integration.run := integration.my_run(run);
  i        integration.integration;
  written  integer;
  archived integer := 0;
  derived  integer := 0;
BEGIN
  SELECT * INTO i FROM integration.integration x WHERE x.id = r.integration_id;
  IF i.kind <> 'loss_events' THEN
    RAISE EXCEPTION 'integration: the integration does not bring in loss events' USING ERRCODE = 'PF031', HINT = 'wrong_kind';
  END IF;
  IF jsonb_typeof(events) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'integration: events are a list' USING ERRCODE = 'PF031', HINT = 'invalid_value';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(events) e WHERE (e ->> 'bu_id')::uuid IS DISTINCT FROM i.bu_id AND NOT EXISTS (
       SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = i.bu_id AND c.descendant_id = (e ->> 'bu_id')::uuid)) THEN
    RAISE EXCEPTION 'integration: a loss event is outside the integration''s business units' USING ERRCODE = 'PF031', HINT = 'outside_scope';
  END IF;
  WITH x AS (
    SELECT * FROM jsonb_to_recordset(events) AS t(external_id text, bu_id uuid, occurred_on date, event_type text, description text, amounts jsonb, digest text)
  ), up AS (
    INSERT INTO integration.loss_event AS e (bu_id, integration_id, external_id, occurred_on, event_type, description, amounts, digest)
    SELECT x.bu_id, i.id, x.external_id, x.occurred_on, x.event_type, x.description, coalesce(x.amounts, '{}'), x.digest FROM x
    ON CONFLICT (integration_id, external_id) DO UPDATE SET bu_id = EXCLUDED.bu_id, occurred_on = EXCLUDED.occurred_on,
      event_type = EXCLUDED.event_type, description = EXCLUDED.description, amounts = EXCLUDED.amounts, digest = EXCLUDED.digest, archived_at = NULL
    WHERE e.digest IS DISTINCT FROM EXCLUDED.digest OR e.archived_at IS NOT NULL
    RETURNING 1
  )
  SELECT count(*) INTO written FROM up;
  IF r.complete THEN
    UPDATE integration.loss_event e SET archived_at = now() WHERE e.integration_id = i.id AND e.archived_at IS NULL
      AND NOT (e.external_id = ANY (ARRAY(SELECT x ->> 'external_id' FROM jsonb_array_elements(events) x)));
    GET DIAGNOSTICS archived = ROW_COUNT;
  END IF;
  IF written + archived > 0 THEN
    SELECT count(*) INTO derived FROM integration.derivation d WHERE integration.propose_derivation(d.reference_class_id);
  END IF;
  RETURN jsonb_build_object('written', written, 'archived', archived, 'derived', derived);
END $$;

-- Derivations (AC-18).

-- A reference class as the caller reads it (RLS): its BU and current
-- document; the caller needs perm at its BU.
CREATE FUNCTION integration.reference_class(class uuid, perm text) RETURNS TABLE (bu_id uuid, document jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); e risk.library_entry;
BEGIN
  SELECT * INTO e FROM risk.library_entry x WHERE x.id = class;
  IF e.id IS NULL OR NOT iam.holds_permission(u, 'library.view', e.bu_id) THEN
    RAISE EXCEPTION 'integration: no such reference class %', class USING ERRCODE = 'P0002';
  END IF;
  IF e.kind <> 'reference_class' THEN
    RAISE EXCEPTION 'integration: only reference classes are derived' USING ERRCODE = 'PF031', HINT = 'not_reference_class';
  END IF;
  IF perm = 'library.edit' AND e.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'integration: the reference class is archived' USING ERRCODE = 'PF031', HINT = 'archived';
  END IF;
  IF NOT iam.holds_permission(u, perm, e.bu_id) THEN
    RAISE EXCEPTION 'integration: this needs % at the reference class''s business unit', perm USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  RETURN QUERY SELECT e.bu_id, convert_from(v.document, 'UTF8')::jsonb FROM risk.library_version v
    WHERE v.entry_id = e.id AND v.version = e.current_version;
END $$;

CREATE FUNCTION integration.derivation_problem(ptr text, msg text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'integration: %', msg USING ERRCODE = 'PF031', HINT = 'invalid_derivation', DETAIL = ptr;
END $$;

-- The events a derivation counts: in the filter's subtree, of its event
-- types and period, within the class's restricted root (design §3.5).
CREATE FUNCTION integration.matching_events(d integration.derivation) RETURNS TABLE (occurred_on date, amounts jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT e.occurred_on, e.amounts FROM integration.loss_event e
  WHERE e.archived_at IS NULL AND e.event_type = ANY (ARRAY(SELECT jsonb_array_elements_text(d.filter -> 'event_types')))
    AND e.occurred_on >= (d.filter ->> 'from')::date AND e.occurred_on < (d.filter ->> 'to')::date
    AND (e.bu_id = (d.filter ->> 'bu_id')::uuid OR EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = (d.filter ->> 'bu_id')::uuid AND c.descendant_id = e.bu_id))
    AND iam.restricted_root(e.bu_id) IS NOT DISTINCT FROM iam.restricted_root(d.bu_id);
$$;

-- The class's period and data from the events matching its derivation:
-- in the filter's subtree, of its event types, within the class's
-- restricted root (design §3.5).
CREATE FUNCTION integration.derive(class uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d     integration.derivation;
  f     jsonb;
  fb    uuid;
  types text[];
  froms date;
  tos   date;
  step  interval;
  root  uuid;
  forms text[];
  out   jsonb;
BEGIN
  SELECT * INTO d FROM integration.derivation x WHERE x.reference_class_id = class;
  IF d.reference_class_id IS NULL THEN
    RETURN NULL;
  END IF;
  f := d.filter;
  fb := (f ->> 'bu_id')::uuid;
  types := ARRAY(SELECT jsonb_array_elements_text(f -> 'event_types'));
  froms := (f ->> 'from')::date;
  tos := (f ->> 'to')::date;
  IF d.data_kind = 'counts' THEN
    step := CASE f ->> 'granularity' WHEN 'month' THEN interval '1 month' WHEN 'quarter' THEN interval '3 months' ELSE interval '1 year' END;
    SELECT jsonb_agg(jsonb_build_object('start', p.s::text, 'end', p.e::text,
             'count', (SELECT count(*) FROM integration.matching_events(d) x WHERE x.occurred_on >= p.s AND x.occurred_on < p.e)) ORDER BY p.s)
      INTO out
      FROM (SELECT g::date AS s, least((g + step)::date, tos) AS e FROM generate_series(froms::timestamp, (tos - 1)::timestamp, step) g) p;
    RETURN jsonb_build_object('period', jsonb_build_object('start', froms::text, 'end', tos::text),
      'data', jsonb_build_object('kind', 'counts', 'series', coalesce(out, '[]')));
  END IF;
  forms := CASE WHEN f ? 'forms' THEN ARRAY(SELECT jsonb_array_elements_text(f -> 'forms')) END;
  SELECT jsonb_agg(to_jsonb(trim_scale(t.total)::text) ORDER BY t.total) INTO out FROM (
    SELECT (SELECT sum((a.value #>> '{}')::numeric) FROM jsonb_each(x.amounts) a WHERE forms IS NULL OR a.key = ANY (forms)) AS total
    FROM integration.matching_events(d) x) t
  WHERE t.total > 0;
  RETURN jsonb_build_object('period', jsonb_build_object('start', froms::text, 'end', tos::text),
    'data', jsonb_build_object('kind', 'losses', 'unit', 'currency', 'amounts', coalesce(out, '[]')));
END $$;

-- Proposes the class's new version when the data differs from the last
-- computed (the derivation's digest); supersedes its pending one.
CREATE FUNCTION integration.propose_derivation(class uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE d integration.derivation; rec jsonb; dg text;
BEGIN
  SELECT * INTO d FROM integration.derivation x WHERE x.reference_class_id = class FOR UPDATE;
  IF d.reference_class_id IS NULL THEN
    RETURN false;
  END IF;
  rec := integration.derive(class);
  dg := encode(sha256(convert_to(rec::text, 'UTF8')), 'hex');
  IF dg IS NOT DISTINCT FROM d.digest THEN
    RETURN false;
  END IF;
  UPDATE integration.proposal p SET state = 'superseded' WHERE p.derivation_id = class AND p.state = 'pending';
  INSERT INTO integration.proposal (bu_id, target_type, target_id, action, document, digest, derivation_id)
  VALUES (d.bu_id, 'reference_class', class, 'update', rec, dg, class);
  UPDATE integration.derivation x SET digest = dg WHERE x.reference_class_id = class;
  RETURN true;
END $$;

CREATE FUNCTION integration.derivation_json(class uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('reference_class_id', d.reference_class_id, 'bu_id', d.bu_id, 'filter', d.filter, 'data_kind', d.data_kind,
    'set_by_name', (SELECT a.display_name FROM iam.app_user a WHERE a.id = d.set_by), 'set_at', d.set_at,
    'pending_proposal', (SELECT p.id FROM integration.proposal p WHERE p.derivation_id = d.reference_class_id AND p.state = 'pending'))
  FROM integration.derivation d WHERE d.reference_class_id = class;
$$;

CREATE FUNCTION integration.derivation_event(u uuid, class uuid, bu uuid, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'integration.derivation_changed', 'severity', 'low', 'actor', u::text, 'target', 'library:' || class,
    'bu_id', bu, 'attributes', attrs || jsonb_build_object('reference_class', class::text)));
$$;

-- filter: {bu_id (a subtree of the class's BU, in its restricted root),
-- event_types (1 to 50), from, to, granularity (month, quarter, year),
-- forms (losses only)}.
CREATE FUNCTION integration.set_derivation(class uuid, filter jsonb, data_kind text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u        uuid := integration.actor();
  bu       uuid;
  cur      jsonb;
  fb       uuid;
  froms    date;
  tos      date;
  n        integer;
  rec      jsonb;
  proposed boolean := false;
  k        text;
BEGIN
  SELECT c.bu_id, c.document INTO bu, cur FROM integration.reference_class(class, 'library.edit') c;
  IF data_kind IS NULL OR data_kind NOT IN ('counts', 'losses') THEN
    PERFORM integration.derivation_problem('/data_kind', 'is counts or losses');
  END IF;
  IF jsonb_typeof(filter) IS DISTINCT FROM 'object' THEN
    PERFORM integration.derivation_problem('/filter', 'is an object');
  END IF;
  FOR k IN SELECT jsonb_object_keys(filter) LOOP
    IF k NOT IN ('bu_id', 'event_types', 'from', 'to', 'granularity', 'forms') THEN
      PERFORM integration.derivation_problem('/filter/' || k, 'is not a known field');
    END IF;
  END LOOP;
  IF NOT coalesce(filter ->> 'bu_id', '') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    PERFORM integration.derivation_problem('/filter/bu_id', 'is a business unit id');
  END IF;
  fb := (filter ->> 'bu_id')::uuid;
  IF fb <> bu AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = bu AND c.descendant_id = fb) THEN
    PERFORM integration.derivation_problem('/filter/bu_id', 'is not in the reference class''s business unit''s subtree');
  END IF;
  IF iam.restricted_root(fb) IS DISTINCT FROM iam.restricted_root(bu) THEN
    PERFORM integration.derivation_problem('/filter/bu_id', 'is in another restricted subtree than the reference class');
  END IF;
  IF jsonb_typeof(filter -> 'event_types') IS DISTINCT FROM 'array' OR jsonb_array_length(filter -> 'event_types') NOT BETWEEN 1 AND 50
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(filter -> 'event_types') t WHERE jsonb_typeof(t) <> 'string' OR char_length(t #>> '{}') NOT BETWEEN 1 AND 100)
     OR (SELECT count(DISTINCT t) FROM jsonb_array_elements(filter -> 'event_types') t) <> jsonb_array_length(filter -> 'event_types') THEN
    PERFORM integration.derivation_problem('/filter/event_types', 'is 1 to 50 distinct event types');
  END IF;
  BEGIN
    froms := (filter ->> 'from')::date;
    tos := (filter ->> 'to')::date;
  EXCEPTION WHEN others THEN
    PERFORM integration.derivation_problem('/filter/from', 'from and to are dates (YYYY-MM-DD)');
  END;
  IF froms IS NULL OR tos IS NULL OR tos <= froms THEN
    PERFORM integration.derivation_problem('/filter/to', 'from and to are dates, to after from');
  END IF;
  IF data_kind = 'counts' THEN
    IF coalesce(filter ->> 'granularity', '') NOT IN ('month', 'quarter', 'year') THEN
      PERFORM integration.derivation_problem('/filter/granularity', 'is month, quarter or year');
    END IF;
    IF filter ? 'forms' THEN
      PERFORM integration.derivation_problem('/filter/forms', 'is used with losses only');
    END IF;
    n := (SELECT count(*) FROM generate_series(froms::timestamp, (tos - 1)::timestamp,
      CASE filter ->> 'granularity' WHEN 'month' THEN interval '1 month' WHEN 'quarter' THEN interval '3 months' ELSE interval '1 year' END));
    IF n > 200 THEN
      PERFORM integration.derivation_problem('/filter/granularity', 'makes more than 200 periods');
    END IF;
  ELSE
    IF filter ? 'granularity' THEN
      PERFORM integration.derivation_problem('/filter/granularity', 'is used with counts only');
    END IF;
    IF filter ? 'forms' AND (jsonb_typeof(filter -> 'forms') IS DISTINCT FROM 'array' OR jsonb_array_length(filter -> 'forms') = 0
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(filter -> 'forms') x WHERE jsonb_typeof(x) <> 'string'
                  OR NOT integration.valid_amounts(jsonb_build_object(x #>> '{}', '1')))) THEN
      PERFORM integration.derivation_problem('/filter/forms', 'are forms of loss');
    END IF;
  END IF;
  INSERT INTO integration.derivation (reference_class_id, bu_id, filter, data_kind, digest, set_by)
  VALUES (class, bu, filter, data_kind, NULL, u)
  ON CONFLICT (reference_class_id) DO UPDATE SET filter = EXCLUDED.filter, data_kind = EXCLUDED.data_kind, set_by = u, set_at = now(),
    digest = CASE WHEN integration.derivation.filter = EXCLUDED.filter AND integration.derivation.data_kind = EXCLUDED.data_kind
                  THEN integration.derivation.digest END; -- unchanged: proposes only if the data changed
  rec := integration.derive(class);
  IF cur -> 'data' = rec -> 'data' AND cur -> 'period' = rec -> 'period' THEN
    -- The class holds the data already.
    UPDATE integration.proposal p SET state = 'superseded' WHERE p.derivation_id = class AND p.state = 'pending';
    UPDATE integration.derivation x SET digest = encode(sha256(convert_to(rec::text, 'UTF8')), 'hex') WHERE x.reference_class_id = class;
  ELSE
    proposed := integration.propose_derivation(class);
  END IF;
  PERFORM integration.derivation_event(u, class, bu, jsonb_build_object('change', 'set', 'data_kind', data_kind, 'proposed', proposed::text));
  RETURN integration.derivation_json(class) || jsonb_build_object('proposed', proposed);
END $$;

CREATE FUNCTION integration.get_derivation(class uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE bu uuid; out jsonb;
BEGIN
  SELECT c.bu_id INTO bu FROM integration.reference_class(class, 'library.view') c;
  out := integration.derivation_json(class);
  IF out IS NULL THEN
    RAISE EXCEPTION 'integration: the reference class has no derivation' USING ERRCODE = 'P0002';
  END IF;
  RETURN out || jsonb_build_object('computed', integration.derive(class));
END $$;

CREATE FUNCTION integration.delete_derivation(class uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); bu uuid; kind text;
BEGIN
  SELECT c.bu_id INTO bu FROM integration.reference_class(class, 'library.edit') c;
  SELECT d.data_kind INTO kind FROM integration.derivation d WHERE d.reference_class_id = class FOR UPDATE;
  IF kind IS NULL THEN
    RAISE EXCEPTION 'integration: the reference class has no derivation' USING ERRCODE = 'P0002';
  END IF;
  UPDATE integration.proposal p SET state = 'superseded' WHERE p.derivation_id = class AND p.state = 'pending';
  DELETE FROM integration.derivation d WHERE d.reference_class_id = class;
  PERFORM integration.derivation_event(u, class, bu, jsonb_build_object('change', 'removed', 'data_kind', kind, 'proposed', 'false'));
END $$;

REVOKE ALL ON FUNCTION integration.loss_event_match(uuid, text[]), integration.put_loss_events(uuid, jsonb),
  integration.reference_class(uuid, text), integration.derivation_problem(text, text), integration.matching_events(integration.derivation), integration.derive(uuid),
  integration.propose_derivation(uuid), integration.derivation_json(uuid), integration.derivation_event(uuid, uuid, uuid, jsonb),
  integration.set_derivation(uuid, jsonb, text), integration.get_derivation(uuid), integration.delete_derivation(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.loss_event_match(uuid, text[]), integration.put_loss_events(uuid, jsonb),
  integration.set_derivation(uuid, jsonb, text), integration.get_derivation(uuid), integration.delete_derivation(uuid) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;
