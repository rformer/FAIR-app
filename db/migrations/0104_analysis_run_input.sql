-- F-005 T-11 (F-005-AC-01, AC-06, AC-15, AC-22; design §4.1, §6.1;
-- decided with Robert Former 2026-11-11): a run's input bundle.
--
-- The bundle is built when the analyst requests the run, under their signed
-- context (design §6.1); the risk service's worker has no context of its own
-- (only the gateway can mint one), so the bundle is kept with the run:
--
-- * analysis.run_input holds it, BU-owned under RLS: analysis data
--   (inserted with the run by whoever may request it), and, being the
--   scenario's content, readable only with scenario read scope too (a
--   RESTRICTIVE select policy, ADR-007 amendment 4). Append-only for every
--   role, moved with its scenario.
-- * analysis.request_run now takes the bundle itself and records its
--   SHA-256 as the run's bundle_digest, so the digest is always the stored
--   bundle's; a reproduction's bundle must have the original's digest.
-- * Every run has its input by the end of its transaction (a deferred
--   constraint trigger), and the worker reads it, and the run's inputs, with
--   its attempt token (analysis.run_bundle, analysis.run_spec).

CREATE TABLE analysis.run_input (
  run_id uuid  PRIMARY KEY REFERENCES analysis.run (id),
  bu_id  uuid  NOT NULL,
  bundle bytea NOT NULL CHECK (octet_length(bundle) BETWEEN 2 AND 8388608)
);

SELECT authz.apply_bu_rls('analysis.run_input', 'analysis');
SELECT authz.allow_definer('analysis.run_input', 'analysis_definer');
GRANT SELECT ON analysis.run_input TO app_rw;
GRANT INSERT (run_id, bu_id, bundle) ON analysis.run_input TO app_rw;

GRANT CREATE ON SCHEMA analysis TO analysis_definer;
SET ROLE analysis_definer;

-- The input: inserted with its run, in its creating transaction, matching
-- the run's digest.
CREATE FUNCTION analysis.input_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record;
BEGIN
  SELECT x.bu_id, x.state, x.requested_at, x.bundle_digest INTO r FROM analysis.run x WHERE x.id = NEW.run_id;
  IF NOT FOUND OR r.state <> 'queued' OR r.requested_at <> now() THEN
    RAISE EXCEPTION 'analysis.run_input: added only with its run' USING ERRCODE = 'PF024';
  END IF;
  IF encode(sha256(NEW.bundle), 'hex') <> r.bundle_digest THEN
    RAISE EXCEPTION 'analysis.run_input: the bundle does not have the run''s digest' USING ERRCODE = 'PF024';
  END IF;
  NEW.bu_id := r.bu_id;
  RETURN NEW;
END $$;

-- Only a move changes an input.
CREATE FUNCTION analysis.input_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF current_user <> 'analysis_definer' OR (to_jsonb(NEW) - 'bu_id') IS DISTINCT FROM (to_jsonb(OLD) - 'bu_id') THEN
    RAISE EXCEPTION 'analysis.run_input: a run''s input never changes' USING ERRCODE = 'PF023';
  END IF;
  RETURN NEW;
END $$;

-- Every run has its input when its transaction commits.
CREATE FUNCTION analysis.run_has_input() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM analysis.run_input i WHERE i.run_id = NEW.id) THEN
    RAISE EXCEPTION 'analysis.run: run % has no input bundle', NEW.id USING ERRCODE = 'PF024';
  END IF;
  RETURN NULL;
END $$;

-- The worker reads a running run's bundle with its attempt token.
CREATE FUNCTION analysis.run_bundle(id uuid, token text) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r analysis.run; b bytea;
BEGIN
  SELECT * INTO r FROM analysis.run x WHERE x.id = run_bundle.id;
  IF NOT FOUND OR r.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: run % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(r.attempt, token, 'the run');
  SELECT i.bundle INTO b FROM analysis.run_input i WHERE i.run_id = r.id;
  RETURN b;
END $$;

-- And the run's inputs (the seed as text: it may exceed bigint).
CREATE FUNCTION analysis.run_spec(id uuid, token text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r analysis.run;
BEGIN
  SELECT * INTO r FROM analysis.run x WHERE x.id = run_spec.id;
  IF NOT FOUND OR r.state <> 'running' THEN
    RAISE EXCEPTION 'analysis: run % is not running', id USING ERRCODE = 'PF024';
  END IF;
  PERFORM analysis.check_attempt(r.attempt, token, 'the run');
  RETURN jsonb_build_object('id', r.id, 'bu_id', r.bu_id, 'scenario_id', r.scenario_id, 'scenario_version', r.scenario_version,
    'bundle_digest', r.bundle_digest, 'seed', r.seed::text, 'iterations', r.iterations, 'control_sets', to_jsonb(r.control_sets),
    'reproduces', r.reproduces, 'requested_by', r.requested_by);
END $$;

-- Moving a scenario moves its runs, results, series and inputs (F-003-AC-19).
CREATE OR REPLACE FUNCTION analysis.scenario_after_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.bu_id IS DISTINCT FROM OLD.bu_id THEN
    UPDATE analysis.run SET bu_id = NEW.bu_id WHERE scenario_id = NEW.id;
    UPDATE analysis.result SET bu_id = NEW.bu_id WHERE run_id IN (SELECT id FROM analysis.run WHERE scenario_id = NEW.id);
    UPDATE analysis.series SET bu_id = NEW.bu_id WHERE run_id IN (SELECT id FROM analysis.run WHERE scenario_id = NEW.id);
    UPDATE analysis.run_input SET bu_id = NEW.bu_id WHERE run_id IN (SELECT id FROM analysis.run WHERE scenario_id = NEW.id);
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION analysis.input_before_insert(), analysis.input_before_update(), analysis.run_has_input(),
  analysis.run_bundle(uuid, text), analysis.run_spec(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION analysis.input_before_insert(), analysis.input_before_update(), analysis.run_has_input() TO fair_owner;
GRANT EXECUTE ON FUNCTION analysis.run_bundle(uuid, text), analysis.run_spec(uuid, text) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA analysis FROM analysis_definer;

-- Reading an input needs the scenario's read scope as well.
SELECT authz.restrict_select('analysis.run_input', 'bu_id = ANY (authz.visible_bus(''scenario'', ''read''))');

-- request_run takes the bundle and records its digest.
DROP FUNCTION analysis.request_run(uuid, integer, text, numeric, integer, text[], uuid, integer, integer, integer);
CREATE FUNCTION analysis.request_run(scenario uuid, version integer, bundle bytea, seed numeric, iterations integer, sets text[],
  reproduces uuid, iterations_min integer, iterations_max integer, max_active integer) RETURNS uuid
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE id uuid := gen_random_uuid(); bu uuid; o record; s text; digest text;
BEGIN
  IF bundle IS NULL THEN
    RAISE EXCEPTION 'analysis: a run needs its input bundle' USING ERRCODE = 'PF024';
  END IF;
  digest := encode(sha256(bundle), 'hex');
  IF iterations IS NULL OR iterations < iterations_min OR iterations > iterations_max THEN
    RAISE EXCEPTION 'analysis: iterations are between % and %', iterations_min, iterations_max USING ERRCODE = 'PF024', HINT = 'iterations';
  END IF;
  IF analysis.active_runs(analysis.actor()) >= max_active THEN
    RAISE EXCEPTION 'analysis: at most % runs queued or running at once', max_active USING ERRCODE = 'PF024', HINT = 'too_many_runs';
  END IF;
  IF request_run.reproduces IS NOT NULL THEN
    SELECT r.scenario_id, r.scenario_version, r.bundle_digest, r.seed, r.iterations, r.control_sets, r.state INTO o FROM analysis.run r WHERE r.id = request_run.reproduces;
    IF NOT FOUND OR o.state <> 'succeeded' THEN
      RAISE EXCEPTION 'analysis: run % is not a succeeded run', request_run.reproduces USING ERRCODE = 'P0002';
    END IF;
    IF (o.scenario_id, o.scenario_version, o.seed, o.iterations, o.control_sets) IS DISTINCT FROM (scenario, version, seed, iterations, sets) THEN
      RAISE EXCEPTION 'analysis: a reproduction has the original''s inputs' USING ERRCODE = 'PF024';
    END IF;
    IF o.bundle_digest <> digest THEN
      RAISE EXCEPTION 'analysis: the input bundle no longer has the original''s digest' USING ERRCODE = 'PF024', HINT = 'bundle_changed';
    END IF;
  END IF;
  SELECT sc.bu_id INTO bu FROM risk.scenario sc WHERE sc.id = scenario;
  INSERT INTO analysis.run (id, bu_id, scenario_id, scenario_version, bundle_digest, seed, iterations, control_sets, reproduces)
  VALUES (id, bu, scenario, version, digest, request_run.seed, request_run.iterations, sets, request_run.reproduces);
  INSERT INTO analysis.run_input (run_id, bu_id, bundle) VALUES (id, bu, request_run.bundle);
  FOREACH s IN ARRAY sets LOOP
    INSERT INTO analysis.result (run_id, bu_id, control_set) VALUES (id, bu, s);
    INSERT INTO analysis.series (run_id, bu_id, control_set) VALUES (id, bu, s);
  END LOOP;
  RETURN id;
END $$;
REVOKE ALL ON FUNCTION analysis.request_run(uuid, integer, bytea, numeric, integer, text[], uuid, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION analysis.request_run(uuid, integer, bytea, numeric, integer, text[], uuid, integer, integer, integer) TO app_rw;

CREATE TRIGGER input_before_insert BEFORE INSERT ON analysis.run_input FOR EACH ROW EXECUTE FUNCTION analysis.input_before_insert();
CREATE TRIGGER input_before_update BEFORE UPDATE ON analysis.run_input FOR EACH ROW EXECUTE FUNCTION analysis.input_before_update();
CREATE TRIGGER refuse_delete BEFORE DELETE ON analysis.run_input FOR EACH ROW EXECUTE FUNCTION analysis.refuse_change();
CREATE TRIGGER refuse_truncate BEFORE TRUNCATE ON analysis.run_input FOR EACH STATEMENT EXECUTE FUNCTION analysis.refuse_change();
CREATE CONSTRAINT TRIGGER run_has_input AFTER INSERT ON analysis.run DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION analysis.run_has_input();
