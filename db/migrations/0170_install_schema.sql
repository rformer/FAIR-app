-- F-014 T-05 (F-014-AC-09, AC-12, AC-13, AC-34; design §5, D-OQ13): the
-- install schema.
--
--   * Owned through install_definer (bootstrap role; re-run
--     scripts/db-bootstrap.sh). Every table is the definer's alone, read and
--     written through its functions; no BU-owned tables, no risk data.
--     fairctl writes as app_migrator (as iam migrate and iam keys register).
--   * install.installation: the singleton (installation id, customer, mode,
--     state, reason, since). The state moves only by install.set_state,
--     along the allowed moves (PF035).
--   * install.decision: the installer's decisions and attestations;
--     append-only; recording the same value again is accepted (resume),
--     a different one refused (PF035).
--   * install.release, install.preflight, install.report: the releases
--     installed, upgraded to, rolled back to or restored; preflight runs; the
--     install reports. Append-only (a release's finish and outcome are set
--     once).
--   * install.state(): what every service reads (internal/server's
--     installation-state middleware); 'open' before an installation is
--     recorded (installations older than F-014). install.status() is the
--     Posture page's (app_posture).
--   * install.submit_events: fairctl replays its install log's events into
--     the trail with their original times and ids (a replay is idempotent).
--   * PF035: refusals (the hint names the rule).

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'install_definer') THEN
    RAISE EXCEPTION 'role install_definer is missing: re-run scripts/db-bootstrap.sh (F-014 T-05)';
  END IF;
END $$;

CREATE SCHEMA install;
REVOKE ALL ON SCHEMA install FROM PUBLIC;
GRANT USAGE ON SCHEMA install TO install_definer, app_migrator, app_rw, app_posture, app_gateway, app_audit, app_notify, app_integrate;

CREATE TABLE install.installation (
  singleton       boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  installation_id uuid        NOT NULL,
  customer_id     text        NOT NULL CHECK (customer_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  mode            text        NOT NULL CHECK (mode IN ('saas', 'self-hosted', 'air-gapped')),
  state           text        NOT NULL CHECK (state IN ('installing', 'open', 'upgrading', 'restoring', 'closed', 'decommissioning')),
  reason          text        CHECK (char_length(reason) <= 1000),
  since           timestamptz NOT NULL DEFAULT now(),
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE install.decision (
  key         text        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.-]{0,99}$'),
  value       jsonb       NOT NULL,
  attested    boolean     NOT NULL DEFAULT false,
  reason      text        CHECK (char_length(reason) <= 1000),
  operator    text        NOT NULL CHECK (char_length(btrim(operator)) BETWEEN 1 AND 200),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CHECK (octet_length(value::text) <= 16384)
);

CREATE TABLE install.release (
  id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  release                     text        NOT NULL CHECK (release ~ '^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'),
  kind                        text        NOT NULL CHECK (kind IN ('install', 'upgrade', 'rollback', 'restore')),
  manifest_digest             text        NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  package_digest              text        CHECK (package_digest ~ '^[0-9a-f]{64}$'),
  component_definition_digest text        CHECK (component_definition_digest ~ '^[0-9a-f]{64}$'),
  operator                    text        NOT NULL CHECK (char_length(btrim(operator)) BETWEEN 1 AND 200),
  started_at                  timestamptz NOT NULL DEFAULT now(),
  finished_at                 timestamptz,
  outcome                     text        CHECK (outcome IN ('succeeded', 'failed', 'removed')),
  CHECK ((finished_at IS NULL) = (outcome IS NULL))
);

CREATE TABLE install.preflight (
  run_id      uuid        PRIMARY KEY,
  release     text        NOT NULL CHECK (char_length(release) BETWEEN 1 AND 100),
  purpose     text        NOT NULL CHECK (purpose IN ('install', 'upgrade', 'check', 'hook')),
  started_at  timestamptz NOT NULL,
  finished_at timestamptz NOT NULL,
  result      text        NOT NULL CHECK (result IN ('passed', 'passed_with_overrides', 'refused')),
  report      jsonb       NOT NULL CHECK (jsonb_typeof(report) = 'object' AND octet_length(report::text) <= 1048576),
  digest      text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CHECK (finished_at >= started_at)
);

CREATE TABLE install.report (
  release_id  uuid        PRIMARY KEY REFERENCES install.release (id),
  report      jsonb       NOT NULL CHECK (jsonb_typeof(report) = 'object' AND octet_length(report::text) <= 1048576),
  text        text        NOT NULL CHECK (octet_length(text) <= 1048576),
  recorded_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON install.installation, install.decision, install.release, install.preflight, install.report FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON install.installation, install.release TO install_definer;
GRANT SELECT, INSERT ON install.decision, install.preflight, install.report TO install_definer;

-- Rules (PF035), for every role.
CREATE FUNCTION install.no_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'install: % rows do not change', TG_TABLE_NAME USING ERRCODE = 'PF035', HINT = 'immutable';
END $$;

CREATE FUNCTION install.refuse_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'install: % is not truncated', TG_TABLE_NAME USING ERRCODE = 'PF035', HINT = 'immutable';
END $$;

-- The allowed state moves (design §3.4, §3.10, §3.11, §3.14).
CREATE FUNCTION install.move_allowed(old_state text, new_state text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT (old_state, new_state) IN (
    ('installing', 'open'),
    ('open', 'upgrading'), ('open', 'restoring'), ('open', 'closed'), ('open', 'decommissioning'),
    ('upgrading', 'open'), ('upgrading', 'restoring'), ('upgrading', 'closed'),
    ('restoring', 'open'), ('restoring', 'closed'),
    ('closed', 'open'), ('closed', 'restoring'), ('closed', 'decommissioning'));
$$;

CREATE FUNCTION install.installation_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.installation_id, NEW.customer_id, NEW.mode, NEW.created_at) IS DISTINCT FROM (OLD.installation_id, OLD.customer_id, OLD.mode, OLD.created_at) THEN
    RAISE EXCEPTION 'install: the installation keeps its identity and mode' USING ERRCODE = 'PF035', HINT = 'immutable';
  END IF;
  IF NOT install.move_allowed(OLD.state, NEW.state) THEN
    RAISE EXCEPTION 'install: % cannot move to %', OLD.state, NEW.state USING ERRCODE = 'PF035', HINT = 'state_move';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER state BEFORE UPDATE ON install.installation FOR EACH ROW EXECUTE FUNCTION install.installation_before_update();
REVOKE ALL ON FUNCTION install.move_allowed(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION install.move_allowed(text, text) TO install_definer;

CREATE FUNCTION install.release_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF OLD.finished_at IS NOT NULL THEN
    RAISE EXCEPTION 'install: a finished release record does not change' USING ERRCODE = 'PF035', HINT = 'release_finished';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['finished_at', 'outcome']) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['finished_at', 'outcome']) THEN
    RAISE EXCEPTION 'install: a release record keeps what was started' USING ERRCODE = 'PF035', HINT = 'immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER finish BEFORE UPDATE ON install.release FOR EACH ROW EXECUTE FUNCTION install.release_before_update();

CREATE TRIGGER no_delete BEFORE DELETE ON install.installation FOR EACH ROW EXECUTE FUNCTION install.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON install.release FOR EACH ROW EXECUTE FUNCTION install.no_change();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON install.decision FOR EACH ROW EXECUTE FUNCTION install.no_change();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON install.preflight FOR EACH ROW EXECUTE FUNCTION install.no_change();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON install.report FOR EACH ROW EXECUTE FUNCTION install.no_change();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON install.installation FOR EACH STATEMENT EXECUTE FUNCTION install.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON install.decision FOR EACH STATEMENT EXECUTE FUNCTION install.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON install.release FOR EACH STATEMENT EXECUTE FUNCTION install.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON install.preflight FOR EACH STATEMENT EXECUTE FUNCTION install.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON install.report FOR EACH STATEMENT EXECUTE FUNCTION install.refuse_truncate();

GRANT USAGE ON SCHEMA iam TO install_definer;
GRANT INSERT ON iam.event_outbox TO install_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO install_definer;
GRANT USAGE ON SCHEMA audit TO install_definer;
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.looks_secret(text) TO install_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA install TO install_definer;
SET ROLE install_definer;

-- Events through the outbox (F-002 T-06), in the caller's transaction.
CREATE FUNCTION install.emit(type text, operator text, target text, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', 'high', 'actor', 'operator:' || btrim(operator), 'target', target,
    'attributes', attrs));
$$;

CREATE FUNCTION install.refuse_secrets(what text, v jsonb) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF audit.looks_secret(v::text) THEN
    RAISE EXCEPTION 'install: the % carries a value that looks like a secret', what USING ERRCODE = 'PF035', HINT = 'secret';
  END IF;
END $$;

-- The installation, recorded once (fairctl install, step 8); the same again
-- is accepted (resume), anything else refused.
CREATE FUNCTION install.record_installation(installation_id uuid, customer_id text, mode text, operator text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i install.installation;
BEGIN
  SELECT * INTO i FROM install.installation;
  IF FOUND THEN
    IF (i.installation_id, i.customer_id, i.mode) IS DISTINCT FROM (record_installation.installation_id, record_installation.customer_id, record_installation.mode) THEN
      RAISE EXCEPTION 'install: this database already belongs to installation %', i.installation_id USING ERRCODE = 'PF035', HINT = 'installed';
    END IF;
    RETURN i.state;
  END IF;
  INSERT INTO install.installation (installation_id, customer_id, mode, state, reason)
  VALUES (record_installation.installation_id, record_installation.customer_id, record_installation.mode, 'installing', NULL);
  RETURN 'installing';
END $$;

-- A state move (fairctl: install, upgrade, restore, close, open,
-- decommission); refused off the allowed moves (PF035).
CREATE FUNCTION install.set_state(new_state text, reason text, operator text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i install.installation;
BEGIN
  IF btrim(coalesce(operator, '')) = '' THEN
    RAISE EXCEPTION 'install: a state move names its operator' USING ERRCODE = 'PF035', HINT = 'operator';
  END IF;
  SELECT * INTO i FROM install.installation FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'install: no installation is recorded' USING ERRCODE = 'PF035', HINT = 'not_installed';
  END IF;
  IF i.state = new_state THEN
    RETURN i.state;
  END IF;
  UPDATE install.installation SET state = new_state, reason = nullif(btrim(set_state.reason), ''), since = now();
  RETURN new_state;
END $$;

-- What every service reads: 'open' until an installation is recorded.
CREATE FUNCTION install.state() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce((SELECT state FROM install.installation), 'open');
$$;

-- A decision or attestation (AC-09, AC-12): the same value again is
-- accepted; a different one is refused.
CREATE FUNCTION install.record_decision(key text, value jsonb, attested boolean, reason text, operator text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE d install.decision;
BEGIN
  PERFORM install.refuse_secrets('decision', value);
  SELECT * INTO d FROM install.decision x WHERE x.key = record_decision.key;
  IF FOUND THEN
    IF d.value IS DISTINCT FROM record_decision.value OR d.attested IS DISTINCT FROM coalesce(record_decision.attested, false) THEN
      RAISE EXCEPTION 'install: decision % is already recorded with another value', key USING ERRCODE = 'PF035', HINT = 'decided';
    END IF;
    RETURN false;
  END IF;
  INSERT INTO install.decision (key, value, attested, reason, operator)
  VALUES (record_decision.key, record_decision.value, coalesce(record_decision.attested, false), nullif(btrim(record_decision.reason), ''), btrim(operator));
  PERFORM install.emit('install.decision_recorded', operator, 'install_decision:' || key,
    jsonb_build_object('key', key, 'attested', CASE WHEN coalesce(record_decision.attested, false) THEN 'true' ELSE 'false' END));
  RETURN true;
END $$;

CREATE FUNCTION install.start_release(release text, kind text, manifest_digest text, package_digest text, component_definition_digest text,
  operator text) RETURNS uuid
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO install.release (release, kind, manifest_digest, package_digest, component_definition_digest, operator)
  VALUES (start_release.release, start_release.kind, start_release.manifest_digest, start_release.package_digest,
    start_release.component_definition_digest, btrim(start_release.operator))
  RETURNING id;
$$;

CREATE FUNCTION install.finish_release(id uuid, outcome text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE install.release r SET finished_at = now(), outcome = finish_release.outcome WHERE r.id = finish_release.id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'install: no release record %', id USING ERRCODE = 'PF035', HINT = 'not_found';
  END IF;
END $$;

-- A preflight run, with the times it ran (it may run before the database
-- exists; fairctl records it afterwards). The same run again is accepted.
CREATE FUNCTION install.record_preflight(run_id uuid, release text, purpose text, started_at timestamptz, finished_at timestamptz, result text,
  report jsonb, digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE p install.preflight;
BEGIN
  PERFORM install.refuse_secrets('preflight report', report);
  SELECT * INTO p FROM install.preflight x WHERE x.run_id = record_preflight.run_id;
  IF FOUND THEN
    IF p.digest <> record_preflight.digest THEN
      RAISE EXCEPTION 'install: preflight run % is already recorded with another report', run_id USING ERRCODE = 'PF035', HINT = 'recorded';
    END IF;
    RETURN false;
  END IF;
  INSERT INTO install.preflight (run_id, release, purpose, started_at, finished_at, result, report, digest)
  VALUES (record_preflight.run_id, record_preflight.release, record_preflight.purpose, record_preflight.started_at, record_preflight.finished_at,
    record_preflight.result, record_preflight.report, record_preflight.digest);
  RETURN true;
END $$;

CREATE FUNCTION install.record_report(release_id uuid, report jsonb, text text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM install.refuse_secrets('install report', report);
  IF audit.looks_secret(text) THEN
    RAISE EXCEPTION 'install: the install report carries a value that looks like a secret' USING ERRCODE = 'PF035', HINT = 'secret';
  END IF;
  INSERT INTO install.report (release_id, report, text) VALUES (record_report.release_id, record_report.report, record_report.text);
END $$;

-- fairctl's install log, replayed into the trail (step 9): each event keeps
-- its id and original time (audit.submit takes both), so a replay after an
-- interruption records nothing twice. Only the installer's own types, and
-- only an operator as actor.
CREATE FUNCTION install.submit_events(events jsonb) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  ev jsonb;
  n integer := 0;
BEGIN
  IF jsonb_typeof(events) <> 'array' OR jsonb_array_length(events) > 1000 THEN
    RAISE EXCEPTION 'install: events are an array of at most 1,000' USING ERRCODE = 'PF035', HINT = 'events';
  END IF;
  FOR ev IN SELECT * FROM jsonb_array_elements(events) LOOP
    IF jsonb_typeof(ev) <> 'object' OR NOT (ev ? 'id' AND ev ? 'time') THEN
      RAISE EXCEPTION 'install: a replayed event has its id and time' USING ERRCODE = 'PF035', HINT = 'events';
    END IF;
    IF NOT (ev->>'type' ~ '^(install|license)\.' OR ev->>'type' ~ '^posture\.deployment_exception_') THEN
      RAISE EXCEPTION 'install: % is not an installer event', ev->>'type' USING ERRCODE = 'PF035', HINT = 'events';
    END IF;
    IF coalesce(ev->>'actor', '') !~ '^operator:\S' THEN
      RAISE EXCEPTION 'install: a replayed event''s actor is an operator' USING ERRCODE = 'PF035', HINT = 'events';
    END IF;
    INSERT INTO iam.event_outbox (topic, payload) VALUES ('audit', ev);
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

-- The Posture page's view (app_posture): no values are secret by
-- construction (refused on the way in).
CREATE FUNCTION install.status() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object(
    'installation', (SELECT jsonb_build_object('installation_id', i.installation_id, 'customer_id', i.customer_id, 'mode', i.mode, 'state', i.state,
                       'reason', i.reason, 'since', i.since) FROM install.installation i),
    'state', install.state(),
    'decisions', coalesce((SELECT jsonb_agg(jsonb_build_object('key', d.key, 'value', d.value, 'attested', d.attested, 'reason', d.reason,
                       'operator', d.operator, 'recorded_at', d.recorded_at) ORDER BY d.key) FROM install.decision d), '[]'),
    'releases', coalesce((SELECT jsonb_agg(jsonb_build_object('id', r.id, 'release', r.release, 'kind', r.kind, 'manifest_digest', r.manifest_digest,
                       'package_digest', r.package_digest, 'component_definition_digest', r.component_definition_digest, 'operator', r.operator,
                       'started_at', r.started_at, 'finished_at', r.finished_at, 'outcome', r.outcome, 'report', rp.report)
                       ORDER BY r.started_at DESC) FROM install.release r LEFT JOIN install.report rp ON rp.release_id = r.id), '[]'),
    'preflight', (SELECT jsonb_build_object('run_id', p.run_id, 'release', p.release, 'purpose', p.purpose, 'started_at', p.started_at,
                       'finished_at', p.finished_at, 'result', p.result, 'report', p.report, 'digest', p.digest)
                  FROM install.preflight p ORDER BY p.finished_at DESC LIMIT 1));
$$;

REVOKE ALL ON FUNCTION install.emit(text, text, text, jsonb), install.refuse_secrets(text, jsonb), install.record_installation(uuid, text, text, text),
  install.set_state(text, text, text), install.state(), install.record_decision(text, jsonb, boolean, text, text),
  install.start_release(text, text, text, text, text, text), install.finish_release(uuid, text),
  install.record_preflight(uuid, text, text, timestamptz, timestamptz, text, jsonb, text), install.record_report(uuid, jsonb, text),
  install.submit_events(jsonb), install.status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION install.record_installation(uuid, text, text, text), install.set_state(text, text, text),
  install.record_decision(text, jsonb, boolean, text, text), install.start_release(text, text, text, text, text, text),
  install.finish_release(uuid, text), install.record_preflight(uuid, text, text, timestamptz, timestamptz, text, jsonb, text),
  install.record_report(uuid, jsonb, text), install.submit_events(jsonb), install.status(), install.state() TO app_migrator;
GRANT EXECUTE ON FUNCTION install.state() TO app_rw, app_posture, app_gateway, app_audit, app_notify, app_integrate;
GRANT EXECUTE ON FUNCTION install.status() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA install FROM install_definer;
