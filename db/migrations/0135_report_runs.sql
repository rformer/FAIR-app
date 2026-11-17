-- F-010 T-09 (F-010-AC-14 to AC-18, AC-22, AC-23; design §3.3, §3.6, §6,
-- §8): report runs, their files and downloads. Functions owned by
-- report_definer:
--   * report.request(kind, bu, params, formats, reason) (invoker, as app_rw
--     under the requester's context): counts the open risks of the scope
--     the requester sees (RLS; a risk report counts its one risk), refuses
--     over 10,000 (PF029 limit_exceeded), then report.add_run.
--   * report.add_run: report.export at the BU (iam.holds_permission; 42501
--     otherwise), at most 3 of the requester's runs queued or running (PF029
--     too_many_running, serialized per requester), the run inserted queued;
--     report.requested in the transaction. The service checks the reason rule
--     (export.reason_required over the scope's BUs, settings) before.
--   * The worker's, as app_rw without a context: report.run_spec(id),
--     report.start_run(id, nonce) (queued or running to running with the
--     delegated token's nonce; a requester no longer active or without
--     report.export at the BU fails the run no_permission), report.progress,
--     report.complete_run (files with sizes and digests, report.generated),
--     report.fail_run (report.failed). Each takes the run's current nonce.
--   * The requester's, from the signed context: report.my_runs, report.get_run
--     and report.download(id, format), which re-checks report.export at the
--     run's BU and records report.downloaded (high) in the transaction.
--     Another user's run is P0002, as a missing one.
--   * report.any_in_subtree(bu, bus): whether one of bus is in bu's subtree
--     (the reason rule's helper; every BU, restricted ones included).
-- Severities: the catalog has no "medium"; requests, generation and failures
-- are low, downloads high (design §8 as amended).

GRANT USAGE ON SCHEMA iam, authz, register TO report_definer;
GRANT SELECT (id, display_name, status) ON iam.app_user TO report_definer;
GRANT SELECT (id, code, name, parent_id, archived_at) ON iam.bu TO report_definer;
GRANT SELECT ON iam.bu_closure TO report_definer;
GRANT SELECT (user_id, scope_version) ON authz.user_scope TO report_definer;
GRANT EXECUTE ON FUNCTION iam.holds_permission(uuid, text, uuid) TO report_definer;
GRANT INSERT ON iam.event_outbox TO report_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO report_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope() TO report_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA report TO report_definer;
SET ROLE report_definer;

-- The signed context's user, or an error: every request and download is attributed.
CREATE FUNCTION report.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'reports need a valid signed database context' USING ERRCODE = 'PF029', HINT = 'no_context';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION report.emit(type text, severity text, actor text, id uuid, bu uuid, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', severity, 'actor', actor, 'target', 'report_run:' || id, 'bu_id', bu,
    'attributes', attrs || jsonb_build_object('run', id::text)));
$$;

CREATE FUNCTION report.any_in_subtree(bu uuid, bus uuid[]) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = any_in_subtree.bu AND c.descendant_id = ANY (bus));
$$;

CREATE FUNCTION report.add_run(kind text, bu uuid, params jsonb, formats text[], reason text, risks integer) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := report.actor();
  id uuid := gen_random_uuid();
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = add_run.bu AND b.archived_at IS NULL) THEN
    RAISE EXCEPTION 'report: no such business unit %', bu USING ERRCODE = 'P0002';
  END IF;
  IF NOT iam.holds_permission(u, 'report.export', bu) THEN
    RAISE EXCEPTION 'report: generating a report needs report.export at its business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF risks > 10000 THEN
    RAISE EXCEPTION 'report: the scope holds % open risks; a report covers at most 10,000', risks USING ERRCODE = 'PF029', HINT = 'limit_exceeded';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('report.run:' || u::text, 0));
  IF (SELECT count(*) FROM report.run r WHERE r.requested_by = u AND r.state IN ('queued', 'running')) >= 3 THEN
    RAISE EXCEPTION 'report: at most 3 reports generating at once' USING ERRCODE = 'PF029', HINT = 'too_many_running';
  END IF;
  INSERT INTO report.run (id, requested_by, bu_id, kind, params, formats, reason)
  VALUES (id, u, bu, kind, coalesce(params, '{}'), formats, nullif(btrim(reason), ''));
  PERFORM report.emit('report.requested', 'low', u::text, id, bu, jsonb_build_object('kind', kind,
    'filters', coalesce(params, '{}')::text, 'formats', array_to_string(formats, ' '), 'reason', coalesce(nullif(btrim(reason), ''), ''),
    'risk_count', risks::text));
  RETURN id;
END $$;

-- As the requester (invoker): the scope's open risks under RLS, then the run.
CREATE FUNCTION report.request(kind text, bu uuid, params jsonb, formats text[], reason text) RETURNS uuid
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE n integer;
BEGIN
  IF kind = 'risk' THEN
    n := 1;
  ELSE
    SELECT count(*) INTO n FROM register.risk r WHERE r.state = 'open' AND r.bu_id IN (SELECT register.subtree(request.bu));
  END IF;
  RETURN report.add_run(kind, bu, params, formats, reason, n);
END $$;

-- The signed context's user, or NULL: the worker checks that its delegated
-- context is honoured before it reads.
CREATE FUNCTION report.reader() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT (authz.ctx_scope()).user_id;
$$;

-- The worker's view of a run (no context): what to read and for whom.
CREATE FUNCTION report.run_spec(id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', r.id, 'state', r.state, 'requested_by', r.requested_by, 'requester_name', u.display_name,
    'scope_version', (SELECT s.scope_version FROM authz.user_scope s WHERE s.user_id = r.requested_by),
    'bu', jsonb_build_object('id', b.id, 'code', b.code, 'name', b.name), 'kind', r.kind, 'params', r.params,
    'formats', to_jsonb(r.formats), 'reason', r.reason, 'schedule_id', r.schedule_id, 'requested_at', r.requested_at,
    'attempts', r.attempts, 'instance', (SELECT x.id FROM iam.bu x WHERE x.parent_id IS NULL))
  FROM report.run r JOIN iam.app_user u ON u.id = r.requested_by JOIN iam.bu b ON b.id = r.bu_id
  WHERE r.id = run_spec.id;
$$;

-- The run's failure, recorded once (final).
CREATE FUNCTION report.failed(r report.run, failure text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE report.run x SET state = 'failed', context_nonce = NULL, failure = left(failed.failure, 500), finished_at = now() WHERE x.id = r.id;
  PERFORM report.emit('report.failed', 'low', 'system:risk', r.id, r.bu_id, jsonb_build_object('kind', r.kind,
    'failure', split_part(failed.failure, ':', 1), 'requested_by', r.requested_by::text));
END $$;

-- Starts (or, for a lost attempt, restarts) a run with the delegated
-- token's nonce: 'started'; 'gone' when the run is finished; 'refused' when
-- the requester is no longer active or holds report.export at the BU no
-- more (the run fails no_permission).
CREATE FUNCTION report.start_run(id uuid, nonce text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r report.run;
BEGIN
  SELECT * INTO r FROM report.run x WHERE x.id = start_run.id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: no such run %', id USING ERRCODE = 'P0002';
  END IF;
  IF r.state IN ('succeeded', 'failed') THEN
    RETURN 'gone';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = r.requested_by AND u.status = 'active')
     OR NOT iam.holds_permission(r.requested_by, 'report.export', r.bu_id) THEN
    PERFORM report.failed(r, 'no_permission: the requester no longer holds report.export at the business unit');
    RETURN 'refused';
  END IF;
  UPDATE report.run x SET state = 'running', context_nonce = nonce, progress = 0, attempts = x.attempts + 1,
    started_at = coalesce(x.started_at, now()) WHERE x.id = r.id;
  RETURN 'started';
END $$;

-- The running run with this nonce, locked; P0002 when there is none (another
-- attempt took it over, or it finished).
CREATE FUNCTION report.running(id uuid, nonce text) RETURNS report.run
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r report.run;
BEGIN
  SELECT * INTO r FROM report.run x WHERE x.id = running.id AND x.state = 'running' AND x.context_nonce = nonce FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: run % is not running with this attempt', id USING ERRCODE = 'P0002', HINT = 'not_running';
  END IF;
  RETURN r;
END $$;

CREATE FUNCTION report.progress(id uuid, nonce text, pct integer) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r report.run := report.running(id, nonce);
BEGIN
  UPDATE report.run x SET progress = greatest(0, least(99, pct)) WHERE x.id = r.id;
END $$;

-- files: [{format, object_key, version_id, size, sha256}].
CREATE FUNCTION report.complete_run(id uuid, nonce text, files jsonb, data_as_of timestamptz, risk_count integer, left_out jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r report.run := report.running(id, nonce);
  f jsonb;
BEGIN
  IF jsonb_typeof(files) <> 'array' OR (SELECT array_agg(x ->> 'format' ORDER BY x ->> 'format') FROM jsonb_array_elements(files) x)
     IS DISTINCT FROM (SELECT array_agg(v ORDER BY v) FROM unnest(r.formats) v) THEN
    RAISE EXCEPTION 'report: a run stores one file per requested format' USING ERRCODE = 'PF029', HINT = 'files';
  END IF;
  FOR f IN SELECT * FROM jsonb_array_elements(files) LOOP
    INSERT INTO report.file (run_id, format, object_key, version_id, size, sha256)
    VALUES (r.id, f ->> 'format', f ->> 'object_key', f ->> 'version_id', (f ->> 'size')::bigint, f ->> 'sha256');
  END LOOP;
  UPDATE report.run x SET state = 'succeeded', context_nonce = NULL, progress = 100, data_as_of = complete_run.data_as_of,
    risk_count = complete_run.risk_count, left_out = coalesce(complete_run.left_out, '{}'), finished_at = now() WHERE x.id = r.id;
  PERFORM report.emit('report.generated', 'low', 'system:risk', r.id, r.bu_id, jsonb_build_object('kind', r.kind,
    'files', (SELECT string_agg((x ->> 'format') || ':' || (x ->> 'sha256'), ' ' ORDER BY x ->> 'format') FROM jsonb_array_elements(files) x),
    'risk_count', coalesce(complete_run.risk_count, 0)::text, 'left_out', coalesce(complete_run.left_out, '{}')::text,
    'requested_by', r.requested_by::text));
END $$;

CREATE FUNCTION report.fail_run(id uuid, nonce text, failure text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r report.run := report.running(id, nonce);
BEGIN
  PERFORM report.failed(r, failure);
END $$;

-- A run as its requester sees it.
CREATE FUNCTION report.run_json(r report.run) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', r.id, 'kind', r.kind, 'bu_id', r.bu_id, 'bu_name', (SELECT b.name FROM iam.bu b WHERE b.id = r.bu_id),
    'params', r.params, 'formats', to_jsonb(r.formats), 'reason', r.reason, 'schedule_id', r.schedule_id, 'state', r.state,
    'progress', r.progress, 'attempts', r.attempts, 'data_as_of', r.data_as_of, 'risk_count', r.risk_count, 'left_out', r.left_out,
    'failure', r.failure, 'requested_at', r.requested_at, 'started_at', r.started_at, 'finished_at', r.finished_at,
    'files', coalesce((SELECT jsonb_agg(jsonb_build_object('format', f.format, 'size', f.size, 'sha256', f.sha256, 'created_at', f.created_at,
      'purged', f.purged_at IS NOT NULL) ORDER BY array_position(r.formats, f.format)) FROM report.file f WHERE f.run_id = r.id), '[]'));
$$;

-- The caller's runs, newest first.
CREATE FUNCTION report.my_runs(lim integer, off integer) RETURNS SETOF jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT report.run_json(r) FROM report.run r
  WHERE r.requested_by = report.actor()
  ORDER BY r.requested_at DESC, r.id
  LIMIT greatest(1, least(lim, 201)) OFFSET greatest(0, off);
$$;

CREATE FUNCTION report.get_run(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r report.run;
BEGIN
  SELECT * INTO r FROM report.run x WHERE x.id = get_run.id AND x.requested_by = report.actor();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: no such run %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN report.run_json(r);
END $$;

-- A download (AC-17): the requester, still holding report.export at the
-- run's BU, of a file not yet purged; recorded in the transaction.
CREATE FUNCTION report.download(id uuid, format text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := report.actor();
  r report.run;
  f report.file;
BEGIN
  SELECT * INTO r FROM report.run x WHERE x.id = download.id AND x.requested_by = u;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: no such run %', id USING ERRCODE = 'P0002';
  END IF;
  IF NOT iam.holds_permission(u, 'report.export', r.bu_id) THEN
    RAISE EXCEPTION 'report: downloading needs report.export at the report''s business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF r.state <> 'succeeded' THEN
    RAISE EXCEPTION 'report: the report has not been generated' USING ERRCODE = 'PF029', HINT = 'not_succeeded';
  END IF;
  SELECT * INTO f FROM report.file x WHERE x.run_id = r.id AND x.format = download.format;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'report: the report has no % file', format USING ERRCODE = 'P0002';
  END IF;
  IF f.purged_at IS NOT NULL THEN
    RAISE EXCEPTION 'report: the file was deleted after its retention' USING ERRCODE = 'PF029', HINT = 'purged';
  END IF;
  PERFORM report.emit('report.downloaded', 'high', u::text, r.id, r.bu_id, jsonb_build_object('kind', r.kind, 'format', f.format,
    'sha256', f.sha256, 'reason', coalesce(r.reason, '')));
  RETURN jsonb_build_object('object_key', f.object_key, 'version_id', f.version_id, 'size', f.size, 'sha256', f.sha256);
END $$;

REVOKE ALL ON FUNCTION report.actor(), report.reader(), report.emit(text, text, text, uuid, uuid, jsonb), report.any_in_subtree(uuid, uuid[]),
  report.add_run(text, uuid, jsonb, text[], text, integer), report.request(text, uuid, jsonb, text[], text), report.run_spec(uuid),
  report.failed(report.run, text), report.start_run(uuid, text), report.running(uuid, text), report.progress(uuid, text, integer),
  report.complete_run(uuid, text, jsonb, timestamptz, integer, jsonb), report.fail_run(uuid, text, text), report.run_json(report.run),
  report.my_runs(integer, integer), report.get_run(uuid), report.download(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION report.reader(), report.any_in_subtree(uuid, uuid[]), report.add_run(text, uuid, jsonb, text[], text, integer),
  report.request(text, uuid, jsonb, text[], text), report.run_spec(uuid), report.start_run(uuid, text), report.progress(uuid, text, integer),
  report.complete_run(uuid, text, jsonb, timestamptz, integer, jsonb), report.fail_run(uuid, text, text), report.my_runs(integer, integer),
  report.get_run(uuid), report.download(uuid, text) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA report FROM report_definer;
