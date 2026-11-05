-- F-002 T-11 (F-002-AC-12, AC-13, AC-14; design §6.5): continuous
-- verification of the trail.
--
-- The audit service's leader verifies the trail itself, in Go, with the
-- same primitives as fair-audit-verify (internal/audit/integrity): the
-- database only hands it the raw trail through read-only functions and
-- records the outcome. Every 15 minutes an incremental run checks the
-- checkpoints closed since the last good run, their segments, and the open
-- segment up to the head; once a day a full run checks the whole retained
-- trail, the archives, and (in SaaS) the write-once copies.
--
-- A failed run opens the Posture finding audit_integrity (critical, AU-9 and
-- AU-6) through posture.audit_finding, which in SaaS also queues a SecOps
-- alert. Only a later successful full run resolves it (AC-13); it can be
-- acknowledged like any finding, which never closes it.
--
-- audit.status() gives the Posture page's Audit trail tile its data (AC-14),
-- to app_posture.

-- Which checkpoints a run reached, and where it failed. An incremental run
-- with nothing new covers no records: to_seq = from_seq - 1.
ALTER TABLE audit.verification
  ADD COLUMN to_segment        bigint CHECK (to_segment >= 0),
  ADD COLUMN failed_at_segment bigint CHECK (failed_at_segment > 0),
  ADD CONSTRAINT verification_failure_needs_failed CHECK (failed_at_segment IS NULL OR ok IS FALSE);
DO $$
DECLARE
  c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint
  WHERE conrelid = 'audit.verification'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%to_seq >= from_seq)%';
  IF c IS NULL THEN
    RAISE EXCEPTION 'audit.verification: the to_seq constraint was not found';
  END IF;
  EXECUTE format('ALTER TABLE audit.verification DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE audit.verification ADD CONSTRAINT verification_range CHECK (to_seq >= from_seq - 1);
CREATE INDEX verification_finished ON audit.verification (finished_at DESC) WHERE finished_at IS NOT NULL;

-- An archive is one object version: the store keeps every version, and only
-- the one written and read back at archive time is the archive (T-18 fills
-- it; the table is empty until then).
ALTER TABLE audit.archive ADD COLUMN version_id text NOT NULL CHECK (btrim(version_id) <> '');

-- --- Reading the trail (read-only; the verifier runs them in one
-- repeatable-read snapshot) -------------------------------------------------

-- The head as it is; no row before the first event.
CREATE FUNCTION audit.verify_head()
RETURNS TABLE (instance text, seq bigint, chain_hash bytea, open_segment bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.instance, h.seq, h.chain_hash, h.open_segment FROM audit.head h;
$$;

CREATE FUNCTION audit.verify_checkpoints(from_segment bigint, n integer)
RETURNS TABLE (segment bigint, statement bytea, signature bytea, worm_key text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.segment, c.statement, c.signature, c.worm_key FROM audit.checkpoint c
  WHERE c.segment >= from_segment ORDER BY c.segment LIMIT least(greatest(n, 1), 10000);
$$;

-- Records from_seq..to_seq in sequence order, at most n.
CREATE FUNCTION audit.verify_records(from_seq bigint, to_seq bigint, n integer)
RETURNS TABLE (seq bigint, segment bigint, body bytea, leaf_hash bytea, chain_hash bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT r.seq, r.segment, r.body, r.leaf_hash, r.chain_hash FROM audit.record r
  WHERE r.seq >= from_seq AND r.seq <= to_seq ORDER BY r.seq LIMIT least(greatest(n, 1), 50000);
$$;

CREATE FUNCTION audit.verify_keys()
RETURNS TABLE (key_id text, public_pem text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT k.key_id, k.public_pem FROM audit.signing_key k ORDER BY k.key_id;
$$;

CREATE FUNCTION audit.verify_archives()
RETURNS TABLE (segment bigint, object_key text, version_id text, digest bytea, record_count bigint, destroyed boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.segment, a.object_key, a.version_id, a.digest, a.record_count, a.destroyed_at IS NOT NULL FROM audit.archive a ORDER BY a.segment;
$$;

-- --- Recording runs ---------------------------------------------------------

CREATE FUNCTION audit.verification_begin(run_kind text, start_seq bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  vid bigint;
BEGIN
  IF run_kind IS NULL OR run_kind NOT IN ('incremental', 'full') OR start_seq IS NULL OR start_seq < 0 THEN
    RAISE EXCEPTION 'audit.verification_begin: kind incremental or full, and a start position' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO audit.verification (kind, from_seq, started_at) VALUES (run_kind, start_seq, clock_timestamp()) RETURNING id INTO vid;
  RETURN vid;
END $$;

-- Records a run's outcome, once. A failure names its first failing record
-- or segment (or neither, when the trail could not be read as a whole).
CREATE FUNCTION audit.verification_end(vid bigint, passed boolean, start_seq bigint, end_seq bigint, end_segment bigint,
  bad_seq bigint, bad_segment bigint, what text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF passed IS NULL OR (passed AND (bad_seq IS NOT NULL OR bad_segment IS NOT NULL OR end_seq IS NULL OR end_segment IS NULL))
     OR (NOT passed AND (end_seq IS NOT NULL OR end_segment IS NOT NULL)) THEN
    RAISE EXCEPTION 'audit.verification_end: a passed run states its range and no failure; a failed run states no range' USING ERRCODE = 'PF004';
  END IF;
  UPDATE audit.verification v SET finished_at = clock_timestamp(), ok = passed, from_seq = coalesce(start_seq, v.from_seq),
    to_seq = end_seq, to_segment = end_segment,
    failed_at_seq = bad_seq, failed_at_segment = bad_segment, detail = left(what, 2000)
  WHERE v.id = vid AND v.finished_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit.verification_end: run % is not open', vid USING ERRCODE = 'PF003';
  END IF;
END $$;

-- Where the next incremental run starts: the last checkpoint a passed run
-- verified (0: none), and when the last full run finished and passed.
CREATE FUNCTION audit.verification_resume(OUT verified_segment bigint, OUT last_full_at timestamptz, OUT last_full_ok boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce((SELECT v.to_segment FROM audit.verification v WHERE v.ok ORDER BY v.finished_at DESC, v.id DESC LIMIT 1), 0),
         (SELECT v.finished_at FROM audit.verification v WHERE v.kind = 'full' AND v.finished_at IS NOT NULL ORDER BY v.finished_at DESC, v.id DESC LIMIT 1),
         (SELECT v.ok FROM audit.verification v WHERE v.kind = 'full' AND v.finished_at IS NOT NULL ORDER BY v.finished_at DESC, v.id DESC LIMIT 1);
$$;

-- --- The Posture page's tile (AC-14) ----------------------------------------

-- state: never (no run yet), failed (a run failed since the last passed full
-- run: the integrity finding is open), overdue (no passed incremental run in
-- 30 minutes or full run in 26 hours), or ok. Forwarding (T-16, T-17) and
-- storage (T-20) fill in their parts as they arrive.
CREATE FUNCTION audit.status() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  last_run  audit.verification;
  last_full audit.verification;
  last_ok   audit.verification;
  good_full timestamptz;
  failed    boolean;
  st        text;
  h         audit.head;
  run       jsonb;
BEGIN
  SELECT * INTO last_run FROM audit.verification v WHERE v.finished_at IS NOT NULL ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT * INTO last_full FROM audit.verification v WHERE v.finished_at IS NOT NULL AND v.kind = 'full' ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT * INTO last_ok FROM audit.verification v WHERE v.ok ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT max(v.finished_at) INTO good_full FROM audit.verification v WHERE v.kind = 'full' AND v.ok;
  SELECT EXISTS (SELECT 1 FROM audit.verification v WHERE v.ok IS FALSE AND (good_full IS NULL OR v.finished_at > good_full)) INTO failed;
  SELECT * INTO h FROM audit.head;
  st := CASE
    WHEN last_run.id IS NULL THEN 'never'
    WHEN failed THEN 'failed'
    WHEN NOT EXISTS (SELECT 1 FROM audit.verification v WHERE v.ok AND v.finished_at > now() - interval '30 minutes')
      OR good_full IS NULL OR good_full < now() - interval '26 hours' THEN 'overdue'
    ELSE 'ok' END;
  RETURN jsonb_build_object(
    'state', st,
    'last_run', CASE WHEN last_run.id IS NULL THEN NULL ELSE jsonb_build_object('id', last_run.id, 'kind', last_run.kind,
      'finished_at', last_run.finished_at, 'ok', last_run.ok, 'to_seq', last_run.to_seq, 'to_segment', last_run.to_segment,
      'failed_at_seq', last_run.failed_at_seq, 'failed_at_segment', last_run.failed_at_segment, 'detail', last_run.detail) END,
    'last_full', CASE WHEN last_full.id IS NULL THEN NULL ELSE jsonb_build_object('id', last_full.id, 'finished_at', last_full.finished_at,
      'ok', last_full.ok, 'to_seq', last_full.to_seq, 'to_segment', last_full.to_segment) END,
    'last_verified_at', last_ok.finished_at,
    'verified_through_seq', last_ok.to_seq,
    'head_seq', coalesce(h.seq, 0),
    'open_segment', h.open_segment,
    'intake_waiting', (SELECT count(*) FROM audit.intake),
    'checkpoint_copies_waiting', (SELECT count(*) FROM audit.checkpoint c WHERE c.worm_key IS NULL),
    'destinations', coalesce((SELECT jsonb_agg(jsonb_build_object('name', d.name, 'kind', d.kind, 'last_seq', d.last_seq,
      'backlog', greatest(coalesce(h.seq, 0) - d.last_seq, 0), 'last_sent_at', d.last_sent_at, 'last_error', d.last_error) ORDER BY d.name)
      FROM audit.destination d), '[]'::jsonb),
    'storage', NULL);
END $$;

REVOKE ALL ON FUNCTION audit.verify_head(), audit.verify_checkpoints(bigint, integer), audit.verify_records(bigint, bigint, integer),
  audit.verify_keys(), audit.verify_archives(), audit.verification_begin(text, bigint),
  audit.verification_end(bigint, boolean, bigint, bigint, bigint, bigint, bigint, text), audit.verification_resume(), audit.status() FROM PUBLIC;
ALTER FUNCTION audit.verify_head() OWNER TO audit_definer;
ALTER FUNCTION audit.verify_checkpoints(bigint, integer) OWNER TO audit_definer;
ALTER FUNCTION audit.verify_records(bigint, bigint, integer) OWNER TO audit_definer;
ALTER FUNCTION audit.verify_keys() OWNER TO audit_definer;
ALTER FUNCTION audit.verify_archives() OWNER TO audit_definer;
ALTER FUNCTION audit.verification_begin(text, bigint) OWNER TO audit_definer;
ALTER FUNCTION audit.verification_end(bigint, boolean, bigint, bigint, bigint, bigint, bigint, text) OWNER TO audit_definer;
ALTER FUNCTION audit.verification_resume() OWNER TO audit_definer;
ALTER FUNCTION audit.status() OWNER TO audit_definer;
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.verify_head(), audit.verify_checkpoints(bigint, integer), audit.verify_records(bigint, bigint, integer),
  audit.verify_keys(), audit.verify_archives(), audit.verification_begin(text, bigint),
  audit.verification_end(bigint, boolean, bigint, bigint, bigint, bigint, bigint, text), audit.verification_resume(), audit.status() TO app_audit;
GRANT EXECUTE ON FUNCTION audit.status() TO app_posture;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT USAGE ON SCHEMA audit TO app_posture;

-- --- The integrity finding (posture) ----------------------------------------

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Opens (or refreshes) the audit_integrity finding when open is true, or
-- resolves it when false (the audit service calls that only after a passed
-- full run). Opening it in SaaS queues a SecOps alert. Returns opened,
-- refreshed, resolved or unchanged.
CREATE FUNCTION posture.audit_finding(open boolean, detail jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  fid      uuid;
  inserted boolean;
  ty       text := 'audit.verification_failed';
BEGIN
  IF open IS NULL THEN
    RAISE EXCEPTION 'posture.audit_finding: open or resolve' USING ERRCODE = 'PF004';
  END IF;
  IF NOT open THEN
    UPDATE posture.drift_finding f SET status = 'resolved', resolved_at = now(), last_seen = now()
    WHERE f.check_id = 'audit_integrity' AND f.subject = 'audit-trail' AND f.status <> 'resolved';
    RETURN CASE WHEN FOUND THEN 'resolved' ELSE 'unchanged' END;
  END IF;
  IF detail IS NULL OR jsonb_typeof(detail) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'posture.audit_finding: the failure detail is an object' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO posture.drift_finding AS d (kind, check_id, severity, controls, subject, detail, remediation)
  VALUES ('app', 'audit_integrity', 'critical', ARRAY['AU-9', 'AU-6'], 'audit-trail', detail,
          'The audit trail failed verification at the position shown. Treat it as a possible tampering incident: preserve the database, '
          || 'compare the platform''s checkpoints with the SIEM and write-once copies (fair-audit-verify compare), and restore or '
          || 'investigate. The finding resolves only when a full verification passes.')
  ON CONFLICT (check_id, subject) WHERE status <> 'resolved' DO UPDATE SET last_seen = now(), detail = EXCLUDED.detail
  RETURNING d.id, (d.xmax = 0) INTO fid, inserted;
  IF inserted AND posture.deployment_mode() = 'saas' THEN
    INSERT INTO posture.secops_outbox (event) VALUES (jsonb_build_object('type', ty, 'finding_id', fid, 'detail', detail, 'at', now()));
  END IF;
  RETURN CASE WHEN inserted THEN 'opened' ELSE 'refreshed' END;
END $$;

REVOKE ALL ON FUNCTION posture.audit_finding(boolean, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.audit_finding(boolean, jsonb) TO app_audit;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
