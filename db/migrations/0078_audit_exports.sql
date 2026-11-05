-- F-002 T-15 (F-002-AC-32, AC-33, AC-34; design §4.3, §5, §6.6): evidence
-- exports.
--
-- A user holding audit.export asks for the records matching a search
-- (POST /exports). audit.export_request records the request with the BUs
-- the export may include, captured from the signed DB context at that
-- moment (AC-33): the BUs the caller can read audit records in (the same
-- visibility as search, AC-19, restricted BUs and roll-up modes included)
-- where an assignment of theirs also grants audit.export. The
-- audit service's River job (schema audit_river, migrations 0076 and 0077)
-- then closes a segment, reads the matching records with that scope
-- (audit.export_rows: the search's own filter conditions, never the job's
-- context), writes the bundle to object storage and completes the export
-- and records audit.exported (high) in one transaction (AC-34).
--
-- Filters are shared with search: audit.filter_conditions validates a
-- filter and returns its conditions, and audit.read_records now uses it.
--
-- Archived ranges are not read here: nothing is archived before T-18,
-- which adds them (decision of 2026-11-05).
--
-- Export details and bundles are for the requester, or a holder of
-- audit.export at the root (audit.export_view). The API's mutations are
-- idempotent per user and key (audit.idempotency, as posture's).

-- 1. The export row gains the stored object's version and a failure reason.
ALTER TABLE audit.export
  ADD COLUMN object_version text,
  ADD COLUMN failure text,
  ADD CONSTRAINT export_ready CHECK (status <> 'ready' OR (record_count IS NOT NULL AND digest IS NOT NULL
    AND checkpoint_segment IS NOT NULL AND object_key IS NOT NULL AND object_version IS NOT NULL)),
  ADD CONSTRAINT export_failed CHECK ((status = 'failed') = (failure IS NOT NULL)),
  ADD CONSTRAINT export_reason CHECK (char_length(reason) <= 1000);

-- 2. Idempotency (server.Idempotent), kept 24 hours.
CREATE TABLE audit.idempotency (
  user_id       uuid        NOT NULL,
  key           text        NOT NULL CHECK (key ~ '^[\x21-\x7e]{8,128}$'),
  request_hash  text        NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  status        integer     CHECK (status BETWEEN 100 AND 599),
  content_type  text,
  body          bytea,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key)
);
REVOKE ALL ON audit.idempotency FROM PUBLIC;
ALTER TABLE audit.idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.idempotency FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON audit.idempotency TO audit_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit.idempotency TO audit_definer;

-- The caller and their permissions, for the export functions.
GRANT EXECUTE ON FUNCTION iam.holds_permission(uuid, text, uuid) TO audit_definer;

-- Whether one of u's assignments at bu or an ancestor grants perm, also
-- across restricted boundaries. Only for narrowing a set that visibility
-- (authz.visible_bus) has already decided: a restricted BU whose roll-up
-- mode lets its ancestors read it is in the reader's scope, and an export
-- right held above it then reaches it as the read right does.
CREATE FUNCTION iam.grants_within(u uuid, perm text, bu uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.user_has_permission(u, perm, bu, true);
$$;
REVOKE ALL ON FUNCTION iam.grants_within(uuid, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.grants_within(uuid, text, uuid) TO audit_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_user() TO audit_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

SET ROLE audit_definer;

-- 3. Filters, shared by search and exports. Validates filter (PF004 for an
-- unknown key or a malformed value) and returns its conditions on audit.record
-- r, with the filter as parameter $3.
CREATE FUNCTION audit.filter_conditions(filter jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  f     jsonb := coalesce(filter, '{}');
  k     text;
  conds text[] := ARRAY[]::text[];
BEGIN
  IF jsonb_typeof(f) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'audit: the filter is an object' USING ERRCODE = 'PF004';
  END IF;
  FOR k IN SELECT jsonb_object_keys(f) LOOP
    IF k <> ALL ('{from,to,type,category,severity,actor,target,bu,request_id,source_ip,approval_id}'::text[]) THEN
      RAISE EXCEPTION 'audit: unknown filter %', k USING ERRCODE = 'PF004';
    END IF;
    IF jsonb_typeof(f -> k) IS DISTINCT FROM 'string' OR btrim(f ->> k) = '' THEN
      RAISE EXCEPTION 'audit: filter % is a non-empty string', k USING ERRCODE = 'PF004';
    END IF;
  END LOOP;
  IF (f ? 'from' AND NOT pg_input_is_valid(f ->> 'from', 'timestamptz')) OR (f ? 'to' AND NOT pg_input_is_valid(f ->> 'to', 'timestamptz'))
     OR (f ? 'bu' AND NOT pg_input_is_valid(f ->> 'bu', 'uuid')) OR (f ? 'source_ip' AND NOT pg_input_is_valid(f ->> 'source_ip', 'cidr')) THEN
    RAISE EXCEPTION 'audit: a malformed filter value' USING ERRCODE = 'PF004';
  END IF;
  IF f ? 'from' THEN conds := array_append(conds, '(r.event_time >= ($3 ->> ''from'')::timestamptz)'); END IF;
  IF f ? 'to' THEN conds := array_append(conds, '(r.event_time < ($3 ->> ''to'')::timestamptz)'); END IF;
  IF f ? 'type' THEN conds := array_append(conds, '(r.type = ($3 ->> ''type''))'); END IF;
  IF f ? 'category' THEN conds := array_append(conds, '(r.category = ($3 ->> ''category''))'); END IF;
  IF f ? 'severity' THEN conds := array_append(conds, '(r.severity = ($3 ->> ''severity''))'); END IF;
  IF f ? 'actor' THEN conds := array_append(conds, '(r.actor = ($3 ->> ''actor''))'); END IF;
  IF f ? 'target' THEN conds := array_append(conds, '(r.target = ($3 ->> ''target''))'); END IF;
  IF f ? 'bu' THEN conds := array_append(conds, '(r.bu_id = ($3 ->> ''bu'')::uuid)'); END IF;
  IF f ? 'request_id' THEN conds := array_append(conds, '(r.request_id = ($3 ->> ''request_id''))'); END IF;
  IF f ? 'source_ip' THEN conds := array_append(conds, '(r.source_ip <<= ($3 ->> ''source_ip'')::cidr)'); END IF;
  IF f ? 'approval_id' THEN conds := array_append(conds, '(r.approval_id = ($3 ->> ''approval_id''))'); END IF;
  RETURN conds;
END $$;
REVOKE ALL ON FUNCTION audit.filter_conditions(jsonb) FROM PUBLIC;

-- Search, history, request and approval views: as in 0075, with the shared
-- filter conditions.
CREATE OR REPLACE FUNCTION audit.read_records(filter jsonb, cursor_seq bigint, newest_first boolean, lim integer)
RETURNS SETOF audit.record_view
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  f        jsonb := coalesce(filter, '{}');
  conds    text[] := audit.filter_conditions(filter);
  excl     boolean := authz.scope_excludes('audit', 'read');
  vis      uuid[];
  hides    uuid[];
  verified bigint;
  failed   bigint;
  good_full timestamptz;
  q        text;
  n        integer := least(greatest(coalesce(lim, 50), 1), 1000);
BEGIN
  -- Visibility: the smaller of the two scope forms (ADR-007 amendment 1).
  IF excl THEN
    hides := authz.scope_hides('audit', 'read');
    IF hides IS NULL THEN
      RETURN;
    END IF;
    conds := array_prepend('r.bu_id <> ALL ($1)', conds);
  ELSE
    vis := authz.visible_bus('audit', 'read');
    IF cardinality(vis) = 0 THEN
      RETURN;
    END IF;
    conds := array_prepend('r.bu_id = ANY ($2)', conds);
  END IF;
  IF cursor_seq IS NOT NULL THEN
    conds := array_append(conds, CASE WHEN newest_first THEN 'r.seq < $4' ELSE 'r.seq > $4' END);
  END IF;

  -- Integrity: what the verification runs (T-11) say about each position.
  SELECT v.to_seq INTO verified FROM audit.verification v WHERE v.ok ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT max(v.finished_at) INTO good_full FROM audit.verification v WHERE v.kind = 'full' AND v.ok;
  SELECT min(coalesce(v.failed_at_seq, (SELECT c.seq_from FROM audit.checkpoint c WHERE c.segment = v.failed_at_segment), 1)) INTO failed
  FROM audit.verification v WHERE v.ok IS FALSE AND (good_full IS NULL OR v.finished_at > good_full);

  q := format($q$
    SELECT x.*, coalesce((SELECT jsonb_object_agg(d.id, d.display_name) FROM iam.user_display_names(ARRAY(
             SELECT v::uuid FROM unnest(ARRAY[x.actor, x.body -> 'attributes' ->> 'approved_by', x.body -> 'attributes' ->> 'decided_by',
                                              x.body -> 'attributes' ->> 'requested_by']) v
             WHERE v ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')) d), '{}'::jsonb)
    FROM (SELECT r.seq, r.event_id, r.event_time, r.received_at, r.producer, r.type, r.category, r.severity, r.actor, r.target, r.bu_id,
                 r.request_id, r.source_ip, r.approval_id, r.skew, r.segment, convert_from(r.body, 'UTF8')::jsonb AS body,
                 CASE WHEN $5 IS NOT NULL AND r.seq >= $5 THEN 'failed' WHEN r.seq <= coalesce($6, 0) THEN 'verified' ELSE 'pending' END AS integrity
          FROM audit.record r WHERE %s ORDER BY r.seq %s LIMIT %s) x
    ORDER BY x.seq %s$q$,
    array_to_string(conds, ' AND '), CASE WHEN newest_first THEN 'DESC' ELSE 'ASC' END, n, CASE WHEN newest_first THEN 'DESC' ELSE 'ASC' END);
  RETURN QUERY EXECUTE q USING hides, vis, f, cursor_seq, failed, verified;
END $$;

-- 4. Requesting an export (AC-32, AC-33): the signed-context user, who must
-- hold audit.export where they can read. Returns the export's id. The scope
-- is the BUs they can read audit records in and hold audit.export at, as
-- of now; the export never includes more, whatever changes later.
CREATE FUNCTION audit.export_request(filter jsonb, record_format text, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u     uuid := (SELECT c.user_id FROM authz.ctx_user() c);
  scope uuid[];
  id    uuid;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'audit exports need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  PERFORM audit.filter_conditions(filter);
  IF record_format IS NULL OR record_format NOT IN ('jsonl', 'csv') THEN
    RAISE EXCEPTION 'audit: the format is jsonl or csv' USING ERRCODE = 'PF004';
  END IF;
  IF reason IS NULL OR btrim(reason) = '' OR char_length(reason) > 1000 THEN
    RAISE EXCEPTION 'audit: a reason of 1 to 1000 characters is required' USING ERRCODE = 'PF004';
  END IF;
  scope := ARRAY(SELECT b FROM unnest(authz.visible_bus('audit', 'read')) b WHERE iam.grants_within(u, 'audit.export', b) ORDER BY b);
  IF cardinality(scope) = 0 THEN
    RAISE EXCEPTION 'audit.export is required' USING ERRCODE = 'PF008';
  END IF;
  INSERT INTO audit.export (requested_by, filter, format, reason, scope_bus)
  VALUES (u, coalesce(filter, '{}'), record_format, btrim(reason), scope) RETURNING audit.export.id INTO id;
  RETURN id;
END $$;

-- One export, to its requester or a holder of audit.export at the root (no
-- row otherwise).
CREATE FUNCTION audit.export_view(of_id uuid)
RETURNS TABLE (id uuid, requested_by uuid, filter jsonb, format text, reason text, scope_bus uuid[], status text,
               record_count bigint, digest bytea, checkpoint_segment bigint, object_key text, object_version text,
               failure text, created_at timestamptz, completed_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT c.user_id FROM authz.ctx_user() c);
BEGIN
  IF u IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT x.id, x.requested_by, x.filter, x.format, x.reason, x.scope_bus, x.status, x.record_count, x.digest,
                      x.checkpoint_segment, x.object_key, x.object_version, x.failure, x.created_at, x.completed_at
  FROM audit.export x
  WHERE x.id = of_id AND (x.requested_by = u OR iam.holds_permission(u, 'audit.export', NULL));
END $$;

-- 5. The export job (the audit service, no user context).

-- The export as requested.
CREATE FUNCTION audit.export_job(of_id uuid)
RETURNS TABLE (requested_by uuid, filter jsonb, format text, reason text, scope_bus uuid[], status text, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT x.requested_by, x.filter, x.format, x.reason, x.scope_bus, x.status, x.created_at FROM audit.export x WHERE x.id = of_id;
$$;

-- The records of a pending export, in sequence order: those matching its
-- filter in its captured scope, after after_seq and up to upto_seq (the
-- export's closing checkpoint), at most lim.
CREATE FUNCTION audit.export_rows(of_id uuid, after_seq bigint, upto_seq bigint, lim integer)
RETURNS TABLE (seq bigint, event_id text, segment bigint, body bytea, event_time timestamptz, received_at timestamptz, producer text, type text,
               category text, severity text, actor text, target text, bu_id uuid, request_id text, source_ip text, approval_id text, skew boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  x     audit.export;
  conds text[];
BEGIN
  SELECT * INTO x FROM audit.export e WHERE e.id = of_id;
  IF NOT FOUND OR x.status <> 'pending' THEN
    RAISE EXCEPTION 'audit: export % is not pending', of_id USING ERRCODE = 'PF003';
  END IF;
  conds := array_prepend('r.bu_id = ANY ($2)', audit.filter_conditions(x.filter));
  conds := conds || ARRAY['r.seq > $4', 'r.seq <= $5'];
  RETURN QUERY EXECUTE format($q$
    SELECT r.seq, r.event_id, r.segment, r.body, r.event_time, r.received_at, r.producer, r.type, r.category, r.severity, r.actor, r.target,
           r.bu_id, r.request_id, host(r.source_ip), r.approval_id, r.skew
    FROM audit.record r WHERE %s ORDER BY r.seq LIMIT %s$q$,
    array_to_string(conds, ' AND '), least(greatest(coalesce(lim, 1000), 1), 50000))
  USING NULL::uuid[], x.scope_bus, x.filter, coalesce(after_seq, 0), upto_seq;
END $$;

-- A closed segment's leaf hashes in order, for the records' Merkle paths.
CREATE FUNCTION audit.segment_leaves(of_segment bigint, OUT seq_from bigint, OUT leaves bytea[])
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c audit.checkpoint;
BEGIN
  SELECT * INTO c FROM audit.checkpoint k WHERE k.segment = of_segment;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit: segment % is not closed', of_segment USING ERRCODE = 'PF003';
  END IF;
  seq_from := c.seq_from;
  leaves := ARRAY(SELECT r.leaf_hash FROM audit.record r WHERE r.seq BETWEEN c.seq_from AND c.seq_to ORDER BY r.seq);
END $$;

-- The export's bundle is stored: ready, with its count, digest, closing
-- checkpoint and object. Only a pending export completes.
CREATE FUNCTION audit.export_complete(of_id uuid, n bigint, d bytea, seg bigint, okey text, over text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE audit.export x SET status = 'ready', record_count = n, digest = d, checkpoint_segment = seg, object_key = okey,
                            object_version = over, completed_at = now()
  WHERE x.id = of_id AND x.status = 'pending';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit: export % is not pending', of_id USING ERRCODE = 'PF003';
  END IF;
END $$;

-- The export cannot be made (after the job's last attempt).
CREATE FUNCTION audit.export_fail(of_id uuid, why text) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (UPDATE audit.export x SET status = 'failed', failure = left(coalesce(nullif(btrim(why), ''), 'failed'), 1000), completed_at = now()
             WHERE x.id = of_id AND x.status = 'pending' RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM u);
$$;

-- 6. Idempotency. outcome: 'new' (reserved), 'replay' (status, content_type,
-- body), 'mismatch', 'in_progress'.
CREATE FUNCTION audit.idempotency_begin(u uuid, k text, h text,
  OUT outcome text, OUT status integer, OUT content_type text, OUT body bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  r audit.idempotency;
BEGIN
  DELETE FROM audit.idempotency i WHERE i.created_at < now() - interval '24 hours';
  DELETE FROM audit.idempotency i WHERE i.status IS NULL AND i.created_at < now() - interval '5 minutes';
  INSERT INTO audit.idempotency (user_id, key, request_hash) VALUES (u, k, h) ON CONFLICT DO NOTHING;
  IF FOUND THEN
    outcome := 'new';
    RETURN;
  END IF;
  SELECT * INTO r FROM audit.idempotency i WHERE i.user_id = u AND i.key = k;
  IF r.request_hash <> h THEN
    outcome := 'mismatch';
  ELSIF r.status IS NULL THEN
    outcome := 'in_progress';
  ELSE
    outcome := 'replay'; status := r.status; content_type := r.content_type; body := r.body;
  END IF;
END $$;

CREATE FUNCTION audit.idempotency_complete(u uuid, k text, s integer, ct text, b bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE audit.idempotency SET status = s, content_type = ct, body = b WHERE user_id = u AND key = k AND status IS NULL;
$$;

CREATE FUNCTION audit.idempotency_abandon(u uuid, k text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM audit.idempotency WHERE user_id = u AND key = k AND status IS NULL;
$$;

REVOKE ALL ON FUNCTION audit.export_request(jsonb, text, text), audit.export_view(uuid), audit.export_job(uuid),
  audit.export_rows(uuid, bigint, bigint, integer), audit.segment_leaves(bigint), audit.export_complete(uuid, bigint, bytea, bigint, text, text),
  audit.export_fail(uuid, text), audit.idempotency_begin(uuid, text, text), audit.idempotency_complete(uuid, text, integer, text, bytea),
  audit.idempotency_abandon(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.export_request(jsonb, text, text), audit.export_view(uuid), audit.export_job(uuid),
  audit.export_rows(uuid, bigint, bigint, integer), audit.segment_leaves(bigint), audit.export_complete(uuid, bigint, bytea, bigint, text, text),
  audit.export_fail(uuid, text), audit.idempotency_begin(uuid, text, text), audit.idempotency_complete(uuid, text, integer, text, bytea),
  audit.idempotency_abandon(uuid, text) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
