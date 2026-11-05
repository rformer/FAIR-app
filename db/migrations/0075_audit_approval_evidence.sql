-- F-002 T-13 (F-002-AC-35; design §3, §5): approval evidence.
--
-- An approval's applied change names the approval: events recorded in the
-- transaction that consumed it carry the attribute approval_id (design §3),
-- whichever feature produced them (decision of 2026-11-05: the trail stamps
-- it, rather than each producer).
--   * iam.consume_approval marks its transaction with the approval it used
--     (the transaction-local setting audit.approval_id). When a transaction
--     consumes several (a profile switch and its conflicts' exceptions), each
--     later event names the one consumed most recently before it.
--   * audit.submit adds approval_id to each later event of that transaction
--     that does not set one itself, once iam.approval_consumed_here confirms
--     the approval really was consumed in this transaction: a producer
--     setting the marker by hand gains nothing. approval_id becomes a
--     reserved attribute, allowed on every type (pkg/audit
--     ReservedAttributes).
--   * Approval events (requested, approved, rejected, expired, consumed) are
--     filed under the request's BU, so an auditor of that BU sees the whole
--     approval (AC-19); requests without a BU stay under the root.
--
-- audit.approval_evidence returns one approval's visible records in order:
-- its own events (target approval:<id>) and every record naming it
-- (approval_id). read_records gains the approval_id filter and the
-- requester among the names it resolves.

-- 1. The marker.
CREATE OR REPLACE FUNCTION iam.consume_approval(request_id uuid, kind text, target_ref text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.approval_request;
BEGIN
  SELECT * INTO r FROM iam.approval_request a WHERE a.id = request_id FOR UPDATE;
  IF NOT FOUND OR r.kind IS DISTINCT FROM consume_approval.kind OR r.target_ref IS DISTINCT FROM consume_approval.target_ref THEN
    RAISE EXCEPTION 'no approval % for % %', request_id, kind, target_ref USING ERRCODE = 'AP004';
  END IF;
  IF r.status <> 'approved' OR r.consumed_at IS NOT NULL OR now() >= r.expires_at THEN
    RAISE EXCEPTION 'approval % is not usable (status %, consumed %, expires %)', request_id, r.status, r.consumed_at, r.expires_at
      USING ERRCODE = 'AP004';
  END IF;
  UPDATE iam.approval_request a SET consumed_at = now() WHERE a.id = r.id RETURNING a.* INTO r;
  -- F-002 T-13: what this transaction records from here on applies r.
  PERFORM set_config('audit.approval_id', r.id::text, true);
  PERFORM iam.approval_audit('approval.consumed', 'info', r.decided_by, r);
  RETURN jsonb_build_object('payload', r.payload, 'requested_by', r.requested_by, 'decided_by', r.decided_by);
END $$;

-- Whether this transaction consumed the approval (consume_approval sets
-- consumed_at to the transaction's start time).
CREATE FUNCTION iam.approval_consumed_here(of_approval uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM iam.approval_request a WHERE a.id = of_approval AND a.consumed_at = now());
$$;
REVOKE ALL ON FUNCTION iam.approval_consumed_here(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.approval_consumed_here(uuid) TO audit_definer;

-- 2. Approval events under the request's BU.
CREATE OR REPLACE FUNCTION iam.approval_audit(event text, severity text, actor uuid, r iam.approval_request) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object(
    'type', event, 'severity', severity, 'actor', coalesce(actor::text, 'system:approvals'),
    'target', 'approval:' || r.id, 'reason', coalesce(r.decision_reason, r.reason), 'bu_id', r.bu_id,
    'attributes', jsonb_build_object('kind', r.kind, 'target_ref', r.target_ref, 'requested_by', r.requested_by,
                                     'decided_by', r.decided_by, 'status', r.status, 'bu_id', r.bu_id,
                                     'expires_at', r.expires_at)));
$$;

-- 3. The stamp.
SET ROLE audit_definer;
CREATE OR REPLACE FUNCTION audit.submit(event jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  et audit.event_type;
  k text;
  v jsonb;
  id text;
  t timestamptz;
  body jsonb;
  ty text;
  ap text;
BEGIN
  IF event IS NULL OR jsonb_typeof(event) <> 'object' THEN
    RAISE EXCEPTION 'audit event: an object is required' USING ERRCODE = 'PF011';
  END IF;
  -- (Read once into ty: pkg/audit's catalog scan treats a 'type' key followed
  -- by a value as an emitted event.)
  ty := event->>'type';

  -- F-002 T-13: an event recorded after this transaction consumed an
  -- approval names it, unless the producer named one itself.
  ap := current_setting('audit.approval_id', true);
  IF coalesce(ap, '') <> '' AND pg_input_is_valid(ap, 'uuid')
     AND jsonb_typeof(coalesce(event->'attributes', '{}')) = 'object' AND NOT coalesce(event->'attributes', '{}') ? 'approval_id'
     AND iam.approval_consumed_here(ap::uuid) THEN
    event := jsonb_set(event, '{attributes}', coalesce(event->'attributes', '{}') || jsonb_build_object('approval_id', ap));
  END IF;

  IF octet_length(event::text) > 65536 THEN
    RAISE EXCEPTION 'audit event: larger than 64 KiB' USING ERRCODE = 'PF011';
  END IF;
  FOR k, v IN SELECT * FROM jsonb_each(event) LOOP
    IF k NOT IN ('id', 'time', 'severity', 'actor', 'target', 'bu_id', 'reason', 'before', 'after',
                 'request_id', 'source_ip', 'attributes', 'type') THEN
      RAISE EXCEPTION 'audit event: unknown field %', k USING ERRCODE = 'PF011';
    END IF;
    IF k NOT IN ('before', 'after', 'attributes') AND jsonb_typeof(v) <> 'string' THEN
      RAISE EXCEPTION 'audit event: % must be a string', k USING ERRCODE = 'PF011';
    END IF;
  END LOOP;

  SELECT * INTO et FROM audit.event_type e WHERE e.type = ty AND e.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit event: type % is not in the catalog', coalesce(ty, '(none)') USING ERRCODE = 'PF011';
  END IF;
  IF NOT coalesce(event->>'severity' = ANY (et.severities), false) THEN
    RAISE EXCEPTION 'audit event: % with severity % (allowed %)', et.type, coalesce(event->>'severity', '(none)'), et.severities
      USING ERRCODE = 'PF011';
  END IF;
  IF btrim(coalesce(event->>'actor', '')) = '' THEN
    RAISE EXCEPTION 'audit event: % without an actor', et.type USING ERRCODE = 'PF011';
  END IF;
  FOREACH k IN ARRAY et.requires LOOP
    IF btrim(coalesce(event->>k, '')) = '' THEN
      RAISE EXCEPTION 'audit event: % without %', et.type, k USING ERRCODE = 'PF011';
    END IF;
  END LOOP;

  IF event ? 'bu_id' THEN
    IF NOT pg_input_is_valid(event->>'bu_id', 'uuid') THEN
      RAISE EXCEPTION 'audit event: bu_id % is not a UUID', event->>'bu_id' USING ERRCODE = 'PF011';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = (event->>'bu_id')::uuid) THEN
      RAISE EXCEPTION 'audit event: unknown BU %', event->>'bu_id' USING ERRCODE = 'PF011';
    END IF;
  ELSIF et.bu = 'required' THEN
    RAISE EXCEPTION 'audit event: % without bu_id', et.type USING ERRCODE = 'PF011';
  END IF;
  IF event ? 'source_ip' AND NOT pg_input_is_valid(event->>'source_ip', 'inet') THEN
    RAISE EXCEPTION 'audit event: source_ip % is not an address', event->>'source_ip' USING ERRCODE = 'PF011';
  END IF;
  IF event ? 'attributes' THEN
    IF jsonb_typeof(event->'attributes') <> 'object' THEN
      RAISE EXCEPTION 'audit event: attributes must be an object' USING ERRCODE = 'PF011';
    END IF;
    FOR k, v IN SELECT * FROM jsonb_each(event->'attributes') LOOP
      IF jsonb_typeof(v) <> 'string' THEN
        RAISE EXCEPTION 'audit event: attribute % must be a string', k USING ERRCODE = 'PF011';
      END IF;
      -- Only the attributes the catalog lists for the type (AC-06); event_id
      -- and approval_id are reserved (allowed on every type).
      IF et.attributes IS NOT NULL AND k NOT IN ('event_id', 'approval_id') AND NOT (k = ANY (et.attributes)) THEN
        RAISE EXCEPTION 'audit event: % with attribute % (not in the catalog)', et.type, k USING ERRCODE = 'PF011';
      END IF;
    END LOOP;
  END IF;

  IF audit.looks_secret(event::text) THEN
    RAISE EXCEPTION 'audit event: % carries a value that looks like a secret', et.type USING ERRCODE = 'PF011';
  END IF;

  IF event ? 'time' THEN
    IF NOT pg_input_is_valid(event->>'time', 'timestamptz') THEN
      RAISE EXCEPTION 'audit event: time % is not a timestamp', event->>'time' USING ERRCODE = 'PF011';
    END IF;
    t := (event->>'time')::timestamptz;
  ELSE
    t := clock_timestamp();
  END IF;
  id := coalesce(event->>'id', replace(gen_random_uuid()::text, '-', ''));
  IF id !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
    RAISE EXCEPTION 'audit event: id % is not valid', id USING ERRCODE = 'PF011';
  END IF;

  body := event || jsonb_build_object('id', id, 'time', to_char(t AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  INSERT INTO audit.intake (event_id, producer, body) VALUES (id, session_user, body)
  ON CONFLICT (event_id) DO NOTHING;
  RETURN id;
END $$;

-- 4. Reading: the approval_id filter, and the requester's name.
CREATE OR REPLACE FUNCTION audit.read_records(filter jsonb, cursor_seq bigint, newest_first boolean, lim integer)
RETURNS SETOF audit.record_view
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  f        jsonb := coalesce(filter, '{}');
  k        text;
  conds    text[] := ARRAY[]::text[];
  excl     boolean := authz.scope_excludes('audit', 'read');
  vis      uuid[];
  hides    uuid[];
  verified bigint;
  failed   bigint;
  good_full timestamptz;
  q        text;
  n        integer := least(greatest(coalesce(lim, 50), 1), 1000);
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

  -- Visibility: the smaller of the two scope forms (ADR-007 amendment 1).
  IF excl THEN
    hides := authz.scope_hides('audit', 'read');
    IF hides IS NULL THEN
      RETURN;
    END IF;
    conds := array_append(conds, 'r.bu_id <> ALL ($1)');
  ELSE
    vis := authz.visible_bus('audit', 'read');
    IF cardinality(vis) = 0 THEN
      RETURN;
    END IF;
    conds := array_append(conds, 'r.bu_id = ANY ($2)');
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

-- AC-35: one approval's visible records, in order: its request, decision
-- and use (target approval:<id>) and every record naming it (approval_id):
-- the change it was requested for and the change it applied.
CREATE FUNCTION audit.approval_evidence(of_approval uuid, after_seq bigint, lim integer) RETURNS SETOF audit.record_view
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT DISTINCT ON (x.seq) x.* FROM (
    SELECT * FROM audit.read_records(jsonb_build_object('target', 'approval:' || of_approval), after_seq, false, lim)
    UNION ALL
    SELECT * FROM audit.read_records(jsonb_build_object('approval_id', of_approval::text), after_seq, false, lim)) x
  ORDER BY x.seq LIMIT least(greatest(coalesce(lim, 50), 1), 1000);
$$;
REVOKE ALL ON FUNCTION audit.approval_evidence(uuid, bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.approval_evidence(uuid, bigint, integer) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
