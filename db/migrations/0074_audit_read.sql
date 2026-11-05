-- F-002 T-12 (F-002-AC-15 to AC-20; design §4.3, §5): reading the trail.
--
-- The audit API (the audit service, as app_audit) reads only through these
-- definer functions. Each takes the caller from the signed DB context
-- (authz.ctx_user, ADR-007) and shows only records whose bu_id is in the
-- caller's read scope for resource type audit (audit.view): records of a
-- restricted BU need an assignment there, and records with no BU (filed
-- under the root) need audit.view at the root (AC-19). A missing, invalid,
-- expired or stale context sees nothing.
--
-- Search is newest first by position (seq) with a cursor; history and
-- request views are in order. Filters are applied with a statement built per
-- call, so each runs with a plan for the filters it has; the (column, seq)
-- indexes below serve a filter and the order together.
--
-- Each row carries its integrity status (verified, pending, or failed, from
-- the verification runs of T-11) and the current display names of the users
-- it names (actor, approved_by, decided_by), from iam.user_display_names,
-- which only these functions can call (AC-18).

-- --- Indexes for seq-ordered filtered search (owned with the table) -------
SET ROLE audit_definer;
CREATE INDEX record_type_seq ON audit.record (type, seq);
CREATE INDEX record_category_seq ON audit.record (category, seq);
CREATE INDEX record_severity_seq ON audit.record (severity, seq);
CREATE INDEX record_actor_seq ON audit.record (actor, seq);
CREATE INDEX record_target_seq ON audit.record (target, seq) WHERE target IS NOT NULL;
CREATE INDEX record_bu_seq ON audit.record (bu_id, seq);
CREATE INDEX record_request_seq ON audit.record (request_id, seq) WHERE request_id IS NOT NULL;
CREATE INDEX record_source_ip_seq ON audit.record USING gist (source_ip inet_ops) WHERE source_ip IS NOT NULL;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- --- Display names (iam) ----------------------------------------------------

-- Current display names of the given users. Only the audit read functions
-- call it, with the ids of records the caller can see.
CREATE FUNCTION iam.user_display_names(ids uuid[]) RETURNS TABLE (id uuid, display_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.id, coalesce(nullif(btrim(u.display_name), ''), u.email) FROM iam.app_user u WHERE u.id = ANY (ids);
$$;
REVOKE ALL ON FUNCTION iam.user_display_names(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.user_display_names(uuid[]) TO audit_definer;
GRANT EXECUTE ON FUNCTION iam.root_bu() TO audit_definer;

-- The scope functions, for the read functions (as for other definers).
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.visible_bus(text, text), authz.scope_excludes(text, text), authz.scope_hides(text, text) TO audit_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
GRANT USAGE ON SCHEMA authz TO audit_definer;

-- The audit API checks grants with authz.Cache (grant_snapshot returns only
-- the signed-context user's own grants).
GRANT USAGE ON SCHEMA authz TO app_audit;
GRANT EXECUTE ON FUNCTION authz.grant_snapshot() TO app_audit;

-- --- Read functions ---------------------------------------------------------

CREATE TYPE audit.record_view AS (
  seq          bigint,
  event_id     text,
  event_time   timestamptz,
  received_at  timestamptz,
  producer     text,
  type         text,
  category     text,
  severity     text,
  actor        text,
  target       text,
  bu_id        uuid,
  request_id   text,
  source_ip    inet,
  approval_id  text,
  skew         boolean,
  segment      bigint,
  body         jsonb,
  integrity    text,
  names        jsonb
);

-- The records the caller may see that match filter, ordered by seq
-- (descending when newest_first), after or before a cursor, at most lim.
-- filter keys: from, to (event time), type, category, severity, actor,
-- target, bu, request_id, source_ip (an address or a CIDR range). Unknown
-- keys and malformed values raise PF004.
CREATE FUNCTION audit.read_records(filter jsonb, cursor_seq bigint, newest_first boolean, lim integer)
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
    IF k <> ALL ('{from,to,type,category,severity,actor,target,bu,request_id,source_ip}'::text[]) THEN
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
             SELECT v::uuid FROM unnest(ARRAY[x.actor, x.body -> 'attributes' ->> 'approved_by', x.body -> 'attributes' ->> 'decided_by']) v
             WHERE v ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')) d), '{}'::jsonb)
    FROM (SELECT r.seq, r.event_id, r.event_time, r.received_at, r.producer, r.type, r.category, r.severity, r.actor, r.target, r.bu_id,
                 r.request_id, r.source_ip, r.approval_id, r.skew, r.segment, convert_from(r.body, 'UTF8')::jsonb AS body,
                 CASE WHEN $5 IS NOT NULL AND r.seq >= $5 THEN 'failed' WHEN r.seq <= coalesce($6, 0) THEN 'verified' ELSE 'pending' END AS integrity
          FROM audit.record r WHERE %s ORDER BY r.seq %s LIMIT %s) x
    ORDER BY x.seq %s$q$,
    array_to_string(conds, ' AND '), CASE WHEN newest_first THEN 'DESC' ELSE 'ASC' END, n, CASE WHEN newest_first THEN 'DESC' ELSE 'ASC' END);
  RETURN QUERY EXECUTE q USING hides, vis, f, cursor_seq, failed, verified;
END $$;

-- AC-15: search, newest first; before is the cursor (the last seq seen).
CREATE FUNCTION audit.search(filter jsonb, before_seq bigint, lim integer) RETURNS SETOF audit.record_view
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT * FROM audit.read_records(filter, before_seq, true, lim);
$$;

-- AC-16: the history of a target or of an actor (one of them), in order.
CREATE FUNCTION audit.history(of_target text, of_actor text, after_seq bigint, lim integer) RETURNS SETOF audit.record_view
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (of_target IS NULL) = (of_actor IS NULL) THEN
    RAISE EXCEPTION 'audit.history: a target or an actor' USING ERRCODE = 'PF004';
  END IF;
  RETURN QUERY SELECT * FROM audit.read_records(
    CASE WHEN of_target IS NOT NULL THEN jsonb_build_object('target', of_target) ELSE jsonb_build_object('actor', of_actor) END,
    after_seq, false, lim);
END $$;

-- AC-17: every visible record of one request, in order.
CREATE FUNCTION audit.request(of_request text, after_seq bigint, lim integer) RETURNS SETOF audit.record_view
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT * FROM audit.read_records(jsonb_build_object('request_id', of_request), after_seq, false, lim);
$$;

-- One visible record and what proves it: its segment's leaf hashes and
-- checkpoint once the segment is closed (no rows when not visible).
CREATE FUNCTION audit.record_proof(of_seq bigint)
RETURNS TABLE (segment bigint, seq_from bigint, leaves bytea[], statement bytea, signature bytea)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r audit.record_view;
  c audit.checkpoint;
BEGIN
  SELECT * INTO r FROM audit.read_records('{}', of_seq + 1, true, 1) x WHERE x.seq = of_seq;
  IF r.seq IS NULL THEN
    RETURN;
  END IF;
  SELECT * INTO c FROM audit.checkpoint k WHERE k.segment = r.segment;
  segment := r.segment;
  IF c.segment IS NOT NULL THEN
    seq_from := c.seq_from;
    leaves := ARRAY(SELECT x.leaf_hash FROM audit.record x WHERE x.seq BETWEEN c.seq_from AND c.seq_to ORDER BY x.seq);
    statement := c.statement;
    signature := c.signature;
  END IF;
  RETURN NEXT;
END $$;

-- Checkpoints and public keys, for verifiers: to holders of audit.view at
-- any BU (they carry no record content).
CREATE FUNCTION audit.can_read() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT authz.scope_excludes('audit', 'read') OR cardinality(authz.visible_bus('audit', 'read')) > 0;
$$;

CREATE FUNCTION audit.checkpoints(from_segment bigint, lim integer)
RETURNS TABLE (segment bigint, statement bytea, signature bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.segment, c.statement, c.signature FROM audit.checkpoint c
  WHERE audit.can_read() AND c.segment >= coalesce(from_segment, 1)
  ORDER BY c.segment LIMIT least(greatest(coalesce(lim, 100), 1), 1000);
$$;

CREATE FUNCTION audit.keys()
RETURNS TABLE (key_id text, public_pem text, active_from timestamptz, retired_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT k.key_id, k.public_pem, k.active_from, k.retired_at FROM audit.signing_key k WHERE audit.can_read() ORDER BY k.active_from;
$$;

-- The root BU, for the API's instance-wide checks (GET /status).
CREATE FUNCTION audit.root_bu() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.root_bu();
$$;

REVOKE ALL ON FUNCTION audit.read_records(jsonb, bigint, boolean, integer),
  audit.search(jsonb, bigint, integer),
  audit.history(text, text, bigint, integer), audit.request(text, bigint, integer), audit.record_proof(bigint), audit.can_read(),
  audit.checkpoints(bigint, integer), audit.keys(), audit.root_bu() FROM PUBLIC;
ALTER FUNCTION audit.read_records(jsonb, bigint, boolean, integer) OWNER TO audit_definer;
ALTER FUNCTION audit.search(jsonb, bigint, integer) OWNER TO audit_definer;
ALTER FUNCTION audit.history(text, text, bigint, integer) OWNER TO audit_definer;
ALTER FUNCTION audit.request(text, bigint, integer) OWNER TO audit_definer;
ALTER FUNCTION audit.record_proof(bigint) OWNER TO audit_definer;
ALTER FUNCTION audit.can_read() OWNER TO audit_definer;
ALTER FUNCTION audit.checkpoints(bigint, integer) OWNER TO audit_definer;
ALTER FUNCTION audit.keys() OWNER TO audit_definer;
ALTER FUNCTION audit.root_bu() OWNER TO audit_definer;
ALTER TYPE audit.record_view OWNER TO audit_definer;
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.search(jsonb, bigint, integer), audit.history(text, text, bigint, integer),
  audit.request(text, bigint, integer), audit.record_proof(bigint), audit.checkpoints(bigint, integer), audit.keys(),
  audit.root_bu() TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
