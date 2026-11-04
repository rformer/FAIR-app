-- F-002 T-03 (F-002-AC-06, AC-19; design §3): the envelope's bu_id, and
-- the catalog's attribute lists enforced by audit.submit.
--
-- Producers of the catalog's "bu: required" types now put the BU the event
-- concerns in a top-level bu_id: BU changes (iam.bu_event and the scope
-- worker's bu.moved), group mappings and their assignments
-- (iam.mapping_event), access reviews (iam.review_event), service accounts
-- (iam.sa_event) and expired assignments (iam.assignment_expiry_sweep). The
-- functions are otherwise unchanged. audit.submit refuses attributes the
-- catalog does not list for the type, and values that look like secrets
-- (the same rule as pkg/audit.LooksSecret).

CREATE OR REPLACE FUNCTION iam.bu_event(event text, actor uuid, b iam.bu, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', 'high', 'actor', actor::text, 'target', 'bu:' || b.id, 'bu_id', b.id, 'reason', reason,
    'attributes', jsonb_build_object('code', b.code, 'restricted', b.restricted, 'rollup_mode', b.rollup_mode) || coalesce(attrs, '{}')));
$$;

CREATE OR REPLACE FUNCTION iam.mapping_event(event text, severity text, actor text, m iam.group_role_mapping, user_id uuid, reason text) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor,
    'bu_id', m.bu_id,
    'target', CASE WHEN user_id IS NULL THEN 'group_mapping:' || m.id ELSE 'user:' || user_id END, 'reason', reason,
    'attributes', jsonb_build_object('mapping', m.id, 'group', m.grp_id, 'role', m.role_id, 'bu', m.bu_id, 'user', user_id)));
$$;

CREATE OR REPLACE FUNCTION iam.review_event(event text, severity text, actor text, target text, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor, 'target', target, 'reason', reason,
                                      -- the campaign's BU for a campaign, the item's for an item
                                      'bu_id', CASE split_part(target, ':', 1)
                                        WHEN 'access_review' THEN (SELECT c.bu_id FROM iam.access_review_campaign c WHERE c.id::text = split_part(target, ':', 2))
                                        WHEN 'access_review_item' THEN (SELECT i.bu_id FROM iam.access_review_item i WHERE i.id::text = split_part(target, ':', 2))
                                      END,
                                      'attributes', coalesce(attrs, '{}')));
$$;

CREATE OR REPLACE FUNCTION iam.sa_event(event text, severity text, actor uuid, sa uuid, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor::text, 'target', 'service_account:' || sa,
    'bu_id', (SELECT s.bu_id FROM iam.service_account s WHERE s.id = sa),
    'reason', reason, 'attributes', jsonb_build_object('name', (SELECT s.name FROM iam.service_account s WHERE s.id = sa)) || coalesce(attrs, '{}')));
$$;

CREATE OR REPLACE FUNCTION iam.assignment_expiry_sweep() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  a iam.assignment;
  n integer := 0;
BEGIN
  FOR a IN
    UPDATE iam.assignment x SET revoked_at = now()
    WHERE x.revoked_at IS NULL AND x.expires_at <= now() AND x.source <> 'mapped'
    RETURNING * LOOP
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'access.assignment_expired', 'severity', 'low', 'actor', 'system:iam',
      'target', a.principal_kind || ':' || a.principal_id, 'bu_id', a.bu_id,
      'attributes', jsonb_build_object('assignment', a.id, 'role', a.role_id, 'bu', a.bu_id,
                                       'granted_by', a.granted_by, 'granted_at', a.granted_at, 'expires_at', a.expires_at)));
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

CREATE OR REPLACE FUNCTION authz.drain_outbox(max_rows integer DEFAULT 1000, OUT drained integer, OUT changed integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  checked_until timestamptz := now();
  r iam.outbox;
  affected uuid[] := '{}';
BEGIN
  drained := 0;
  changed := 0;
  IF NOT pg_try_advisory_xact_lock(hashtext('authz.scope')) THEN
    drained := -1;
    RETURN;
  END IF;

  -- Expiry has no write to trigger on; T-32 revokes, this keeps scope right meanwhile.
  INSERT INTO iam.outbox (kind, ref)
  SELECT 'principal', jsonb_build_object('kind', a.principal_kind, 'id', a.principal_id)
  FROM iam.assignment a, authz.worker_state w
  WHERE a.revoked_at IS NULL AND a.expires_at > w.expiry_checked_until AND a.expires_at <= checked_until;
  UPDATE authz.worker_state SET expiry_checked_until = checked_until;

  FOR r IN DELETE FROM iam.outbox WHERE id IN (SELECT o.id FROM iam.outbox o ORDER BY o.id LIMIT max_rows) RETURNING * LOOP
    drained := drained + 1;
    affected := affected || ARRAY(SELECT authz.outbox_users(r.kind, r.ref));
    IF r.kind = 'bu' AND (r.ref->>'moved')::boolean THEN
      INSERT INTO iam.event_outbox (topic, payload)
      VALUES ('audit', jsonb_build_object(
        'type', 'bu.moved', 'severity', 'info', 'actor', coalesce(r.ref->>'actor', 'system'), 'bu_id', r.ref->>'id',
        'attributes', jsonb_build_object('bu_id', r.ref->>'id', 'old_parent', r.ref->>'old_parent',
                                         'new_parent', r.ref->>'new_parent', 'at', r.created_at)));
    END IF;
  END LOOP;
  IF drained > 0 THEN
    SELECT count(*) INTO changed FROM authz.refresh_scopes(affected);
  END IF;
END $$;

-- The same rule as pkg/audit.LooksSecret: JWTs, PEM private keys, bearer
-- or basic credentials, the session cookie.
CREATE FUNCTION audit.looks_secret(s text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT s ~ 'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.|-----BEGIN [A-Z ]*PRIVATE KEY-----|__Host-sid='
      OR s ~* '\m(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}';
$$;
REVOKE ALL ON FUNCTION audit.looks_secret(text) FROM PUBLIC;
ALTER FUNCTION audit.looks_secret(text) OWNER TO audit_definer;

-- audit_definer owns audit.submit, so it replaces it.
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
BEGIN
  IF event IS NULL OR jsonb_typeof(event) <> 'object' THEN
    RAISE EXCEPTION 'audit event: an object is required' USING ERRCODE = 'PF011';
  END IF;
  -- (Read once into ty: pkg/audit's catalog scan treats a 'type' key followed
  -- by a value as an emitted event.)
  ty := event->>'type';
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
      -- is reserved.
      IF et.attributes IS NOT NULL AND k <> 'event_id' AND NOT (k = ANY (et.attributes)) THEN
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
RESET ROLE;
SET LOCAL ROLE fair_owner;
