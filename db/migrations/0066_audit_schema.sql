-- F-002 T-02 (F-002-AC-04, AC-08; design §4.1, §4.3): the audit schema.
--
-- Access model (as posture's, F-015 design §5): application roles hold no
-- table privileges, reads included. Producers reach the trail only through
-- audit.submit, a SECURITY DEFINER function owned by audit_definer (a
-- bootstrap, non-login role); the sequencer and the read functions arrive
-- with T-07 and T-12. Every table has RLS enabled and forced with a single
-- policy for audit_definer, so a mistaken grant exposes no rows and the
-- schema owner (fair_owner) sees none either.
--
-- Records and checkpoints are append-only: triggers refuse UPDATE, DELETE and
-- TRUNCATE for every role, the owner included. The one exception is the
-- retention function (T-18), which deletes archived segments while it holds
-- the transaction-local flag audit.archiving. A database superuser can still
-- get round all of this; that is detected, not prevented (design §8).

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_definer') THEN
    RAISE EXCEPTION 'role audit_definer is missing: re-run scripts/db-bootstrap.sh (F-002 T-02)';
  END IF;
END $$;

CREATE SCHEMA audit AUTHORIZATION fair_owner;
REVOKE ALL ON SCHEMA audit FROM PUBLIC;
GRANT USAGE ON SCHEMA audit TO app_rw, app_posture, app_gateway, audit_definer;
-- audit_definer owns the partitioned record table, so it creates partitions.
GRANT CREATE ON SCHEMA audit TO audit_definer;
ALTER DEFAULT PRIVILEGES FOR ROLE fair_owner IN SCHEMA audit REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE fair_owner IN SCHEMA audit REVOKE ALL ON FUNCTIONS FROM PUBLIC;

-- The event catalog as data (pkg/audit/catalog.yaml), synced by iam migrate
-- (audit.sync_event_types). Types leaving the catalog are retired, not
-- deleted: their records stay valid, new events of the type are refused.
CREATE TABLE audit.event_type (
  type         text        PRIMARY KEY CHECK (type ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$'),
  category     text        NOT NULL CHECK (category ~ '^[a-z][a-z0-9_]*$'),
  severities   text[]      NOT NULL CHECK (cardinality(severities) > 0 AND severities <@ ARRAY['info', 'low', 'high', 'critical']),
  requires     text[]      NOT NULL DEFAULT '{}' CHECK (requires <@ ARRAY['target', 'reason']),
  bu           text        NOT NULL DEFAULT 'optional' CHECK (bu IN ('required', 'optional')),
  attributes   text[],     -- the attribute names a type may carry (T-03); NULL: not declared yet
  description  text        NOT NULL CHECK (btrim(description) <> ''),
  added_at     timestamptz NOT NULL DEFAULT now(),
  retired_at   timestamptz
);

-- Accepted events not yet sequenced (§6.1). No order and no chain, so
-- producers never contend; event_id makes a retried event a no-op.
CREATE TABLE audit.intake (
  id           bigserial   PRIMARY KEY,
  event_id     text        NOT NULL UNIQUE CHECK (event_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  producer     text        NOT NULL,          -- the producing DB role, never taken from the body
  body         jsonb       NOT NULL CHECK (jsonb_typeof(body) = 'object'),
  accepted_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- The trail, online part (§4.1, §4.2), partitioned by month on event_time.
-- Owned by audit_definer so the sequencer (T-07) can add partitions through
-- audit.ensure_partition. seq is unique by construction (one sequencer
-- holding audit.head) and checked by verification; event_id likewise.
-- bu_id has no foreign key: audit.submit checks the BU exists, BUs are never
-- deleted, and records outlive the online schema (archives carry bu_id
-- too); a key would also tie the trail into iam.bu's TRUNCATE cascade.
CREATE TABLE audit.record (
  seq          bigint      NOT NULL CHECK (seq > 0),
  event_id     text        NOT NULL,
  event_time   timestamptz NOT NULL,
  received_at  timestamptz NOT NULL,
  producer     text        NOT NULL,
  type         text        NOT NULL,
  category     text        NOT NULL,
  severity     text        NOT NULL CHECK (severity IN ('info', 'low', 'high', 'critical')),
  actor        text        NOT NULL,
  target       text,
  bu_id        uuid        NOT NULL,          -- checked by audit.submit; no foreign key (see below)
  request_id   text,
  source_ip    inet,
  approval_id  text,
  skew         boolean     NOT NULL DEFAULT false,
  body         bytea       NOT NULL,
  leaf_hash    bytea       NOT NULL CHECK (length(leaf_hash) = 32),
  chain_hash   bytea       NOT NULL CHECK (length(chain_hash) = 32),
  segment      bigint      NOT NULL CHECK (segment > 0),
  PRIMARY KEY (seq, event_time)
) PARTITION BY RANGE (event_time);
CREATE INDEX record_event_time ON audit.record (event_time);
CREATE INDEX record_type_time ON audit.record (type, event_time);
CREATE INDEX record_actor_time ON audit.record (actor, event_time);
CREATE INDEX record_target_time ON audit.record (target, event_time) WHERE target IS NOT NULL;
CREATE INDEX record_bu_time ON audit.record (bu_id, event_time);
CREATE INDEX record_request ON audit.record (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX record_approval ON audit.record (approval_id) WHERE approval_id IS NOT NULL;
CREATE INDEX record_event_id ON audit.record (event_id);
CREATE INDEX record_segment ON audit.record (segment, seq);

-- The single chain head, locked by the sequencer for each batch.
CREATE TABLE audit.head (
  singleton          boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  instance           text        NOT NULL CHECK (btrim(instance) <> ''),
  seq                bigint      NOT NULL CHECK (seq >= 0),
  chain_hash         bytea       NOT NULL CHECK (length(chain_hash) = 32),
  open_segment       bigint      NOT NULL CHECK (open_segment > 0),
  segment_opened_at  timestamptz NOT NULL
);

-- Signed segment closes (ADR-011). Kept forever, also after destruction.
CREATE TABLE audit.checkpoint (
  segment               bigint      PRIMARY KEY CHECK (segment > 0),
  seq_from              bigint      NOT NULL CHECK (seq_from > 0),
  seq_to                bigint      NOT NULL CHECK (seq_to >= seq_from - 1),
  merkle_root           bytea       NOT NULL CHECK (length(merkle_root) = 32),
  chain_hash            bytea       NOT NULL CHECK (length(chain_hash) = 32),
  prev_checkpoint_hash  bytea       NOT NULL CHECK (length(prev_checkpoint_hash) = 32),
  issued_at             timestamptz NOT NULL,
  key_id                text        NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$'),
  statement             bytea       NOT NULL,
  signature             bytea       NOT NULL,
  worm_key              text        -- the write-once copy's object key, once written
);

-- Public checkpoint keys by key id (rotation keeps old keys).
CREATE TABLE audit.signing_key (
  key_id       text        PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{64}$'),
  public_pem   text        NOT NULL CHECK (public_pem LIKE '-----BEGIN PUBLIC KEY-----%'),
  active_from  timestamptz NOT NULL DEFAULT now(),
  retired_at   timestamptz CHECK (retired_at IS NULL OR retired_at >= active_from)
);

-- Segments moved to object storage (T-18).
CREATE TABLE audit.archive (
  segment        bigint      PRIMARY KEY REFERENCES audit.checkpoint (segment),
  object_key     text        NOT NULL CHECK (btrim(object_key) <> ''),
  digest         bytea       NOT NULL CHECK (length(digest) = 32),
  record_count   bigint      NOT NULL CHECK (record_count >= 0),
  archived_at    timestamptz NOT NULL DEFAULT now(),
  destroy_after  timestamptz NOT NULL,
  destroyed_at   timestamptz CHECK (destroyed_at IS NULL OR destroyed_at >= destroy_after)
);

-- Legal holds (AC-29, T-19).
CREATE TABLE audit.hold (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  filter          jsonb       NOT NULL CHECK (jsonb_typeof(filter) = 'object'),
  reason          text        NOT NULL CHECK (btrim(reason) <> ''),
  placed_by       uuid        NOT NULL REFERENCES iam.app_user (id),
  placed_at       timestamptz NOT NULL DEFAULT now(),
  released_by     uuid        REFERENCES iam.app_user (id),
  released_at     timestamptz,
  release_reason  text        CHECK (release_reason IS NULL OR btrim(release_reason) <> ''),
  CHECK ((released_at IS NULL) = (released_by IS NULL) AND (released_at IS NULL) = (release_reason IS NULL))
);

CREATE TABLE audit.hold_segment (
  hold_id  uuid   NOT NULL REFERENCES audit.hold (id),
  segment  bigint NOT NULL REFERENCES audit.checkpoint (segment),
  PRIMARY KEY (hold_id, segment)
);

-- Evidence exports (AC-32 to AC-34, T-15).
CREATE TABLE audit.export (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  requested_by        uuid        NOT NULL REFERENCES iam.app_user (id),
  filter              jsonb       NOT NULL CHECK (jsonb_typeof(filter) = 'object'),
  format              text        NOT NULL CHECK (format IN ('jsonl', 'csv')),
  reason              text        NOT NULL CHECK (btrim(reason) <> ''),
  scope_bus           uuid[]      NOT NULL,
  status              text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'failed')),
  record_count        bigint      CHECK (record_count >= 0),
  digest              bytea       CHECK (length(digest) = 32),
  checkpoint_segment  bigint      REFERENCES audit.checkpoint (segment),
  object_key          text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  completed_at        timestamptz,
  CHECK ((status = 'pending') = (completed_at IS NULL))
);

-- Verification runs (AC-12 to AC-14, T-11).
CREATE TABLE audit.verification (
  id             bigserial   PRIMARY KEY,
  kind           text        NOT NULL CHECK (kind IN ('incremental', 'full')),
  from_seq       bigint      NOT NULL CHECK (from_seq >= 0),
  to_seq         bigint      CHECK (to_seq >= from_seq),
  started_at     timestamptz NOT NULL DEFAULT now(),
  finished_at    timestamptz,
  ok             boolean,
  failed_at_seq  bigint,
  detail         text,
  CHECK ((finished_at IS NULL) = (ok IS NULL)),
  CHECK (failed_at_seq IS NULL OR ok IS FALSE)
);

-- Forwarding cursors (AC-23, T-16, T-17).
CREATE TABLE audit.destination (
  name          text        PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_-]*$'),
  kind          text        NOT NULL CHECK (kind IN ('syslog', 'otlp')),
  last_seq      bigint      NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  last_sent_at  timestamptz,
  last_error    text
);

-- Defence in depth: RLS enabled and forced, one policy for audit_definer.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['event_type', 'intake', 'record', 'head', 'checkpoint', 'signing_key', 'archive',
                           'hold', 'hold_segment', 'export', 'verification', 'destination'] LOOP
    EXECUTE format('REVOKE ALL ON audit.%I FROM PUBLIC', t);
    EXECUTE format('ALTER TABLE audit.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE audit.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY definer_only ON audit.%I TO audit_definer USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;
REVOKE ALL ON SEQUENCE audit.intake_id_seq, audit.verification_id_seq FROM PUBLIC;

-- What audit_definer may do; the triggers below narrow it further.
GRANT SELECT, INSERT, UPDATE, DELETE ON audit.event_type TO audit_definer;
GRANT SELECT, INSERT, DELETE ON audit.intake TO audit_definer;
GRANT USAGE ON SEQUENCE audit.intake_id_seq, audit.verification_id_seq TO audit_definer;
GRANT SELECT, INSERT, UPDATE ON audit.head TO audit_definer;
GRANT SELECT, INSERT ON audit.checkpoint TO audit_definer;
GRANT UPDATE (worm_key) ON audit.checkpoint TO audit_definer;
GRANT SELECT, INSERT ON audit.signing_key TO audit_definer;
GRANT UPDATE (retired_at) ON audit.signing_key TO audit_definer;
GRANT SELECT, INSERT ON audit.archive TO audit_definer;
GRANT UPDATE (destroyed_at) ON audit.archive TO audit_definer;
GRANT SELECT, INSERT ON audit.hold TO audit_definer;
GRANT UPDATE (released_by, released_at, release_reason) ON audit.hold TO audit_definer;
GRANT SELECT, INSERT, DELETE ON audit.hold_segment TO audit_definer;
GRANT SELECT, INSERT, UPDATE ON audit.export TO audit_definer;
GRANT SELECT, INSERT, UPDATE ON audit.verification TO audit_definer;
GRANT SELECT, INSERT, UPDATE ON audit.destination TO audit_definer;
-- submit checks bu_id against the BU table.
GRANT USAGE ON SCHEMA iam TO audit_definer;
GRANT SELECT (id) ON iam.bu TO audit_definer;

-- Append-only (AC-08). PF012: the audit trail cannot be changed.
CREATE FUNCTION audit.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  col text;
BEGIN
  -- PL/pgSQL does not short-circuit AND, so fields are read through jsonb and
  -- only for the table that has them.
  IF TG_OP = 'DELETE' AND TG_TABLE_NAME LIKE 'record%' THEN
    IF current_setting('audit.archiving', true) = 'on' THEN
      RETURN OLD;
    END IF;
  ELSIF TG_OP = 'UPDATE' AND TG_TABLE_NAME IN ('checkpoint', 'signing_key') THEN
    col := CASE TG_TABLE_NAME WHEN 'checkpoint' THEN 'worm_key' ELSE 'retired_at' END;
    -- One column may be set once, from NULL, with nothing else changing.
    IF to_jsonb(OLD)->>col IS NULL AND to_jsonb(NEW)->>col IS NOT NULL THEN
      IF (to_jsonb(OLD) - col) = (to_jsonb(NEW) - col) THEN
        RETURN NEW;
      END IF;
    END IF;
  END IF;
  RAISE EXCEPTION 'audit.%: the audit trail is append-only (% refused)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'PF012';
END $$;

CREATE TRIGGER record_append_only BEFORE UPDATE OR DELETE ON audit.record
  FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER record_no_truncate BEFORE TRUNCATE ON audit.record
  FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER checkpoint_append_only BEFORE UPDATE OR DELETE ON audit.checkpoint
  FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER checkpoint_no_truncate BEFORE TRUNCATE ON audit.checkpoint
  FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER signing_key_append_only BEFORE UPDATE OR DELETE ON audit.signing_key
  FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();
CREATE TRIGGER signing_key_no_truncate BEFORE TRUNCATE ON audit.signing_key
  FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

-- Monthly partitions of audit.record, created before the sequencer inserts
-- into a month (T-07). Idempotent.
CREATE FUNCTION audit.ensure_partition(at timestamptz) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  lo timestamptz := date_trunc('month', at, 'UTC');
  name text := 'record_' || to_char(lo AT TIME ZONE 'UTC', 'YYYYMM');
BEGIN
  IF at IS NULL THEN
    RAISE EXCEPTION 'audit.ensure_partition: a time is required' USING ERRCODE = 'PF004';
  END IF;
  IF to_regclass('audit.' || name) IS NULL THEN
    EXECUTE format('CREATE TABLE audit.%I PARTITION OF audit.record FOR VALUES FROM (%L) TO (%L)',
                   name, lo, lo + interval '1 month');
    EXECUTE format('REVOKE ALL ON audit.%I FROM PUBLIC', name);
    EXECUTE format('ALTER TABLE audit.%I ENABLE ROW LEVEL SECURITY', name);
    EXECUTE format('ALTER TABLE audit.%I FORCE ROW LEVEL SECURITY', name);
    EXECUTE format('CREATE POLICY definer_only ON audit.%I TO audit_definer USING (true) WITH CHECK (true)', name);
    -- Row triggers are cloned from audit.record; statement triggers are not.
    EXECUTE format('CREATE TRIGGER partition_no_truncate BEFORE TRUNCATE ON audit.%I FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change()', name);
  END IF;
  RETURN name;
END $$;
REVOKE ALL ON FUNCTION audit.ensure_partition(timestamptz) FROM PUBLIC;
ALTER FUNCTION audit.ensure_partition(timestamptz) OWNER TO audit_definer;

-- audit.submit (§4.3, §6.1): checks an event against the catalog and the
-- envelope and accepts it into intake, in the caller's transaction. A
-- retried event (same id) is accepted once. PF011: not a valid event.
CREATE FUNCTION audit.submit(event jsonb) RETURNS text
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
    END LOOP;
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
REVOKE ALL ON FUNCTION audit.submit(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.submit(jsonb) TO app_rw, app_posture, app_gateway;
ALTER FUNCTION audit.submit(jsonb) OWNER TO audit_definer;

-- audit.sync_event_types (iam migrate, in the release transaction as
-- fair_owner): makes audit.event_type equal to the build's catalog. Payload:
-- {"events": [{type, category, severities, requires, bu?, attributes?,
-- description}]}. Returns {added, changed, retired, restored}.
CREATE FUNCTION audit.sync_event_types(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  e jsonb;
  old audit.event_type;
  sev text[];
  req text[];
  attrs text[];
  added text[] := '{}';
  changed text[] := '{}';
  retired text[] := '{}';
  restored text[] := '{}';
  seen text[] := '{}';
  ty text;
BEGIN
  IF coalesce(jsonb_typeof(payload->'events'), '') <> 'array' OR jsonb_array_length(payload->'events') = 0 THEN
    RAISE EXCEPTION 'audit.sync_event_types: the catalog has no events' USING ERRCODE = 'PF004';
  END IF;
  FOR e IN SELECT * FROM jsonb_array_elements(payload->'events') LOOP
    -- jsonb_typeof of a missing key is NULL: coalesce, or the test passes.
    IF coalesce(jsonb_typeof(e->'type'), '') <> 'string' OR coalesce(jsonb_typeof(e->'category'), '') <> 'string'
       OR coalesce(jsonb_typeof(e->'description'), '') <> 'string' OR coalesce(jsonb_typeof(e->'severities'), '') <> 'array'
       OR coalesce(jsonb_typeof(e->'requires'), 'array') <> 'array' OR coalesce(jsonb_typeof(e->'attributes'), 'array') NOT IN ('array', 'null')
       OR coalesce(jsonb_typeof(e->'bu'), 'string') <> 'string' THEN
      RAISE EXCEPTION 'audit.sync_event_types: malformed entry %', e USING ERRCODE = 'PF004';
    END IF;
    ty := e->>'type';
    IF ty = ANY (seen) THEN
      RAISE EXCEPTION 'audit.sync_event_types: % listed twice', ty USING ERRCODE = 'PF004';
    END IF;
    seen := seen || ty;
    sev := ARRAY(SELECT jsonb_array_elements_text(e->'severities'));
    req := ARRAY(SELECT jsonb_array_elements_text(coalesce(e->'requires', '[]')));
    attrs := CASE WHEN jsonb_typeof(e->'attributes') = 'array' THEN ARRAY(SELECT jsonb_array_elements_text(e->'attributes') ORDER BY 1) END;
    SELECT * INTO old FROM audit.event_type t WHERE t.type = ty FOR UPDATE;
    IF NOT FOUND THEN
      INSERT INTO audit.event_type (type, category, severities, requires, bu, attributes, description)
      VALUES (ty, e->>'category', sev, req, coalesce(e->>'bu', 'optional'), attrs, e->>'description');
      added := added || ty;
      CONTINUE;
    END IF;
    IF old.retired_at IS NOT NULL THEN
      restored := restored || old.type;
    ELSIF (old.category, old.severities, old.requires, old.bu, old.attributes, old.description)
          IS DISTINCT FROM (e->>'category', sev, req, coalesce(e->>'bu', 'optional'), attrs, e->>'description') THEN
      changed := changed || old.type;
    END IF;
    UPDATE audit.event_type t SET category = e->>'category', severities = sev, requires = req, bu = coalesce(e->>'bu', 'optional'),
      attributes = attrs, description = e->>'description', retired_at = NULL
    WHERE t.type = old.type;
  END LOOP;
  WITH r AS (
    UPDATE audit.event_type t SET retired_at = now() WHERE t.retired_at IS NULL AND NOT (t.type = ANY (seen)) RETURNING t.type
  )
  SELECT coalesce(array_agg(r.type ORDER BY r.type), '{}') INTO retired FROM r;
  RETURN jsonb_build_object('added', to_jsonb(added), 'changed', to_jsonb(changed), 'retired', to_jsonb(retired),
                            'restored', to_jsonb(restored));
END $$;
REVOKE ALL ON FUNCTION audit.sync_event_types(jsonb) FROM PUBLIC;
ALTER FUNCTION audit.sync_event_types(jsonb) OWNER TO audit_definer;
-- fair_owner (iam migrate) syncs the release's catalog; as in 0013, the new
-- owner grants it.
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.sync_event_types(jsonb) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

REVOKE ALL ON FUNCTION audit.refuse_change() FROM PUBLIC;
-- ensure_partition (as audit_definer) attaches it to new partitions.
GRANT EXECUTE ON FUNCTION audit.refuse_change() TO audit_definer;

-- Last: audit_definer owns the record table (and so its partitions), which
-- lets the sequencer add partitions. fair_owner cannot alter it afterwards.
ALTER TABLE audit.record OWNER TO audit_definer;
