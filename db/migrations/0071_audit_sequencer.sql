-- F-002 T-07 (F-002-AC-03, AC-05, AC-07; design §4.2, §6.2): the
-- sequencer's database side.
--
-- One leader (internal/audit.Leader) moves accepted events from audit.intake
-- into audit.record in batches, each in one transaction:
--   1. audit.sequence_head() locks the chain head (creating it, with a new
--      instance id and the genesis hash, on first use);
--   2. audit.sequence_pending(n) returns the oldest intake rows, after
--      dropping any whose event is already recorded (a retry that arrived
--      after its first copy was sequenced: exactly once, AC-01);
--   3. the service builds each record body (ADR-011: the event plus
--      received_at, producer and the resolved bu_id, serialized with sorted
--      keys) and its leaf and chain hashes (internal/audit/integrity);
--   4. audit.sequence_append checks all of it and appends.
-- sequence_append trusts nothing it is given: the head must be where the
-- service read it, every body must be its intake row's event with that
-- row's producer and receipt time (so neither can be forged, AC-05), and the
-- hashes must be SHA-256 as ADR-011 defines them. A record's columns are
-- derived from its body. Rows that commit late with lower ids are simply
-- taken by a later batch.
-- New SQLSTATE: PF013, the sequencer's input does not match the trail.

-- The root BU, for events that name none (AC-19).
GRANT SELECT (parent_id) ON iam.bu TO audit_definer;

CREATE FUNCTION audit.sequence_head(OUT instance text, OUT seq bigint, OUT chain_hash bytea, OUT open_segment bigint, OUT root_bu uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h audit.head;
  id text;
BEGIN
  SELECT * INTO h FROM audit.head FOR UPDATE;
  IF NOT FOUND THEN
    id := gen_random_uuid()::text;
    INSERT INTO audit.head (instance, seq, chain_hash, open_segment, segment_opened_at)
    VALUES (id, 0, sha256(convert_to('fair-audit-v1' || id, 'UTF8')), 1, clock_timestamp())
    ON CONFLICT (singleton) DO NOTHING;
    SELECT * INTO h FROM audit.head FOR UPDATE;
  END IF;
  instance := h.instance;
  seq := h.seq;
  chain_hash := h.chain_hash;
  open_segment := h.open_segment;
  root_bu := (SELECT b.id FROM iam.bu b WHERE b.parent_id IS NULL);
END $$;

CREATE FUNCTION audit.sequence_pending(n integer)
RETURNS TABLE (id bigint, event_id text, producer text, body jsonb, accepted_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF n IS NULL OR n < 1 OR n > 5000 THEN
    RAISE EXCEPTION 'audit.sequence_pending: batch size % (1 to 5000)', n USING ERRCODE = 'PF004';
  END IF;
  -- Retries of events already recorded are dropped, not recorded twice.
  DELETE FROM audit.intake i WHERE i.id IN (
    SELECT x.id FROM audit.intake x WHERE EXISTS (SELECT 1 FROM audit.record r WHERE r.event_id = x.event_id)
    ORDER BY x.id LIMIT n);
  RETURN QUERY SELECT x.id, x.event_id, x.producer, x.body, x.accepted_at FROM audit.intake x ORDER BY x.id LIMIT n;
END $$;

CREATE FUNCTION audit.sequence_append(expect_seq bigint, expect_chain bytea, ids bigint[], bodies bytea[], leaves bytea[],
  chains bytea[], max_skew interval) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h       audit.head;
  root    uuid := (SELECT b.id FROM iam.bu b WHERE b.parent_id IS NULL);
  n       integer := coalesce(cardinality(ids), 0);
  i       integer;
  row     audit.intake;
  b       jsonb;
  want    jsonb;
  prev    bytea;
  leaf    bytea;
  link    bytea;
  s       bigint;
  t       timestamptz;
  ty      text;
BEGIN
  IF n = 0 OR coalesce(cardinality(bodies), 0) <> n OR coalesce(cardinality(leaves), 0) <> n OR coalesce(cardinality(chains), 0) <> n THEN
    RAISE EXCEPTION 'audit.sequence_append: ids, bodies, leaves and chains must be equal, non-empty arrays' USING ERRCODE = 'PF013';
  END IF;
  SELECT * INTO h FROM audit.head FOR UPDATE;
  IF NOT FOUND OR h.seq IS DISTINCT FROM expect_seq OR h.chain_hash IS DISTINCT FROM expect_chain THEN
    RAISE EXCEPTION 'audit.sequence_append: the chain head is not at % (another sequencer?)', expect_seq USING ERRCODE = 'PF013';
  END IF;
  prev := h.chain_hash;
  s := h.seq;
  FOR i IN 1 .. n LOOP
    DELETE FROM audit.intake x WHERE x.id = ids[i] RETURNING * INTO row;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'audit.sequence_append: intake row % is gone', ids[i] USING ERRCODE = 'PF013';
    END IF;
    BEGIN
      b := convert_from(bodies[i], 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'audit.sequence_append: body % is not JSON', i USING ERRCODE = 'PF013';
    END;
    -- The body is the intake event, with the intake row's producer and
    -- receipt time and the resolved BU: nothing else, nothing changed.
    want := row.body || jsonb_build_object('producer', row.producer, 'bu_id', coalesce(row.body->>'bu_id', root::text));
    -- IS DISTINCT FROM and coalesce throughout: a missing key must fail the
    -- check, not make it NULL (which IF treats as passing).
    IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR (b - 'received_at') IS DISTINCT FROM want
       OR NOT pg_input_is_valid(coalesce(b->>'received_at', ''), 'timestamptz')
       OR (b->>'received_at')::timestamptz IS DISTINCT FROM row.accepted_at THEN
      RAISE EXCEPTION 'audit.sequence_append: body % does not match intake row %', i, row.id USING ERRCODE = 'PF013';
    END IF;
    s := s + 1;
    leaf := sha256('\x00'::bytea || bodies[i]);
    link := sha256('\x01'::bytea || prev || int8send(s) || leaf);
    IF leaves[i] IS DISTINCT FROM leaf OR chains[i] IS DISTINCT FROM link THEN
      RAISE EXCEPTION 'audit.sequence_append: record % has the wrong leaf or chain hash', s USING ERRCODE = 'PF013';
    END IF;
    t := (b->>'time')::timestamptz;
    ty := b->>'type'; -- (pkg/audit's catalog scan reads a 'type' key and a value as an event)
    PERFORM audit.ensure_partition(t);
    INSERT INTO audit.record (seq, event_id, event_time, received_at, producer, type, category, severity, actor, target, bu_id,
                              request_id, source_ip, approval_id, skew, body, leaf_hash, chain_hash, segment)
    VALUES (s, row.event_id, t, row.accepted_at, row.producer, ty,
            (SELECT e.category FROM audit.event_type e WHERE e.type = ty), b->>'severity', b->>'actor', b->>'target',
            (b->>'bu_id')::uuid, b->>'request_id', (b->>'source_ip')::inet, b->'attributes'->>'approval_id',
            abs(extract(epoch FROM t - row.accepted_at)) > extract(epoch FROM coalesce(max_skew, interval '5 minutes')),
            bodies[i], leaf, link, h.open_segment);
    prev := link;
  END LOOP;
  UPDATE audit.head x SET seq = s, chain_hash = prev;
  RETURN s;
END $$;

REVOKE ALL ON FUNCTION audit.sequence_head(), audit.sequence_pending(integer),
  audit.sequence_append(bigint, bytea, bigint[], bytea[], bytea[], bytea[], interval) FROM PUBLIC;
ALTER FUNCTION audit.sequence_head() OWNER TO audit_definer;
ALTER FUNCTION audit.sequence_pending(integer) OWNER TO audit_definer;
ALTER FUNCTION audit.sequence_append(bigint, bytea, bigint[], bytea[], bytea[], bytea[], interval) OWNER TO audit_definer;
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.sequence_head(), audit.sequence_pending(integer),
  audit.sequence_append(bigint, bytea, bigint[], bytea[], bytea[], bytea[], interval) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- The audit service registers F-002's settings and reads them as every
-- service does (settings.Client; audit.max_clock_skew flags records, AC-05).
GRANT USAGE ON SCHEMA posture TO app_audit;
SET ROLE posture_definer; -- their owner
GRANT EXECUTE ON FUNCTION posture.effective_settings(), posture.settings_version(), posture.register_settings(text, text, jsonb) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
