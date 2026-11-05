-- F-002 T-18 (F-002-AC-25, AC-26; design §6.7): archiving segments past the
-- online retention.
--
-- The leader's archiver (internal/audit.Archiver) finds closed segments
-- whose newest record is older than audit.retention_online
-- (audit.archive_candidates), writes each to the audit store as
-- segments/<instance>/<n>.jsonl.gz (the T-10 format: the signed checkpoint,
-- then every record's exact body with its leaf and chain hashes), locked
-- until destroy_after, reads it back and checks it, and only then calls
-- audit.archive_segment: it records the archive and deletes the segment's
-- rows, in the transaction that records audit.records_archived. A failed
-- upload or check deletes nothing. Segments without records are not
-- archived (nothing to move; their checkpoints stay).
--
-- Archived records leave search, history and the other read views (their
-- rows are gone) but stay verifiable (the verifier reads the archive) and
-- exportable: audit.export_archived applies an export's filter and
-- captured scope to an archived segment's bodies, with the same conditions
-- as search (audit.filter_conditions) over the columns the sequencer
-- derives from a body (audit.record_from_body).

SET ROLE audit_definer;

-- Closed, unarchived segments with records, whose newest event is older
-- than older_than; oldest first, at most n.
CREATE FUNCTION audit.archive_candidates(older_than timestamptz, n integer)
RETURNS TABLE (segment bigint, seq_from bigint, seq_to bigint, newest timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.segment, c.seq_from, c.seq_to, m.newest
  FROM audit.checkpoint c
  CROSS JOIN LATERAL (SELECT max(r.event_time) AS newest FROM audit.record r WHERE r.seq BETWEEN c.seq_from AND c.seq_to) m
  WHERE c.seq_to >= c.seq_from
    AND NOT EXISTS (SELECT 1 FROM audit.archive a WHERE a.segment = c.segment)
    AND m.newest IS NOT NULL AND m.newest < older_than
  ORDER BY c.segment
  LIMIT least(greatest(coalesce(n, 10), 1), 1000);
$$;

-- The segment's archive is stored and checked: record it and remove the
-- segment's rows. The caller has read the object back (digest d); the row
-- count must be the archive's record count and the segment's size.
CREATE FUNCTION audit.archive_segment(seg bigint, okey text, over text, d bytea, n bigint, until timestamptz) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c       audit.checkpoint;
  online  bigint;
  deleted bigint;
BEGIN
  SELECT * INTO c FROM audit.checkpoint k WHERE k.segment = seg;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit.archive_segment: segment % is not closed', seg USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM audit.archive a WHERE a.segment = seg) THEN
    RAISE EXCEPTION 'audit.archive_segment: segment % is already archived', seg USING ERRCODE = 'PF003';
  END IF;
  IF btrim(coalesce(okey, '')) = '' OR btrim(coalesce(over, '')) = '' OR d IS NULL OR length(d) <> 32 OR until IS NULL OR until <= now() THEN
    RAISE EXCEPTION 'audit.archive_segment: an object, version, digest and future destruction time are required' USING ERRCODE = 'PF004';
  END IF;
  SELECT count(*) INTO online FROM audit.record r WHERE r.seq BETWEEN c.seq_from AND c.seq_to;
  IF n IS DISTINCT FROM c.seq_to - c.seq_from + 1 OR online <> n THEN
    RAISE EXCEPTION 'audit.archive_segment: segment % holds % records online and % in the segment; the archive has %',
      seg, online, c.seq_to - c.seq_from + 1, n USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO audit.archive (segment, object_key, version_id, digest, record_count, destroy_after)
  VALUES (seg, okey, over, d, n, until);
  PERFORM set_config('audit.archiving', 'on', true);
  DELETE FROM audit.record r WHERE r.seq BETWEEN c.seq_from AND c.seq_to;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  PERFORM set_config('audit.archiving', 'off', true);
  IF deleted <> n THEN
    RAISE EXCEPTION 'audit.archive_segment: % rows removed, % expected', deleted, n USING ERRCODE = 'PF003';
  END IF;
  RETURN deleted;
END $$;

-- The columns the sequencer derives from a record's body (0071
-- audit.sequence_append), for an archived record.
CREATE FUNCTION audit.record_from_body(seq bigint, segment bigint, body bytea) RETURNS audit.record
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  b jsonb := convert_from(body, 'UTF8')::jsonb;
  r audit.record;
BEGIN
  r.seq := seq;
  r.segment := segment;
  r.event_id := b->>'id';
  r.event_time := (b->>'time')::timestamptz;
  r.received_at := (b->>'received_at')::timestamptz;
  r.producer := b->>'producer';
  r.type := b->>'type';
  r.category := (SELECT e.category FROM audit.event_type e WHERE e.type = b->>'type');
  r.severity := b->>'severity';
  r.actor := b->>'actor';
  r.target := b->>'target';
  r.bu_id := (b->>'bu_id')::uuid;
  r.request_id := b->>'request_id';
  r.source_ip := (b->>'source_ip')::inet;
  r.approval_id := b->'attributes'->>'approval_id';
  r.body := body;
  RETURN r;
END $$;
REVOKE ALL ON FUNCTION audit.record_from_body(bigint, bigint, bytea) FROM PUBLIC;

-- The live archives a pending export covers, in order: segments up to its
-- closing checkpoint (destroyed ones are gone).
CREATE FUNCTION audit.export_archives(of_id uuid, upto_seq bigint)
RETURNS TABLE (segment bigint, seq_from bigint, seq_to bigint, object_key text, version_id text, digest bytea, record_count bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM audit.export x WHERE x.id = of_id AND x.status = 'pending') THEN
    RAISE EXCEPTION 'audit: export % is not pending', of_id USING ERRCODE = 'PF003';
  END IF;
  RETURN QUERY SELECT a.segment, c.seq_from, c.seq_to, a.object_key, a.version_id, a.digest, a.record_count
  FROM audit.archive a JOIN audit.checkpoint c ON c.segment = a.segment
  WHERE a.destroyed_at IS NULL AND c.seq_to <= upto_seq
  ORDER BY a.segment;
END $$;

-- An archived segment's records (seqs and bodies, from its object) that a
-- pending export includes: its filter in its captured scope, as
-- audit.export_rows applies them online. skew is not in a body (it
-- depended on audit.max_clock_skew when the record was sequenced): NULL.
CREATE FUNCTION audit.export_archived(of_id uuid, seg bigint, seqs bigint[], bodies bytea[])
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
  IF NOT EXISTS (SELECT 1 FROM audit.archive a WHERE a.segment = seg AND a.destroyed_at IS NULL) THEN
    RAISE EXCEPTION 'audit: segment % is not archived', seg USING ERRCODE = 'PF003';
  END IF;
  IF cardinality(seqs) IS DISTINCT FROM cardinality(bodies) THEN
    RAISE EXCEPTION 'audit: % positions and % bodies', cardinality(seqs), cardinality(bodies) USING ERRCODE = 'PF004';
  END IF;
  conds := array_prepend('r.bu_id = ANY ($2)', audit.filter_conditions(x.filter));
  RETURN QUERY EXECUTE format($q$
    SELECT r.seq, r.event_id, r.segment, r.body, r.event_time, r.received_at, r.producer, r.type, r.category, r.severity, r.actor, r.target,
           r.bu_id, r.request_id, host(r.source_ip), r.approval_id, NULL::boolean
    FROM unnest($4, $5) AS i(s, b), LATERAL audit.record_from_body(i.s, $6, i.b) r
    WHERE %s ORDER BY r.seq$q$, array_to_string(conds, ' AND '))
  USING NULL::uuid[], x.scope_bus, x.filter, seqs, bodies, seg;
END $$;

REVOKE ALL ON FUNCTION audit.archive_candidates(timestamptz, integer), audit.archive_segment(bigint, text, text, bytea, bigint, timestamptz),
  audit.export_archives(uuid, bigint), audit.export_archived(uuid, bigint, bigint[], bytea[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.archive_candidates(timestamptz, integer), audit.archive_segment(bigint, text, text, bytea, bigint, timestamptz),
  audit.export_archives(uuid, bigint), audit.export_archived(uuid, bigint, bigint[], bytea[]) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
