-- F-002 T-19 (F-002-AC-27, AC-28, AC-29; design §6.7): legal holds and
-- destruction.
--
-- Holds (decisions of 2026-11-05, Robert Former): placing or releasing one
-- needs audit.hold at the root BU (privileged; Platform Admin), and a hold's
-- filter covers the whole trail. A hold covers matching records until it
-- is released, including records that arrive after it was placed.
--   * audit.hold_place records the hold and, in the same transaction, the
--     closed online segments holding matching records (audit.hold_segment).
--     Archived segments are checked by the audit service, which reads their
--     objects (audit.hold_match_archived) and then marks the hold checked;
--     until every active hold is checked, nothing is destroyed.
--   * audit.archive_segment (replaced here) marks the segment held by every
--     active hold matching its records before they leave the database, and
--     records the segment's newest event time.
--   * The S3 legal hold on an archive follows the database: the service sets
--     it while an active hold covers the segment and clears it after
--     (archive.legal_hold records what is applied).
--   * audit.hold_release ends a hold; its segments stay listed (history).
--
-- Destruction (AC-27): an archive is destroyed only when its lock has
-- ended (destroy_after), its newest record is older than the total
-- retention now in force (a longer retention keeps it longer; a shorter one
-- never shortens a lock), and no active hold covers it. audit.destroy_segment
-- records the destruction (the service then deletes the object and records
-- that it is gone); checkpoints are kept, so verification starts from the
-- first retained one.

ALTER TABLE audit.archive
  ADD COLUMN newest_at timestamptz,
  ADD COLUMN legal_hold boolean NOT NULL DEFAULT false,
  ADD COLUMN object_removed_at timestamptz CHECK (object_removed_at IS NULL OR destroyed_at IS NOT NULL);
ALTER TABLE audit.hold
  ADD COLUMN archives_checked_at timestamptz,
  ADD CONSTRAINT hold_reason_length CHECK (char_length(reason) <= 1000 AND (release_reason IS NULL OR char_length(release_reason) <= 1000));
GRANT UPDATE (newest_at, legal_hold, object_removed_at) ON audit.archive TO audit_definer;
GRANT SELECT, INSERT, UPDATE ON audit.hold TO audit_definer;
GRANT SELECT, INSERT ON audit.hold_segment TO audit_definer;

SET ROLE audit_definer;

-- The signed-context user, who must hold audit.hold at the root.
CREATE FUNCTION audit.hold_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT c.user_id FROM authz.ctx_user() c);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'legal holds need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, 'audit.hold', NULL) THEN
    RAISE EXCEPTION 'audit.hold at the root is required' USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- Marks the closed online segments holding records that match hold h.
CREATE FUNCTION audit.hold_mark_online(h uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  f     jsonb := (SELECT x.filter FROM audit.hold x WHERE x.id = h);
  conds text[] := audit.filter_conditions(f);
  n     bigint;
BEGIN
  EXECUTE format($q$
    INSERT INTO audit.hold_segment (hold_id, segment)
    SELECT DISTINCT $1, r.segment FROM audit.record r
    WHERE EXISTS (SELECT 1 FROM audit.checkpoint c WHERE c.segment = r.segment) %s
    ON CONFLICT DO NOTHING$q$,
    CASE WHEN cardinality(conds) = 0 THEN '' ELSE 'AND ' || array_to_string(conds, ' AND ') END)
  USING h, NULL::uuid[], f;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

-- AC-29: place a hold. Returns its id.
CREATE FUNCTION audit.hold_place(filter jsonb, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u  uuid := audit.hold_actor();
  id uuid;
BEGIN
  PERFORM audit.filter_conditions(filter);
  IF reason IS NULL OR btrim(reason) = '' OR char_length(reason) > 1000 THEN
    RAISE EXCEPTION 'audit: a reason of 1 to 1000 characters is required' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO audit.hold (filter, reason, placed_by) VALUES (coalesce(filter, '{}'), btrim(reason), u) RETURNING audit.hold.id INTO id;
  PERFORM audit.hold_mark_online(id);
  RETURN id;
END $$;

-- Release a hold. Returns the segments no active hold covers any more.
CREATE FUNCTION audit.hold_release(of_id uuid, reason text) RETURNS bigint[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := audit.hold_actor();
BEGIN
  IF reason IS NULL OR btrim(reason) = '' OR char_length(reason) > 1000 THEN
    RAISE EXCEPTION 'audit: a reason of 1 to 1000 characters is required' USING ERRCODE = 'PF004';
  END IF;
  UPDATE audit.hold x SET released_by = u, released_at = now(), release_reason = btrim(hold_release.reason)
  WHERE x.id = of_id AND x.released_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit: no active hold %', of_id USING ERRCODE = 'PF003';
  END IF;
  RETURN ARRAY(SELECT s.segment FROM audit.hold_segment s WHERE s.hold_id = of_id
               AND NOT EXISTS (SELECT 1 FROM audit.hold_segment o JOIN audit.hold x ON x.id = o.hold_id
                               WHERE o.segment = s.segment AND x.released_at IS NULL)
               ORDER BY s.segment);
END $$;

-- Every hold, newest first, with its segment count (holders of audit.hold
-- at the root only).
CREATE FUNCTION audit.holds()
RETURNS TABLE (id uuid, filter jsonb, reason text, placed_by uuid, placed_at timestamptz, released_by uuid, released_at timestamptz,
               release_reason text, archives_checked_at timestamptz, segments bigint, names jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM audit.hold_actor();
  RETURN QUERY SELECT x.id, x.filter, x.reason, x.placed_by, x.placed_at, x.released_by, x.released_at, x.release_reason,
                      x.archives_checked_at, (SELECT count(*) FROM audit.hold_segment s WHERE s.hold_id = x.id),
                      coalesce((SELECT jsonb_object_agg(d.id, d.display_name)
                                FROM iam.user_display_names(ARRAY[x.placed_by, x.released_by]) d), '{}'::jsonb)
  FROM audit.hold x ORDER BY x.placed_at DESC, x.id;
END $$;

-- The service's side: active holds not yet checked against the archives,
-- and the live archives to check them against.
CREATE FUNCTION audit.holds_unchecked() RETURNS TABLE (id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT x.id FROM audit.hold x WHERE x.released_at IS NULL AND x.archives_checked_at IS NULL ORDER BY x.placed_at;
$$;

-- Whether any of an archived segment's records (from its object) match
-- hold h; when they do, the segment is marked held.
CREATE FUNCTION audit.hold_match_archived(h uuid, seg bigint, seqs bigint[], bodies bytea[]) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  f     jsonb := (SELECT x.filter FROM audit.hold x WHERE x.id = h AND x.released_at IS NULL);
  conds text[];
  hit   boolean;
BEGIN
  IF f IS NULL THEN
    RAISE EXCEPTION 'audit: no active hold %', h USING ERRCODE = 'PF003';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM audit.archive a WHERE a.segment = seg AND a.destroyed_at IS NULL) THEN
    RAISE EXCEPTION 'audit: segment % is not archived', seg USING ERRCODE = 'PF003';
  END IF;
  conds := audit.filter_conditions(f);
  EXECUTE format($q$
    SELECT EXISTS (SELECT 1 FROM unnest($4, $5) AS i(s, b), LATERAL audit.record_from_body(i.s, $6, i.b) r %s)$q$,
    CASE WHEN cardinality(conds) = 0 THEN '' ELSE 'WHERE ' || array_to_string(conds, ' AND ') END)
  INTO hit USING NULL::uuid[], NULL::uuid[], f, seqs, bodies, seg;
  IF hit THEN
    INSERT INTO audit.hold_segment (hold_id, segment) VALUES (h, seg) ON CONFLICT DO NOTHING;
  END IF;
  RETURN hit;
END $$;

CREATE FUNCTION audit.hold_checked(h uuid) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE audit.hold x SET archives_checked_at = now() WHERE x.id = h AND x.archives_checked_at IS NULL;
$$;

-- Archives whose S3 legal hold differs from what the active holds say:
-- want is the legal hold they should have.
CREATE FUNCTION audit.legal_hold_drift()
RETURNS TABLE (segment bigint, object_key text, version_id text, want boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.segment, a.object_key, a.version_id, h.held
  FROM audit.archive a
  CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM audit.hold_segment s JOIN audit.hold x ON x.id = s.hold_id
                                     WHERE s.segment = a.segment AND x.released_at IS NULL) AS held) h
  WHERE a.destroyed_at IS NULL AND a.legal_hold IS DISTINCT FROM h.held
  ORDER BY a.segment;
$$;

CREATE FUNCTION audit.legal_hold_set(seg bigint, applied boolean) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE audit.archive a SET legal_hold = applied WHERE a.segment = seg;
$$;

-- Archives due for destruction: lock ended, the newest record older than
-- the total retention in force (older_than = now − total), no active hold,
-- and every active hold checked against the archives.
CREATE FUNCTION audit.destroy_candidates(older_than timestamptz, n integer)
RETURNS TABLE (segment bigint, seq_from bigint, seq_to bigint, object_key text, version_id text, record_count bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.segment, c.seq_from, c.seq_to, a.object_key, a.version_id, a.record_count
  FROM audit.archive a JOIN audit.checkpoint c ON c.segment = a.segment
  WHERE a.destroyed_at IS NULL AND a.destroy_after <= now()
    AND a.newest_at IS NOT NULL AND a.newest_at < older_than
    AND NOT EXISTS (SELECT 1 FROM audit.hold_segment s JOIN audit.hold x ON x.id = s.hold_id
                    WHERE s.segment = a.segment AND x.released_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM audit.hold x WHERE x.released_at IS NULL AND x.archives_checked_at IS NULL)
  ORDER BY a.segment
  LIMIT least(greatest(coalesce(n, 10), 1), 1000);
$$;

-- Record a destruction, re-checking every condition.
CREATE FUNCTION audit.destroy_segment(seg bigint, older_than timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM audit.destroy_candidates(older_than, 1000) d WHERE d.segment = seg) THEN
    RAISE EXCEPTION 'audit.destroy_segment: segment % is not due for destruction (lock, retention or a hold)', seg USING ERRCODE = 'PF003';
  END IF;
  UPDATE audit.archive a SET destroyed_at = now() WHERE a.segment = seg;
END $$;

-- Destroyed archives whose object is still to be deleted, and the record
-- that it is gone.
CREATE FUNCTION audit.destroy_pending() RETURNS TABLE (segment bigint, object_key text, version_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.segment, a.object_key, a.version_id FROM audit.archive a
  WHERE a.destroyed_at IS NOT NULL AND a.object_removed_at IS NULL ORDER BY a.segment;
$$;

CREATE FUNCTION audit.object_removed(seg bigint) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE audit.archive a SET object_removed_at = now() WHERE a.segment = seg AND a.destroyed_at IS NOT NULL AND a.object_removed_at IS NULL;
$$;

-- Archiving (as in 0080), now also recording the newest event time and
-- marking the segment held by every active hold its records match.
CREATE OR REPLACE FUNCTION audit.archive_segment(seg bigint, okey text, over text, d bytea, n bigint, until timestamptz) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c       audit.checkpoint;
  online  bigint;
  deleted bigint;
  newest  timestamptz;
  h       audit.hold;
  conds   text[];
  hit     boolean;
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
  SELECT count(*), max(r.event_time) INTO online, newest FROM audit.record r WHERE r.seq BETWEEN c.seq_from AND c.seq_to;
  IF n IS DISTINCT FROM c.seq_to - c.seq_from + 1 OR online <> n THEN
    RAISE EXCEPTION 'audit.archive_segment: segment % holds % records online and % in the segment; the archive has %',
      seg, online, c.seq_to - c.seq_from + 1, n USING ERRCODE = 'PF003';
  END IF;
  -- Holds cover matching records until released, later ones included.
  FOR h IN SELECT * FROM audit.hold x WHERE x.released_at IS NULL LOOP
    conds := audit.filter_conditions(h.filter);
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM audit.record r WHERE r.seq BETWEEN $4 AND $5 %s)',
      CASE WHEN cardinality(conds) = 0 THEN '' ELSE 'AND ' || array_to_string(conds, ' AND ') END)
    INTO hit USING NULL::uuid[], NULL::uuid[], h.filter, c.seq_from, c.seq_to;
    IF hit THEN
      INSERT INTO audit.hold_segment (hold_id, segment) VALUES (h.id, seg) ON CONFLICT DO NOTHING;
    END IF;
  END LOOP;
  INSERT INTO audit.archive (segment, object_key, version_id, digest, record_count, destroy_after, newest_at)
  VALUES (seg, okey, over, d, n, until, newest);
  PERFORM set_config('audit.archiving', 'on', true);
  DELETE FROM audit.record r WHERE r.seq BETWEEN c.seq_from AND c.seq_to;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  PERFORM set_config('audit.archiving', 'off', true);
  IF deleted <> n THEN
    RAISE EXCEPTION 'audit.archive_segment: % rows removed, % expected', deleted, n USING ERRCODE = 'PF003';
  END IF;
  RETURN deleted;
END $$;

REVOKE ALL ON FUNCTION audit.hold_actor(), audit.hold_mark_online(uuid), audit.hold_place(jsonb, text), audit.hold_release(uuid, text),
  audit.holds(), audit.holds_unchecked(), audit.hold_match_archived(uuid, bigint, bigint[], bytea[]), audit.hold_checked(uuid),
  audit.legal_hold_drift(), audit.legal_hold_set(bigint, boolean), audit.destroy_candidates(timestamptz, integer),
  audit.destroy_segment(bigint, timestamptz), audit.destroy_pending(), audit.object_removed(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.hold_place(jsonb, text), audit.hold_release(uuid, text),
  audit.holds(), audit.holds_unchecked(), audit.hold_match_archived(uuid, bigint, bigint[], bytea[]), audit.hold_checked(uuid),
  audit.legal_hold_drift(), audit.legal_hold_set(bigint, boolean), audit.destroy_candidates(timestamptz, integer),
  audit.destroy_segment(bigint, timestamptz), audit.destroy_pending(), audit.object_removed(bigint) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
