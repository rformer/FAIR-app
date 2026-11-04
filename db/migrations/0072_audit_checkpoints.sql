-- F-002 T-09 (F-002-AC-09, AC-10; design §4.2, §6.3; ADR-011): checkpoints.
--
-- The leader closes the open segment every 15 minutes and whenever an
-- export needs it, empty segments included: it builds the checkpoint
-- statement (ADR-011), signs it with the checkpoint key (which never enters
-- the database) and hands both to audit.checkpoint_close. That function
-- checks the statement against the trail itself, since it cannot check the
-- signature (the verifier does, T-10/T-11): the instance, the segment open
-- in the head, the record range, the chain hash at its end, the Merkle root
-- of its leaves (recomputed here), the link to the previous checkpoint, a
-- registered and unretired key, and a current issue time. It then records
-- the checkpoint and opens the next segment. Public keys are registered by
-- the service at startup (audit.signing_key_register); a new key retires the
-- previous one, and retired keys stay for verifying older checkpoints.
-- audit.checkpoint_set_worm records the write-once copy's object key, once.
-- New SQLSTATE: PF014, a checkpoint that does not match the trail.

-- RFC 9162 Merkle tree hash over leaf hashes, level by level (an unpaired
-- last node is carried up): the same root as internal/audit/integrity.Root.
CREATE FUNCTION audit.merkle_root(leaves bytea[]) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  level bytea[] := coalesce(leaves, '{}');
  n     integer := cardinality(coalesce(leaves, '{}'));
BEGIN
  IF n = 0 THEN
    RETURN sha256(''::bytea);
  END IF;
  -- Each level in one pass (appending element by element would be
  -- quadratic for a busy segment).
  WHILE n > 1 LOOP
    level := (SELECT array_agg(CASE WHEN i < n THEN sha256('\x01'::bytea || level[i] || level[i + 1]) ELSE level[i] END ORDER BY i)
              FROM generate_series(1, n, 2) AS i);
    n := cardinality(level);
  END LOOP;
  RETURN level[1];
END $$;

CREATE FUNCTION audit.signing_key_register(kid text, pem text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  k audit.signing_key;
BEGIN
  IF kid IS NULL OR kid !~ '^[0-9a-f]{64}$' OR pem IS NULL OR pem NOT LIKE '-----BEGIN PUBLIC KEY-----%' THEN
    RAISE EXCEPTION 'audit.signing_key_register: a key id (hex SHA-256) and a PEM public key are required' USING ERRCODE = 'PF004';
  END IF;
  -- The key id is the SHA-256 of the key's PKIX encoding.
  IF encode(sha256(decode(regexp_replace(regexp_replace(pem, '-----[A-Z ]+-----', '', 'g'), '\s', '', 'g'), 'base64')), 'hex') <> kid THEN
    RAISE EXCEPTION 'audit.signing_key_register: the key id is not the SHA-256 of the public key' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO k FROM audit.signing_key s WHERE s.key_id = kid;
  IF FOUND THEN
    IF k.retired_at IS NOT NULL THEN
      RAISE EXCEPTION 'audit.signing_key_register: key % was retired; a retired key never signs again', kid USING ERRCODE = 'PF004';
    END IF;
    RETURN false;
  END IF;
  UPDATE audit.signing_key s SET retired_at = now() WHERE s.retired_at IS NULL;
  INSERT INTO audit.signing_key (key_id, public_pem) VALUES (kid, pem);
  RETURN true;
END $$;

CREATE FUNCTION audit.checkpoint_state(OUT instance text, OUT segment bigint, OUT seq_from bigint, OUT seq_to bigint,
  OUT chain_hash bytea, OUT prev_checkpoint_hash bytea, OUT leaves bytea[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h    audit.head;
  last audit.checkpoint;
BEGIN
  PERFORM audit.sequence_head(); -- creates the head on first use
  SELECT * INTO h FROM audit.head FOR UPDATE;
  SELECT * INTO last FROM audit.checkpoint c ORDER BY c.segment DESC LIMIT 1;
  instance := h.instance;
  segment := h.open_segment;
  seq_from := coalesce(last.seq_to, 0) + 1;
  seq_to := h.seq;
  chain_hash := h.chain_hash;
  prev_checkpoint_hash := CASE WHEN last.segment IS NULL THEN sha256(convert_to('fair-audit-v1' || h.instance, 'UTF8'))
                               ELSE sha256(last.statement) END;
  leaves := ARRAY(SELECT r.leaf_hash FROM audit.record r WHERE r.segment = h.open_segment ORDER BY r.seq);
END $$;

CREATE FUNCTION audit.checkpoint_close(stmt bytea, sig bytea) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  st    record;
  j     jsonb;
  k     audit.signing_key;
  n     bigint;
BEGIN
  SELECT * INTO st FROM audit.checkpoint_state();
  BEGIN
    j := convert_from(stmt, 'UTF8')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'audit.checkpoint_close: the statement is not JSON' USING ERRCODE = 'PF014';
  END;
  SELECT count(*) INTO n FROM audit.record r WHERE r.segment = st.segment;
  SELECT * INTO k FROM audit.signing_key s WHERE s.key_id = j->>'key_id';
  -- IS DISTINCT FROM throughout: a missing field fails, never passes as NULL.
  IF jsonb_typeof(j) IS DISTINCT FROM 'object'
     OR (j->>'v') IS DISTINCT FROM '1'
     OR (j->>'instance') IS DISTINCT FROM st.instance
     OR (j->>'segment') IS DISTINCT FROM st.segment::text
     OR (j->>'seq_from') IS DISTINCT FROM st.seq_from::text
     OR (j->>'seq_to') IS DISTINCT FROM st.seq_to::text
     OR n IS DISTINCT FROM st.seq_to - st.seq_from + 1
     OR (j->>'chain_hash') IS DISTINCT FROM encode(st.chain_hash, 'hex')
     OR (j->>'prev_checkpoint_hash') IS DISTINCT FROM encode(st.prev_checkpoint_hash, 'hex')
     OR (j->>'merkle_root') IS DISTINCT FROM encode(audit.merkle_root(st.leaves), 'hex') THEN
    RAISE EXCEPTION 'audit.checkpoint_close: the statement does not match segment % of the trail', st.segment USING ERRCODE = 'PF014';
  END IF;
  IF k.key_id IS NULL OR k.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'audit.checkpoint_close: key % is not a registered, active checkpoint key', j->>'key_id' USING ERRCODE = 'PF014';
  END IF;
  IF NOT pg_input_is_valid(coalesce(j->>'issued_at', ''), 'timestamptz')
     OR abs(extract(epoch FROM (j->>'issued_at')::timestamptz - clock_timestamp())) > 60 THEN
    RAISE EXCEPTION 'audit.checkpoint_close: the statement''s issue time is not now' USING ERRCODE = 'PF014';
  END IF;
  IF sig IS NULL OR length(sig) < 8 THEN
    RAISE EXCEPTION 'audit.checkpoint_close: a signature is required' USING ERRCODE = 'PF014';
  END IF;
  INSERT INTO audit.checkpoint (segment, seq_from, seq_to, merkle_root, chain_hash, prev_checkpoint_hash, issued_at, key_id, statement, signature)
  VALUES (st.segment, st.seq_from, st.seq_to, audit.merkle_root(st.leaves), st.chain_hash, st.prev_checkpoint_hash,
          (j->>'issued_at')::timestamptz, k.key_id, stmt, sig);
  UPDATE audit.head SET open_segment = st.segment + 1, segment_opened_at = clock_timestamp();
  RETURN st.segment;
END $$;

-- Checkpoints whose write-once copy is not recorded yet, oldest first.
CREATE FUNCTION audit.checkpoint_unsaved(n integer)
RETURNS TABLE (segment bigint, statement bytea, signature bytea, instance text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.segment, c.statement, c.signature, h.instance FROM audit.checkpoint c, audit.head h
  WHERE c.worm_key IS NULL ORDER BY c.segment LIMIT n;
$$;

CREATE FUNCTION audit.checkpoint_set_worm(seg bigint, object_key text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF btrim(coalesce(object_key, '')) = '' THEN
    RAISE EXCEPTION 'audit.checkpoint_set_worm: an object key is required' USING ERRCODE = 'PF004';
  END IF;
  UPDATE audit.checkpoint c SET worm_key = object_key WHERE c.segment = seg AND c.worm_key IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit.checkpoint_set_worm: checkpoint % has no unsaved copy', seg USING ERRCODE = 'PF003';
  END IF;
END $$;

REVOKE ALL ON FUNCTION audit.merkle_root(bytea[]), audit.signing_key_register(text, text), audit.checkpoint_state(),
  audit.checkpoint_close(bytea, bytea), audit.checkpoint_unsaved(integer), audit.checkpoint_set_worm(bigint, text) FROM PUBLIC;
ALTER FUNCTION audit.merkle_root(bytea[]) OWNER TO audit_definer;
ALTER FUNCTION audit.signing_key_register(text, text) OWNER TO audit_definer;
ALTER FUNCTION audit.checkpoint_state() OWNER TO audit_definer;
ALTER FUNCTION audit.checkpoint_close(bytea, bytea) OWNER TO audit_definer;
ALTER FUNCTION audit.checkpoint_unsaved(integer) OWNER TO audit_definer;
ALTER FUNCTION audit.checkpoint_set_worm(bigint, text) OWNER TO audit_definer;
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.signing_key_register(text, text), audit.checkpoint_state(), audit.checkpoint_close(bytea, bytea),
  audit.checkpoint_unsaved(integer), audit.checkpoint_set_worm(bigint, text) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
