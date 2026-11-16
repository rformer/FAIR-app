-- F-009 T-01b (F-009-AC-10; design §4, amended 2026-11-16): F-015's
-- reserved set type, for notification.allowed_hosts.
--   * A set value is a JSON array of strings, sorted (byte order) and
--     without repeats, at most 64 elements, each 1 to 255 bytes without
--     control characters; "*" stands for every element and appears alone
--     (pkg/settings ValidSet; the property test keeps Go and SQL equal).
--   * subset_is_stricter: a proper subset is stricter; a set that adds any
--     element is weaker, so every added element is a loosening (with
--     loosening_needs_approval, dual approval). The universal set {"*"}
--     includes every set, so it serves as a bound meaning "any".
--   * Sets are never BU-scopable: inclusion is a partial order, and the
--     strictest of several would be none of them.

ALTER TABLE posture.setting_def ADD CONSTRAINT setting_def_set_not_bu CHECK (type <> 'set' OR NOT bu_scopable);

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

CREATE OR REPLACE FUNCTION posture.check_value(k text, v jsonb) RETURNS posture.setting_def
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d   posture.setting_def;
  bad boolean;
  max_int constant numeric := 9223372036854775807; -- int64, as in Go
BEGIN
  SELECT * INTO d FROM posture.setting_def WHERE key = k;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown setting %', k USING ERRCODE = 'PF004';
  END IF;
  -- Nested CASEs, not OR: SQL does not guarantee short-circuit evaluation,
  -- and a cast of the wrong JSON type must not error before the type test.
  bad := v IS NULL OR CASE
       WHEN d.type = 'duration' THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true
                                          ELSE posture.duration_ns(v #>> '{}') NOT BETWEEN 0 AND max_int END
       WHEN d.type = 'int'      THEN CASE WHEN jsonb_typeof(v) <> 'number' THEN true
                                          ELSE (v #>> '{}')::numeric <> trunc((v #>> '{}')::numeric)
                                            OR (v #>> '{}')::numeric NOT BETWEEN 0 AND max_int END
       WHEN d.type = 'bool'     THEN jsonb_typeof(v) <> 'boolean'
       WHEN d.type = 'enum'     THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true ELSE NOT (v #>> '{}') = ANY (d.enum_order) END
       WHEN d.type = 'string'   THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true
                                          ELSE octet_length(v #>> '{}') > 255 OR (v #>> '{}') ~ '[[:cntrl:]]' END
       WHEN d.type = 'set'      THEN CASE WHEN jsonb_typeof(v) <> 'array' THEN true
                                          WHEN jsonb_array_length(v) > 64 THEN true
                                          WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(v) e WHERE jsonb_typeof(e) <> 'string') THEN true
                                          ELSE EXISTS (SELECT 1 FROM jsonb_array_elements_text(v) e
                                                       WHERE e = '' OR octet_length(e) > 255 OR e ~ '[[:cntrl:]]')
                                            OR (v @> '["*"]' AND jsonb_array_length(v) > 1)
                                            OR v <> (SELECT coalesce(jsonb_agg(e ORDER BY e COLLATE "C"), '[]'::jsonb)
                                                     FROM (SELECT DISTINCT jsonb_array_elements_text(v) AS e) x) END
       ELSE true
     END;
  IF bad THEN
    RAISE EXCEPTION 'invalid value % for % (%)', v, k, d.type USING ERRCODE = 'PF004';
  END IF;
  RETURN d;
END $$;

-- -1: a is weaker than b; 0: as strict; 1: stricter. Sets by inclusion
-- (pkg/settings compareSets): a proper subset of b, or any set when b is
-- universal, is stricter; anything else that differs is weaker.
CREATE OR REPLACE FUNCTION posture.compare(d posture.setting_def, a jsonb, b jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN d.type = 'set' THEN
           CASE WHEN a = b THEN 0 WHEN b = '["*"]'::jsonb OR b @> a THEN 1 ELSE -1 END
         ELSE sign(posture.rank(d, a) - posture.rank(d, b))::integer END;
$$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
