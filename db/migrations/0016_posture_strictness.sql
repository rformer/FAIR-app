-- F-015 T-13 (design §3, AC-35): strictness parity with pkg/settings and
-- strictest-of.
--
-- The database and the Go library must agree on which values are valid and
-- which is stricter (a property test compares them on random values). Go
-- rejects negative ints and anything beyond int64 (time.Duration is int64
-- nanoseconds); check_value now does too. The set type stays refused until a
-- setting needs it (decision of 2026-10-26).
--
-- posture_definer owns these functions, so it replaces and creates them.

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
  -- (Assigned first: an IF condition ends at the first THEN.)
  bad := v IS NULL OR CASE
       WHEN d.type = 'duration' THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true
                                          ELSE posture.duration_ns(v #>> '{}') NOT BETWEEN 0 AND max_int END
       WHEN d.type = 'int'      THEN CASE WHEN jsonb_typeof(v) <> 'number' THEN true
                                          ELSE (v #>> '{}')::numeric <> trunc((v #>> '{}')::numeric)
                                            OR (v #>> '{}')::numeric NOT BETWEEN 0 AND max_int END
       WHEN d.type = 'bool'     THEN jsonb_typeof(v) <> 'boolean'
       WHEN d.type = 'enum'     THEN CASE WHEN jsonb_typeof(v) <> 'string' THEN true ELSE NOT (v #>> '{}') = ANY (d.enum_order) END
       ELSE true -- 'set': not supported until a setting needs it
     END;
  IF bad THEN
    RAISE EXCEPTION 'invalid value % for % (%)', v, k, d.type USING ERRCODE = 'PF004';
  END IF;
  RETURN d;
END $$;

-- The strictest of vals (AC-35), which must be valid for d; NULL when there
-- are none. Ties keep the first. T-22 resolves BU inheritance with it.
CREATE FUNCTION posture.strictest(d posture.setting_def, vals jsonb[]) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  best jsonb;
  v    jsonb;
BEGIN
  FOREACH v IN ARRAY coalesce(vals, '{}') LOOP
    IF best IS NULL OR posture.compare(d, v, best) > 0 THEN
      best := v;
    END IF;
  END LOOP;
  RETURN best;
END $$;
REVOKE ALL ON FUNCTION posture.strictest(posture.setting_def, jsonb[]) FROM PUBLIC;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
