-- F-003 T-04 (F-003-AC-07; design §3.4): the installation currency.
--
-- `risk currency set CODE` (cmd/risk, as app_migrator acting as fair_owner)
-- records the ISO 4217 code in risk.instance. It can change only while no
-- stored version holds a magnitude: afterwards every amount would silently
-- change meaning, so the change is refused (PF019). The check reads every
-- BU's versions, which RLS hides from every role but bu_guard_definer (the
-- archive guard's role, which sees every row of BU-owned tables and only
-- ever returns counts); risk.has_magnitudes, owned by it, returns only
-- whether one exists.

GRANT USAGE ON SCHEMA risk TO bu_guard_definer;
GRANT CREATE ON SCHEMA risk TO bu_guard_definer;
SET ROLE bu_guard_definer;
CREATE FUNCTION risk.has_magnitudes() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM risk.scenario_version v WHERE position('"unit":"currency"' IN convert_from(v.document, 'UTF8')) > 0)
      OR EXISTS (SELECT 1 FROM risk.library_version v WHERE position('"unit":"currency"' IN convert_from(v.document, 'UTF8')) > 0);
$$;
REVOKE ALL ON FUNCTION risk.has_magnitudes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.has_magnitudes() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM bu_guard_definer;

-- Sets the currency and returns the previous code ('' if none). Refuses a
-- code that is not three capital letters, and any change once a magnitude
-- is stored. Setting the same code again changes nothing.
CREATE FUNCTION risk.set_currency(code text, operator text) RETURNS text
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE prev text;
BEGIN
  IF code IS NULL OR code !~ '^[A-Z]{3}$' THEN
    RAISE EXCEPTION 'risk: % is not an ISO 4217 currency code (three capital letters)', code USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF operator IS NULL OR char_length(btrim(operator)) NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'risk: the operator is required' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT i.currency INTO prev FROM risk.instance i FOR UPDATE;
  IF prev = code THEN
    RETURN prev;
  END IF;
  IF prev IS NOT NULL AND risk.has_magnitudes() THEN
    RAISE EXCEPTION 'risk: the currency is %; it cannot change once amounts are stored in it', prev USING ERRCODE = 'PF019';
  END IF;
  INSERT INTO risk.instance (currency, set_at, set_by) VALUES (code, now(), btrim(operator))
  ON CONFLICT (singleton) DO UPDATE SET currency = EXCLUDED.currency, set_at = EXCLUDED.set_at, set_by = EXCLUDED.set_by;
  RETURN coalesce(prev, '');
END $$;
REVOKE ALL ON FUNCTION risk.set_currency(text, text) FROM PUBLIC;
