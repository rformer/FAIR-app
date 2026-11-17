-- F-010 T-09b (F-010-AC-22; F-001 AC-36 as amended 2026-11-17): service
-- accounts for BI tools.
--
--   * iam.sa_privileged_scopes(): the privileged permissions a service
--     account may hold as a scope: report.export alone. Every other
--     privileged or admin permission stays refused (PF004), as before.
--   * iam.sa_check_scopes accepts them; iam.sa_unheld always counts them as
--     unheld, so adding one goes through a service_account.scopes approval
--     (T-26: another holder of service_account.manage at the BU decides),
--     never at once, even for an actor who holds the permission. Removing
--     one applies at once. The approval and the change are audited high
--     (service_account.created, service_account.scopes_changed) as before.

CREATE FUNCTION iam.sa_privileged_scopes() RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY['report.export'];
$$;
REVOKE ALL ON FUNCTION iam.sa_privileged_scopes() FROM PUBLIC;

-- A scope list: live catalog permissions, not privileged or admin unless
-- listed by iam.sa_privileged_scopes() (AC-36 as amended), sorted and
-- distinct.
CREATE OR REPLACE FUNCTION iam.sa_check_scopes(scopes text[]) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  bad text;
BEGIN
  IF scopes IS NULL OR cardinality(scopes) = 0 OR array_position(scopes, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'a service account needs at least one scope' USING ERRCODE = 'PF004';
  END IF;
  SELECT s INTO bad FROM unnest(scopes) s WHERE NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.key = s AND p.retired_at IS NULL) LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'unknown or retired permission %', bad USING ERRCODE = 'PF004';
  END IF;
  SELECT s INTO bad FROM unnest(scopes) s JOIN iam.permission p ON p.key = s
  WHERE (p.privileged OR p.action = 'admin') AND s <> ALL (iam.sa_privileged_scopes()) ORDER BY s LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'service accounts may not hold privileged permission % (AC-36)', bad USING ERRCODE = 'PF004';
  END IF;
  RETURN ARRAY(SELECT DISTINCT s COLLATE "C" FROM unnest(scopes) s ORDER BY 1);
END $$;

-- The scopes in perms that need an approval: those actor does not hold at
-- bu, and every privileged scope (always dual control).
CREATE OR REPLACE FUNCTION iam.sa_unheld(actor uuid, bu uuid, perms text[]) RETURNS text[]
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY(SELECT s FROM unnest(perms) s
               WHERE s = ANY (iam.sa_privileged_scopes()) OR NOT iam.user_has_permission(actor, s, bu)
               ORDER BY s COLLATE "C");
$$;
