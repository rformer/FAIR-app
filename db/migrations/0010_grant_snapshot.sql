-- F-001 T-12 (AC-24, NFR; design §2 "authz library", §5.2): the effective
-- grant snapshot behind authz.Check().
--
-- authz.grant_snapshot() returns, for the user named by the signed database
-- context only, every permission they hold and the BUs it applies to, under
-- the §3 effective-access rule (live assignments, direct or via a group;
-- active role, current version; paths not blocked by a restricted BU). It
-- returns nothing for an invalid or stale context, so a service can neither
-- read another user's grants nor act on an outdated token. The library caches
-- the result per (user, scope_version).

-- grant_snapshot is owned by fair_owner (it reads iam tables) and verifies
-- the context through authz.ctx_scope, which authz_definer owns.
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

CREATE FUNCTION authz.grant_snapshot()
RETURNS TABLE (scope_version bigint, permission text, bus uuid[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH s AS (
    SELECT c.user_id, c.scope_version FROM authz.ctx_scope() c WHERE c.user_id IS NOT NULL
  ), held AS (
    SELECT a.role_id, a.bu_id
    FROM s JOIN iam.assignment a ON a.principal_kind = 'user' AND a.principal_id = s.user_id
    WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
    UNION ALL
    SELECT a.role_id, a.bu_id
    FROM s
    JOIN iam.grp_member m ON m.user_id = s.user_id
    JOIN iam.assignment a ON a.principal_kind = 'group' AND a.principal_id = m.grp_id
    WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
  )
  SELECT s.scope_version, p, array_agg(DISTINCT c.descendant_id ORDER BY c.descendant_id)
  FROM s
  JOIN iam.app_user au ON au.id = s.user_id AND au.status = 'active'
  CROSS JOIN held h
  JOIN iam.role r ON r.id = h.role_id AND r.status = 'active'
  JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  CROSS JOIN LATERAL unnest(v.permissions) p
  JOIN iam.bu_closure c ON c.ancestor_id = h.bu_id AND NOT c.blocked
  GROUP BY s.scope_version, p;
$$;

GRANT EXECUTE ON FUNCTION authz.grant_snapshot() TO app_rw, app_engine;
