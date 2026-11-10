-- F-004 T-13 (F-004-AC-01; design §5, change of 2026-11-10): the people an
-- analyst may name as estimators at a BU.
--
-- A holder of estimate.request and scenario.edit at a BU sees the id and
-- display name of each active person (not a service account) who holds
-- estimate.submit there: the names a request form offers. Nothing else
-- about them, and no calibration (that stays behind calibration_of and its
-- calibration.record_viewed event). Anyone else is told the BU does not
-- exist (P0002, 404).

-- The active people holding perm at bu (set-wise iam.user_has_permission,
-- without crossing restricted boundaries), at most lim of them by name.
CREATE FUNCTION iam.permission_holders(perm text, bu uuid, lim integer)
RETURNS TABLE (id uuid, display_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH g AS (
    SELECT a.principal_kind, a.principal_id
    FROM iam.assignment a
    JOIN iam.role r ON r.id = a.role_id AND r.status = 'active'
    JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
    JOIN iam.bu_closure c ON c.ancestor_id = a.bu_id AND c.descendant_id = bu
    WHERE a.revoked_at IS NULL
      AND (a.expires_at IS NULL OR a.expires_at > now())
      AND perm = ANY (v.permissions)
      AND NOT c.blocked
  )
  SELECT u.id, coalesce(nullif(btrim(u.display_name), ''), u.email) AS display_name
  FROM iam.app_user u
  WHERE u.status = 'active' AND u.source::text <> 'service'
    AND (u.id IN (SELECT g.principal_id FROM g WHERE g.principal_kind = 'user')
      OR u.id IN (SELECT m.user_id FROM iam.grp_member m JOIN g ON g.principal_kind = 'group' AND g.principal_id = m.grp_id))
  ORDER BY 2, 1
  LIMIT lim;
$$;
REVOKE ALL ON FUNCTION iam.permission_holders(text, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.permission_holders(text, uuid, integer) TO estimate_definer;

GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;

-- The people the caller may name as estimators at bu, by name (at most 500).
CREATE FUNCTION estimate.estimators(bu uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.actor();
BEGIN
  IF bu IS NULL OR NOT iam.holds_permission(u, 'estimate.request', bu) OR NOT iam.holds_permission(u, 'scenario.edit', bu) THEN
    RAISE EXCEPTION 'estimate: no such business unit %', bu USING ERRCODE = 'P0002';
  END IF;
  RETURN coalesce((SELECT jsonb_agg(jsonb_build_object('user_id', h.id, 'name', h.display_name) ORDER BY h.display_name, h.id)
                   FROM iam.permission_holders('estimate.submit', bu, 500) h), '[]');
END $$;
REVOKE ALL ON FUNCTION estimate.estimators(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.estimators(uuid) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;
