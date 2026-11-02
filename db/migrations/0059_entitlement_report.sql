-- F-001 T-38 (AC-48, AC-64; design §6 /entitlements/report): the
-- entitlement report and the restricted-BU access listing.
--
--   * iam.entitlement_report: one row per user and live assignment (a group's
--     assignment once per member; a service account's private role as the
--     account's scopes), with the role's permissions, the BU and whether it
--     is restricted, how it was granted (manual, a group, a group mapping,
--     a service account), by whom and when, the expiry, the user's last
--     sign-in and status, and whether the user is a break-glass account.
--     Rows are limited to BUs where the signed-context caller holds
--     entitlement.view (restricted subtrees only by an explicit assignment,
--     AC-64), and for a file export also entitlement.export.
--   * iam.restricted_bu_access: every restricted BU the caller may see (an
--     explicit entitlement.view inside it, or bu.restrict at its parent, as
--     T-30's BU list), and everyone with access to it, from the materialized
--     scopes: read, write or aggregate-only roll-up, per resource type. The
--     number of restricted BUs the caller does not see is given, not their
--     names.
--   * iam.entitlement_export_audit: a file export is audited high
--     (entitlement.exported), with its filters and row counts.

CREATE FUNCTION iam.entitlement_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'entitlement reports need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION iam.entitlement_report(for_export boolean, only_user uuid, only_role uuid, under_bu uuid, only_source text,
  restricted_only boolean, expiring_before timestamptz, include_inactive boolean)
RETURNS TABLE (user_id uuid, email text, display_name text, user_kind text, user_status text, last_login_at timestamptz,
               breakglass boolean, role_id uuid, role_name text, role_builtin boolean, permissions text[], bu_id uuid, bu_code text,
               bu_name text, bu_restricted boolean, source text, via_group text, granted_by uuid, granted_by_email text,
               granted_at timestamptz, expires_at timestamptz, assignment_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.entitlement_actor();
BEGIN
  IF only_source IS NOT NULL AND only_source NOT IN ('manual', 'group', 'mapped', 'service_account', 'breakglass') THEN
    RAISE EXCEPTION 'source is manual, group, mapped, service_account or breakglass' USING ERRCODE = 'PF004';
  END IF;
  RETURN QUERY
  WITH visible AS (
    SELECT b.id FROM iam.bu b
    WHERE iam.user_has_permission(actor, 'entitlement.view', b.id)
      AND (NOT for_export OR iam.user_has_permission(actor, 'entitlement.export', b.id))
      AND (under_bu IS NULL OR EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = under_bu AND c.descendant_id = b.id))
  ), held AS (
    SELECT a.*, a.principal_id AS member, NULL::text AS grp
    FROM iam.assignment a WHERE a.principal_kind = 'user'
    UNION ALL
    SELECT a.*, m.user_id, g.display_name
    FROM iam.assignment a JOIN iam.grp_member m ON m.grp_id = a.principal_id JOIN iam.grp g ON g.id = a.principal_id
    WHERE a.principal_kind = 'group'
  )
  SELECT u.id, u.email, u.display_name,
    CASE u.source::text WHEN 'service' THEN 'service_account' WHEN 'breakglass' THEN 'breakglass' ELSE 'user' END,
    u.status::text, u.last_login_at, u.source::text = 'breakglass',
    r.id, CASE WHEN r.service_account_id IS NOT NULL THEN 'service account scopes' ELSE r.name END, r.builtin, v.permissions,
    b.id, b.code, b.name, b.restricted,
    CASE WHEN h.source::text = 'service' THEN 'service_account' WHEN h.source::text = 'mapped' THEN 'mapped'
         WHEN u.source::text = 'breakglass' THEN 'breakglass' WHEN h.grp IS NOT NULL THEN 'group' ELSE 'manual' END,
    coalesce(h.grp, (SELECT g.display_name FROM iam.group_role_mapping gm JOIN iam.grp g ON g.id = gm.grp_id WHERE gm.id = h.mapping_id)),
    h.granted_by, (SELECT gb.email FROM iam.app_user gb WHERE gb.id = h.granted_by), h.granted_at, h.expires_at, h.id
  FROM held h
  JOIN visible vb ON vb.id = h.bu_id
  JOIN iam.app_user u ON u.id = h.member
  JOIN iam.role r ON r.id = h.role_id
  JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  JOIN iam.bu b ON b.id = h.bu_id
  WHERE h.revoked_at IS NULL AND (h.expires_at IS NULL OR h.expires_at > now())
    AND (include_inactive OR u.status = 'active')
    AND (only_user IS NULL OR u.id = only_user)
    AND (only_role IS NULL OR r.id = only_role)
    AND (NOT restricted_only OR b.restricted)
    AND (expiring_before IS NULL OR h.expires_at < expiring_before)
    AND (only_source IS NULL OR only_source =
         CASE WHEN h.source::text = 'service' THEN 'service_account' WHEN h.source::text = 'mapped' THEN 'mapped'
              WHEN u.source::text = 'breakglass' THEN 'breakglass' WHEN h.grp IS NOT NULL THEN 'group' ELSE 'manual' END)
  ORDER BY lower(u.email), b.code, lower(r.name), h.id;
END $$;

-- The restricted BUs the caller may see, everyone with access to each, and
-- how many restricted BUs are not shown (hidden_count, the same on every row;
-- one row with NULL BU when none is shown).
CREATE FUNCTION iam.restricted_bu_access()
RETURNS TABLE (bu_id uuid, bu_code text, bu_name text, parent_code text, rollup_mode text, archived boolean, user_id uuid,
               email text, display_name text, user_kind text, access text, resource_types text[], hidden_count integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.entitlement_actor();
BEGIN
  RETURN QUERY
  WITH seen AS (
    SELECT b.id FROM iam.bu b
    WHERE b.restricted
      AND (iam.user_has_permission(actor, 'entitlement.view', b.id)
           OR (b.parent_id IS NOT NULL AND iam.user_has_permission(actor, 'bu.restrict', b.parent_id)))
  ), hidden AS (
    SELECT count(*)::integer AS n FROM iam.bu b WHERE b.restricted AND b.id NOT IN (SELECT s.id FROM seen s)
  ), acc AS (
    SELECT us.user_id AS uid, x.bu, x.kind, x.rtype
    FROM authz.user_scope us,
    LATERAL (
      SELECT (jsonb_array_elements_text(e.value))::uuid AS bu, 'write'::text AS kind, e.key AS rtype FROM jsonb_each(us.write_bus) e
      UNION ALL
      SELECT (jsonb_array_elements_text(e.value))::uuid, 'read', e.key FROM jsonb_each(us.read_bus) e
      UNION ALL
      SELECT (jsonb_array_elements_text(e.value))::uuid, 'aggregate', e.key FROM jsonb_each(us.rollup_aggregate_bus) e
    ) x
    WHERE x.bu IN (SELECT s.id FROM seen s)
  ), best AS (  -- per user and BU: the strongest access, and the resource types granting any
    SELECT a.uid, a.bu,
      CASE WHEN bool_or(a.kind = 'write') THEN 'write' WHEN bool_or(a.kind = 'read') THEN 'read' ELSE 'aggregate' END AS kind,
      array_agg(DISTINCT a.rtype ORDER BY a.rtype) AS rtypes
    FROM acc a GROUP BY a.uid, a.bu
  )
  SELECT b.id, b.code, b.name, p.code, b.rollup_mode::text, b.archived_at IS NOT NULL, u.id, u.email, u.display_name,
    CASE WHEN u.id IS NULL THEN NULL WHEN u.source::text = 'service' THEN 'service_account' WHEN u.source::text = 'breakglass' THEN 'breakglass'
         ELSE 'user' END,
    x.kind, x.rtypes, (SELECT h.n FROM hidden h)
  FROM seen s
  JOIN iam.bu b ON b.id = s.id
  LEFT JOIN iam.bu p ON p.id = b.parent_id
  LEFT JOIN best x ON x.bu = b.id
  LEFT JOIN iam.app_user u ON u.id = x.uid
  UNION ALL
  SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, (SELECT h.n FROM hidden h)
  WHERE NOT EXISTS (SELECT 1 FROM seen)
  ORDER BY 2 NULLS FIRST, 8 NULLS FIRST;
END $$;

-- A file export of the report or the listing (audited high).
CREATE FUNCTION iam.entitlement_export_audit(report text, fmt text, filters jsonb, row_count integer) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.entitlement_actor();
BEGIN
  IF report NOT IN ('entitlements', 'restricted_bus') OR fmt NOT IN ('csv', 'pdf') THEN
    RAISE EXCEPTION 'unknown report or format' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE iam.user_has_permission(actor, 'entitlement.export', b.id)) THEN
    RAISE EXCEPTION 'entitlement.export is required' USING ERRCODE = 'PF008';
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'entitlement.exported', 'severity', 'high', 'actor', actor::text,
    'target', 'report:' || report, 'attributes', jsonb_build_object('format', fmt, 'filters', coalesce(filters, '{}'), 'rows', row_count)));
END $$;

REVOKE ALL ON FUNCTION iam.entitlement_actor(), iam.entitlement_report(boolean, uuid, uuid, uuid, text, boolean, timestamptz, boolean),
  iam.restricted_bu_access(), iam.entitlement_export_audit(text, text, jsonb, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.entitlement_report(boolean, uuid, uuid, uuid, text, boolean, timestamptz, boolean),
  iam.restricted_bu_access(), iam.entitlement_export_audit(text, text, jsonb, integer) TO app_rw;
