-- F-011 T-18 (F-011-AC-01, AC-02; design §6.1): what the integration form
-- offers (GET /api/v1/integrations/options, the integrate service).
--
--   * integration.options(): the business units where the caller holds
--     integration.manage (iam.holds_permission, so grants above a
--     restricted business unit do not reach it), not archived, by name; and
--     the active service accounts a connector there may push as: at one of
--     those business units or above it on an unblocked path (as
--     integration.check_connector requires), by name.


GRANT CREATE ON SCHEMA integration TO integration_definer;
SET ROLE integration_definer;

CREATE FUNCTION integration.options() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := integration.actor(); bus uuid[];
BEGIN
  SELECT coalesce(array_agg(b.id), '{}') INTO bus FROM iam.bu b
  WHERE b.archived_at IS NULL AND iam.holds_permission(u, 'integration.manage', b.id);
  RETURN jsonb_build_object(
    'bus', coalesce((SELECT jsonb_agg(jsonb_build_object('id', b.id, 'code', b.code, 'name', b.name) ORDER BY lower(b.name), b.id)
                     FROM iam.bu b WHERE b.id = ANY (bus)), '[]'),
    'service_accounts', coalesce((SELECT jsonb_agg(jsonb_build_object('id', s.id, 'name', s.name, 'bu_id', s.bu_id,
                                    'bu_name', (SELECT x.name FROM iam.bu x WHERE x.id = s.bu_id)) ORDER BY lower(s.name), s.id)
                                  FROM iam.service_account s JOIN iam.app_user a ON a.id = s.id AND a.status = 'active'
                                  WHERE EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = s.bu_id AND c.descendant_id = ANY (bus) AND NOT c.blocked)),
                                 '[]'));
END $$;

REVOKE ALL ON FUNCTION integration.options() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integration.options() TO app_integrate;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA integration FROM integration_definer;
