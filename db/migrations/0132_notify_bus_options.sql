-- F-009 T-13 (design §6): the business units a webhook may take notices of,
-- for the channels page: every active BU's id, name, code, parent and
-- whether it is restricted, to holders of notification.manage or view at
-- the root (who administer installation-wide channels; names only).

GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;
CREATE FUNCTION notify.bus() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM notify.require('notification.view');
  RETURN coalesce((SELECT jsonb_agg(jsonb_build_object('id', b.id, 'name', b.name, 'code', b.code, 'parent_id', b.parent_id,
      'restricted', iam.restricted_root(b.id) IS NOT NULL) ORDER BY b.depth, b.name)
    FROM iam.bu b WHERE b.archived_at IS NULL), '[]');
END $$;
REVOKE ALL ON FUNCTION notify.bus() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notify.bus() TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;
