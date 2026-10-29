-- F-001 T-22 (AC-10; design §5.3): deactivation propagation.
--
-- When a user stops being active (SCIM deactivation or deletion, and any
-- later path: an administrator, the inactivity sweep, a lockout), in the
-- same transaction:
--   * every live session is revoked (user_disabled), each audited and
--     announced on iam.session.revoked;
--   * the user's authz.user_scope row is deleted, so DB context tokens
--     already minted for the user see no BU at once, and iam.scope.changed
--     (revoked) tells services to drop their cached grants;
--   * iam.user.deactivated is announced.
-- The gateway reads sessions per request, so the next request is refused;
-- no token outlives that (internal JWTs are minted per request). The
-- scope worker's own recompute, queued by the status change, agrees.

CREATE FUNCTION iam.user_deactivated() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s iam.session;
  n integer := 0;
BEGIN
  FOR s IN UPDATE iam.session x SET revoked_at = now(), revoked_reason = 'user_disabled'
           WHERE x.user_id = NEW.id AND x.revoked_at IS NULL RETURNING * LOOP
    PERFORM iam.session_event('session.revoked', 'high', 'system:iam', s, 'user_disabled');
    n := n + 1;
  END LOOP;
  -- As the scope worker does when it removes a row: services evict the
  -- user's cached grants on iam.scope.changed (revoked).
  DELETE FROM authz.user_scope us WHERE us.user_id = NEW.id;
  IF FOUND THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('iam.scope.changed', jsonb_build_object('user_id', NEW.id, 'scope_version', -1, 'revoked', true));
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('iam.user.deactivated', jsonb_build_object('user_id', NEW.id, 'status', NEW.status, 'reason', NEW.disabled_reason,
                                                     'sessions_revoked', n));
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION iam.user_deactivated() FROM PUBLIC;

CREATE TRIGGER app_user_deactivated AFTER UPDATE OF status ON iam.app_user
  FOR EACH ROW WHEN (OLD.status = 'active' AND NEW.status <> 'active') EXECUTE FUNCTION iam.user_deactivated();
