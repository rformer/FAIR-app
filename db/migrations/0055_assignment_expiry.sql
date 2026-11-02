-- F-001 T-32 (AC-23): the assignment expiry sweep.
--
-- Expired assignments already grant nothing when scopes are computed
-- (authz.compute_scopes, iam.user_has_permission), but a materialized scope
-- keeps them until it is recomputed. iam.assignment_expiry_sweep revokes
-- every expired manual assignment as the system (revoked_by NULL), which the
-- outbox turns into a scope recompute, and audits each. The iam worker runs it
-- every minute. Mapped assignments carry no expiry; they end with their
-- membership or mapping (T-24). An assignment cannot be granted already
-- expired (0005's CHECK against granted_at, which the insert trigger sets).

CREATE INDEX assignment_expiry ON iam.assignment (expires_at) WHERE revoked_at IS NULL AND expires_at IS NOT NULL;

-- The update trigger (0048): a system revocation (no revoker) is allowed for
-- expired assignments only.
CREATE OR REPLACE FUNCTION iam.assignment_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.principal_kind, NEW.principal_id, NEW.role_id, NEW.bu_id, NEW.source, NEW.mapping_id, NEW.granted_by, NEW.granted_at, NEW.expires_at)
     IS DISTINCT FROM
     (OLD.id, OLD.principal_kind, OLD.principal_id, OLD.role_id, OLD.bu_id, OLD.source, OLD.mapping_id, OLD.granted_by, OLD.granted_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'assignment: assignments are immutable; revoke and grant a new one' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'assignment: already revoked' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.revoked_at IS NULL THEN
    RETURN NEW;  -- no-op update
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('iam.assignment'));
  NEW.revoked_at := now();
  -- A mapped assignment ends with its membership or mapping: the mapping
  -- functions revoke it (no revoker); nobody else may.
  IF OLD.source = 'mapped' THEN
    IF NOT iam.in_mapping_sync() THEN
      RAISE EXCEPTION 'assignment: mapped assignments end with their group membership or mapping (AC-13)' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.revoked_by IS NULL THEN
    -- The system ends expired assignments (T-32, AC-23); every other
    -- revocation names its revoker.
    IF OLD.expires_at IS NOT NULL AND OLD.expires_at <= now() THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'assignment: revoked_by is required; only expired assignments end without a revoker' USING ERRCODE = 'not_null_violation';
  END IF;
  IF NEW.revoked_by IN (SELECT iam.principal_users(OLD.principal_kind, OLD.principal_id)) THEN
    RAISE EXCEPTION 'assignment: users cannot change their own assignments (AC-28)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT iam.can_assign_at(NEW.revoked_by, OLD.bu_id) THEN
    RAISE EXCEPTION 'assignment: revoker lacks access.assign at BU % (AC-22)', OLD.bu_id USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION iam.assignment_expiry_sweep() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  a iam.assignment;
  n integer := 0;
BEGIN
  FOR a IN
    UPDATE iam.assignment x SET revoked_at = now()
    WHERE x.revoked_at IS NULL AND x.expires_at <= now() AND x.source <> 'mapped'
    RETURNING * LOOP
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'access.assignment_expired', 'severity', 'low', 'actor', 'system:iam',
      'target', a.principal_kind || ':' || a.principal_id,
      'attributes', jsonb_build_object('assignment', a.id, 'role', a.role_id, 'bu', a.bu_id,
                                       'granted_by', a.granted_by, 'granted_at', a.granted_at, 'expires_at', a.expires_at)));
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

REVOKE ALL ON FUNCTION iam.assignment_expiry_sweep() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.assignment_expiry_sweep() TO app_rw;
