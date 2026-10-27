-- F-001 T-26 (AC-30, AC-41, AC-53, AC-63; design §5.5): the generic
-- dual-approval engine, pulled forward before F-015 T-14 (approved
-- 2026-10-26).
--
-- A requester asks for approval of one kind of change; a different person
-- who holds that kind's approve permission at the request's BU (the root
-- when none) approves or rejects it before it expires (72 h by default);
-- the approved action then consumes the approval exactly once. Every step is
-- audited through iam.event_outbox in the same transaction.
--
-- Who acts is never a parameter: requester and approver come from the
-- signed database context (authz.ctx_scope, ADR-007), so self-approval is
-- impossible in the database, not only in the API. Application roles have
-- no table privileges; they call the functions.
--
-- Errors use SQLSTATE class AP:
--   AP001 no valid signed context / inactive actor   AP002 self-approval
--   AP003 actor may not approve this kind            AP004 not applicable
--   AP005 invalid request

CREATE TABLE iam.approval_kind (
  kind                text     PRIMARY KEY CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  approve_permission  text     NOT NULL, -- checked against iam.permission when used (filled by sync_release)
  ttl                 interval NOT NULL DEFAULT interval '72 hours'
                               CHECK (ttl > interval '0' AND ttl <= interval '30 days'),
  description         text     NOT NULL CHECK (btrim(description) <> '')
);
REVOKE ALL ON iam.approval_kind FROM PUBLIC;

-- Approver authority per kind (decision of 2026-10-26: the holder of the
-- kind's permission; today only Platform Admin holds these).
INSERT INTO iam.approval_kind (kind, approve_permission, description) VALUES
  ('access.admin_risk_combination', 'access.approve',    'A user would hold both admin and risk-data permissions (F-001 AC-30)'),
  ('breakglass.enable',             'breakglass.manage', 'Enable break-glass after install (F-001 AC-41)'),
  ('sod.exception',                 'sod.manage',        'Separation-of-duties exception for a custom role (F-001 AC-53)'),
  ('bu.unrestrict',                 'bu.restrict',       'Un-restrict a BU (F-001 AC-63)'),
  ('bu.rollup_loosen',              'bu.restrict',       'Loosen a restricted BU''s roll-up visibility (F-001 AC-63)'),
  ('settings.out_of_bounds',        'settings.approve',  'Security setting outside the active profile bound (F-015 AC-21)');

CREATE TABLE iam.approval_request (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind             text        NOT NULL REFERENCES iam.approval_kind (kind),
  target_ref       text        NOT NULL CHECK (btrim(target_ref) <> ''), -- what is approved, e.g. a change id
  payload          jsonb       NOT NULL DEFAULT '{}',
  reason           text        NOT NULL CHECK (btrim(reason) <> ''),
  bu_id            uuid        REFERENCES iam.bu (id), -- where approver authority is checked; NULL = root
  requested_by     uuid        NOT NULL REFERENCES iam.app_user (id),
  status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  decided_by       uuid        REFERENCES iam.app_user (id),
  decided_at       timestamptz,
  decision_reason  text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  consumed_at      timestamptz,
  CHECK (decided_by <> requested_by),                                -- design §3: no self-approval
  CHECK ((status IN ('approved', 'rejected')) = (decided_by IS NOT NULL AND decided_at IS NOT NULL)),
  CHECK (consumed_at IS NULL OR status = 'approved'),
  CHECK (expires_at > created_at)
);
CREATE INDEX approval_request_pending ON iam.approval_request (expires_at) WHERE status = 'pending';
REVOKE ALL ON iam.approval_request FROM PUBLIC;

-- The verified acting user, from the signed database context.
CREATE FUNCTION iam.approval_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL OR NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = u AND status = 'active') THEN
    RAISE EXCEPTION 'approvals need a valid signed database context for an active user' USING ERRCODE = 'AP001';
  END IF;
  RETURN u;
END $$;

-- May u decide requests of this kind at bu (NULL = root)?
CREATE FUNCTION iam.may_approve(u uuid, k text, bu uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM iam.approval_kind ak
    JOIN iam.permission p ON p.key = ak.approve_permission AND p.privileged
    WHERE ak.kind = k
      AND iam.user_has_permission(u, ak.approve_permission, coalesce(bu, (SELECT id FROM iam.bu WHERE parent_id IS NULL))));
$$;

CREATE FUNCTION iam.approval_audit(event text, severity text, actor uuid, r iam.approval_request) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object(
    'type', event, 'severity', severity, 'actor', coalesce(actor::text, 'system:approvals'),
    'target', 'approval:' || r.id, 'reason', coalesce(r.decision_reason, r.reason),
    'attributes', jsonb_build_object('kind', r.kind, 'target_ref', r.target_ref, 'requested_by', r.requested_by,
                                     'decided_by', r.decided_by, 'status', r.status, 'bu_id', r.bu_id,
                                     'expires_at', r.expires_at)));
$$;

-- Requests approval as the signed-context user. Returns the request id.
CREATE FUNCTION iam.request_approval(kind text, target_ref text, reason text, payload jsonb DEFAULT '{}', bu_id uuid DEFAULT NULL)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.approval_actor();
  ttl   interval;
  r     iam.approval_request;
BEGIN
  SELECT ak.ttl INTO ttl FROM iam.approval_kind ak WHERE ak.kind = request_approval.kind;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown approval kind %', kind USING ERRCODE = 'AP005';
  END IF;
  IF btrim(coalesce(reason, '')) = '' OR btrim(coalesce(target_ref, '')) = '' THEN
    RAISE EXCEPTION 'an approval request needs a target and a stated reason' USING ERRCODE = 'AP005';
  END IF;
  INSERT INTO iam.approval_request AS a (kind, target_ref, payload, reason, bu_id, requested_by, expires_at)
  VALUES (request_approval.kind, request_approval.target_ref, coalesce(request_approval.payload, '{}'),
          request_approval.reason, request_approval.bu_id, actor, now() + ttl)
  RETURNING a.* INTO r;
  PERFORM iam.approval_audit('approval.requested', 'info', actor, r);
  RETURN r.id;
END $$;

-- Approves or rejects a pending request as the signed-context user, who must
-- not be the requester and must hold the kind's approve permission at the
-- request's BU. Returns the new status.
CREATE FUNCTION iam.decide_approval(request_id uuid, approve boolean, reason text DEFAULT NULL) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.approval_actor();
  r     iam.approval_request;
BEGIN
  SELECT * INTO r FROM iam.approval_request a WHERE a.id = request_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'approval request % does not exist', request_id USING ERRCODE = 'AP004';
  END IF;
  IF r.requested_by = actor THEN
    RAISE EXCEPTION 'the approver must be a different person than the requester' USING ERRCODE = 'AP002';
  END IF;
  IF NOT iam.may_approve(actor, r.kind, r.bu_id) THEN
    RAISE EXCEPTION 'you may not decide % requests here' , r.kind USING ERRCODE = 'AP003';
  END IF;
  IF r.status <> 'pending' THEN
    RAISE EXCEPTION 'approval request % is %, not pending', request_id, r.status USING ERRCODE = 'AP004';
  END IF;
  IF now() >= r.expires_at THEN
    RAISE EXCEPTION 'approval request % expired at %', request_id, r.expires_at USING ERRCODE = 'AP004';
  END IF;
  IF NOT approve AND btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a rejection needs a stated reason' USING ERRCODE = 'AP005';
  END IF;
  UPDATE iam.approval_request a
  SET status = CASE WHEN approve THEN 'approved' ELSE 'rejected' END,
      decided_by = actor, decided_at = now(), decision_reason = nullif(btrim(coalesce(decide_approval.reason, '')), '')
  WHERE a.id = r.id
  RETURNING a.* INTO r;
  PERFORM iam.approval_audit(CASE WHEN approve THEN 'approval.approved' ELSE 'approval.rejected' END,
                             CASE WHEN approve THEN 'high' ELSE 'info' END, actor, r);
  RETURN r.status;
END $$;

-- Marks overdue pending requests expired (scheduled job). Returns how many.
CREATE FUNCTION iam.expire_approvals() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.approval_request;
  n integer := 0;
BEGIN
  FOR r IN UPDATE iam.approval_request a SET status = 'expired'
           WHERE a.status = 'pending' AND a.expires_at <= now() RETURNING a.* LOOP
    PERFORM iam.approval_audit('approval.expired', 'info', NULL, r);
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

-- Used once, by the action it approved, in that action's transaction (a
-- SECURITY DEFINER function of the consuming feature). Refuses anything but
-- an unconsumed, unexpired approval of exactly this kind and target, and
-- returns the request's payload.
CREATE FUNCTION iam.consume_approval(request_id uuid, kind text, target_ref text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.approval_request;
BEGIN
  SELECT * INTO r FROM iam.approval_request a WHERE a.id = request_id FOR UPDATE;
  IF NOT FOUND OR r.kind IS DISTINCT FROM consume_approval.kind OR r.target_ref IS DISTINCT FROM consume_approval.target_ref THEN
    RAISE EXCEPTION 'no approval % for % %', request_id, kind, target_ref USING ERRCODE = 'AP004';
  END IF;
  IF r.status <> 'approved' OR r.consumed_at IS NOT NULL OR now() >= r.expires_at THEN
    RAISE EXCEPTION 'approval % is not usable (status %, consumed %, expires %)', request_id, r.status, r.consumed_at, r.expires_at
      USING ERRCODE = 'AP004';
  END IF;
  UPDATE iam.approval_request a SET consumed_at = now() WHERE a.id = r.id RETURNING a.* INTO r;
  PERFORM iam.approval_audit('approval.consumed', 'info', r.decided_by, r);
  RETURN r.payload;
END $$;

-- A request, for the signed-context user if they are its requester or may
-- decide it; otherwise nothing (indistinguishable from a missing request).
CREATE FUNCTION iam.approval(request_id uuid) RETURNS SETOF iam.approval_request
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.* FROM iam.approval_request a
  WHERE a.id = request_id
    AND (a.requested_by = iam.approval_actor() OR iam.may_approve(iam.approval_actor(), a.kind, a.bu_id));
$$;

REVOKE ALL ON FUNCTION iam.approval_actor(), iam.may_approve(uuid, text, uuid),
  iam.approval_audit(text, text, uuid, iam.approval_request), iam.request_approval(text, text, text, jsonb, uuid),
  iam.decide_approval(uuid, boolean, text), iam.expire_approvals(), iam.consume_approval(uuid, text, text),
  iam.approval(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.request_approval(text, text, text, jsonb, uuid), iam.decide_approval(uuid, boolean, text),
  iam.expire_approvals(), iam.approval(uuid) TO app_rw;
-- consume_approval is granted to each consuming feature's definer role with
-- that feature (F-015 T-14: posture_definer).
