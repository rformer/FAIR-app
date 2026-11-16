-- F-009 T-05 (F-009-AC-01, AC-03, AC-04; design §3.1, §3.2, §3.4): fanning
-- notices out to their recipients.
--
--   * notify.recipient: each recipient of a notice, once: how they came to
--     receive it (named, or holding a permission), and either their in-app
--     notification or why they were dropped (inactive, no_permission,
--     not_visible), as AC-04 asks.
--   * Recipients (design §3.1, OQ6): the users a notice names; the active
--     holders of its permission at its BU (inherited, never across a
--     restricted boundary: iam.permission_holders); for an acceptance's
--     decision_needed, the approvers who may decide it now (as the inbox:
--     acceptance.notice_deciders). At most 50 by name; how many more were
--     left out is recorded on the notice.
--   * Re-checks (design §3.2): active; still holding the permission they
--     came by; the item still visible: an acceptance in their acceptance
--     read scope at its BU, an estimate request still addressed to them
--     (estimate.notice_addressed). Posture, break-glass and finding notices
--     need only the permission (or being named).
--   * Deliveries: by email when the SMTP relay is live (none when muted, an
--     optional kind; dropped as no_email without an address; held for the
--     digest when the user takes one and the kind is optional); to each
--     enabled webhook that takes the kind and whose BU subtree holds the
--     notice's BU, and, for a restricted unit, is itself inside that
--     restricted subtree (OQ8).

CREATE TABLE notify.recipient (
  notice_id uuid        NOT NULL REFERENCES notify.notice (id) ON DELETE CASCADE,
  user_id   uuid        NOT NULL REFERENCES iam.app_user (id),
  via       text,       -- the permission they hold, or null: named
  in_app    boolean     NOT NULL,
  reason    text        CHECK (reason IN ('inactive', 'no_permission', 'not_visible')),
  at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (notice_id, user_id),
  CHECK (in_app = (reason IS NULL))
);
REVOKE ALL ON notify.recipient FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON notify.recipient TO notify_definer;

-- A notice's left_out is set by its fan-out, with fanned_out_at.
CREATE OR REPLACE FUNCTION notify.notice_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.kind, NEW.source, NEW.source_id, NEW.envelope, NEW.item_type, NEW.item_id, NEW.bu_id, NEW.restricted, NEW.recipients,
      NEW.queued_at, NEW.collected_at)
     IS DISTINCT FROM (OLD.kind, OLD.source, OLD.source_id, OLD.envelope, OLD.item_type, OLD.item_id, OLD.bu_id, OLD.restricted, OLD.recipients,
      OLD.queued_at, OLD.collected_at)
     OR (OLD.fanned_out_at IS NOT NULL AND (NEW.fanned_out_at, NEW.left_out) IS DISTINCT FROM (OLD.fanned_out_at, OLD.left_out)) THEN
    RAISE EXCEPTION 'notify: a notice does not change once collected' USING ERRCODE = 'PF028', HINT = 'notice_fixed';
  END IF;
  RETURN NEW;
END $$;

GRANT EXECUTE ON FUNCTION iam.permission_holders(text, uuid, integer) TO notify_definer, acceptance_definer;

GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;
CREATE FUNCTION estimate.notice_addressed(request uuid, u uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM estimate.request_estimator x WHERE x.request_id = notice_addressed.request AND x.user_id = u AND x.removed_at IS NULL)
$$;
REVOKE ALL ON FUNCTION estimate.notice_addressed(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.notice_addressed(uuid, uuid) TO notify_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;
-- The approvers who may decide acceptance id now (as acceptance.decide and
-- the inbox): acceptance.approve at its tier's BU, neither its requester
-- nor its risk's owner, not yet decided in this round; only while pending
-- or suspended.
CREATE FUNCTION acceptance.notice_deciders(id uuid) RETURNS TABLE (user_id uuid, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.id, h.display_name
  FROM acceptance.acceptance x
  CROSS JOIN LATERAL iam.permission_holders('acceptance.approve', x.tier_bu_id, 100000) h
  WHERE x.id = notice_deciders.id AND x.state IN ('pending', 'suspended')
    AND h.id <> x.requested_by AND h.id IS DISTINCT FROM (register.notice_risk(x.risk_id) ->> 'owner')::uuid
    AND NOT EXISTS (SELECT 1 FROM acceptance.step s WHERE s.acceptance_id = x.id AND s.actor = h.id AND s.kind IN ('approved', 'rejected')
      AND s.n > (SELECT max(q.n) FROM acceptance.step q WHERE q.acceptance_id = x.id AND q.kind IN ('requested', 'review_requested')))
  ORDER BY h.display_name, h.id
$$;
REVOKE ALL ON FUNCTION acceptance.notice_deciders(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.notice_deciders(uuid) TO notify_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;

-- Why user may not receive notice n now (null: they may): inactive, no
-- longer holding the permission they came by, or no longer seeing the item.
CREATE FUNCTION notify.recheck(n notify.notice, u uuid, via text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM iam.app_user x WHERE x.id = u AND x.status = 'active') THEN 'inactive'
    WHEN via IS NOT NULL AND NOT EXISTS (SELECT 1 FROM iam.permission_holders(via, n.bu_id, 100000) h WHERE h.id = u) THEN 'no_permission'
    WHEN n.item_type = 'acceptance' AND NOT coalesce((SELECT (s.read_bus -> 'acceptance') ? n.bu_id::text FROM authz.user_scope s WHERE s.user_id = u), false)
      THEN 'not_visible'
    WHEN n.item_type = 'estimate_request' AND NOT estimate.notice_addressed(n.item_id::uuid, u) THEN 'not_visible'
  END
$$;

CREATE FUNCTION notify.fan_out(batch integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  n         notify.notice;
  k         notify.kind;
  c         record;
  smtp      uuid;
  why       text;
  cap       constant integer := 50;
  total     integer;
  notices   integer := 0;
  in_app    integer := 0;
  dropped   integer := 0;
  emails    integer := 0;
  hooks     integer := 0;
  rows_     integer;
BEGIN
  IF batch IS NULL OR batch < 1 OR batch > 10000 THEN
    RAISE EXCEPTION 'notify.fan_out: batch is 1 to 10,000' USING ERRCODE = 'PF028', HINT = 'invalid_batch';
  END IF;
  SELECT x.id INTO smtp FROM notify.channel x WHERE x.kind = 'smtp' AND x.removed_at IS NULL AND x.enabled;
  FOR n IN SELECT * FROM notify.notice x WHERE x.fanned_out_at IS NULL ORDER BY x.seq LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    SELECT * INTO k FROM notify.kind x WHERE x.kind = n.kind;
    -- The candidates: named users, then permission holders or deciders,
    -- the first 50 by name of the latter.
    total := CASE WHEN n.recipients ? 'permission_holders'
                  THEN (SELECT count(*) FROM iam.permission_holders(n.recipients ->> 'permission_holders', n.bu_id, 100000))
                  WHEN n.recipients ? 'deciders' THEN (SELECT count(*) FROM acceptance.notice_deciders((n.recipients ->> 'deciders')::uuid))
                  ELSE 0 END;
    FOR c IN
      SELECT DISTINCT ON (x.user_id) x.user_id, x.via, x.ord FROM (
        SELECT v::uuid AS user_id, NULL::text AS via, 0::bigint AS ord FROM jsonb_array_elements_text(coalesce(n.recipients -> 'users', '[]')) v
        UNION ALL
        SELECT h.id, n.recipients ->> 'permission_holders', row_number() OVER ()
        FROM iam.permission_holders(n.recipients ->> 'permission_holders', n.bu_id, cap) h WHERE n.recipients ? 'permission_holders'
        UNION ALL
        SELECT d.user_id, 'acceptance.approve', d.rn
        FROM (SELECT y.user_id, row_number() OVER () AS rn FROM acceptance.notice_deciders((n.recipients ->> 'deciders')::uuid) y LIMIT cap) d
        WHERE n.recipients ? 'deciders'
      ) x ORDER BY x.user_id, x.ord
    LOOP
      why := notify.recheck(n, c.user_id, CASE WHEN c.via = 'acceptance.approve' THEN NULL ELSE c.via END);
      INSERT INTO notify.recipient (notice_id, user_id, via, in_app, reason) VALUES (n.id, c.user_id, c.via, why IS NULL, why);
      IF why IS NOT NULL THEN
        dropped := dropped + 1;
        CONTINUE;
      END IF;
      INSERT INTO notify.inbox (notice_id, user_id) VALUES (n.id, c.user_id);
      in_app := in_app + 1;
      -- Email: unless muted (an optional kind); held for the digest when the
      -- user takes one and the kind is optional; dropped without an address.
      IF smtp IS NOT NULL AND n.kind <> 'notify.test'
         AND NOT (NOT k.mandatory AND EXISTS (SELECT 1 FROM notify.preference p WHERE p.user_id = c.user_id AND p.kind = n.kind AND p.email_muted)) THEN
        IF (SELECT nullif(btrim(u.email), '') FROM iam.app_user u WHERE u.id = c.user_id) IS NULL THEN
          INSERT INTO notify.delivery (notice_id, channel_id, user_id, state, reason) VALUES (n.id, smtp, c.user_id, 'dropped', 'no_email');
        ELSE
          INSERT INTO notify.delivery (notice_id, channel_id, user_id, digest)
          VALUES (n.id, smtp, c.user_id, NOT k.mandatory AND coalesce((SELECT o.digest FROM notify.user_option o WHERE o.user_id = c.user_id), false));
          emails := emails + 1;
        END IF;
      END IF;
    END LOOP;
    -- Webhooks (OQ8).
    INSERT INTO notify.delivery (notice_id, channel_id)
    SELECT n.id, w.id FROM notify.channel w
    WHERE w.kind = 'webhook' AND w.removed_at IS NULL AND w.enabled AND n.kind = ANY (w.kinds)
      AND EXISTS (SELECT 1 FROM iam.bu_closure x WHERE x.ancestor_id = w.bu_id AND x.descendant_id = n.bu_id)
      AND (NOT n.restricted OR EXISTS (SELECT 1 FROM iam.bu_closure x WHERE x.ancestor_id = iam.restricted_root(n.bu_id) AND x.descendant_id = w.bu_id));
    GET DIAGNOSTICS rows_ = ROW_COUNT;
    hooks := hooks + rows_;
    UPDATE notify.notice x SET fanned_out_at = now(), left_out = greatest(total - cap, 0) WHERE x.id = n.id;
    notices := notices + 1;
  END LOOP;
  RETURN jsonb_build_object('notices', notices, 'in_app', in_app, 'dropped', dropped, 'emails', emails, 'webhooks', hooks);
END $$;

REVOKE ALL ON FUNCTION notify.recheck(notify.notice, uuid, text), notify.fan_out(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notify.fan_out(integer) TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;
