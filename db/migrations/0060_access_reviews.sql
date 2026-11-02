-- F-001 T-39 (AC-49; design §3 access_review_campaign / access_review_item,
-- §6 /access-reviews): access review campaigns.
--
--   * A campaign (access_review.manage at its BU; optionally limited to
--     roles; optionally naming its reviewers) snapshots, when it opens, the
--     live access in the BU's subtree: one item per user assignment, per
--     group assignment, per group mapping (T-24) and per service account,
--     and the break-glass accounts. It has a due date and a policy for
--     undecided items: keep (marked expired_unreviewed) or revoke.
--   * A holder of access_review.decide at an item's BU (restricted BUs by an
--     explicit assignment; one of the named reviewers when the campaign has
--     them) certifies or revokes it, never for their own access and never
--     for access they granted. A revocation needs a comment and applies at
--     once: the assignment ends (a group's for all its members), the
--     mapping is removed, the service account is disabled. Break-glass
--     accounts are certified only (break-glass has its own disable). The
--     scope worker removes the access within its 60-second SLA.
--   * The assignment trigger accepts these revocations: by the reviewer
--     whose decision is recorded (who may not hold access.assign), and,
--     under the revoke policy, by the system.
--   * Every decision, opening and closing is audited.

CREATE TABLE iam.access_review_campaign (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text        NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  bu_id       uuid        NOT NULL REFERENCES iam.bu (id),
  role_ids    uuid[],                       -- NULL: every role
  reviewers   uuid[],                       -- NULL: every holder of access_review.decide
  due_at      timestamptz NOT NULL,
  on_expiry   text        NOT NULL CHECK (on_expiry IN ('keep', 'revoke')),
  reason      text        NOT NULL CHECK (btrim(reason) <> ''),
  state       text        NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
  created_by  uuid        NOT NULL REFERENCES iam.app_user (id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  closed_at   timestamptz,
  closed_by   text,
  CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
  CHECK (due_at > created_at)
);
REVOKE ALL ON iam.access_review_campaign FROM PUBLIC;

CREATE TABLE iam.access_review_item (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id         uuid        NOT NULL REFERENCES iam.access_review_campaign (id),
  kind                text        NOT NULL CHECK (kind IN ('user', 'group', 'mapped', 'service_account', 'breakglass')),
  assignment_id       uuid        REFERENCES iam.assignment (id),
  mapping_id          uuid        REFERENCES iam.group_role_mapping (id),
  role_id             uuid        NOT NULL REFERENCES iam.role (id),
  bu_id               uuid        NOT NULL REFERENCES iam.bu (id),
  granted_by          uuid        REFERENCES iam.app_user (id),
  snapshot            jsonb       NOT NULL,
  decision            text        CHECK (decision IN ('certify', 'revoke', 'expired_unreviewed', 'revoked_by_policy')),
  decided_by          uuid        REFERENCES iam.app_user (id),
  decided_at          timestamptz,
  comment             text,
  outcome             text,       -- what the decision did: revoked, mapping_removed, account_disabled, already_ended, kept
  CHECK ((kind = 'mapped') = (mapping_id IS NOT NULL) AND (kind = 'mapped') = (assignment_id IS NULL)),
  CHECK ((decision IS NULL) = (decided_at IS NULL)),
  CHECK (decision IS DISTINCT FROM 'revoke' OR btrim(coalesce(comment, '')) <> '')
);
CREATE INDEX access_review_item_campaign ON iam.access_review_item (campaign_id);
CREATE INDEX access_review_item_assignment ON iam.access_review_item (assignment_id) WHERE decision IN ('revoke', 'revoked_by_policy');
REVOKE ALL ON iam.access_review_item FROM PUBLIC;

-- The assignment trigger (0055), with the review paths.
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
    -- The system ends expired assignments (T-32, AC-23) and those an access
    -- review's revoke policy ended (T-39); every other revocation names its
    -- revoker.
    IF OLD.expires_at IS NOT NULL AND OLD.expires_at <= now() THEN
      RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM iam.access_review_item i WHERE i.assignment_id = OLD.id AND i.decision = 'revoked_by_policy' AND i.outcome IS NULL) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'assignment: revoked_by is required; only expired assignments end without a revoker' USING ERRCODE = 'not_null_violation';
  END IF;
  IF NEW.revoked_by IN (SELECT iam.principal_users(OLD.principal_kind, OLD.principal_id)) THEN
    RAISE EXCEPTION 'assignment: users cannot change their own assignments (AC-28)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- AC-22, or an access reviewer's recorded revoke decision (T-39, AC-49).
  IF NOT iam.can_assign_at(NEW.revoked_by, OLD.bu_id)
     AND NOT EXISTS (SELECT 1 FROM iam.access_review_item i
                     WHERE i.assignment_id = OLD.id AND i.decision = 'revoke' AND i.decided_by = NEW.revoked_by AND i.outcome IS NULL) THEN
    RAISE EXCEPTION 'assignment: revoker lacks access.assign at BU % (AC-22)', OLD.bu_id USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION iam.review_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'access reviews need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION iam.review_event(event text, severity text, actor text, target text, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor, 'target', target, 'reason', reason,
                                      'attributes', coalesce(attrs, '{}')));
$$;

-- The users whose access an item is (for the no-self-review rule).
CREATE FUNCTION iam.review_item_users(i iam.access_review_item) RETURNS SETOF uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.principal_users(a.principal_kind, a.principal_id) FROM iam.assignment a WHERE a.id = i.assignment_id
  UNION
  SELECT gm.user_id FROM iam.group_role_mapping m JOIN iam.grp_member gm ON gm.grp_id = m.grp_id WHERE m.id = i.mapping_id;
$$;

CREATE FUNCTION iam.access_review_open(campaign_name text, bu uuid, roles uuid[], reviewer_ids uuid[], due timestamptz,
  expiry_policy text, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.review_actor();
  c     iam.access_review_campaign;
  n     integer;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = bu) OR NOT iam.user_has_permission(actor, 'access_review.manage', bu) THEN
    RAISE EXCEPTION 'access_review.manage is required at BU %', bu USING ERRCODE = 'PF008';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  IF due IS NULL OR due < now() + interval '1 hour' OR due > now() + interval '366 days' THEN
    RAISE EXCEPTION 'the due date is between an hour and a year away' USING ERRCODE = 'PF004';
  END IF;
  IF expiry_policy IS NULL OR expiry_policy NOT IN ('keep', 'revoke') THEN
    RAISE EXCEPTION 'on_expiry is keep or revoke' USING ERRCODE = 'PF004';
  END IF;
  IF reviewer_ids IS NOT NULL AND (cardinality(reviewer_ids) = 0 OR EXISTS (
       SELECT 1 FROM unnest(reviewer_ids) r WHERE NOT iam.user_has_permission(r, 'access_review.decide', bu))) THEN
    RAISE EXCEPTION 'every named reviewer must hold access_review.decide at the BU' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO iam.access_review_campaign (name, bu_id, role_ids, reviewers, due_at, on_expiry, reason, created_by)
  VALUES (btrim(campaign_name), bu, roles, reviewer_ids, due, expiry_policy, btrim(reason), actor) RETURNING * INTO c;
  -- Assignments (not mapped ones: their mapping is the item).
  INSERT INTO iam.access_review_item (campaign_id, kind, assignment_id, role_id, bu_id, granted_by, snapshot)
  SELECT c.id,
    CASE WHEN a.source::text = 'service' THEN 'service_account' WHEN a.principal_kind = 'group' THEN 'group'
         WHEN u.source::text = 'breakglass' THEN 'breakglass' ELSE 'user' END,
    a.id, a.role_id, a.bu_id, a.granted_by,
    jsonb_build_object('principal', coalesce(u.email, g.display_name), 'principal_name', coalesce(u.display_name, g.display_name),
      'role', CASE WHEN r.service_account_id IS NOT NULL THEN 'service account scopes' ELSE r.name END,
      'permissions', to_jsonb(v.permissions), 'bu', b.code, 'bu_restricted', b.restricted,
      'granted_by', (SELECT x.email FROM iam.app_user x WHERE x.id = a.granted_by), 'granted_at', a.granted_at, 'expires_at', a.expires_at,
      'members', CASE WHEN a.principal_kind = 'group' THEN coalesce((SELECT jsonb_agg(m.email ORDER BY m.email) FROM iam.grp_member gm
                                                           JOIN iam.app_user m ON m.id = gm.user_id WHERE gm.grp_id = a.principal_id), '[]') END)
  FROM iam.assignment a
  JOIN iam.bu_closure cl ON cl.ancestor_id = bu AND cl.descendant_id = a.bu_id
  JOIN iam.bu b ON b.id = a.bu_id
  JOIN iam.role r ON r.id = a.role_id
  JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  LEFT JOIN iam.app_user u ON a.principal_kind = 'user' AND u.id = a.principal_id
  LEFT JOIN iam.grp g ON a.principal_kind = 'group' AND g.id = a.principal_id
  WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now()) AND a.source::text <> 'mapped'
    AND (roles IS NULL OR a.role_id = ANY (roles));
  -- Group mappings.
  INSERT INTO iam.access_review_item (campaign_id, kind, mapping_id, role_id, bu_id, granted_by, snapshot)
  SELECT c.id, 'mapped', m.id, m.role_id, m.bu_id, m.created_by,
    jsonb_build_object('principal', g.display_name, 'principal_name', g.display_name, 'role', r.name, 'permissions', to_jsonb(v.permissions),
      'bu', b.code, 'bu_restricted', b.restricted, 'granted_by', (SELECT x.email FROM iam.app_user x WHERE x.id = m.created_by),
      'granted_at', m.created_at, 'idp_group', g.external_id,
      'members', coalesce((SELECT jsonb_agg(u.email ORDER BY u.email) FROM iam.grp_member gm JOIN iam.app_user u ON u.id = gm.user_id
                           WHERE gm.grp_id = m.grp_id), '[]'))
  FROM iam.group_role_mapping m
  JOIN iam.bu_closure cl ON cl.ancestor_id = bu AND cl.descendant_id = m.bu_id
  JOIN iam.bu b ON b.id = m.bu_id
  JOIN iam.grp g ON g.id = m.grp_id
  JOIN iam.role r ON r.id = m.role_id
  JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  WHERE m.removed_at IS NULL AND (roles IS NULL OR m.role_id = ANY (roles));
  SELECT count(*) INTO n FROM iam.access_review_item i WHERE i.campaign_id = c.id;
  PERFORM iam.review_event('access_review.campaign_opened', 'high', actor::text, 'access_review:' || c.id, c.reason,
    jsonb_build_object('name', c.name, 'bu', bu, 'items', n, 'due_at', c.due_at, 'on_expiry', c.on_expiry,
                       'roles', to_jsonb(roles), 'reviewers', to_jsonb(reviewer_ids)));
  RETURN c.id;
END $$;

-- Ends an item's access (a reviewer's revoke, or the revoke policy with
-- actor NULL). Returns the outcome.
CREATE FUNCTION iam.review_revoke(i iam.access_review_item, actor uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  m iam.group_role_mapping;
  a iam.assignment;
  u uuid;
BEGIN
  IF i.kind = 'breakglass' THEN
    RETURN 'kept';
  END IF;
  IF i.kind = 'mapped' THEN
    UPDATE iam.group_role_mapping x SET removed_at = now(), removed_by = actor
    WHERE x.id = i.mapping_id AND x.removed_at IS NULL RETURNING * INTO m;
    IF NOT FOUND THEN
      RETURN 'already_ended';
    END IF;
    PERFORM iam.mapping_event('group_mapping.removed', 'high', coalesce(actor::text, 'system:reviews'), m, NULL,
      'access review ' || i.campaign_id);
    FOR u IN SELECT x.principal_id FROM iam.assignment x WHERE x.mapping_id = m.id AND x.revoked_at IS NULL LOOP
      PERFORM iam.mapping_reconcile(m.id, u);
    END LOOP;
    DELETE FROM iam.group_mapping_skip s WHERE s.mapping_id = m.id;
    RETURN 'mapping_removed';
  END IF;
  SELECT * INTO a FROM iam.assignment x WHERE x.id = i.assignment_id FOR UPDATE;
  IF a.revoked_at IS NOT NULL OR (a.expires_at IS NOT NULL AND a.expires_at <= now()) THEN
    RETURN 'already_ended';
  END IF;
  IF i.kind = 'service_account' THEN
    UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'access_review' WHERE x.id = a.principal_id AND x.status = 'active';
    DELETE FROM iam.sa_access_token t WHERE t.service_account_id = a.principal_id;
    RETURN 'account_disabled';
  END IF;
  UPDATE iam.assignment x SET revoked_at = now(), revoked_by = actor WHERE x.id = a.id;
  RETURN 'revoked';
END $$;

CREATE FUNCTION iam.access_review_decide(item uuid, choice text, note text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.review_actor();
  i     iam.access_review_item;
  c     iam.access_review_campaign;
  res   text;
BEGIN
  SELECT * INTO i FROM iam.access_review_item x WHERE x.id = item FOR UPDATE;
  IF NOT FOUND OR NOT iam.user_has_permission(actor, 'access_review.decide', i.bu_id) THEN
    RAISE EXCEPTION 'no review item %', item USING ERRCODE = 'P0002';
  END IF;
  SELECT * INTO c FROM iam.access_review_campaign x WHERE x.id = i.campaign_id FOR UPDATE;
  IF c.state <> 'open' OR c.due_at <= now() THEN
    RAISE EXCEPTION 'the campaign is closed' USING ERRCODE = 'PF003';
  END IF;
  IF c.reviewers IS NOT NULL AND actor <> ALL (c.reviewers) THEN
    RAISE EXCEPTION 'this campaign names its reviewers' USING ERRCODE = 'PF008';
  END IF;
  IF i.decision IS NOT NULL THEN
    RAISE EXCEPTION 'the item was decided already (%)', i.decision USING ERRCODE = 'PF003';
  END IF;
  IF choice IS NULL OR choice NOT IN ('certify', 'revoke') THEN
    RAISE EXCEPTION 'the decision is certify or revoke' USING ERRCODE = 'PF004';
  END IF;
  IF actor IN (SELECT iam.review_item_users(i)) THEN
    RAISE EXCEPTION 'nobody reviews their own access' USING ERRCODE = 'PF008';
  END IF;
  IF actor = i.granted_by THEN
    RAISE EXCEPTION 'nobody reviews access they granted' USING ERRCODE = 'PF008';
  END IF;
  IF choice = 'revoke' AND btrim(coalesce(note, '')) = '' THEN
    RAISE EXCEPTION 'a revocation needs a comment' USING ERRCODE = 'PF004';
  END IF;
  IF choice = 'revoke' AND i.kind = 'breakglass' THEN
    RAISE EXCEPTION 'break-glass accounts are certified here; disable break-glass to end them' USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.access_review_item x SET decision = choice, decided_by = actor, decided_at = now(), comment = nullif(btrim(coalesce(note, '')), '')
  WHERE x.id = i.id RETURNING * INTO i;
  res := CASE WHEN choice = 'revoke' THEN iam.review_revoke(i, actor) ELSE 'kept' END;
  UPDATE iam.access_review_item x SET outcome = res WHERE x.id = i.id;
  PERFORM iam.review_event('access_review.decided', CASE WHEN choice = 'revoke' THEN 'high' ELSE 'info' END, actor::text,
    'access_review_item:' || i.id, i.comment,
    jsonb_build_object('campaign', c.id, 'decision', choice, 'outcome', res, 'kind', i.kind, 'principal', i.snapshot->>'principal',
                       'role', i.snapshot->>'role', 'bu', i.snapshot->>'bu', 'assignment', i.assignment_id, 'mapping', i.mapping_id));
  RETURN res;
END $$;

-- Closes a campaign: undecided items follow its policy. actor NULL: the
-- system, at the due date.
CREATE FUNCTION iam.review_close(c iam.access_review_campaign, actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  i      iam.access_review_item;
  res    text;
  counts jsonb;
BEGIN
  FOR i IN SELECT * FROM iam.access_review_item x WHERE x.campaign_id = c.id AND x.decision IS NULL ORDER BY x.id FOR UPDATE LOOP
    IF c.on_expiry = 'revoke' AND i.kind <> 'breakglass' THEN
      UPDATE iam.access_review_item x SET decision = 'revoked_by_policy', decided_at = now() WHERE x.id = i.id RETURNING * INTO i;
      BEGIN
        res := iam.review_revoke(i, NULL);
      EXCEPTION WHEN insufficient_privilege OR check_violation THEN
        res := 'kept: ' || SQLERRM;
      END;
      UPDATE iam.access_review_item x SET outcome = res WHERE x.id = i.id;
      PERFORM iam.review_event('access_review.decided', 'high', 'system:reviews', 'access_review_item:' || i.id, 'campaign due; policy revoke',
        jsonb_build_object('campaign', c.id, 'decision', 'revoked_by_policy', 'outcome', res, 'kind', i.kind,
                           'principal', i.snapshot->>'principal', 'role', i.snapshot->>'role', 'bu', i.snapshot->>'bu'));
    ELSE
      UPDATE iam.access_review_item x SET decision = 'expired_unreviewed', decided_at = now(), outcome = 'kept' WHERE x.id = i.id;
    END IF;
  END LOOP;
  UPDATE iam.access_review_campaign x SET state = 'closed', closed_at = now(), closed_by = actor WHERE x.id = c.id;
  SELECT jsonb_object_agg(d, n) INTO counts FROM (
    SELECT x.decision AS d, count(*) AS n FROM iam.access_review_item x WHERE x.campaign_id = c.id GROUP BY x.decision) s;
  PERFORM iam.review_event('access_review.campaign_closed', 'high', actor, 'access_review:' || c.id, NULL,
    jsonb_build_object('name', c.name, 'on_expiry', c.on_expiry, 'decisions', coalesce(counts, '{}')));
  RETURN coalesce(counts, '{}');
END $$;

CREATE FUNCTION iam.access_review_close(campaign uuid, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.review_actor();
  c     iam.access_review_campaign;
BEGIN
  SELECT * INTO c FROM iam.access_review_campaign x WHERE x.id = campaign FOR UPDATE;
  IF NOT FOUND OR NOT iam.user_has_permission(actor, 'access_review.manage', c.bu_id) THEN
    RAISE EXCEPTION 'no campaign %', campaign USING ERRCODE = 'P0002';
  END IF;
  IF c.state <> 'open' THEN
    RAISE EXCEPTION 'the campaign is closed already' USING ERRCODE = 'PF003';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  RETURN iam.review_close(c, actor::text);
END $$;

-- The due-date sweep (iam worker, every minute). Returns campaigns closed.
CREATE FUNCTION iam.access_review_sweep() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  c iam.access_review_campaign;
  n integer := 0;
BEGIN
  FOR c IN SELECT * FROM iam.access_review_campaign x WHERE x.state = 'open' AND x.due_at <= now() ORDER BY x.due_at FOR UPDATE SKIP LOCKED LOOP
    PERFORM iam.review_close(c, 'system:reviews');
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

-- Campaigns the caller manages (access_review.manage at the BU) or reviews
-- in (an item where they hold access_review.decide), with progress.
CREATE FUNCTION iam.access_review_list(one uuid)
RETURNS TABLE (id uuid, name text, bu_id uuid, bu_code text, role_ids uuid[], reviewers uuid[], due_at timestamptz, on_expiry text,
               reason text, state text, created_by uuid, created_at timestamptz, closed_at timestamptz, closed_by text, manages boolean,
               items integer, decided integer, revoked integer, open_for_me integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.review_actor();
BEGIN
  RETURN QUERY
  WITH mine AS (
    SELECT i.campaign_id, i.decision, i.id, i.kind,
      iam.user_has_permission(actor, 'access_review.decide', i.bu_id) AS can
    FROM iam.access_review_item i WHERE one IS NULL OR i.campaign_id = one
  )
  SELECT c.id, c.name, c.bu_id, b.code, c.role_ids, c.reviewers, c.due_at, c.on_expiry, c.reason, c.state, c.created_by, c.created_at,
    c.closed_at, c.closed_by, iam.user_has_permission(actor, 'access_review.manage', c.bu_id),
    (SELECT count(*)::integer FROM iam.access_review_item i WHERE i.campaign_id = c.id),
    (SELECT count(*)::integer FROM iam.access_review_item i WHERE i.campaign_id = c.id AND i.decision IS NOT NULL),
    (SELECT count(*)::integer FROM iam.access_review_item i WHERE i.campaign_id = c.id AND i.decision IN ('revoke', 'revoked_by_policy')),
    (SELECT count(*)::integer FROM mine m WHERE m.campaign_id = c.id AND m.can AND m.decision IS NULL
       AND (c.reviewers IS NULL OR actor = ANY (c.reviewers)))
  FROM iam.access_review_campaign c JOIN iam.bu b ON b.id = c.bu_id
  WHERE (one IS NULL OR c.id = one)
    AND (iam.user_has_permission(actor, 'access_review.manage', c.bu_id) OR EXISTS (SELECT 1 FROM mine m WHERE m.campaign_id = c.id AND m.can))
  ORDER BY c.created_at DESC, c.id;
END $$;

-- A campaign's items the caller may see: all of them for its managers,
-- otherwise those at BUs where the caller holds access_review.decide.
CREATE FUNCTION iam.access_review_items(campaign uuid)
RETURNS TABLE (id uuid, kind text, assignment_id uuid, mapping_id uuid, role_id uuid, bu_id uuid, snapshot jsonb, decision text,
               decided_by uuid, decided_at timestamptz, comment text, outcome text, can_decide boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor  uuid := iam.review_actor();
  c      iam.access_review_campaign;
  manage boolean;
BEGIN
  SELECT * INTO c FROM iam.access_review_campaign x WHERE x.id = campaign;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no campaign %', campaign USING ERRCODE = 'P0002';
  END IF;
  manage := iam.user_has_permission(actor, 'access_review.manage', c.bu_id);
  RETURN QUERY
  SELECT i.id, i.kind, i.assignment_id, i.mapping_id, i.role_id, i.bu_id, i.snapshot, i.decision, i.decided_by, i.decided_at, i.comment,
    i.outcome,
    c.state = 'open' AND c.due_at > now() AND i.decision IS NULL AND iam.user_has_permission(actor, 'access_review.decide', i.bu_id)
      AND (c.reviewers IS NULL OR actor = ANY (c.reviewers)) AND actor NOT IN (SELECT iam.review_item_users(i))
      AND actor IS DISTINCT FROM i.granted_by
  FROM iam.access_review_item i
  WHERE i.campaign_id = c.id AND (manage OR iam.user_has_permission(actor, 'access_review.decide', i.bu_id))
  ORDER BY i.snapshot->>'bu', i.snapshot->>'principal', i.snapshot->>'role', i.id;
END $$;

REVOKE ALL ON FUNCTION iam.review_actor(), iam.review_event(text, text, text, text, text, jsonb), iam.review_item_users(iam.access_review_item),
  iam.access_review_open(text, uuid, uuid[], uuid[], timestamptz, text, text), iam.review_revoke(iam.access_review_item, uuid),
  iam.access_review_decide(uuid, text, text), iam.review_close(iam.access_review_campaign, text), iam.access_review_close(uuid, text),
  iam.access_review_sweep(), iam.access_review_list(uuid), iam.access_review_items(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.access_review_open(text, uuid, uuid[], uuid[], timestamptz, text, text), iam.access_review_decide(uuid, text, text),
  iam.access_review_close(uuid, text), iam.access_review_sweep(), iam.access_review_list(uuid), iam.access_review_items(uuid) TO app_rw;
