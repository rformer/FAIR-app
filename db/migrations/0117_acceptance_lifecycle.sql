-- F-008 T-04 (F-008-AC-01 to AC-07, AC-11, AC-15, AC-18; design §3.2,
-- §3.4): requests and decisions. Definer functions owned by
-- acceptance_definer take the caller from the signed context and check it:
--   * acceptance.request(risk, justification, conditions, expires_on,
--     renews): acceptance.request at the risk's BU (write scope); an open
--     risk the caller sees, treatment decision accept, exposure current
--     (register.exposure_status), the expiry after today and within
--     acceptance.max_duration_days; one open request per risk (a renewal of
--     an active acceptance beside it). The tier is placed on the risk's mean
--     annualized loss (register.exposure_for) and resolved to the BU levels
--     up from the risk's (tier 3: the root); the evidence (the exposure, the
--     pins, the tier and its settings) is copied into the requested step.
--   * acceptance.decide(id, decision, rationale, expires_on): approve or
--     reject, by a holder of acceptance.approve at the tier's BU who is
--     neither the requester nor the risk's owner, once per round; an
--     approval may shorten the expiry; enough approvals activate (a
--     renewal ends the acceptance it renews first, in the same
--     transaction); one rejection ends the request.
--   * acceptance.withdraw(id, reason): the requester, while pending.
--   * acceptance.revoke(id, reason): an approver who could approve it at
--     its tier, while active or suspended.
--   * Closing a risk ends its open acceptances (risk_closed); moving it
--     moves them, re-resolving pending and suspended ones' tier BU from the
--     new BU; approved_bu_id keeps where it was approved (needs review).
-- Refusals are PF027 (hint: the reason) or 42501 (hint not_your_tier,
-- separation_of_duties); unknown or unseen ids P0002. Events in the
-- transaction (acceptance.emit).

GRANT SELECT ON register.risk, register.risk_scenario, register.treatment TO acceptance_definer;
GRANT SELECT ON iam.bu, iam.bu_closure TO acceptance_definer;
GRANT USAGE ON SCHEMA iam, authz TO acceptance_definer;
GRANT EXECUTE ON FUNCTION iam.instance_setting(text), iam.holds_permission(uuid, text, uuid) TO acceptance_definer;
GRANT INSERT ON iam.event_outbox TO acceptance_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO acceptance_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_scope(), authz.visible_bus(text, text), authz.scope_excludes(text, text), authz.scope_hides(text, text)
  TO acceptance_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
SET ROLE register_definer;
GRANT EXECUTE ON FUNCTION register.exposure_status(uuid) TO acceptance_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;

-- The signed context's user, or an error: every request and decision is attributed.
CREATE FUNCTION acceptance.actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'acceptances need a valid signed database context' USING ERRCODE = 'PF027', HINT = 'no_context';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION acceptance.emit(type text, severity text, actor text, id uuid, bu uuid, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', severity, 'actor', actor, 'target', 'acceptance:' || id, 'bu_id', bu,
    'attributes', attrs || jsonb_build_object('acceptance', id::text)));
$$;

-- An acceptance setting in force (an integer).
CREATE FUNCTION acceptance.setting(key text) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT (iam.instance_setting(key) #>> '{}')::integer
$$;

-- The tier of a mean annualized loss with its settings in force (design §3.4).
CREATE FUNCTION acceptance.place(mean numeric) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t1 integer := acceptance.setting('acceptance.tier1_max');
  t2 integer := acceptance.setting('acceptance.tier2_max');
BEGIN
  IF t1 IS NULL OR t2 IS NULL THEN
    RAISE EXCEPTION 'acceptance: the tiers are not set' USING ERRCODE = 'PF027', HINT = 'no_tiers';
  END IF;
  IF mean <= t1 THEN
    RETURN jsonb_build_object('n', 1, 'max', t1, 'levels_up', acceptance.setting('acceptance.tier1_levels_up'),
      'approvals', acceptance.setting('acceptance.tier1_approvals'));
  ELSIF mean <= t2 THEN
    RETURN jsonb_build_object('n', 2, 'max', t2, 'levels_up', acceptance.setting('acceptance.tier2_levels_up'),
      'approvals', acceptance.setting('acceptance.tier2_approvals'));
  END IF;
  RETURN jsonb_build_object('n', 3, 'max', NULL, 'levels_up', NULL, 'approvals', acceptance.setting('acceptance.tier3_approvals'));
END $$;

-- The BU levels_up above bu (null, or beyond the root: the root).
CREATE FUNCTION acceptance.tier_bu(bu uuid, levels_up integer) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN levels_up IS NULL THEN (SELECT r.id FROM iam.bu r WHERE r.parent_id IS NULL)
    ELSE (SELECT c.ancestor_id FROM iam.bu_closure c JOIN iam.bu a ON a.id = c.ancestor_id
          WHERE c.descendant_id = tier_bu.bu AND a.depth = greatest(0, (SELECT b.depth FROM iam.bu b WHERE b.id = tier_bu.bu) - levels_up)) END
$$;

-- Adds step kind to acceptance id.
CREATE FUNCTION acceptance.add_step(id uuid, kind text, actor uuid, reason text, data jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE h acceptance.acceptance;
BEGIN
  UPDATE acceptance.acceptance x SET steps = x.steps + 1 WHERE x.id = add_step.id RETURNING * INTO h;
  INSERT INTO acceptance.step (acceptance_id, n, bu_id, kind, actor, reason, data) VALUES (h.id, h.steps, h.bu_id, kind, actor, reason, coalesce(data, '{}'));
END $$;

-- A text of 1 to max characters (required) or none.
CREATE FUNCTION acceptance.text_ok(v text, max integer, required boolean) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN v IS NULL OR btrim(v) = '' THEN NOT required ELSE char_length(v) <= max END
$$;

CREATE FUNCTION acceptance.request(risk uuid, justification text, conditions text, expires_on date, renews uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := acceptance.actor();
  r register.risk;
  decision text;
  status text;
  exp jsonb;
  tier jsonb;
  tbu uuid;
  max_days integer := acceptance.setting('acceptance.max_duration_days');
  old acceptance.acceptance;
  id uuid := gen_random_uuid();
  pins jsonb;
BEGIN
  -- The risk, as the caller sees it in the register.
  SELECT * INTO r FROM register.risk x WHERE x.id = request.risk;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'acceptance: no such risk %', risk USING ERRCODE = 'P0002';
  END IF;
  IF NOT r.bu_id = ANY (authz.visible_bus('acceptance', 'write')) THEN
    RAISE EXCEPTION 'acceptance: requesting acceptance needs acceptance.request at the risk''s business unit' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF NOT acceptance.text_ok(justification, 5000, true) OR NOT acceptance.text_ok(conditions, 5000, false) THEN
    RAISE EXCEPTION 'acceptance: a justification (1 to 5,000 characters) is required; conditions are at most 5,000' USING ERRCODE = 'PF027',
      HINT = 'invalid_request', DETAIL = CASE WHEN NOT acceptance.text_ok(justification, 5000, true) THEN '/justification: is 1 to 5,000 characters'
                                              ELSE '/conditions: is at most 5,000 characters' END;
  END IF;
  IF r.state <> 'open' THEN
    RAISE EXCEPTION 'acceptance: the risk is closed' USING ERRCODE = 'PF027', HINT = 'risk_closed';
  END IF;
  SELECT t.decision INTO decision FROM register.treatment t WHERE t.risk_id = r.id;
  IF decision IS DISTINCT FROM 'accept' THEN
    RAISE EXCEPTION 'acceptance: the risk''s treatment decision is not accept' USING ERRCODE = 'PF027', HINT = 'not_accept';
  END IF;
  status := register.exposure_status(r.id) ->> 'status';
  IF status IS DISTINCT FROM 'current' THEN
    RAISE EXCEPTION 'acceptance: the risk''s exposure is %; only a current exposure can be accepted', coalesce(status, 'not visible')
      USING ERRCODE = 'PF027', HINT = 'exposure_not_current';
  END IF;
  IF expires_on IS NULL OR expires_on <= current_date OR expires_on > current_date + max_days THEN
    RAISE EXCEPTION 'acceptance: the expiry is after today and at most % days away', max_days USING ERRCODE = 'PF027', HINT = 'invalid_expiry',
      DETAIL = '/expires_on: is after today and at most ' || max_days || ' days away';
  END IF;
  IF renews IS NOT NULL THEN
    SELECT * INTO old FROM acceptance.acceptance x WHERE x.id = request.renews AND x.risk_id = r.id;
    IF NOT FOUND OR old.state <> 'active' THEN
      RAISE EXCEPTION 'acceptance: only an active acceptance of this risk is renewed' USING ERRCODE = 'PF027', HINT = 'not_renewable';
    END IF;
  ELSIF EXISTS (SELECT 1 FROM acceptance.acceptance x WHERE x.risk_id = r.id AND x.state IN ('active', 'suspended')) THEN
    RAISE EXCEPTION 'acceptance: the risk is accepted already; renew its acceptance' USING ERRCODE = 'PF027', HINT = 'already_accepted';
  END IF;
  exp := register.exposure_for(r.id);
  IF exp -> 'mean' IS NULL OR exp -> 'mean' = 'null'::jsonb THEN
    RAISE EXCEPTION 'acceptance: the risk''s exposure has no mean' USING ERRCODE = 'PF027', HINT = 'exposure_not_current';
  END IF;
  tier := acceptance.place((exp ->> 'mean')::numeric);
  tbu := acceptance.tier_bu(r.bu_id, (tier ->> 'levels_up')::integer);
  SELECT coalesce(jsonb_agg(jsonb_build_object('scenario_id', l.scenario_id, 'run_id', l.run_id, 'control_set', l.control_set,
    'run_scenario_version', l.run_scenario_version) ORDER BY l.scenario_id), '[]') INTO pins
  FROM register.risk_scenario l WHERE l.risk_id = r.id;
  BEGIN
    INSERT INTO acceptance.acceptance (id, bu_id, risk_id, renews, state, tier, tier_bu_id, approvals_needed, mean, expires_on, requested_by)
    VALUES (id, r.bu_id, r.id, renews, 'pending', (tier ->> 'n')::integer, tbu, (tier ->> 'approvals')::integer, (exp ->> 'mean')::numeric,
            expires_on, u);
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'acceptance: the risk has a pending request already' USING ERRCODE = 'PF027', HINT = 'pending_exists';
  END;
  PERFORM acceptance.add_step(id, 'requested', u, btrim(justification), jsonb_build_object(
    'justification', btrim(justification), 'conditions', nullif(btrim(coalesce(conditions, '')), ''), 'expires_on', expires_on,
    'risk_version', r.current_version, 'exposure', exp, 'pins', pins, 'exposure_aggregate_id', r.exposure_aggregate_id,
    'tier', tier || jsonb_build_object('bu_id', tbu), 'renews', renews));
  INSERT INTO acceptance.notice_outbox (kind, acceptance_id) VALUES ('decision_needed', id) ON CONFLICT DO NOTHING;
  PERFORM acceptance.emit('acceptance.requested', 'low', u::text, id, r.bu_id, jsonb_build_object('risk', r.id::text, 'tier', tier ->> 'n',
    'expires_on', expires_on::text, 'renews', coalesce(renews::text, '')));
  RETURN id;
END $$;

-- The caller's authority over acceptance h: approve there, and neither
-- the requester nor the risk's owner. Returns the caller.
CREATE FUNCTION acceptance.approver(h acceptance.acceptance) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := acceptance.actor();
BEGIN
  IF NOT iam.holds_permission(u, 'acceptance.approve', h.tier_bu_id) THEN
    IF h.bu_id = ANY (authz.visible_bus('acceptance', 'read')) THEN
      RAISE EXCEPTION 'acceptance: deciding this acceptance needs acceptance.approve at its tier''s business unit' USING ERRCODE = '42501', HINT = 'not_your_tier';
    END IF;
    RAISE EXCEPTION 'acceptance: no such acceptance %', h.id USING ERRCODE = 'P0002';
  END IF;
  IF u = h.requested_by OR u::text = register.exposure_for(h.risk_id) ->> 'owner' THEN
    RAISE EXCEPTION 'acceptance: the requester and the risk''s owner do not decide its acceptance' USING ERRCODE = '42501', HINT = 'separation_of_duties';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION acceptance.decide(id uuid, decision text, rationale text, expires_on date) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h acceptance.acceptance;
  u uuid;
  rnd integer;
  approvals integer;
  was text;
  old acceptance.acceptance;
BEGIN
  PERFORM acceptance.actor();
  SELECT * INTO h FROM acceptance.acceptance x WHERE x.id = decide.id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'acceptance: no such acceptance %', id USING ERRCODE = 'P0002';
  END IF;
  u := acceptance.approver(h);
  IF h.state NOT IN ('pending', 'suspended') THEN
    RAISE EXCEPTION 'acceptance: the acceptance is %, not awaiting a decision', h.state USING ERRCODE = 'PF027', HINT = 'not_pending';
  END IF;
  IF decision IS NULL OR decision NOT IN ('approve', 'reject') THEN
    RAISE EXCEPTION 'acceptance: the decision is approve or reject' USING ERRCODE = 'PF027', HINT = 'invalid_request', DETAIL = '/decision: is approve or reject';
  END IF;
  IF NOT acceptance.text_ok(rationale, 5000, true) THEN
    RAISE EXCEPTION 'acceptance: a rationale (1 to 5,000 characters) is required' USING ERRCODE = 'PF027', HINT = 'invalid_request',
      DETAIL = '/rationale: is 1 to 5,000 characters';
  END IF;
  -- This round: the steps since the request or the last review.
  SELECT max(s.n) INTO rnd FROM acceptance.step s WHERE s.acceptance_id = h.id AND s.kind IN ('requested', 'review_requested');
  IF EXISTS (SELECT 1 FROM acceptance.step s WHERE s.acceptance_id = h.id AND s.n > rnd AND s.kind IN ('approved', 'rejected') AND s.actor = u) THEN
    RAISE EXCEPTION 'acceptance: you have decided this acceptance already' USING ERRCODE = 'PF027', HINT = 'already_decided';
  END IF;
  was := h.state;
  IF decision = 'reject' THEN
    PERFORM acceptance.add_step(h.id, 'rejected', u, btrim(rationale), '{}');
    UPDATE acceptance.acceptance x SET state = 'ended', end_reason = 'rejected', ended_at = now() WHERE x.id = h.id;
    PERFORM acceptance.emit('acceptance.rejected', 'high', u::text, h.id, h.bu_id, jsonb_build_object('risk', h.risk_id::text, 'reason', btrim(rationale),
      'tier', h.tier::text));
    RETURN 'ended';
  END IF;
  IF expires_on IS NOT NULL THEN
    IF expires_on <= current_date OR expires_on > h.expires_on THEN
      RAISE EXCEPTION 'acceptance: an approval may only shorten the expiry, to a date after today' USING ERRCODE = 'PF027', HINT = 'invalid_expiry',
        DETAIL = '/expires_on: is after today and no later than ' || h.expires_on;
    END IF;
    UPDATE acceptance.acceptance x SET expires_on = decide.expires_on WHERE x.id = h.id;
  END IF;
  PERFORM acceptance.add_step(h.id, 'approved', u, btrim(rationale), jsonb_build_object('expires_on', expires_on));
  PERFORM acceptance.emit('acceptance.approved', 'high', u::text, h.id, h.bu_id, jsonb_build_object('risk', h.risk_id::text, 'reason', btrim(rationale),
    'tier', h.tier::text));
  SELECT count(*) INTO approvals FROM acceptance.step s WHERE s.acceptance_id = h.id AND s.n > rnd AND s.kind = 'approved';
  IF approvals < h.approvals_needed THEN
    RETURN h.state;
  END IF;
  -- Enough: active. A renewal first ends the acceptance it renews.
  IF h.renews IS NOT NULL THEN
    SELECT * INTO old FROM acceptance.acceptance x WHERE x.id = h.renews FOR UPDATE;
    IF old.state IN ('active', 'suspended') THEN
      UPDATE acceptance.acceptance x SET state = 'ended', end_reason = 'replaced', ended_at = now() WHERE x.id = old.id;
      PERFORM acceptance.add_step(old.id, 'replaced', u, NULL, jsonb_build_object('by', h.id));
      PERFORM acceptance.emit('acceptance.replaced', 'low', u::text, old.id, old.bu_id, jsonb_build_object('risk', old.risk_id::text, 'by', h.id::text));
    END IF;
  END IF;
  UPDATE acceptance.acceptance x SET state = 'active', activated_at = now(), approved_bu_id = (SELECT r.bu_id FROM register.risk r WHERE r.id = h.risk_id)
  WHERE x.id = h.id;
  IF was = 'suspended' THEN
    PERFORM acceptance.add_step(h.id, 'reactivated', u, NULL, '{}');
    PERFORM acceptance.emit('acceptance.reactivated', 'low', u::text, h.id, h.bu_id, jsonb_build_object('risk', h.risk_id::text, 'tier', h.tier::text));
  ELSE
    PERFORM acceptance.add_step(h.id, 'activated', u, NULL, '{}');
    PERFORM acceptance.emit('acceptance.activated', 'low', u::text, h.id, h.bu_id, jsonb_build_object('risk', h.risk_id::text, 'tier', h.tier::text,
      'expires_on', (SELECT x.expires_on FROM acceptance.acceptance x WHERE x.id = h.id)::text));
  END IF;
  INSERT INTO acceptance.notice_outbox (kind, user_id, acceptance_id) VALUES ('decided', h.requested_by, h.id) ON CONFLICT DO NOTHING;
  RETURN 'active';
END $$;

CREATE FUNCTION acceptance.withdraw(id uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := acceptance.actor(); h acceptance.acceptance;
BEGIN
  SELECT * INTO h FROM acceptance.acceptance x WHERE x.id = withdraw.id AND x.bu_id = ANY (authz.visible_bus('acceptance', 'read')) FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'acceptance: no such acceptance %', id USING ERRCODE = 'P0002';
  END IF;
  IF h.requested_by <> u THEN
    RAISE EXCEPTION 'acceptance: only the requester withdraws a request' USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  IF h.state <> 'pending' THEN
    RAISE EXCEPTION 'acceptance: only a pending request is withdrawn' USING ERRCODE = 'PF027', HINT = 'not_pending';
  END IF;
  IF NOT acceptance.text_ok(reason, 1000, true) THEN
    RAISE EXCEPTION 'acceptance: a reason is required' USING ERRCODE = 'PF027', HINT = 'invalid_request', DETAIL = '/reason: is 1 to 1,000 characters';
  END IF;
  PERFORM acceptance.add_step(h.id, 'withdrawn', u, btrim(reason), '{}');
  UPDATE acceptance.acceptance x SET state = 'ended', end_reason = 'withdrawn', ended_at = now() WHERE x.id = h.id;
  PERFORM acceptance.emit('acceptance.withdrawn', 'low', u::text, h.id, h.bu_id, jsonb_build_object('risk', h.risk_id::text, 'reason', btrim(reason)));
END $$;

CREATE FUNCTION acceptance.revoke(id uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid; h acceptance.acceptance;
BEGIN
  PERFORM acceptance.actor();
  SELECT * INTO h FROM acceptance.acceptance x WHERE x.id = revoke.id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'acceptance: no such acceptance %', id USING ERRCODE = 'P0002';
  END IF;
  u := acceptance.approver(h);
  IF h.state NOT IN ('active', 'suspended') THEN
    RAISE EXCEPTION 'acceptance: only an active or suspended acceptance is revoked' USING ERRCODE = 'PF027', HINT = 'not_active';
  END IF;
  IF NOT acceptance.text_ok(reason, 1000, true) THEN
    RAISE EXCEPTION 'acceptance: a reason is required' USING ERRCODE = 'PF027', HINT = 'invalid_request', DETAIL = '/reason: is 1 to 1,000 characters';
  END IF;
  PERFORM acceptance.add_step(h.id, 'revoked', u, btrim(reason), '{}');
  UPDATE acceptance.acceptance x SET state = 'ended', end_reason = 'revoked', ended_at = now() WHERE x.id = h.id;
  PERFORM acceptance.emit('acceptance.revoked', 'high', u::text, h.id, h.bu_id, jsonb_build_object('risk', h.risk_id::text, 'reason', btrim(reason)));
END $$;

-- A risk closed or moved (register.risk): its acceptances follow.
CREATE FUNCTION acceptance.risk_after_update() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a acceptance.acceptance; u uuid := (authz.ctx_scope()).user_id;
BEGIN
  IF NEW.state = 'closed' AND OLD.state = 'open' THEN
    FOR a IN SELECT * FROM acceptance.acceptance x WHERE x.risk_id = NEW.id AND x.state IN ('pending', 'active', 'suspended') FOR UPDATE LOOP
      PERFORM acceptance.add_step(a.id, 'ended', u, 'the risk was closed', jsonb_build_object('end_reason', 'risk_closed'));
      UPDATE acceptance.acceptance x SET state = 'ended', end_reason = 'risk_closed', ended_at = now() WHERE x.id = a.id;
      PERFORM acceptance.emit('acceptance.ended', 'low', coalesce(u::text, 'system:risk'), a.id, a.bu_id,
        jsonb_build_object('risk', NEW.id::text, 'end_reason', 'risk_closed'));
    END LOOP;
  END IF;
  IF NEW.bu_id IS DISTINCT FROM OLD.bu_id THEN
    UPDATE acceptance.step s SET bu_id = NEW.bu_id WHERE s.acceptance_id IN (SELECT x.id FROM acceptance.acceptance x WHERE x.risk_id = NEW.id);
    UPDATE acceptance.acceptance x SET bu_id = NEW.bu_id,
      tier_bu_id = CASE WHEN x.state IN ('pending', 'suspended')
        THEN acceptance.tier_bu(NEW.bu_id, (SELECT (s.data #>> '{tier,levels_up}')::integer FROM acceptance.step s
                                            WHERE s.acceptance_id = x.id AND s.kind IN ('requested', 'review_requested') ORDER BY s.n DESC LIMIT 1))
        ELSE x.tier_bu_id END
    WHERE x.risk_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION acceptance.actor(), acceptance.emit(text, text, text, uuid, uuid, jsonb), acceptance.setting(text), acceptance.place(numeric),
  acceptance.tier_bu(uuid, integer), acceptance.add_step(uuid, text, uuid, text, jsonb), acceptance.text_ok(text, integer, boolean),
  acceptance.request(uuid, text, text, date, uuid), acceptance.approver(acceptance.acceptance), acceptance.decide(uuid, text, text, date),
  acceptance.withdraw(uuid, text), acceptance.revoke(uuid, text), acceptance.risk_after_update() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.request(uuid, text, text, date, uuid), acceptance.decide(uuid, text, text, date), acceptance.withdraw(uuid, text),
  acceptance.revoke(uuid, text), acceptance.place(numeric), acceptance.tier_bu(uuid, integer) TO app_rw;
GRANT EXECUTE ON FUNCTION acceptance.risk_after_update() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

CREATE TRIGGER acceptance_follows AFTER UPDATE OF state, bu_id ON register.risk FOR EACH ROW EXECUTE FUNCTION acceptance.risk_after_update();
