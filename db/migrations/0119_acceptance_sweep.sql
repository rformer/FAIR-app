-- F-008 T-06 (F-008-AC-09, AC-10, AC-13; design §3.2, §3.6): the
-- acceptance job, run by the risk service's leader every minute (no signed
-- context: the system acts, attributed system:risk):
--   * expiry: an active or suspended acceptance on or past its expiry date
--     ends as expired; its owner and requester are told;
--   * notices: 30, 14 and 7 days before expiry, to the risk's owner and the
--     requester, each once; after an outage only the tightest lead that
--     still applies is sent (the outbox's unique key keeps each once);
--   * a higher tier (AC-13): an active acceptance whose risk's current
--     exposure now falls in a higher tier than its own is suspended, and a
--     review opened at that tier (its BU, approvals and settings in the
--     review_requested step); its approvals reactivate it (decide). A stale
--     exposure, or a lower tier, changes nothing.
-- Returns {expired, notices, suspended}.
--
-- notice_outbox gains tier: a suspension's notices (suspended to the owner
-- and requester, decision_needed for the approvers) name the tier it was
-- suspended into, so a later suspension into a higher tier is queued again
-- while each stays once (design §3.6).

ALTER TABLE acceptance.notice_outbox ADD COLUMN tier integer CHECK (tier BETWEEN 1 AND 3);
ALTER TABLE acceptance.notice_outbox DROP CONSTRAINT notice_outbox_acceptance_id_kind_user_id_lead_days_key;
ALTER TABLE acceptance.notice_outbox ADD CONSTRAINT notice_outbox_once UNIQUE NULLS NOT DISTINCT (acceptance_id, kind, user_id, lead_days, tier);

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;

CREATE FUNCTION acceptance.notify(id uuid, kind text, lead integer, tier integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE h acceptance.acceptance; owner uuid; n integer := 0; c integer; u uuid;
BEGIN
  SELECT * INTO h FROM acceptance.acceptance x WHERE x.id = notify.id;
  owner := (register.exposure_for(h.risk_id) ->> 'owner')::uuid;
  FOREACH u IN ARRAY ARRAY(SELECT DISTINCT v FROM unnest(ARRAY[owner, h.requested_by]) v WHERE v IS NOT NULL) LOOP
    INSERT INTO acceptance.notice_outbox (kind, user_id, acceptance_id, lead_days, tier) VALUES (kind, u, h.id, lead, tier) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS c = ROW_COUNT;
    n := n + c;
  END LOOP;
  RETURN n;
END $$;

CREATE FUNCTION acceptance.sweep() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  a acceptance.acceptance;
  expired integer := 0;
  notices integer := 0;
  suspended integer := 0;
  exp jsonb;
  placed jsonb;
  lead integer;
  tbu uuid;
BEGIN
  -- Expiry (AC-09).
  FOR a IN SELECT * FROM acceptance.acceptance x WHERE x.state IN ('active', 'suspended') AND x.expires_on <= current_date FOR UPDATE SKIP LOCKED LOOP
    PERFORM acceptance.add_step(a.id, 'expired', NULL, NULL, jsonb_build_object('expires_on', a.expires_on));
    UPDATE acceptance.acceptance x SET state = 'expired', ended_at = now() WHERE x.id = a.id;
    PERFORM acceptance.emit('acceptance.expired', 'low', 'system:risk', a.id, a.bu_id, jsonb_build_object('risk', a.risk_id::text, 'expires_on', a.expires_on::text));
    notices := notices + acceptance.notify(a.id, 'expired', NULL, NULL);
    expired := expired + 1;
  END LOOP;
  -- Notices before expiry (AC-10): the tightest lead that applies, once.
  FOR a IN SELECT * FROM acceptance.acceptance x WHERE x.state = 'active' AND x.expires_on - current_date <= 30 LOOP
    lead := CASE WHEN a.expires_on - current_date <= 7 THEN 7 WHEN a.expires_on - current_date <= 14 THEN 14 ELSE 30 END;
    notices := notices + acceptance.notify(a.id, 'expiring', lead, NULL);
  END LOOP;
  -- A higher tier (AC-13): suspended, a review opened at that tier.
  FOR a IN SELECT * FROM acceptance.acceptance x WHERE x.state = 'active' FOR UPDATE SKIP LOCKED LOOP
    exp := register.exposure_for(a.risk_id);
    CONTINUE WHEN exp ->> 'status' IS DISTINCT FROM 'current' OR exp -> 'mean' IS NULL OR exp -> 'mean' = 'null'::jsonb;
    placed := acceptance.place((exp ->> 'mean')::numeric);
    CONTINUE WHEN (placed ->> 'n')::integer <= a.tier;
    tbu := acceptance.tier_bu(a.bu_id, (placed ->> 'levels_up')::integer);
    PERFORM acceptance.add_step(a.id, 'suspended', NULL, 'the exposure is now in a higher tier', jsonb_build_object('exposure', exp, 'from_tier', a.tier));
    UPDATE acceptance.acceptance x SET state = 'suspended', tier = (placed ->> 'n')::integer, tier_bu_id = tbu, approvals_needed = (placed ->> 'approvals')::integer,
      mean = (exp ->> 'mean')::numeric WHERE x.id = a.id;
    PERFORM acceptance.add_step(a.id, 'review_requested', NULL, NULL, jsonb_build_object('exposure', exp, 'tier', placed || jsonb_build_object('bu_id', tbu)));
    PERFORM acceptance.emit('acceptance.suspended', 'low', 'system:risk', a.id, a.bu_id, jsonb_build_object('risk', a.risk_id::text,
      'from_tier', a.tier::text, 'tier', placed ->> 'n'));
    PERFORM acceptance.emit('acceptance.review_requested', 'low', 'system:risk', a.id, a.bu_id, jsonb_build_object('risk', a.risk_id::text,
      'tier', placed ->> 'n'));
    notices := notices + acceptance.notify(a.id, 'suspended', NULL, (placed ->> 'n')::integer);
    INSERT INTO acceptance.notice_outbox (kind, acceptance_id, tier) VALUES ('decision_needed', a.id, (placed ->> 'n')::integer) ON CONFLICT DO NOTHING;
    suspended := suspended + 1;
  END LOOP;
  RETURN jsonb_build_object('expired', expired, 'notices', notices, 'suspended', suspended);
END $$;

REVOKE ALL ON FUNCTION acceptance.notify(uuid, text, integer, integer), acceptance.sweep() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.sweep() TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;
