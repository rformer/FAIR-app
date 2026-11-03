-- F-001 T-24b (AC-12, AC-13; design §3, §5.1): group membership from login
-- claims, for IdPs without SCIM (and JIT users).
--
--   * iam.grp.source: 'scim' (T-21, every group so far) or 'claim'. A claim
--     group belongs to one IdP and is declared by an administrator with the
--     claim value the IdP sends (a group name, path or object id) and a
--     display name (idp.manage, reason, audited high). Group-to-role
--     mappings (T-24) take claim groups like any other group.
--   * At each sign-in, iam.login_group_claims sets the user's membership in
--     that IdP's claim groups from the claim: declared values join, the
--     others leave; values nobody declared are ignored. An absent or empty
--     claim means no claim groups. A claim the IdP could not send whole
--     (Entra overage) or that FAIR will not read (over 500 values or a value
--     over 256 characters) leaves memberships as they were and is audited;
--     the sign-in goes on. The T-24 triggers grant and revoke the mapped
--     assignments in the same transaction.
--   * SCIM never sees or changes claim groups, and claims never change SCIM
--     groups: the SCIM functions are recreated with source = 'scim'.
--   * Removing a claim group marks it deleted (as SCIM DELETE does; the
--     history stays) and is refused while a live mapping uses it.

ALTER TABLE iam.grp ADD COLUMN source text NOT NULL DEFAULT 'scim' CHECK (source IN ('scim', 'claim')),
                    ADD COLUMN claim_value text,
                    ADD CONSTRAINT grp_claim_value CHECK ((source = 'claim') = (claim_value IS NOT NULL)),
                    ADD CONSTRAINT grp_claim_value_len CHECK (claim_value IS NULL OR length(claim_value) BETWEEN 1 AND 256),
                    ADD CONSTRAINT grp_claim_idp CHECK (source <> 'claim' OR idp_id IS NOT NULL);
CREATE UNIQUE INDEX grp_claim_value_live ON iam.grp (idp_id, claim_value) WHERE source = 'claim' AND scim_deleted_at IS NULL;

-- SCIM: only SCIM groups (otherwise as in 0044) ------------------------------

CREATE OR REPLACE FUNCTION iam.scim_user_list(th bytea, one uuid)
RETURNS TABLE (id uuid, version integer, resource jsonb, created_at timestamptz, updated_at timestamptz, groups jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  idp uuid := iam.scim_idp(th);
BEGIN
  RETURN QUERY
  SELECT u.id, u.scim_version, u.scim_resource, u.created_at, coalesce(u.scim_updated_at, u.created_at),
    coalesce((SELECT jsonb_agg(jsonb_build_object('value', g.id, 'display', g.display_name) ORDER BY g.display_name, g.id)
              FROM iam.grp_member m JOIN iam.grp g ON g.id = m.grp_id AND g.scim_deleted_at IS NULL AND g.source = 'scim'
              WHERE m.user_id = u.id), '[]'::jsonb)
  FROM iam.app_user u
  WHERE u.idp_id = idp AND u.source = 'scim' AND u.scim_deleted_at IS NULL AND u.scim_resource IS NOT NULL
    AND (one IS NULL OR u.id = one)
  ORDER BY u.created_at, u.id;
END $$;

CREATE OR REPLACE FUNCTION iam.scim_group_list(th bytea, one uuid)
RETURNS TABLE (id uuid, version integer, resource jsonb, created_at timestamptz, updated_at timestamptz, members jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  idp uuid := iam.scim_idp(th);
BEGIN
  RETURN QUERY
  SELECT g.id, g.scim_version, g.scim_resource, g.created_at, coalesce(g.scim_updated_at, g.created_at),
    coalesce((SELECT jsonb_agg(jsonb_build_object('value', u.id, 'display', u.display_name) ORDER BY u.id)
              FROM iam.grp_member m JOIN iam.app_user u ON u.id = m.user_id WHERE m.grp_id = g.id), '[]'::jsonb)
  FROM iam.grp g
  WHERE g.idp_id = idp AND g.source = 'scim' AND g.scim_deleted_at IS NULL AND (one IS NULL OR g.id = one)
  ORDER BY g.created_at, g.id;
END $$;

CREATE OR REPLACE FUNCTION iam.scim_group_write(th bytea, gid uuid, if_version integer, resource jsonb, display_name text,
  external_id text, members uuid[])
RETURNS TABLE (id uuid, version integer, created_at timestamptz, updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  idp     uuid := iam.scim_idp(th);
  g       iam.grp;
  was     iam.grp;
  bad     uuid;
  added   integer;
  removed integer;
BEGIN
  IF display_name IS NULL OR btrim(display_name) = '' THEN
    RAISE EXCEPTION 'displayName is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT m INTO bad FROM unnest(coalesce(members, '{}')) m
  WHERE NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = m AND u.idp_id = idp AND u.source = 'scim' AND u.scim_deleted_at IS NULL)
  LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'member % is not a user of this provider', bad USING ERRCODE = 'PF004';
  END IF;
  IF gid IS NULL THEN
    INSERT INTO iam.grp (display_name, external_id, idp_id, scim_resource, scim_version, scim_updated_at, source)
    VALUES (btrim(display_name), external_id, idp, resource, 1, now(), 'scim') RETURNING * INTO g;
  ELSE
    SELECT * INTO was FROM iam.grp x WHERE x.id = gid AND x.idp_id = idp AND x.source = 'scim' AND x.scim_deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'no group %', gid USING ERRCODE = 'PF003';
    END IF;
    IF if_version IS NOT NULL AND if_version <> was.scim_version THEN
      RAISE EXCEPTION 'the group changed (version %)', was.scim_version USING ERRCODE = 'PF010';
    END IF;
    UPDATE iam.grp x SET display_name = btrim(scim_group_write.display_name), external_id = scim_group_write.external_id,
      scim_resource = resource, scim_version = x.scim_version + 1, scim_updated_at = now()
    WHERE x.id = gid RETURNING * INTO g;
  END IF;
  -- Only the difference, so the scope outbox sees real changes.
  DELETE FROM iam.grp_member m WHERE m.grp_id = g.id AND m.user_id <> ALL (coalesce(members, '{}'));
  GET DIAGNOSTICS removed = ROW_COUNT;
  INSERT INTO iam.grp_member (grp_id, user_id)
  SELECT DISTINCT g.id, m FROM unnest(coalesce(members, '{}')) m ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS added = ROW_COUNT;
  PERFORM iam.scim_event(CASE WHEN gid IS NULL THEN 'scim.group.created' ELSE 'scim.group.updated' END, 'info', th, idp,
    'group:' || g.id, jsonb_build_object('display_name', g.display_name, 'members_added', added, 'members_removed', removed));
  RETURN QUERY SELECT g.id, g.scim_version, g.created_at, g.scim_updated_at;
END $$;

CREATE OR REPLACE FUNCTION iam.scim_group_delete(th bytea, gid uuid, if_version integer) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  idp uuid := iam.scim_idp(th);
  was iam.grp;
BEGIN
  SELECT * INTO was FROM iam.grp x WHERE x.id = gid AND x.idp_id = idp AND x.source = 'scim' AND x.scim_deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no group %', gid USING ERRCODE = 'PF003';
  END IF;
  IF if_version IS NOT NULL AND if_version <> was.scim_version THEN
    RAISE EXCEPTION 'the group changed (version %)', was.scim_version USING ERRCODE = 'PF010';
  END IF;
  DELETE FROM iam.grp_member m WHERE m.grp_id = gid;
  UPDATE iam.grp x SET scim_deleted_at = now(), scim_version = x.scim_version + 1 WHERE x.id = gid;
  PERFORM iam.scim_event('scim.group.deleted', 'high', th, idp, 'group:' || gid, jsonb_build_object('display_name', was.display_name));
END $$;

-- A SCIM user deleted leaves its SCIM groups only; its claim groups follow
-- its status (inactive members are skipped by the mappings) and its next
-- sign-in, which a deleted user does not have.

-- Declaring claim groups (the IdP API, signed context) ----------------------

CREATE FUNCTION iam.claim_group_event(event text, actor uuid, g iam.grp, reason text) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', 'high', 'actor', actor::text, 'target', 'group:' || g.id,
    'reason', reason, 'attributes', jsonb_build_object('idp', g.idp_id, 'claim_value', g.claim_value, 'display_name', g.display_name)));
$$;

-- idp.view
CREATE FUNCTION iam.claim_group_list(idp uuid)
RETURNS TABLE (id uuid, claim_value text, display_name text, created_at timestamptz, members integer, mappings integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('idp.view');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.idp i WHERE i.id = claim_group_list.idp) THEN
    RAISE EXCEPTION 'no IdP %', idp USING ERRCODE = 'P0002';
  END IF;
  RETURN QUERY
  SELECT g.id, g.claim_value, g.display_name, g.created_at,
    (SELECT count(*)::integer FROM iam.grp_member m WHERE m.grp_id = g.id),
    (SELECT count(*)::integer FROM iam.group_role_mapping x WHERE x.grp_id = g.id AND x.removed_at IS NULL)
  FROM iam.grp g
  WHERE g.idp_id = claim_group_list.idp AND g.source = 'claim' AND g.scim_deleted_at IS NULL
  ORDER BY lower(g.display_name), g.id;
END $$;

-- idp.manage; P0002 no IdP, PF004 bad value or name, 23505 value declared.
CREATE FUNCTION iam.claim_group_add(idp uuid, value text, name text, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('idp.manage');
  g iam.grp;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.idp i WHERE i.id = claim_group_add.idp) THEN
    RAISE EXCEPTION 'no IdP %', idp USING ERRCODE = 'P0002';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  IF value IS NULL OR value = '' OR length(value) > 256 OR value ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'a claim value is 1 to 256 characters, without control characters' USING ERRCODE = 'PF004';
  END IF;
  IF name IS NULL OR btrim(name) = '' OR length(btrim(name)) > 200 THEN
    RAISE EXCEPTION 'a display name is 1 to 200 characters' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO iam.grp (display_name, idp_id, source, claim_value) VALUES (btrim(name), idp, 'claim', value) RETURNING * INTO g;
  PERFORM iam.claim_group_event('idp.claim_group_added', u, g, reason);
  RETURN g.id;
END $$;

-- idp.manage; P0002 no such claim group, PF003 a live mapping uses it.
CREATE FUNCTION iam.claim_group_remove(idp uuid, gid uuid, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('idp.manage');
  g iam.grp;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO g FROM iam.grp x
  WHERE x.id = gid AND x.idp_id = claim_group_remove.idp AND x.source = 'claim' AND x.scim_deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no claim group %', gid USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.group_role_mapping m WHERE m.grp_id = gid AND m.removed_at IS NULL) THEN
    RAISE EXCEPTION 'claim group % is mapped to roles; remove its mappings first', g.display_name USING ERRCODE = 'PF003';
  END IF;
  DELETE FROM iam.grp_member m WHERE m.grp_id = gid;
  UPDATE iam.grp x SET scim_deleted_at = now() WHERE x.id = gid RETURNING * INTO g;
  PERFORM iam.claim_group_event('idp.claim_group_removed', u, g, reason);
END $$;

-- At sign-in (the iam service, app_rw) ---------------------------------------

-- Sets uid's membership in idp's claim groups. claim: 'present' (vals is
-- the claim, NULL or empty meaning none), 'absent' (no claim: none),
-- 'overage' or 'unreadable' (memberships unchanged, audited). Returns what
-- changed: {"joined": [...], "left": [...]} (group ids), or {"kept": true}.
CREATE FUNCTION iam.login_group_claims(uid uuid, idp uuid, claim text, vals text[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u      iam.app_user;
  want   uuid[];
  joined uuid[];
  gone   uuid[];
BEGIN
  IF claim NOT IN ('present', 'absent', 'overage', 'unreadable') THEN
    RAISE EXCEPTION 'unknown claim status %', claim USING ERRCODE = '22023';
  END IF;
  SELECT * INTO u FROM iam.app_user x WHERE x.id = uid;
  IF NOT FOUND OR u.idp_id IS DISTINCT FROM idp THEN
    RAISE EXCEPTION 'user % does not sign in with IdP %', uid, idp USING ERRCODE = 'PF004';
  END IF;
  IF claim IN ('overage', 'unreadable') THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'authn.group_claims_unreadable', 'severity', 'high', 'actor', 'system:iam',
      'target', 'user:' || uid, 'reason', CASE claim WHEN 'overage' THEN 'the IdP sent a group overage instead of the groups'
        ELSE 'the group claim is over 500 values, has a value over 256 characters, or is not a list of strings' END,
      'attributes', jsonb_build_object('idp', idp, 'claim', claim)));
    RETURN jsonb_build_object('kept', true);
  END IF;
  IF claim = 'present' AND (cardinality(vals) > 500 OR EXISTS (SELECT 1 FROM unnest(vals) v WHERE v IS NULL OR length(v) > 256)) THEN
    RAISE EXCEPTION 'a group claim holds at most 500 values of at most 256 characters' USING ERRCODE = 'PF004';
  END IF;
  want := ARRAY(SELECT g.id FROM iam.grp g
                WHERE g.idp_id = idp AND g.source = 'claim' AND g.scim_deleted_at IS NULL
                  AND claim = 'present' AND g.claim_value = ANY (coalesce(vals, '{}')));
  WITH d AS (
    DELETE FROM iam.grp_member m USING iam.grp g
    WHERE m.user_id = uid AND g.id = m.grp_id AND g.idp_id = idp AND g.source = 'claim' AND m.grp_id <> ALL (want)
    RETURNING m.grp_id)
  SELECT coalesce(array_agg(d.grp_id ORDER BY d.grp_id), '{}') INTO gone FROM d;
  WITH i AS (
    INSERT INTO iam.grp_member (grp_id, user_id) SELECT w, uid FROM unnest(want) w ON CONFLICT DO NOTHING RETURNING grp_id)
  SELECT coalesce(array_agg(i.grp_id ORDER BY i.grp_id), '{}') INTO joined FROM i;
  IF cardinality(joined) > 0 OR cardinality(gone) > 0 THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'authn.group_claims_applied', 'severity', 'info', 'actor', 'system:iam',
      'target', 'user:' || uid, 'attributes', jsonb_build_object('idp', idp, 'claim', claim, 'joined', to_jsonb(joined), 'left', to_jsonb(gone))));
  END IF;
  RETURN jsonb_build_object('joined', to_jsonb(joined), 'left', to_jsonb(gone));
END $$;

REVOKE ALL ON FUNCTION iam.claim_group_event(text, uuid, iam.grp, text), iam.claim_group_list(uuid),
  iam.claim_group_add(uuid, text, text, text), iam.claim_group_remove(uuid, uuid, text),
  iam.login_group_claims(uuid, uuid, text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.claim_group_list(uuid), iam.claim_group_add(uuid, text, text, text),
  iam.claim_group_remove(uuid, uuid, text), iam.login_group_claims(uuid, uuid, text, text[]) TO app_rw;
