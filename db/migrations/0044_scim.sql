-- F-001 T-21 (AC-07, AC-08; design §3, §6): the SCIM 2.0 service provider.
--
--   * iam.api_token (design §3): SCIM bearer tokens, one IdP each, stored as
--     SHA-256 of 256-bit random tokens; issued, listed and revoked through
--     the iam API with scim.manage (signed context), audited (high); they
--     expire (at most a year) and are rotated by issuing a new one.
--   * Users and groups provisioned by SCIM belong to the token's IdP. Each
--     keeps its SCIM resource (minus id, meta and members), a version for
--     ETags, and is deleted softly (SCIM DELETE): it disappears from SCIM,
--     the user is disabled and loses its identifiers and memberships, the
--     history stays.
--   * iam.scim_*: the SCIM functions for the iam service (app_rw). Each
--     takes the token's hash and acts only for that token's IdP, so holding
--     app_rw is not enough to provision. Writes are audited (scim.*).
--   * app_user.external_id stays the login subject; SCIM's externalId is
--     kept in scim_external_id.

CREATE TABLE iam.api_token (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_kind    text        NOT NULL CHECK (owner_kind IN ('scim', 'service_account')),
  owner_id      uuid        NOT NULL,
  name          text        NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
  token_hash    bytea       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  prefix        text        NOT NULL CHECK (prefix ~ '^[A-Za-z0-9_-]{4,16}$'),
  scopes        text[]      NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  created_by    uuid        REFERENCES iam.app_user (id),
  expires_at    timestamptz NOT NULL,
  last_used_at  timestamptz,
  revoked_at    timestamptz,
  revoked_by    uuid        REFERENCES iam.app_user (id),
  CHECK (expires_at > created_at)
);
CREATE INDEX api_token_owner ON iam.api_token (owner_kind, owner_id);
REVOKE ALL ON iam.api_token FROM PUBLIC;

ALTER TABLE iam.app_user ADD COLUMN user_name text,
                         ADD COLUMN scim_external_id text,
                         ADD COLUMN scim_resource jsonb,
                         ADD COLUMN scim_version integer NOT NULL DEFAULT 1,
                         ADD COLUMN scim_updated_at timestamptz,
                         ADD COLUMN scim_deleted_at timestamptz;
CREATE UNIQUE INDEX app_user_idp_user_name ON iam.app_user (idp_id, lower(user_name)) WHERE user_name IS NOT NULL;

ALTER TABLE iam.grp ADD COLUMN idp_id uuid REFERENCES iam.idp (id),
                    ADD COLUMN scim_resource jsonb,
                    ADD COLUMN scim_version integer NOT NULL DEFAULT 1,
                    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
                    ADD COLUMN scim_updated_at timestamptz,
                    ADD COLUMN scim_deleted_at timestamptz;

-- The IdP of a live SCIM token (PF007 otherwise); notes its use.
CREATE FUNCTION iam.scim_idp(th bytea) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t iam.api_token;
BEGIN
  SELECT * INTO t FROM iam.api_token x
  WHERE x.token_hash = th AND x.owner_kind = 'scim' AND x.revoked_at IS NULL AND x.expires_at > now();
  IF NOT FOUND OR NOT EXISTS (SELECT 1 FROM iam.idp i WHERE i.id = t.owner_id) THEN
    RAISE EXCEPTION 'invalid SCIM token' USING ERRCODE = 'PF007';
  END IF;
  IF t.last_used_at IS NULL OR t.last_used_at < now() - interval '60 seconds' THEN
    UPDATE iam.api_token x SET last_used_at = now() WHERE x.id = t.id;
  END IF;
  RETURN t.owner_id;
END $$;

-- The token's IdP and which SCIM attribute is its users' login subject
-- (the IdP setting scim_subject_attribute: userName by default, or
-- externalId).
CREATE FUNCTION iam.scim_provider(th bytea) RETURNS TABLE (idp uuid, subject_attribute text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT i.id, coalesce(i.metadata->>'scim_subject_attribute', 'userName') FROM iam.idp i WHERE i.id = iam.scim_idp(th);
$$;

CREATE FUNCTION iam.scim_actor(th bytea) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT 'scim:' || x.id FROM iam.api_token x WHERE x.token_hash = th;
$$;

CREATE FUNCTION iam.scim_event(event text, severity text, th bytea, idp uuid, target text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', iam.scim_actor(th), 'target', target,
    'attributes', jsonb_build_object('idp', idp) || coalesce(attrs, '{}')));
$$;

-- Users ------------------------------------------------------------------

CREATE FUNCTION iam.scim_user_list(th bytea, one uuid)
RETURNS TABLE (id uuid, version integer, resource jsonb, created_at timestamptz, updated_at timestamptz, groups jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  idp uuid := iam.scim_idp(th);
BEGIN
  RETURN QUERY
  SELECT u.id, u.scim_version, u.scim_resource, u.created_at, coalesce(u.scim_updated_at, u.created_at),
    coalesce((SELECT jsonb_agg(jsonb_build_object('value', g.id, 'display', g.display_name) ORDER BY g.display_name, g.id)
              FROM iam.grp_member m JOIN iam.grp g ON g.id = m.grp_id AND g.scim_deleted_at IS NULL
              WHERE m.user_id = u.id), '[]'::jsonb)
  FROM iam.app_user u
  WHERE u.idp_id = idp AND u.source = 'scim' AND u.scim_deleted_at IS NULL AND u.scim_resource IS NOT NULL
    AND (one IS NULL OR u.id = one)
  ORDER BY u.created_at, u.id;
END $$;

-- Creates (uid NULL) or replaces a user. if_version: the ETag the client
-- holds (NULL: no precondition). PF003 not found, PF010 version mismatch.
CREATE FUNCTION iam.scim_user_write(th bytea, uid uuid, if_version integer, resource jsonb, user_name text, subject text,
  external_id text, email text, display_name text, active boolean)
RETURNS TABLE (id uuid, version integer, created_at timestamptz, updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  idp uuid := iam.scim_idp(th);
  u   iam.app_user;
  was iam.app_user;
BEGIN
  IF user_name IS NULL OR btrim(user_name) = '' OR email IS NULL OR btrim(email) = '' THEN
    RAISE EXCEPTION 'userName and an email are required' USING ERRCODE = 'PF004';
  END IF;
  IF uid IS NULL THEN
    INSERT INTO iam.app_user (idp_id, external_id, email, display_name, status, source, user_name, scim_external_id,
                              scim_resource, scim_version, scim_updated_at, disabled_reason)
    VALUES (idp, subject, btrim(email), coalesce(display_name, ''), CASE WHEN active THEN 'active' ELSE 'disabled' END::iam.user_status,
            'scim', btrim(user_name), external_id, resource, 1, now(), CASE WHEN active THEN NULL ELSE 'scim' END)
    RETURNING * INTO u;
    PERFORM iam.scim_event('scim.user.created', 'info', th, idp, 'user:' || u.id,
      jsonb_build_object('user_name', u.user_name, 'active', active));
  ELSE
    SELECT * INTO was FROM iam.app_user x
    WHERE x.id = uid AND x.idp_id = idp AND x.source = 'scim' AND x.scim_deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'no user %', uid USING ERRCODE = 'PF003';
    END IF;
    IF if_version IS NOT NULL AND if_version <> was.scim_version THEN
      RAISE EXCEPTION 'the user changed (version %)', was.scim_version USING ERRCODE = 'PF010';
    END IF;
    UPDATE iam.app_user x SET external_id = subject, email = btrim(scim_user_write.email),
      display_name = coalesce(scim_user_write.display_name, ''), user_name = btrim(scim_user_write.user_name),
      scim_external_id = scim_user_write.external_id, scim_resource = resource, scim_version = x.scim_version + 1,
      scim_updated_at = now(),
      status = CASE WHEN NOT active AND x.status = 'active' THEN 'disabled'::iam.user_status
                    WHEN active AND x.status = 'disabled' AND x.disabled_reason = 'scim' THEN 'active'::iam.user_status
                    ELSE x.status END,
      disabled_reason = CASE WHEN NOT active AND x.status = 'active' THEN 'scim'
                             WHEN active AND x.status = 'disabled' AND x.disabled_reason = 'scim' THEN NULL
                             ELSE x.disabled_reason END
    WHERE x.id = uid RETURNING * INTO u;
    PERFORM iam.scim_event(CASE WHEN was.status = 'active' AND u.status = 'disabled' THEN 'scim.user.deactivated'
                                WHEN was.status = 'disabled' AND u.status = 'active' THEN 'scim.user.reactivated'
                                ELSE 'scim.user.updated' END,
      CASE WHEN was.status <> u.status THEN 'high' ELSE 'info' END, th, idp, 'user:' || u.id,
      jsonb_build_object('user_name', u.user_name, 'active', u.status = 'active', 'version', u.scim_version));
  END IF;
  RETURN QUERY SELECT u.id, u.scim_version, u.created_at, u.scim_updated_at;
END $$;

-- SCIM DELETE: the user leaves SCIM and is disabled; its identifiers are
-- released (email, userName, subject) so it can be provisioned again.
CREATE FUNCTION iam.scim_user_delete(th bytea, uid uuid, if_version integer) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  idp uuid := iam.scim_idp(th);
  was iam.app_user;
BEGIN
  SELECT * INTO was FROM iam.app_user x
  WHERE x.id = uid AND x.idp_id = idp AND x.source = 'scim' AND x.scim_deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no user %', uid USING ERRCODE = 'PF003';
  END IF;
  IF if_version IS NOT NULL AND if_version <> was.scim_version THEN
    RAISE EXCEPTION 'the user changed (version %)', was.scim_version USING ERRCODE = 'PF010';
  END IF;
  DELETE FROM iam.grp_member m WHERE m.user_id = uid;
  UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'scim_deleted', scim_deleted_at = now(),
    email = x.id || '@deleted.invalid', user_name = NULL, external_id = NULL, scim_version = x.scim_version + 1
  WHERE x.id = uid;
  PERFORM iam.scim_event('scim.user.deleted', 'high', th, idp, 'user:' || uid,
    jsonb_build_object('user_name', was.user_name, 'email', was.email));
END $$;

-- Groups -----------------------------------------------------------------

CREATE FUNCTION iam.scim_group_list(th bytea, one uuid)
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
  WHERE g.idp_id = idp AND g.scim_deleted_at IS NULL AND (one IS NULL OR g.id = one)
  ORDER BY g.created_at, g.id;
END $$;

-- Creates (gid NULL) or replaces a group with exactly members (users of
-- the same IdP; PF004 otherwise).
CREATE FUNCTION iam.scim_group_write(th bytea, gid uuid, if_version integer, resource jsonb, display_name text,
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
    INSERT INTO iam.grp (display_name, external_id, idp_id, scim_resource, scim_version, scim_updated_at)
    VALUES (btrim(display_name), external_id, idp, resource, 1, now()) RETURNING * INTO g;
  ELSE
    SELECT * INTO was FROM iam.grp x WHERE x.id = gid AND x.idp_id = idp AND x.scim_deleted_at IS NULL FOR UPDATE;
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

CREATE FUNCTION iam.scim_group_delete(th bytea, gid uuid, if_version integer) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  idp uuid := iam.scim_idp(th);
  was iam.grp;
BEGIN
  SELECT * INTO was FROM iam.grp x WHERE x.id = gid AND x.idp_id = idp AND x.scim_deleted_at IS NULL FOR UPDATE;
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

-- Tokens (the iam API, signed context, scim.manage) -------------------------

CREATE FUNCTION iam.scim_token_create(idp uuid, token_name text, th bytea, token_prefix text, expires timestamptz, reason text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('scim.manage');
  t iam.api_token;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.idp i WHERE i.id = idp) THEN
    RAISE EXCEPTION 'no IdP %', idp USING ERRCODE = 'PF003';
  END IF;
  IF expires <= now() OR expires > now() + interval '366 days' THEN
    RAISE EXCEPTION 'a SCIM token expires within a year' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO iam.api_token (owner_kind, owner_id, name, token_hash, prefix, scopes, created_by, expires_at)
  VALUES ('scim', idp, btrim(token_name), th, token_prefix, '{scim}', u, expires) RETURNING * INTO t;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'token.created', 'severity', 'high', 'actor', u::text, 'target', 'token:' || t.id,
    'reason', reason, 'attributes', jsonb_build_object('kind', 'scim', 'idp', idp, 'name', t.name, 'prefix', t.prefix,
                                                       'expires_at', t.expires_at)));
  RETURN t.id;
END $$;

CREATE FUNCTION iam.scim_token_list(idp uuid)
RETURNS TABLE (id uuid, name text, prefix text, created_at timestamptz, created_by uuid, expires_at timestamptz,
               last_used_at timestamptz, revoked_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.idp_actor('scim.manage');
  RETURN QUERY SELECT t.id, t.name, t.prefix, t.created_at, t.created_by, t.expires_at, t.last_used_at, t.revoked_at
  FROM iam.api_token t WHERE t.owner_kind = 'scim' AND t.owner_id = idp ORDER BY t.created_at DESC, t.id;
END $$;

CREATE FUNCTION iam.scim_token_revoke(idp uuid, token uuid, reason text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('scim.manage');
  t iam.api_token;
BEGIN
  UPDATE iam.api_token x SET revoked_at = now(), revoked_by = u
  WHERE x.id = token AND x.owner_kind = 'scim' AND x.owner_id = idp AND x.revoked_at IS NULL RETURNING * INTO t;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'token.revoked', 'severity', 'high', 'actor', u::text, 'target', 'token:' || t.id,
    'reason', reason, 'attributes', jsonb_build_object('kind', 'scim', 'idp', idp, 'name', t.name, 'prefix', t.prefix)));
  RETURN true;
END $$;

REVOKE ALL ON FUNCTION iam.scim_idp(bytea), iam.scim_provider(bytea), iam.scim_actor(bytea), iam.scim_event(text, text, bytea, uuid, text, jsonb),
  iam.scim_user_list(bytea, uuid), iam.scim_user_write(bytea, uuid, integer, jsonb, text, text, text, text, text, boolean),
  iam.scim_user_delete(bytea, uuid, integer), iam.scim_group_list(bytea, uuid),
  iam.scim_group_write(bytea, uuid, integer, jsonb, text, text, uuid[]), iam.scim_group_delete(bytea, uuid, integer),
  iam.scim_token_create(uuid, text, bytea, text, timestamptz, text), iam.scim_token_list(uuid),
  iam.scim_token_revoke(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.scim_idp(bytea), iam.scim_provider(bytea), iam.scim_user_list(bytea, uuid),
  iam.scim_user_write(bytea, uuid, integer, jsonb, text, text, text, text, text, boolean),
  iam.scim_user_delete(bytea, uuid, integer), iam.scim_group_list(bytea, uuid),
  iam.scim_group_write(bytea, uuid, integer, jsonb, text, text, uuid[]), iam.scim_group_delete(bytea, uuid, integer),
  iam.scim_token_create(uuid, text, bytea, text, timestamptz, text), iam.scim_token_list(uuid),
  iam.scim_token_revoke(uuid, uuid, text) TO app_rw;
