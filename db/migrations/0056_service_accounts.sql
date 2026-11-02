-- F-001 T-33 (AC-36, AC-37, AC-38; design §3, §6): service accounts and
-- their tokens.
--
--   * A service account is an iam.app_user (source 'service': no IdP, no
--     sign-in, never in SCIM or groups) plus an iam.service_account row. Its
--     API scopes are the permissions of a private role (iam.role
--     .service_account_id), assigned once at its BU (assignment source
--     'service'). The access rule, scope worker, grant snapshot, signed DB
--     context, RLS, restricted-BU blocking and SoD therefore apply unchanged.
--   * Scopes (AC-36) are live, non-privileged catalog permissions. Scopes the
--     actor holds at the BU apply at once; others need a T-26 approval
--     (kind service_account.scopes, approved by another holder of
--     service_account.manage at the BU), then service_account_apply.
--   * Client secrets (AC-37) are iam.api_token rows (owner_kind
--     service_account) holding HMAC-SHA-256(token pepper, secret); the
--     pepper is iam's and the gateway's, never the database's. They expire
--     within token.max_lifetime (fail closed when unset).
--   * mTLS (AC-38): certificates pinned by SHA-256 thumbprint (RFC 8705
--     self-signed or CA-issued alike), expiring at the earlier of notAfter
--     and token.max_lifetime.
--   * The gateway's token endpoint (client_credentials) issues 10-minute
--     access tokens, stored as HMACs (iam.sa_access_token) and checked per
--     request; those issued over mTLS are bound to the certificate. Disabling
--     the account or revoking the credential ends them at once.
--   * Token issuance is the account's activity for the inactivity sweep
--     (last_login_at).

ALTER TYPE iam.user_source ADD VALUE IF NOT EXISTS 'service';
ALTER TYPE iam.assignment_source ADD VALUE IF NOT EXISTS 'service';

-- A service account never signs in through an IdP (text comparison: the
-- new enum value cannot be used in this transaction).
ALTER TABLE iam.app_user ADD CONSTRAINT app_user_service_no_idp
  CHECK (source::text <> 'service' OR (idp_id IS NULL AND external_id IS NULL AND scim_id IS NULL));

ALTER TABLE iam.role ADD COLUMN service_account_id uuid UNIQUE REFERENCES iam.app_user (id);

CREATE FUNCTION iam.role_service_account_fixed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'role: service_account_id is immutable' USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER role_service_account_fixed BEFORE UPDATE OF service_account_id ON iam.role
  FOR EACH ROW WHEN (NEW.service_account_id IS DISTINCT FROM OLD.service_account_id) EXECUTE FUNCTION iam.role_service_account_fixed();

CREATE TABLE iam.service_account (
  id           uuid        PRIMARY KEY REFERENCES iam.app_user (id),
  name         text        NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
  bu_id        uuid        NOT NULL REFERENCES iam.bu (id),
  role_id      uuid        NOT NULL UNIQUE REFERENCES iam.role (id),
  auth_method  text        NOT NULL CHECK (auth_method IN ('client_credentials', 'mtls')),
  created_by   uuid        NOT NULL REFERENCES iam.app_user (id),
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX service_account_name ON iam.service_account (lower(btrim(name)));
REVOKE ALL ON iam.service_account FROM PUBLIC;

CREATE TABLE iam.sa_certificate (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  service_account_id  uuid        NOT NULL REFERENCES iam.service_account (id),
  name                text        NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
  thumbprint          bytea       NOT NULL UNIQUE CHECK (length(thumbprint) = 32),
  subject             text        NOT NULL,
  not_before          timestamptz NOT NULL,
  not_after           timestamptz NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  created_by          uuid        NOT NULL REFERENCES iam.app_user (id),
  expires_at          timestamptz NOT NULL,
  last_used_at        timestamptz,
  revoked_at          timestamptz,
  revoked_by          uuid        REFERENCES iam.app_user (id),
  CHECK (expires_at <= not_after AND expires_at > created_at)
);
CREATE INDEX sa_certificate_owner ON iam.sa_certificate (service_account_id);
REVOKE ALL ON iam.sa_certificate FROM PUBLIC;

CREATE TABLE iam.sa_access_token (
  token_hmac          bytea       PRIMARY KEY CHECK (length(token_hmac) = 32),
  service_account_id  uuid        NOT NULL REFERENCES iam.service_account (id),
  credential_id       uuid        NOT NULL,  -- the api_token or sa_certificate it was issued for
  thumbprint          bytea       CHECK (thumbprint IS NULL OR length(thumbprint) = 32),  -- RFC 8705 binding
  issued_at           timestamptz NOT NULL DEFAULT now(),
  expires_at          timestamptz NOT NULL,
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '15 minutes')
);
CREATE INDEX sa_access_token_owner ON iam.sa_access_token (service_account_id, expires_at);
REVOKE ALL ON iam.sa_access_token FROM PUBLIC;

INSERT INTO iam.approval_kind (kind, approve_permission, description) VALUES
  ('service_account.scopes', 'service_account.manage', 'Service account scopes its requester does not hold (F-001 AC-36)');

-- token.max_lifetime (AC-37); refuses when unset or not positive.
CREATE FUNCTION iam.token_max_lifetime() RETURNS interval
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  raw    jsonb := iam.instance_setting('token.max_lifetime');
  period interval;
BEGIN
  IF raw IS NULL OR jsonb_typeof(raw) <> 'string' THEN
    RAISE EXCEPTION 'token.max_lifetime is not set' USING ERRCODE = 'PF003';
  END IF;
  period := (raw #>> '{}')::interval;
  IF period <= interval '0' THEN
    RAISE EXCEPTION 'token.max_lifetime % is not positive', period USING ERRCODE = 'PF004';
  END IF;
  RETURN period;
END $$;

-- The signed-context user (PF007 without one).
CREATE FUNCTION iam.sa_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'service account administration needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  RETURN u;
END $$;

-- The service account the actor manages (service_account.manage at its BU);
-- others do not exist for the actor (P0002).
CREATE FUNCTION iam.sa_managed(actor uuid, sa uuid) RETURNS iam.service_account
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s iam.service_account;
BEGIN
  SELECT * INTO s FROM iam.service_account x WHERE x.id = sa;
  IF NOT FOUND OR NOT iam.user_has_permission(actor, 'service_account.manage', s.bu_id) THEN
    RAISE EXCEPTION 'no service account %', sa USING ERRCODE = 'P0002';
  END IF;
  RETURN s;
END $$;

-- A scope list: live, non-privileged catalog permissions (AC-36), sorted
-- and distinct.
CREATE FUNCTION iam.sa_check_scopes(scopes text[]) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  bad text;
BEGIN
  IF scopes IS NULL OR cardinality(scopes) = 0 OR array_position(scopes, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'a service account needs at least one scope' USING ERRCODE = 'PF004';
  END IF;
  SELECT s INTO bad FROM unnest(scopes) s WHERE NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.key = s AND p.retired_at IS NULL) LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'unknown or retired permission %', bad USING ERRCODE = 'PF004';
  END IF;
  SELECT s INTO bad FROM unnest(scopes) s JOIN iam.permission p ON p.key = s WHERE p.privileged OR p.action = 'admin' ORDER BY s LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'service accounts may not hold privileged permission % (AC-36)', bad USING ERRCODE = 'PF004';
  END IF;
  RETURN ARRAY(SELECT DISTINCT s COLLATE "C" FROM unnest(scopes) s ORDER BY 1);
END $$;

-- The scopes in perms that actor does not hold at bu.
CREATE FUNCTION iam.sa_unheld(actor uuid, bu uuid, perms text[]) RETURNS text[]
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY(SELECT s FROM unnest(perms) s WHERE NOT iam.user_has_permission(actor, s, bu) ORDER BY s COLLATE "C");
$$;

CREATE FUNCTION iam.sa_event(event text, severity text, actor uuid, sa uuid, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor::text, 'target', 'service_account:' || sa,
    'reason', reason, 'attributes', jsonb_build_object('name', (SELECT s.name FROM iam.service_account s WHERE s.id = sa)) || coalesce(attrs, '{}')));
$$;

CREATE FUNCTION iam.sa_new_bu(actor uuid, bu uuid) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = bu) OR NOT iam.user_has_permission(actor, 'service_account.manage', bu) THEN
    RAISE EXCEPTION 'service_account.manage is required at BU %', bu USING ERRCODE = 'PF008';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = bu AND b.archived_at IS NOT NULL) THEN
    RAISE EXCEPTION 'BU % is archived', bu USING ERRCODE = 'PF003';
  END IF;
END $$;

-- Creates the account: its user row, private role, version 1 and the
-- assignment at its BU.
CREATE FUNCTION iam.sa_create_now(actor uuid, sa_name text, bu uuid, perms text[], method text, reason text, extra jsonb) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  id  uuid := gen_random_uuid();
  rid uuid;
BEGIN
  INSERT INTO iam.app_user (id, email, display_name, source)
  VALUES (id, 'sa-' || id || '@service-account.invalid', btrim(sa_name), 'service');
  INSERT INTO iam.role (name, created_by, service_account_id) VALUES ('sa:' || id, actor, id) RETURNING iam.role.id INTO rid;
  INSERT INTO iam.role_version (role_id, version, permissions, changed_by, change_reason) VALUES (rid, 1, perms, actor, btrim(reason));
  INSERT INTO iam.service_account (id, name, bu_id, role_id, auth_method, created_by)
  VALUES (id, btrim(sa_name), bu, rid, method, actor);
  INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, source)
  VALUES ('user', id, rid, bu, actor, 'service');
  PERFORM iam.sa_event('service_account.created', 'high', actor, id, btrim(reason),
    jsonb_build_object('bu_id', bu, 'scopes', to_jsonb(perms), 'auth_method', method) || coalesce(extra, '{}'));
  RETURN id;
END $$;

-- A new version of the account's role.
CREATE FUNCTION iam.sa_scopes_now(actor uuid, s iam.service_account, perms text[], reason text, extra jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  cur text[] := iam.role_permissions(s.role_id);
BEGIN
  INSERT INTO iam.role_version (role_id, version, permissions, changed_by, change_reason)
  VALUES (s.role_id, (SELECT r.current_version + 1 FROM iam.role r WHERE r.id = s.role_id), perms, actor, btrim(reason));
  PERFORM iam.sa_event('service_account.scopes_changed', 'high', actor, s.id, btrim(reason),
    jsonb_build_object('added', to_jsonb(ARRAY(SELECT p FROM unnest(perms) p WHERE p <> ALL (cur) ORDER BY p COLLATE "C")),
                       'removed', to_jsonb(ARRAY(SELECT p FROM unnest(cur) p WHERE p <> ALL (perms) ORDER BY p COLLATE "C")))
    || coalesce(extra, '{}'));
END $$;

-- Creates a service account, or asks for approval of the scopes the actor
-- does not hold at the BU (then id is NULL and approval_id is set).
CREATE FUNCTION iam.service_account_create(sa_name text, bu uuid, scopes text[], method text, reason text)
RETURNS TABLE (id uuid, approval_id uuid, unheld text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
  perms text[];
  miss  text[];
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  IF method IS NULL OR method NOT IN ('client_credentials', 'mtls') THEN
    RAISE EXCEPTION 'auth_method is client_credentials or mtls' USING ERRCODE = 'PF004';
  END IF;
  IF char_length(btrim(coalesce(sa_name, ''))) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'a name of 1 to 100 characters is required' USING ERRCODE = 'PF004';
  END IF;
  PERFORM iam.sa_new_bu(actor, bu);
  IF EXISTS (SELECT 1 FROM iam.service_account s WHERE lower(btrim(s.name)) = lower(btrim(sa_name))) THEN
    RAISE EXCEPTION 'a service account named "%" exists', btrim(sa_name) USING ERRCODE = '23505';
  END IF;
  perms := iam.sa_check_scopes(scopes);
  miss := iam.sa_unheld(actor, bu, perms);
  IF cardinality(miss) = 0 THEN
    RETURN QUERY SELECT iam.sa_create_now(actor, sa_name, bu, perms, method, reason, NULL), NULL::uuid, miss;
    RETURN;
  END IF;
  RETURN QUERY SELECT NULL::uuid,
    iam.request_approval('service_account.scopes', 'service_account:create:' || bu || ':' || lower(btrim(sa_name)), btrim(reason),
      jsonb_build_object('op', 'create', 'name', btrim(sa_name), 'bu_id', bu, 'scopes', to_jsonb(perms), 'auth_method', method,
                         'unheld', to_jsonb(miss)), bu),
    miss;
END $$;

-- Renames (at once) and changes scopes: removals and scopes the actor holds
-- at once, other additions through an approval (approval_id set; the
-- scopes stay as they are until it is applied).
CREATE FUNCTION iam.service_account_update(sa uuid, new_name text, scopes text[], reason text)
RETURNS TABLE (approval_id uuid, unheld text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
  s     iam.service_account := iam.sa_managed(actor, sa);
  cur   text[] := iam.role_permissions(s.role_id);
  perms text[];
  miss  text[] := '{}';
  done  boolean := false;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  PERFORM 1 FROM iam.service_account x WHERE x.id = sa FOR UPDATE;
  IF new_name IS NOT NULL AND btrim(new_name) IS DISTINCT FROM s.name THEN
    IF char_length(btrim(new_name)) NOT BETWEEN 1 AND 100 THEN
      RAISE EXCEPTION 'a name of 1 to 100 characters is required' USING ERRCODE = 'PF004';
    END IF;
    IF EXISTS (SELECT 1 FROM iam.service_account x WHERE x.id <> sa AND lower(btrim(x.name)) = lower(btrim(new_name))) THEN
      RAISE EXCEPTION 'a service account named "%" exists', btrim(new_name) USING ERRCODE = '23505';
    END IF;
    UPDATE iam.service_account x SET name = btrim(new_name) WHERE x.id = sa;
    UPDATE iam.app_user x SET display_name = btrim(new_name) WHERE x.id = sa;
    PERFORM iam.sa_event('service_account.renamed', 'info', actor, sa, btrim(reason), jsonb_build_object('before', s.name));
    done := true;
  END IF;
  IF scopes IS NOT NULL THEN
    perms := iam.sa_check_scopes(scopes);
    IF perms IS DISTINCT FROM cur THEN
      miss := iam.sa_unheld(actor, s.bu_id, ARRAY(SELECT p FROM unnest(perms) p WHERE p <> ALL (cur)));
      IF cardinality(miss) = 0 THEN
        PERFORM iam.sa_scopes_now(actor, s, perms, reason, NULL);
      ELSE
        RETURN QUERY SELECT iam.request_approval('service_account.scopes', 'service_account:' || sa || ':scopes', btrim(reason),
          jsonb_build_object('op', 'update', 'service_account_id', sa, 'from', to_jsonb(cur), 'scopes', to_jsonb(perms),
                             'unheld', to_jsonb(miss)), s.bu_id), miss;
        RETURN;
      END IF;
      done := true;
    END IF;
  END IF;
  IF NOT done THEN
    RAISE EXCEPTION 'no change' USING ERRCODE = 'PF003';
  END IF;
  RETURN QUERY SELECT NULL::uuid, miss;
END $$;

-- Applies an approved service_account.scopes request; returns the account.
CREATE FUNCTION iam.service_account_apply(approval uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
  req   iam.approval_request;
  used  jsonb;
  pl    jsonb;
  s     iam.service_account;
  perms text[];
  extra jsonb;
BEGIN
  SELECT * INTO req FROM iam.approval_request a WHERE a.id = approval AND a.kind = 'service_account.scopes';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no service account approval %', approval USING ERRCODE = 'P0002';
  END IF;
  pl := req.payload;
  IF pl->>'op' = 'create' THEN
    PERFORM iam.sa_new_bu(actor, (pl->>'bu_id')::uuid);
  ELSE
    s := iam.sa_managed(actor, (pl->>'service_account_id')::uuid);
  END IF;
  used := iam.consume_approval(approval, req.kind, req.target_ref);  -- {payload, requested_by, decided_by} (0018)
  extra := jsonb_build_object('approval', approval, 'requested_by', used->>'requested_by', 'approved_by', used->>'decided_by');
  perms := iam.sa_check_scopes(ARRAY(SELECT jsonb_array_elements_text(pl->'scopes')));
  IF pl->>'op' = 'create' THEN
    IF EXISTS (SELECT 1 FROM iam.service_account x WHERE lower(btrim(x.name)) = lower(pl->>'name')) THEN
      RAISE EXCEPTION 'a service account named "%" exists', pl->>'name' USING ERRCODE = '23505';
    END IF;
    RETURN iam.sa_create_now(actor, pl->>'name', (pl->>'bu_id')::uuid, perms, pl->>'auth_method', req.reason, extra);
  END IF;
  PERFORM 1 FROM iam.service_account x WHERE x.id = s.id FOR UPDATE;
  IF iam.role_permissions(s.role_id) IS DISTINCT FROM ARRAY(SELECT jsonb_array_elements_text(pl->'from')) THEN
    RAISE EXCEPTION 'the scopes changed since the request; ask again' USING ERRCODE = 'PF003';
  END IF;
  PERFORM iam.sa_scopes_now(actor, s, perms, req.reason, extra);
  RETURN s.id;
END $$;

-- Disables (ending every access token) or enables an account.
CREATE FUNCTION iam.service_account_set_status(sa uuid, enable boolean, reason text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
  s     iam.service_account := iam.sa_managed(actor, sa);
  was   iam.app_user;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO was FROM iam.app_user x WHERE x.id = sa FOR UPDATE;
  IF enable AND was.status = 'active' OR NOT enable AND was.status <> 'active' THEN
    RAISE EXCEPTION 'the service account is % already', CASE WHEN enable THEN 'enabled' ELSE 'disabled' END USING ERRCODE = 'PF003';
  END IF;
  IF enable THEN
    UPDATE iam.app_user x SET status = 'active', disabled_reason = NULL, reactivated_at = now() WHERE x.id = sa;
  ELSE
    UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'admin' WHERE x.id = sa;
    DELETE FROM iam.sa_access_token t WHERE t.service_account_id = sa;
  END IF;
  PERFORM iam.sa_event(CASE WHEN enable THEN 'service_account.enabled' ELSE 'service_account.disabled' END, 'high', actor, sa,
    btrim(reason), jsonb_build_object('before', jsonb_build_object('status', was.status, 'disabled_reason', was.disabled_reason)));
  RETURN CASE WHEN enable THEN 'active' ELSE 'disabled' END;
END $$;

-- The accounts at BUs where the caller holds service_account.manage.
CREATE FUNCTION iam.service_account_list(one uuid)
RETURNS TABLE (id uuid, name text, bu_id uuid, bu_code text, auth_method text, status text, disabled_reason text, scopes text[],
               created_by uuid, created_at timestamptz, last_used_at timestamptz, live_secrets integer, live_certificates integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
BEGIN
  RETURN QUERY
  SELECT s.id, s.name, s.bu_id, b.code, s.auth_method, u.status::text, u.disabled_reason, iam.role_permissions(s.role_id),
    s.created_by, s.created_at, u.last_login_at,
    (SELECT count(*)::integer FROM iam.api_token t WHERE t.owner_kind = 'service_account' AND t.owner_id = s.id
       AND t.revoked_at IS NULL AND t.expires_at > now()),
    (SELECT count(*)::integer FROM iam.sa_certificate c WHERE c.service_account_id = s.id AND c.revoked_at IS NULL AND c.expires_at > now())
  FROM iam.service_account s JOIN iam.app_user u ON u.id = s.id JOIN iam.bu b ON b.id = s.bu_id
  WHERE (one IS NULL OR s.id = one) AND iam.user_has_permission(actor, 'service_account.manage', s.bu_id)
  ORDER BY lower(s.name), s.id;
END $$;

-- Client secrets (client_credentials accounts). expires NULL means the
-- longest allowed (token.max_lifetime).
CREATE FUNCTION iam.sa_secret_create(sa uuid, token_name text, th bytea, token_prefix text, expires timestamptz, reason text)
RETURNS TABLE (id uuid, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
  s     iam.service_account := iam.sa_managed(actor, sa);
  most  interval := iam.token_max_lifetime();
  t     iam.api_token;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  IF s.auth_method <> 'client_credentials' THEN
    RAISE EXCEPTION 'the service account authenticates with mTLS; register a certificate' USING ERRCODE = 'PF003';
  END IF;
  IF (SELECT x.status FROM iam.app_user x WHERE x.id = sa) <> 'active' THEN
    RAISE EXCEPTION 'the service account is disabled' USING ERRCODE = 'PF003';
  END IF;
  expires := coalesce(expires, now() + most);
  IF expires <= now() OR expires > now() + most THEN
    RAISE EXCEPTION 'a token expires within token.max_lifetime (%)', most USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO iam.api_token (owner_kind, owner_id, name, token_hash, prefix, created_by, expires_at)
  VALUES ('service_account', sa, btrim(coalesce(token_name, '')), th, token_prefix, actor, expires) RETURNING * INTO t;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'token.created', 'severity', 'high', 'actor', actor::text, 'target', 'token:' || t.id,
    'reason', btrim(reason), 'attributes', jsonb_build_object('kind', 'service_account', 'service_account', sa, 'name', t.name,
                                                             'prefix', t.prefix, 'expires_at', t.expires_at)));
  RETURN QUERY SELECT t.id, t.expires_at;
END $$;

CREATE FUNCTION iam.sa_secret_list(sa uuid)
RETURNS TABLE (id uuid, name text, prefix text, created_at timestamptz, created_by uuid, expires_at timestamptz,
               last_used_at timestamptz, revoked_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.sa_managed(iam.sa_actor(), sa);
  RETURN QUERY SELECT t.id, t.name, t.prefix, t.created_at, t.created_by, t.expires_at, t.last_used_at, t.revoked_at
  FROM iam.api_token t WHERE t.owner_kind = 'service_account' AND t.owner_id = sa ORDER BY t.created_at DESC, t.id;
END $$;

-- Revokes a secret or a certificate and the access tokens issued for it.
CREATE FUNCTION iam.sa_credential_revoke(sa uuid, credential uuid, reason text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
  t     iam.api_token;
  c     iam.sa_certificate;
BEGIN
  PERFORM iam.sa_managed(actor, sa);
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  UPDATE iam.api_token x SET revoked_at = now(), revoked_by = actor
  WHERE x.id = credential AND x.owner_kind = 'service_account' AND x.owner_id = sa AND x.revoked_at IS NULL RETURNING * INTO t;
  IF FOUND THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'token.revoked', 'severity', 'high', 'actor', actor::text, 'target', 'token:' || t.id,
      'reason', btrim(reason), 'attributes', jsonb_build_object('kind', 'service_account', 'service_account', sa, 'name', t.name, 'prefix', t.prefix)));
  ELSE
    UPDATE iam.sa_certificate x SET revoked_at = now(), revoked_by = actor
    WHERE x.id = credential AND x.service_account_id = sa AND x.revoked_at IS NULL RETURNING * INTO c;
    IF NOT FOUND THEN
      RETURN false;
    END IF;
    PERFORM iam.sa_event('service_account.certificate_revoked', 'high', actor, sa, btrim(reason),
      jsonb_build_object('certificate', c.id, 'thumbprint', encode(c.thumbprint, 'hex'), 'subject', c.subject));
  END IF;
  DELETE FROM iam.sa_access_token x WHERE x.credential_id = credential;
  RETURN true;
END $$;

-- mTLS certificates (pinned by SHA-256 thumbprint of the DER certificate).
CREATE FUNCTION iam.sa_certificate_add(sa uuid, cert_name text, thumb bytea, subj text, nbf timestamptz, naf timestamptz, reason text)
RETURNS TABLE (id uuid, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.sa_actor();
  s     iam.service_account := iam.sa_managed(actor, sa);
  c     iam.sa_certificate;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  IF s.auth_method <> 'mtls' THEN
    RAISE EXCEPTION 'the service account authenticates with client secrets' USING ERRCODE = 'PF003';
  END IF;
  IF (SELECT x.status FROM iam.app_user x WHERE x.id = sa) <> 'active' THEN
    RAISE EXCEPTION 'the service account is disabled' USING ERRCODE = 'PF003';
  END IF;
  IF naf <= now() THEN
    RAISE EXCEPTION 'the certificate has expired' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO iam.sa_certificate (service_account_id, name, thumbprint, subject, not_before, not_after, created_by, expires_at)
  VALUES (sa, btrim(coalesce(cert_name, '')), thumb, subj, nbf, naf, actor, least(naf, now() + iam.token_max_lifetime())) RETURNING * INTO c;
  PERFORM iam.sa_event('service_account.certificate_added', 'high', actor, sa, btrim(reason),
    jsonb_build_object('certificate', c.id, 'thumbprint', encode(c.thumbprint, 'hex'), 'subject', c.subject, 'expires_at', c.expires_at));
  RETURN QUERY SELECT c.id, c.expires_at;
END $$;

CREATE FUNCTION iam.sa_certificate_list(sa uuid)
RETURNS TABLE (id uuid, name text, thumbprint text, subject text, not_before timestamptz, not_after timestamptz, created_at timestamptz,
               created_by uuid, expires_at timestamptz, last_used_at timestamptz, revoked_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.sa_managed(iam.sa_actor(), sa);
  RETURN QUERY SELECT c.id, c.name, encode(c.thumbprint, 'hex'), c.subject, c.not_before, c.not_after, c.created_at, c.created_by,
    c.expires_at, c.last_used_at, c.revoked_at
  FROM iam.sa_certificate c WHERE c.service_account_id = sa ORDER BY c.created_at DESC, c.id;
END $$;

-- The gateway's token endpoint (client_credentials, RFC 6749 §4.4): one
-- credential, a client secret's HMAC or a certificate thumbprint. Returns
-- 'ok' with the account's scopes and the token's expiry, 'invalid_client'
-- (audited) or 'invalid_scope' (requested scopes beyond the account's).
-- Tokens issued over mTLS are bound to the certificate (RFC 8705 §3).
CREATE FUNCTION iam.sa_token_issue(client uuid, secret_hmac bytea, thumb bytea, requested text[], access_hmac bytea, ttl interval, client_ip text)
RETURNS TABLE (status text, scopes text[], expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s     iam.service_account;
  st    iam.user_status;
  cred  uuid;
  why   text;
  perms text[];
  exp   timestamptz;
BEGIN
  IF ttl IS NULL OR ttl <= interval '0' OR ttl > interval '15 minutes' THEN
    RAISE EXCEPTION 'access tokens live at most 15 minutes' USING ERRCODE = '22023';
  END IF;
  IF (secret_hmac IS NULL) = (thumb IS NULL) THEN
    RAISE EXCEPTION 'exactly one credential' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO s FROM iam.service_account x WHERE x.id = client;
  IF NOT FOUND THEN
    why := 'unknown_client';
  ELSE
    SELECT u.status INTO st FROM iam.app_user u WHERE u.id = client;
    IF st <> 'active' THEN
      why := 'disabled';
    ELSIF secret_hmac IS NOT NULL THEN
      SELECT t.id INTO cred FROM iam.api_token t
      WHERE t.token_hash = secret_hmac AND t.owner_kind = 'service_account' AND t.owner_id = client
        AND t.revoked_at IS NULL AND t.expires_at > now();
      why := CASE WHEN s.auth_method <> 'client_credentials' THEN 'wrong_method' WHEN cred IS NULL THEN 'invalid_secret' END;
    ELSE
      SELECT c.id INTO cred FROM iam.sa_certificate c
      WHERE c.thumbprint = thumb AND c.service_account_id = client AND c.revoked_at IS NULL
        AND c.expires_at > now() AND c.not_before <= now();
      why := CASE WHEN s.auth_method <> 'mtls' THEN 'wrong_method' WHEN cred IS NULL THEN 'invalid_certificate' END;
    END IF;
  END IF;
  IF why IS NOT NULL THEN
    INSERT INTO iam.event_outbox (topic, payload)
    VALUES ('audit', jsonb_build_object('type', 'authn.client_credentials_failed', 'severity', CASE WHEN s.id IS NULL THEN 'low' ELSE 'high' END,
      'actor', 'system:gateway', 'target', 'service_account:' || client, 'reason', why,
      'attributes', jsonb_build_object('ip', client_ip, 'method', CASE WHEN thumb IS NULL THEN 'client_secret' ELSE 'mtls' END,
                                       'thumbprint', encode(thumb, 'hex'))));
    RETURN QUERY SELECT 'invalid_client'::text, NULL::text[], NULL::timestamptz;
    RETURN;
  END IF;
  perms := iam.role_permissions(s.role_id);
  IF requested IS NOT NULL AND NOT (requested <@ perms) THEN
    RETURN QUERY SELECT 'invalid_scope'::text, perms, NULL::timestamptz;
    RETURN;
  END IF;
  DELETE FROM iam.sa_access_token x WHERE x.service_account_id = client AND x.expires_at <= now();
  exp := now() + ttl;
  INSERT INTO iam.sa_access_token (token_hmac, service_account_id, credential_id, thumbprint, expires_at)
  VALUES (access_hmac, client, cred, thumb, exp);
  UPDATE iam.api_token x SET last_used_at = now() WHERE x.id = cred;
  UPDATE iam.sa_certificate x SET last_used_at = now() WHERE x.id = cred;
  UPDATE iam.app_user x SET last_login_at = now() WHERE x.id = client;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'authn.client_credentials', 'severity', 'info', 'actor', client::text,
    'target', 'service_account:' || client,
    'attributes', jsonb_build_object('ip', client_ip, 'method', CASE WHEN thumb IS NULL THEN 'client_secret' ELSE 'mtls' END,
                                     'credential', cred, 'expires_at', exp)));
  RETURN QUERY SELECT 'ok'::text, perms, exp;
END $$;

-- A live access token: its account (active), credential (live) and the
-- account's scope version.
CREATE FUNCTION iam.sa_access_lookup(access_hmac bytea)
RETURNS TABLE (user_id uuid, scope_version bigint, issued_at timestamptz, expires_at timestamptz, thumbprint bytea, auth_method text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.service_account_id, coalesce(us.scope_version, 0::bigint), a.issued_at, a.expires_at, a.thumbprint, s.auth_method
  FROM iam.sa_access_token a
  JOIN iam.service_account s ON s.id = a.service_account_id
  JOIN iam.app_user u ON u.id = s.id AND u.status = 'active'
  LEFT JOIN authz.user_scope us ON us.user_id = s.id
  WHERE a.token_hmac = access_hmac AND a.expires_at > now()
    AND (EXISTS (SELECT 1 FROM iam.api_token t WHERE t.id = a.credential_id AND t.owner_id = s.id AND t.revoked_at IS NULL AND t.expires_at > now())
      OR EXISTS (SELECT 1 FROM iam.sa_certificate c WHERE c.id = a.credential_id AND c.service_account_id = s.id
                   AND c.revoked_at IS NULL AND c.expires_at > now()));
$$;

-- The assignment trigger (0048) with the service-account path: a service
-- account's one assignment is its private role at its BU, granted by a
-- holder of service_account.manage there; a private role is assigned to no
-- one else.
CREATE OR REPLACE FUNCTION iam.assignment_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r iam.role;
  perms text[];
  b iam.bu;
  u uuid;
  m iam.group_role_mapping;
BEGIN
  -- Serialize assignment writes so the AC-30 check sees every concurrent grant.
  PERFORM pg_advisory_xact_lock(hashtext('iam.assignment'));
  NEW.granted_at := now();
  NEW.revoked_at := NULL;
  NEW.revoked_by := NULL;

  IF NEW.source = 'mapped' THEN
    -- Only the mapping functions write mapped assignments, for an active
    -- member of a live mapping's group, matching the mapping.
    IF NOT iam.in_mapping_sync() THEN
      RAISE EXCEPTION 'assignment: mapped assignments are written by group mappings only' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO m FROM iam.group_role_mapping x WHERE x.id = NEW.mapping_id AND x.removed_at IS NULL;
    IF NOT FOUND OR NEW.principal_kind <> 'user' OR NEW.role_id <> m.role_id OR NEW.bu_id <> m.bu_id
       OR NOT EXISTS (SELECT 1 FROM iam.grp_member gm WHERE gm.grp_id = m.grp_id AND gm.user_id = NEW.principal_id) THEN
      RAISE EXCEPTION 'assignment: not a member of a live mapping' USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  SELECT * INTO r FROM iam.role WHERE id = NEW.role_id;
  IF NOT FOUND THEN
    RETURN NEW;  -- the foreign key reports it
  END IF;
  IF NEW.source::text = 'service' THEN
    IF NEW.principal_kind <> 'user' OR NEW.expires_at IS NOT NULL OR NEW.mapping_id IS NOT NULL
       OR NOT EXISTS (SELECT 1 FROM iam.service_account s
                      WHERE s.id = NEW.principal_id AND s.role_id = NEW.role_id AND s.bu_id = NEW.bu_id)
       OR EXISTS (SELECT 1 FROM iam.assignment a WHERE a.role_id = NEW.role_id) THEN
      RAISE EXCEPTION 'assignment: a service account holds its own role at its BU, once' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.granted_by IS NULL OR NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = NEW.granted_by AND status = 'active')
       OR NOT iam.user_has_permission(NEW.granted_by, 'service_account.manage', NEW.bu_id) THEN
      RAISE EXCEPTION 'assignment: grantor lacks service_account.manage at BU %', NEW.bu_id USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSIF r.service_account_id IS NOT NULL THEN
    RAISE EXCEPTION 'assignment: role "%" belongs to a service account', r.name USING ERRCODE = 'check_violation';
  END IF;
  IF r.status <> 'active' OR r.current_version = 0 THEN
    RAISE EXCEPTION 'assignment: role "%" is not assignable', r.name USING ERRCODE = 'check_violation';
  END IF;
  SELECT v.permissions INTO perms FROM iam.role_version v WHERE v.role_id = r.id AND v.version = r.current_version;

  SELECT * INTO b FROM iam.bu WHERE id = NEW.bu_id;
  IF FOUND AND b.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'assignment: BU % is archived', b.id USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.principal_kind = 'user' AND NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = NEW.principal_id)
     OR NEW.principal_kind = 'group' AND NOT EXISTS (SELECT 1 FROM iam.grp WHERE id = NEW.principal_id) THEN
    RAISE EXCEPTION 'assignment: unknown % %', NEW.principal_kind, NEW.principal_id USING ERRCODE = 'foreign_key_violation';
  END IF;

  IF NEW.source = 'mapped' THEN
    -- The grantor's authority was checked when the mapping was created;
    -- AC-28 still holds for its creator.
    IF NEW.principal_id = m.created_by THEN
      RAISE EXCEPTION 'assignment: users cannot assign roles to themselves (AC-28)' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = NEW.principal_id AND status = 'active') THEN
      RAISE EXCEPTION 'assignment: the user is not active' USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.source::text = 'service' THEN
    NULL;  -- checked above
  ELSIF NEW.granted_by IS NULL THEN
    IF NOT iam.in_assignment_bootstrap() THEN
      RAISE EXCEPTION 'assignment: granted_by is required' USING ERRCODE = 'not_null_violation';
    END IF;
  ELSE
    IF NOT EXISTS (SELECT 1 FROM iam.app_user WHERE id = NEW.granted_by AND status = 'active') THEN
      RAISE EXCEPTION 'assignment: grantor is not an active user' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- AC-28: no self-assignment, directly or through a group.
    IF NEW.granted_by IN (SELECT iam.principal_users(NEW.principal_kind, NEW.principal_id)) THEN
      RAISE EXCEPTION 'assignment: users cannot assign roles to themselves (AC-28)' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- AC-22: authority at the target BU.
    IF NOT iam.can_assign_at(NEW.granted_by, NEW.bu_id) THEN
      RAISE EXCEPTION 'assignment: grantor lacks access.assign at BU % (AC-22)', NEW.bu_id USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- AC-22: only root-level grantors grant roles with admin permissions.
    IF EXISTS (SELECT 1 FROM iam.permission WHERE key = ANY (perms) AND action = 'admin')
       AND NOT iam.is_root_grantor(NEW.granted_by) THEN
      RAISE EXCEPTION 'assignment: role "%" contains admin permissions; only root-level grantors may assign it (AC-22)', r.name
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;

  -- AC-30: no affected user may combine admin and risk-data permissions.
  FOR u IN SELECT iam.principal_users(NEW.principal_kind, NEW.principal_id) LOOP
    IF EXISTS (SELECT 1 FROM iam.permission p
               WHERE p.action = 'admin' AND (p.key = ANY (perms) OR p.key IN (SELECT iam.user_permissions(u))))
       AND EXISTS (SELECT 1 FROM iam.permission p
               WHERE p.risk_data AND (p.key = ANY (perms) OR p.key IN (SELECT iam.user_permissions(u)))) THEN
      RAISE EXCEPTION 'assignment: user % would hold both admin and risk-data permissions; this needs dual approval (AC-30, T-26)', u
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;

-- A service account's role changes only with the account (0051).
CREATE OR REPLACE FUNCTION iam.role_write_version(actor uuid, role uuid, perms text[], reason text, event text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d     jsonb := iam.role_diff(role, perms);
  r     iam.role;
  users integer;
BEGIN
  SELECT * INTO r FROM iam.role x WHERE x.id = role FOR UPDATE;
  IF r.service_account_id IS NOT NULL THEN
    RAISE EXCEPTION 'role "%" belongs to a service account; change its scopes there', r.name USING ERRCODE = 'PF003';
  END IF;
  IF r.status = 'retired' THEN
    RAISE EXCEPTION 'role "%" is retired', r.name USING ERRCODE = 'PF003';
  END IF;
  IF cardinality(perms) = 0 THEN
    RAISE EXCEPTION 'a role needs at least one permission' USING ERRCODE = 'PF004';
  END IF;
  users := (d->>'admin_risk_users')::integer;
  IF users > 0 THEN
    RAISE EXCEPTION '% user(s) of role "%" would hold both admin and risk-data permissions; this needs dual approval (AC-30)', users, r.name
      USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO iam.role_version (role_id, version, permissions, changed_by, change_reason)
  VALUES (role, r.current_version + 1, perms, actor, btrim(reason));
  PERFORM iam.role_event(event, 'info', actor, role, btrim(reason),
    jsonb_build_object('version', r.current_version + 1, 'added', d->'added', 'removed', d->'removed', 'affected_users', d->'affected_users'));
  IF jsonb_array_length(d->'privileged_added') > 0 THEN
    PERFORM iam.role_event('role.privileged_added', 'high', actor, role, btrim(reason),
      jsonb_build_object('version', r.current_version + 1, 'permissions', d->'privileged_added'));
  END IF;
  RETURN r.current_version + 1;
END $$;

-- Role lists and exports leave service accounts' roles out (0051, 0052).
CREATE OR REPLACE FUNCTION iam.role_list(only_role uuid)
RETURNS TABLE (id uuid, name text, builtin boolean, status text, current_version integer, permissions text[], privileged text[],
               created_at timestamptz, assignments bigint, users bigint, mappings bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN QUERY
  SELECT r.id, r.name, r.builtin, r.status::text, r.current_version, coalesce(v.permissions, '{}'),
    ARRAY(SELECT k.key FROM iam.permission k WHERE k.privileged AND k.key = ANY (coalesce(v.permissions, '{}')) ORDER BY k.key),
    r.created_at,
    (SELECT count(*) FROM iam.assignment a WHERE a.role_id = r.id AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())),
    (SELECT count(*) FROM iam.role_affected_users(r.id)),
    (SELECT count(*) FROM iam.group_role_mapping m WHERE m.role_id = r.id AND m.removed_at IS NULL)
  FROM iam.role r LEFT JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
  WHERE (only_role IS NULL OR r.id = only_role) AND r.service_account_id IS NULL
  ORDER BY r.builtin DESC, lower(r.name);
END $$;

CREATE OR REPLACE FUNCTION iam.role_export(ids uuid[]) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.role_actor(NULL);
  RETURN jsonb_build_object('format', 'fair.roles.v1', 'catalog_version', (SELECT c.version FROM iam.permission_catalog c),
    'exported_at', now(),
    'roles', coalesce((SELECT jsonb_agg(jsonb_build_object('name', r.name, 'permissions', to_jsonb(v.permissions)) ORDER BY r.name)
                       FROM iam.role r JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
                       WHERE NOT r.builtin AND r.status <> 'retired' AND r.service_account_id IS NULL AND (ids IS NULL OR r.id = ANY (ids))), '[]'));
END $$;

-- Group mappings never map a service account's role (0048).
CREATE OR REPLACE FUNCTION iam.mapping_authorize(actor uuid, role uuid, bu uuid) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r     iam.role;
  perms text[];
BEGIN
  IF NOT iam.user_has_permission(actor, 'access.map_groups', bu) THEN
    RAISE EXCEPTION 'access.map_groups is required at this BU' USING ERRCODE = 'PF008';
  END IF;
  SELECT * INTO r FROM iam.role x WHERE x.id = role;
  IF NOT FOUND OR r.status <> 'active' OR r.current_version = 0 OR r.service_account_id IS NOT NULL THEN
    RAISE EXCEPTION 'the role is not assignable' USING ERRCODE = 'PF004';
  END IF;
  SELECT v.permissions INTO perms FROM iam.role_version v WHERE v.role_id = r.id AND v.version = r.current_version;
  IF EXISTS (SELECT 1 FROM iam.permission p WHERE p.key = ANY (perms) AND p.action = 'admin')
     AND NOT iam.holds_permission(actor, 'access.map_groups', NULL) THEN
    RAISE EXCEPTION 'role "%" contains admin permissions; only root-level mappers may map it (AC-22)', r.name USING ERRCODE = 'PF008';
  END IF;
END $$;

-- User administration covers people; service accounts have their own API
-- (0047).
CREATE OR REPLACE FUNCTION iam.user_admin_list(only_user uuid, status_filter text, source_filter text, idp_filter uuid, q text,
  lim integer, skip integer)
RETURNS TABLE (id uuid, email text, display_name text, status text, disabled_reason text, source text, idp_id uuid,
               external_id text, user_name text, last_login_at timestamptz, created_at timestamptz, reactivated_at timestamptz,
               live_sessions integer, groups jsonb, assignments jsonb, total bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.user_admin_actor();
  bus   uuid[] := ARRAY(SELECT iam.user_view_bus(actor));
  root  boolean := iam.holds_permission(actor, 'user.view', NULL);
BEGIN
  RETURN QUERY
  WITH principals AS (SELECT * FROM iam.assigned_in(bus)),
  visible AS (
    SELECT u.* FROM iam.app_user u
    WHERE u.source::text <> 'service'
      AND (root OR u.id IN (SELECT p.id FROM principals p WHERE p.kind = 'user')
               OR EXISTS (SELECT 1 FROM iam.grp_member m JOIN principals p ON p.kind = 'group' AND p.id = m.grp_id
                          WHERE m.user_id = u.id))
      AND (only_user IS NULL OR u.id = only_user)
      AND (status_filter IS NULL OR u.status::text = status_filter)
      AND (source_filter IS NULL OR u.source::text = source_filter)
      AND (idp_filter IS NULL OR u.idp_id = idp_filter)
      AND (q IS NULL OR lower(u.email) LIKE lower(q) || '%' OR lower(u.display_name) LIKE lower(q) || '%')
  )
  SELECT v.id, v.email, v.display_name, v.status::text, v.disabled_reason, v.source::text, v.idp_id, v.external_id, v.user_name,
    v.last_login_at, v.created_at, v.reactivated_at,
    (SELECT count(*)::integer FROM iam.session s WHERE s.user_id = v.id AND s.revoked_at IS NULL),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', g.id, 'display_name', g.display_name) ORDER BY g.display_name, g.id)
              FROM iam.grp_member m JOIN iam.grp g ON g.id = m.grp_id AND g.scim_deleted_at IS NULL WHERE m.user_id = v.id), '[]'),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', a.id, 'role', r.name, 'bu', b.code, 'bu_id', b.id,
                                                  'via_group', CASE WHEN a.principal_kind = 'group' THEN a.principal_id END,
                                                  'expires_at', a.expires_at) ORDER BY b.code, r.name, a.id)
              FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id JOIN iam.bu b ON b.id = a.bu_id
              WHERE a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
                AND ((a.principal_kind = 'user' AND a.principal_id = v.id)
                  OR (a.principal_kind = 'group' AND EXISTS (SELECT 1 FROM iam.grp_member m WHERE m.grp_id = a.principal_id AND m.user_id = v.id)))
                AND (root OR a.bu_id = ANY (bus))), '[]'),
    count(*) OVER ()
  FROM visible v ORDER BY lower(v.email), v.id
  LIMIT greatest(least(coalesce(lim, 100), 1000), 0) OFFSET greatest(coalesce(skip, 0), 0);
END $$;

CREATE OR REPLACE FUNCTION iam.user_admin_action(target uuid, action text, reason text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.user_admin_actor();
  was   iam.app_user;
  u     iam.app_user;
BEGIN
  IF NOT iam.holds_permission(actor, 'user.manage', NULL) THEN
    RAISE EXCEPTION 'user.manage is required' USING ERRCODE = 'PF008';
  END IF;
  IF action NOT IN ('disable', 'enable', 'unlock') THEN
    RAISE EXCEPTION 'unknown action %', action USING ERRCODE = '22023';
  END IF;
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO was FROM iam.app_user x WHERE x.id = target AND x.source::text <> 'service' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no user %', target USING ERRCODE = 'P0002';
  END IF;
  IF target = actor THEN
    RAISE EXCEPTION 'you cannot % your own account', action USING ERRCODE = 'PF003';
  END IF;
  CASE action
  WHEN 'disable' THEN
    IF was.status <> 'active' THEN
      RAISE EXCEPTION 'the user is % already', was.status USING ERRCODE = 'PF003';
    END IF;
    IF iam.is_root_grantor(target) AND NOT EXISTS (
         SELECT 1 FROM iam.app_user o WHERE o.id <> target AND o.status = 'active' AND iam.is_root_grantor(o.id)) THEN
      RAISE EXCEPTION 'the last active root administrator cannot be disabled' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'admin' WHERE x.id = target RETURNING * INTO u;
  WHEN 'enable' THEN
    IF was.status = 'locked' THEN
      RAISE EXCEPTION 'the user is locked; unlock it' USING ERRCODE = 'PF003';
    END IF;
    IF was.status = 'active' THEN
      RAISE EXCEPTION 'the user is active already' USING ERRCODE = 'PF003';
    END IF;
    IF was.disabled_reason IN ('scim', 'scim_deleted') THEN
      RAISE EXCEPTION 'the user was disabled by its identity provider; re-enable it there' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.app_user x SET status = 'active', disabled_reason = NULL, reactivated_at = now() WHERE x.id = target RETURNING * INTO u;
  WHEN 'unlock' THEN
    IF was.status <> 'locked' THEN
      RAISE EXCEPTION 'the user is not locked' USING ERRCODE = 'PF003';
    END IF;
    UPDATE iam.app_user x SET status = 'active', disabled_reason = NULL, reactivated_at = now() WHERE x.id = target RETURNING * INTO u;
  END CASE;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'user.' || CASE action WHEN 'disable' THEN 'disabled' WHEN 'enable' THEN 'enabled' ELSE 'unlocked' END,
    'severity', 'high', 'actor', actor::text, 'target', 'user:' || target, 'reason', reason,
    'attributes', jsonb_build_object('email', u.email, 'before', jsonb_build_object('status', was.status, 'disabled_reason', was.disabled_reason),
                                     'after', jsonb_build_object('status', u.status, 'disabled_reason', u.disabled_reason))));
  RETURN u.status::text;
END $$;

REVOKE ALL ON FUNCTION iam.token_max_lifetime(), iam.sa_actor(), iam.sa_managed(uuid, uuid), iam.sa_check_scopes(text[]),
  iam.sa_unheld(uuid, uuid, text[]), iam.sa_event(text, text, uuid, uuid, text, jsonb), iam.sa_new_bu(uuid, uuid),
  iam.sa_create_now(uuid, text, uuid, text[], text, text, jsonb), iam.sa_scopes_now(uuid, iam.service_account, text[], text, jsonb),
  iam.service_account_create(text, uuid, text[], text, text), iam.service_account_update(uuid, text, text[], text),
  iam.service_account_apply(uuid), iam.service_account_set_status(uuid, boolean, text), iam.service_account_list(uuid),
  iam.sa_secret_create(uuid, text, bytea, text, timestamptz, text), iam.sa_secret_list(uuid), iam.sa_credential_revoke(uuid, uuid, text),
  iam.sa_certificate_add(uuid, text, bytea, text, timestamptz, timestamptz, text), iam.sa_certificate_list(uuid),
  iam.sa_token_issue(uuid, bytea, bytea, text[], bytea, interval, text), iam.sa_access_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.service_account_create(text, uuid, text[], text, text), iam.service_account_update(uuid, text, text[], text),
  iam.service_account_apply(uuid), iam.service_account_set_status(uuid, boolean, text), iam.service_account_list(uuid),
  iam.sa_secret_create(uuid, text, bytea, text, timestamptz, text), iam.sa_secret_list(uuid), iam.sa_credential_revoke(uuid, uuid, text),
  iam.sa_certificate_add(uuid, text, bytea, text, timestamptz, timestamptz, text), iam.sa_certificate_list(uuid) TO app_rw;
GRANT EXECUTE ON FUNCTION iam.sa_token_issue(uuid, bytea, bytea, text[], bytea, interval, text), iam.sa_access_lookup(bytea) TO app_gateway;
