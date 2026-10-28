-- F-001 T-15 (AC-01, AC-04; design §3 Identity, §5.1, §7; ADR-009): SAML
-- login.
--
--   iam.idp                 identity providers (design §3). SAML metadata as
--                           JSON: entity_id, sso_url, certificates (PEM) and
--                           allow_idp_initiated. Managed by T-17 (upload,
--                           discovery); read here through iam.idp_for_login.
--   iam.saml_request        pending AuthnRequests, for InResponseTo, consumed
--                           once, 10 minutes at most
--   iam.saml_assertion      the replay cache: assertion IDs until they expire
--   iam.login_ticket_used   login tickets the gateway redeemed (single use)
--
-- The iam service (app_rw) reaches these through SECURITY DEFINER functions
-- only; the gateway (app_gateway) only redeems tickets. Logins are audited
-- through the outbox (authn.login.success, authn.login.denied).

CREATE TABLE iam.idp (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind               text        NOT NULL CHECK (kind IN ('saml', 'oidc', 'keycloak')),
  name               text        NOT NULL UNIQUE CHECK (btrim(name) <> ''),
  email_domains      text[]      NOT NULL DEFAULT '{}',
  metadata           jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(metadata) = 'object'),
  metadata_source    text        CHECK (metadata_source IN ('url', 'file')),
  mfa_evidence_rule  jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(mfa_evidence_rule) = 'object'),
  enabled            boolean     NOT NULL DEFAULT true,
  created_at         timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON iam.idp FROM PUBLIC;

ALTER TABLE iam.app_user ADD CONSTRAINT app_user_idp_fk FOREIGN KEY (idp_id) REFERENCES iam.idp (id);
CREATE UNIQUE INDEX app_user_idp_external ON iam.app_user (idp_id, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE iam.saml_request (
  idp_id      uuid        NOT NULL REFERENCES iam.idp (id),
  request_id  text        NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
  return_to   text        NOT NULL CHECK (return_to ~ '^/' AND return_to !~ '^//' AND length(return_to) <= 2048),
  expires_at  timestamptz NOT NULL,
  PRIMARY KEY (idp_id, request_id)
);
CREATE TABLE iam.saml_assertion (
  idp_id        uuid        NOT NULL REFERENCES iam.idp (id),
  assertion_id  text        NOT NULL CHECK (length(assertion_id) BETWEEN 1 AND 256),
  expires_at    timestamptz NOT NULL,
  PRIMARY KEY (idp_id, assertion_id)
);
CREATE TABLE iam.login_ticket_used (
  ticket_id   uuid        PRIMARY KEY,
  expires_at  timestamptz NOT NULL
);
REVOKE ALL ON iam.saml_request, iam.saml_assertion, iam.login_ticket_used FROM PUBLIC;

-- An enabled IdP's login configuration (NULL row: unknown or disabled).
CREATE FUNCTION iam.idp_for_login(idp uuid)
RETURNS TABLE (kind text, name text, metadata jsonb, mfa_evidence_rule jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT i.kind, i.name, i.metadata, i.mfa_evidence_rule FROM iam.idp i WHERE i.id = idp AND i.enabled;
$$;

CREATE FUNCTION iam.saml_request_save(idp uuid, request text, return_path text, expires timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF expires > now() + interval '10 minutes' THEN
    RAISE EXCEPTION 'a pending request lives at most 10 minutes' USING ERRCODE = '22023';
  END IF;
  DELETE FROM iam.saml_request r WHERE r.expires_at < now(); -- keep the table small
  INSERT INTO iam.saml_request (idp_id, request_id, return_to, expires_at) VALUES (idp, request, return_path, expires);
END $$;

-- The pending request's return path, deleted; NULL when there is none.
CREATE FUNCTION iam.saml_request_consume(idp uuid, request text) RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM iam.saml_request r WHERE r.idp_id = idp AND r.request_id = request AND r.expires_at > now() RETURNING r.return_to;
$$;

-- Records an assertion ID; false when it was already recorded (a replay).
CREATE FUNCTION iam.saml_assertion_record(idp uuid, assertion text, until timestamptz) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  DELETE FROM iam.saml_assertion a WHERE a.expires_at < now() - interval '1 hour';
  INSERT INTO iam.saml_assertion (idp_id, assertion_id, expires_at) VALUES (idp, assertion, until);
  RETURN true;
EXCEPTION WHEN unique_violation THEN
  RETURN false;
END $$;

-- The user an IdP's subject identifies: (idp, external id). status says
-- whether they may sign in; no row when unknown (JIT is T-23).
CREATE FUNCTION iam.login_user(idp uuid, external text) RETURNS TABLE (user_id uuid, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.id, u.status::text FROM iam.app_user u WHERE u.idp_id = idp AND u.external_id = external;
$$;

-- A login outcome for the audit trail.
CREATE FUNCTION iam.authn_event(event text, severity text, actor text, idp uuid, attributes jsonb, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF event NOT IN ('authn.login.success', 'authn.login.denied') OR severity NOT IN ('info', 'low', 'high') THEN
    RAISE EXCEPTION 'unknown login event %', event USING ERRCODE = '22023';
  END IF;
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', severity, 'actor', actor, 'target', 'idp:' || idp,
                                      'reason', reason, 'attributes', coalesce(attributes, '{}')));
END $$;

-- The gateway redeems a login ticket once; false when already redeemed.
CREATE FUNCTION iam.login_ticket_use(ticket uuid, expires timestamptz) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF expires > now() + interval '2 minutes' THEN
    RAISE EXCEPTION 'a login ticket lives at most a minute' USING ERRCODE = '22023';
  END IF;
  DELETE FROM iam.login_ticket_used t WHERE t.expires_at < now() - interval '1 hour';
  INSERT INTO iam.login_ticket_used (ticket_id, expires_at) VALUES (ticket, expires);
  RETURN true;
EXCEPTION WHEN unique_violation THEN
  RETURN false;
END $$;

REVOKE ALL ON FUNCTION iam.idp_for_login(uuid), iam.saml_request_save(uuid, text, text, timestamptz),
  iam.saml_request_consume(uuid, text), iam.saml_assertion_record(uuid, text, timestamptz), iam.login_user(uuid, text),
  iam.authn_event(text, text, text, uuid, jsonb, text), iam.login_ticket_use(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.idp_for_login(uuid), iam.saml_request_save(uuid, text, text, timestamptz),
  iam.saml_request_consume(uuid, text), iam.saml_assertion_record(uuid, text, timestamptz), iam.login_user(uuid, text),
  iam.authn_event(text, text, text, uuid, jsonb, text) TO app_rw;
GRANT EXECUTE ON FUNCTION iam.login_ticket_use(uuid, timestamptz) TO app_gateway;
