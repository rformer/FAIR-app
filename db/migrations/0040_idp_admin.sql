-- F-001 T-17 (AC-02, AC-03; design §3, §5.1 step 1, §6, §10): multiple IdPs,
-- home-realm discovery, and IdP administration.
--
--   * email_domains are lower-case domain names, and an enabled IdP's
--     domains overlap no other enabled IdP's (a domain routes to one IdP).
--   * iam.idp_discover(domain): the enabled IdP serving a domain (iam
--     service, app_rw), for POST /api/v1/auth/discover.
--   * iam.idp_admin_*: the IdP API (/api/v1/idps): list and read need
--     idp.view, changes idp.manage, from the signed DB context; every change
--     is audited (high) through the outbox in the same transaction. Metadata
--     is written as a whole (parsed and pinned by the iam service).
--   * iam.idempotency: Idempotency-Key outcomes for iam's API (as
--     posture.idempotency, migration 0033).

-- Domains: lower case, valid, unique among enabled IdPs.
CREATE FUNCTION iam.idp_check_domains() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d text;
  other text;
BEGIN
  NEW.email_domains := (SELECT coalesce(array_agg(DISTINCT lower(btrim(x)) ORDER BY lower(btrim(x))), '{}')
                        FROM unnest(NEW.email_domains) x WHERE btrim(x) <> '');
  FOREACH d IN ARRAY NEW.email_domains LOOP
    IF d !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' THEN
      RAISE EXCEPTION 'invalid email domain %', d USING ERRCODE = 'PF004';
    END IF;
  END LOOP;
  IF NEW.enabled THEN
    SELECT i.name INTO other FROM iam.idp i
    WHERE i.enabled AND i.id <> NEW.id AND i.email_domains && NEW.email_domains LIMIT 1;
    IF FOUND THEN
      RAISE EXCEPTION 'an email domain of % is already routed to IdP %', NEW.name, other USING ERRCODE = 'PF003';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER idp_domains BEFORE INSERT OR UPDATE ON iam.idp FOR EACH ROW EXECUTE FUNCTION iam.idp_check_domains();
CREATE INDEX idp_domains_gin ON iam.idp USING gin (email_domains) WHERE enabled;

-- The enabled IdP serving an email domain (no row: none).
CREATE FUNCTION iam.idp_discover(domain text) RETURNS TABLE (id uuid, kind text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT i.id, i.kind FROM iam.idp i WHERE i.enabled AND lower(btrim(domain)) = ANY (i.email_domains) LIMIT 1;
$$;

-- The signed-context user holding perm (PF007 / PF008 otherwise).
CREATE FUNCTION iam.idp_actor(perm text) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'the IdP API needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, perm, NULL) THEN
    RAISE EXCEPTION '% is required', perm USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION iam.idp_event(event text, actor uuid, i iam.idp, reason text, changes jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', 'high', 'actor', actor::text, 'target', 'idp:' || i.id,
    'reason', reason, 'attributes', jsonb_build_object('name', i.name, 'kind', i.kind, 'enabled', i.enabled,
    'email_domains', i.email_domains, 'metadata_source', i.metadata_source) || coalesce(changes, '{}')));
$$;

CREATE FUNCTION iam.idp_admin_list()
RETURNS TABLE (id uuid, kind text, name text, email_domains text[], metadata jsonb, metadata_source text,
               mfa_evidence_rule jsonb, enabled boolean, created_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.idp_actor('idp.view');
  RETURN QUERY SELECT i.id, i.kind, i.name, i.email_domains, i.metadata, i.metadata_source, i.mfa_evidence_rule, i.enabled, i.created_at
  FROM iam.idp i ORDER BY i.name, i.id;
END $$;

CREATE FUNCTION iam.idp_admin_create(idp_kind text, idp_name text, domains text[], reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('idp.manage');
  i iam.idp;
BEGIN
  -- A new IdP has no metadata yet, so it starts disabled.
  INSERT INTO iam.idp (kind, name, email_domains, enabled) VALUES (idp_kind, idp_name, coalesce(domains, '{}'), false) RETURNING * INTO i;
  PERFORM iam.idp_event('idp.created', u, i, reason, NULL);
  RETURN i.id;
END $$;

-- Changes name, domains or enabled (NULL: unchanged). Enabling needs
-- metadata.
CREATE FUNCTION iam.idp_admin_update(idp uuid, idp_name text, domains text[], idp_enabled boolean, reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('idp.manage');
  i iam.idp;
BEGIN
  SELECT * INTO i FROM iam.idp x WHERE x.id = idp FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no IdP %', idp USING ERRCODE = 'PF003';
  END IF;
  IF coalesce(idp_enabled, i.enabled) AND i.metadata = '{}'::jsonb THEN
    RAISE EXCEPTION 'IdP % has no metadata; upload or fetch it before enabling', i.name USING ERRCODE = 'PF003';
  END IF;
  UPDATE iam.idp x SET name = coalesce(idp_name, x.name), email_domains = coalesce(domains, x.email_domains),
    enabled = coalesce(idp_enabled, x.enabled) WHERE x.id = idp RETURNING * INTO i;
  PERFORM iam.idp_event(CASE WHEN idp_enabled IS NULL THEN 'idp.updated' WHEN idp_enabled THEN 'idp.enabled' ELSE 'idp.disabled' END,
    u, i, reason, NULL);
END $$;

-- Replaces an IdP's metadata (parsed, validated and pinned by the iam
-- service). fingerprints are its trust anchors' SHA-256 fingerprints, for
-- the audit trail.
CREATE FUNCTION iam.idp_admin_set_metadata(idp uuid, md jsonb, source text, fingerprints text[], reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := iam.idp_actor('idp.manage');
  i iam.idp;
BEGIN
  UPDATE iam.idp x SET metadata = md, metadata_source = source WHERE x.id = idp RETURNING * INTO i;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no IdP %', idp USING ERRCODE = 'PF003';
  END IF;
  PERFORM iam.idp_event('idp.metadata_changed', u, i, reason, jsonb_build_object('fingerprints', fingerprints));
END $$;

-- Idempotency-Key outcomes for iam's API, kept 24 hours (server.Idempotent).
CREATE TABLE iam.idempotency (
  user_id       uuid        NOT NULL,
  key           text        NOT NULL CHECK (key ~ '^[\x21-\x7e]{8,128}$'),
  request_hash  text        NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  status        integer     CHECK (status BETWEEN 100 AND 599),
  content_type  text,
  body          bytea,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key)
);
REVOKE ALL ON iam.idempotency FROM PUBLIC;

CREATE FUNCTION iam.idempotency_begin(u uuid, k text, h text,
  OUT outcome text, OUT status integer, OUT content_type text, OUT body bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  r iam.idempotency;
BEGIN
  DELETE FROM iam.idempotency i WHERE i.created_at < now() - interval '24 hours';
  DELETE FROM iam.idempotency i WHERE i.status IS NULL AND i.created_at < now() - interval '5 minutes';
  INSERT INTO iam.idempotency (user_id, key, request_hash) VALUES (u, k, h) ON CONFLICT DO NOTHING;
  IF FOUND THEN
    outcome := 'new';
    RETURN;
  END IF;
  SELECT * INTO r FROM iam.idempotency i WHERE i.user_id = u AND i.key = k;
  IF r.request_hash <> h THEN
    outcome := 'mismatch';
  ELSIF r.status IS NULL THEN
    outcome := 'in_progress';
  ELSE
    outcome := 'replay'; status := r.status; content_type := r.content_type; body := r.body;
  END IF;
END $$;

CREATE FUNCTION iam.idempotency_complete(u uuid, k text, s integer, ct text, b bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE iam.idempotency SET status = s, content_type = ct, body = b WHERE user_id = u AND key = k AND status IS NULL;
$$;

CREATE FUNCTION iam.idempotency_abandon(u uuid, k text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM iam.idempotency WHERE user_id = u AND key = k AND status IS NULL;
$$;

REVOKE ALL ON FUNCTION iam.idp_check_domains(), iam.idp_discover(text), iam.idp_actor(text),
  iam.idp_event(text, uuid, iam.idp, text, jsonb), iam.idp_admin_list(), iam.idp_admin_create(text, text, text[], text),
  iam.idp_admin_update(uuid, text, text[], boolean, text), iam.idp_admin_set_metadata(uuid, jsonb, text, text[], text),
  iam.idempotency_begin(uuid, text, text), iam.idempotency_complete(uuid, text, integer, text, bytea),
  iam.idempotency_abandon(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.idp_discover(text), iam.idp_admin_list(), iam.idp_admin_create(text, text, text[], text),
  iam.idp_admin_update(uuid, text, text[], boolean, text), iam.idp_admin_set_metadata(uuid, jsonb, text, text[], text),
  iam.idempotency_begin(uuid, text, text), iam.idempotency_complete(uuid, text, integer, text, bytea),
  iam.idempotency_abandon(uuid, text) TO app_rw;

-- The API checks idp.view at the root BU (authz.Cache).
GRANT EXECUTE ON FUNCTION iam.root_bu() TO app_rw;
