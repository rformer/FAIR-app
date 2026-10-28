-- F-015 T-31 (AC-03, AC-43; design §7): what the Posture API reads, and its
-- idempotency store. The API checks posture.view (at the root, or at the
-- BU asked about) before calling any of the read functions, which, like
-- every posture function, application roles reach only through
-- app_posture; mutations go through the existing functions, which take the
-- actor from the signed DB context and check their own permissions.

-- The API checks the caller's grants (authz.Cache over grant_snapshot,
-- which returns only the signed-context user's own grants).
GRANT USAGE ON SCHEMA authz TO app_posture;
GRANT EXECUTE ON FUNCTION authz.grant_snapshot() TO app_posture;

-- The root BU, for instance-wide permission checks.
CREATE FUNCTION iam.root_bu() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT id FROM iam.bu WHERE parent_id IS NULL;
$$;
REVOKE ALL ON FUNCTION iam.root_bu() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.root_bu() TO posture_definer;

-- Mutation outcomes per user and Idempotency-Key (server.Idempotent),
-- kept 24 hours. status NULL: in progress (taken over after 5 minutes).
CREATE TABLE posture.idempotency (
  user_id       uuid        NOT NULL,
  key           text        NOT NULL CHECK (key ~ '^[\x21-\x7e]{8,128}$'),
  request_hash  text        NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  status        integer     CHECK (status BETWEEN 100 AND 599),
  content_type  text,
  body          bytea,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key)
);
REVOKE ALL ON posture.idempotency FROM PUBLIC;
ALTER TABLE posture.idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.idempotency FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.idempotency TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON posture.idempotency TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- AC-43: the Posture page, visible to posture.view holders, shows profiles,
-- their differences and pending switches; reading them (profile_reader,
-- T-20) now also accepts posture.view. Every profile write still needs
-- profile.manage (profile_actor).
CREATE OR REPLACE FUNCTION posture.profile_reader() RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL OR NOT (iam.holds_permission(u, 'posture.view', NULL) OR iam.holds_permission(u, 'profile.manage', NULL)
                       OR iam.holds_permission(u, 'profile.approve', NULL)) THEN
    RAISE EXCEPTION 'posture.view, profile.manage or profile.approve is required' USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- As in T-19, but readable under profile_reader's rule.
CREATE OR REPLACE FUNCTION posture.custom_profile_view(pid text, ver text)
RETURNS TABLE (key text, type text, base_default jsonb, base_bound jsonb, default_value jsonb, bound jsonb,
               direction text, loosened boolean, justification text, params text[])
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := posture.profile_reader();
  p posture.profile;
BEGIN
  SELECT * INTO p FROM posture.profile x WHERE x.id = pid AND x.version = ver AND x.kind = 'custom';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom profile % % does not exist', pid, ver USING ERRCODE = 'PF003';
  END IF;
  RETURN QUERY
  SELECT v.key, sd.type, b.default_value, b.bound, v.default_value, v.bound,
         CASE WHEN sd.key IS NULL THEN 'unregistered'
              WHEN posture.compare(sd, v.bound, b.bound) < 0 OR posture.compare(sd, v.default_value, b.default_value) < 0 THEN 'loosen'
              WHEN posture.compare(sd, v.bound, b.bound) > 0 OR posture.compare(sd, v.default_value, b.default_value) > 0 THEN 'tighten'
              ELSE 'unchanged' END,
         v.loosened, v.justification, coalesce(sd.params, '{}')
  FROM posture.profile_value v
  JOIN posture.profile_value b ON b.profile_id = p.base_profile_id AND b.version = p.base_version AND b.key = v.key
  LEFT JOIN posture.setting_def sd ON sd.key = v.key
  WHERE v.profile_id = pid AND v.version = ver
  ORDER BY v.key;
END $$;

CREATE FUNCTION posture.root_bu() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.root_bu();
$$;

-- outcome: 'new' (reserved), 'replay' (status, content_type, body), 'mismatch', 'in_progress'.
CREATE FUNCTION posture.idempotency_begin(u uuid, k text, h text,
  OUT outcome text, OUT status integer, OUT content_type text, OUT body bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
  r posture.idempotency;
BEGIN
  DELETE FROM posture.idempotency i WHERE i.created_at < now() - interval '24 hours';
  DELETE FROM posture.idempotency i WHERE i.status IS NULL AND i.created_at < now() - interval '5 minutes';
  INSERT INTO posture.idempotency (user_id, key, request_hash) VALUES (u, k, h) ON CONFLICT DO NOTHING;
  IF FOUND THEN
    outcome := 'new';
    RETURN;
  END IF;
  SELECT * INTO r FROM posture.idempotency i WHERE i.user_id = u AND i.key = k;
  IF r.request_hash <> h THEN
    outcome := 'mismatch';
  ELSIF r.status IS NULL THEN
    outcome := 'in_progress';
  ELSE
    outcome := 'replay'; status := r.status; content_type := r.content_type; body := r.body;
  END IF;
END $$;

CREATE FUNCTION posture.idempotency_complete(u uuid, k text, s integer, ct text, b bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE posture.idempotency SET status = s, content_type = ct, body = b WHERE user_id = u AND key = k AND status IS NULL;
$$;

CREATE FUNCTION posture.idempotency_abandon(u uuid, k text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM posture.idempotency WHERE user_id = u AND key = k AND status IS NULL;
$$;

-- AC-03: every registered setting with its instance value, source, the
-- active profile's default and bound, and deviation status.
CREATE FUNCTION posture.registry_view()
RETURNS TABLE (key text, type text, direction text, enum_order text[], bu_scopable boolean, owner_feature text,
               params text[], hard_floor jsonb, value jsonb, source text, profile_default jsonb, bound jsonb,
               deviation text, exception_id uuid, exception_expires timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH ap AS (SELECT a.profile_id, a.version, p.family FROM posture.active_profile a
              JOIN posture.profile p ON p.id = a.profile_id AND p.version = a.version)
  SELECT d.key, d.type, d.direction, d.enum_order, d.bu_scopable, d.owner_feature, d.params, d.hard_floor,
         coalesce(s.value, pv.default_value), coalesce(s.source, 'profile'), pv.default_value, pv.bound,
         CASE
           WHEN pv.key IS NULL THEN 'unbound'
           WHEN posture.below_floor(d, ap.family, coalesce(s.value, pv.default_value)) THEN 'below_floor'
           WHEN posture.compare(d, coalesce(s.value, pv.default_value), pv.bound) >= 0 THEN 'in_bounds'
           WHEN e.state IN ('active', 'revert_failed') THEN 'exception'
           ELSE 'out_of_bounds'
         END,
         e.id, e.expires_at
  FROM posture.setting_def d
  LEFT JOIN ap ON true
  LEFT JOIN posture.profile_value pv ON pv.profile_id = ap.profile_id AND pv.version = ap.version AND pv.key = d.key
  LEFT JOIN posture.setting_value s ON s.key = d.key AND s.bu_id IS NULL
  LEFT JOIN posture.exception e ON e.id = s.exception_id
  ORDER BY d.key;
$$;

-- BU overrides (the API filters them to the BUs the caller may see).
CREATE FUNCTION posture.bu_overrides()
RETURNS TABLE (key text, bu_id uuid, value jsonb, source text, exception_id uuid, updated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.key, s.bu_id, s.value, s.source, s.exception_id, s.updated_at
  FROM posture.setting_value s WHERE s.bu_id IS NOT NULL ORDER BY s.key, s.bu_id;
$$;

-- Recent setting changes, newest first.
CREATE FUNCTION posture.changes_view(max_rows integer)
RETURNS TABLE (change_id uuid, key text, bu_id uuid, old_value jsonb, new_value jsonb, direction text, explanation text,
               requested_by uuid, approval_request_id uuid, state text, created_at timestamptz, applied_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.id, c.key, c.bu_id, c.old_value, c.new_value, c.direction, c.explanation, c.requested_by, c.approval_request_id,
         c.state, c.created_at, c.applied_at
  FROM posture.change c ORDER BY c.created_at DESC, c.id LIMIT least(greatest(max_rows, 1), 500);
$$;

-- Exceptions (settings and overlay), active first, by expiry.
CREATE FUNCTION posture.exceptions_view()
RETURNS TABLE (exception_id uuid, key text, bu_id uuid, is_overlay boolean, value jsonb, bound_at_creation jsonb, justification text,
               owner_id uuid, approved_by uuid, created_at timestamptz, expires_at timestamptz, renewed_from uuid, state text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT e.id, e.key, e.bu_id, e.overlay, e.value, e.bound_at_creation, e.justification, e.owner_id, e.approved_by,
         e.created_at, e.expires_at, e.renewed_from, e.state
  FROM posture.exception e
  ORDER BY e.state NOT IN ('active', 'revert_failed'), e.expires_at, e.id;
$$;

-- Profiles, every version.
CREATE FUNCTION posture.profiles_view()
RETURNS TABLE (profile_id text, version text, name text, family text, kind text, base_profile_id text, base_version text,
               status text, label_deviates boolean, active boolean, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT p.id, p.version, p.name, p.family, p.kind, p.base_profile_id, p.base_version, p.status, p.label_deviates,
         EXISTS (SELECT 1 FROM posture.active_profile a WHERE a.profile_id = p.id AND a.version = p.version), p.created_at
  FROM posture.profile p ORDER BY p.kind, p.id, p.created_at;
$$;

REVOKE ALL ON FUNCTION posture.root_bu(), posture.idempotency_begin(uuid, text, text), posture.idempotency_complete(uuid, text, integer, text, bytea),
  posture.idempotency_abandon(uuid, text), posture.registry_view(), posture.bu_overrides(), posture.changes_view(integer),
  posture.exceptions_view(), posture.profiles_view() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.root_bu(), posture.idempotency_begin(uuid, text, text), posture.idempotency_complete(uuid, text, integer, text, bytea),
  posture.idempotency_abandon(uuid, text), posture.registry_view(), posture.bu_overrides(), posture.changes_view(integer),
  posture.exceptions_view(), posture.profiles_view() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
