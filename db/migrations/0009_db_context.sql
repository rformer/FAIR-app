-- F-001 T-09 (AC-24, AC-25, AC-27; ADR-007; design §4): signed database
-- context and BU row-level security.
--
-- Services start each transaction with SET LOCAL authz.ctx = '<token>':
--
--   v1.<key_id>.<user_id>.<scope_version>.<expiry_unix>.<nonce>.<hmac>
--
-- where <hmac> is lowercase hex HMAC-SHA-256, keyed by authz.ctx_key, over
-- everything before the last dot (pkg/authz.MintDBContext). RLS policies call
-- authz.visible_bus, owned by the non-login authz_definer, which returns the
-- caller's BUs from authz.user_scope only for a valid, unexpired token whose
-- scope_version is current. Anything else yields an empty set (fail closed).
-- Application roles cannot read the keys.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA authz;

-- Tokens live at most 5 minutes (design §4); allow some clock skew.
CREATE FUNCTION authz.ctx_max_ttl() RETURNS integer
LANGUAGE sql IMMUTABLE AS $$ SELECT 600 $$;

-- Key management (installer and rotation runbook; fair_owner only). During a
-- rotation the old key stays valid until retired_at, so in-flight tokens keep
-- working (design §4.8).
ALTER TABLE authz.ctx_key ADD CONSTRAINT ctx_key_id_format CHECK (key_id ~ '^[A-Za-z0-9_-]{1,64}$');

CREATE FUNCTION authz.add_ctx_key(new_key_id text, new_secret bytea) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO authz.ctx_key (key_id, secret) VALUES (new_key_id, new_secret);
$$;

CREATE FUNCTION authz.retire_ctx_key(old_key_id text, valid_until timestamptz DEFAULT now() + interval '10 minutes') RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE authz.ctx_key SET retired_at = valid_until WHERE key_id = old_key_id AND retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ctx_key: no active key %', old_key_id USING ERRCODE = 'no_data_found';
  END IF;
END $$;

-- The caller's scope row for a valid context token, or NULL.
CREATE FUNCTION authz.ctx_scope() RETURNS authz.user_scope
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  tok text := current_setting('authz.ctx', true);
  parts text[];
  k bytea;
  uid uuid;
  ver bigint;
  exp bigint;
  s authz.user_scope;
BEGIN
  IF tok IS NULL OR tok = '' THEN
    RETURN NULL;
  END IF;
  parts := string_to_array(tok, '.');
  IF cardinality(parts) <> 7 OR parts[1] <> 'v1' THEN
    RETURN NULL;
  END IF;
  SELECT c.secret INTO k FROM authz.ctx_key c
  WHERE c.key_id = parts[2] AND (c.retired_at IS NULL OR c.retired_at > now());
  IF k IS NULL THEN
    RETURN NULL;
  END IF;
  IF encode(authz.hmac(convert_to(array_to_string(parts[1:6], '.'), 'UTF8'), k, 'sha256'), 'hex') <> parts[7] THEN
    RETURN NULL;
  END IF;
  BEGIN
    uid := parts[3]::uuid;
    ver := parts[4]::bigint;
    exp := parts[5]::bigint;
  EXCEPTION WHEN others THEN
    RETURN NULL;
  END;
  IF exp <= extract(epoch FROM now()) OR exp > extract(epoch FROM now()) + authz.ctx_max_ttl() THEN
    RETURN NULL;
  END IF;
  SELECT * INTO s FROM authz.user_scope u WHERE u.user_id = uid;
  IF NOT FOUND OR s.scope_version <> ver THEN
    RETURN NULL;  -- no access, or a stale token
  END IF;
  RETURN s;
END $$;

-- BUs the caller may read (mode 'read') or write (mode 'write') for a
-- resource type. Empty for any invalid context or unknown mode.
CREATE FUNCTION authz.visible_bus(resource_type text, mode text DEFAULT 'read') RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(ARRAY(
    SELECT b::uuid FROM authz.ctx_scope() s,
      jsonb_array_elements_text(CASE mode WHEN 'read' THEN s.read_bus WHEN 'write' THEN s.write_bus END -> resource_type) b
  ), '{}');
$$;

-- authz_definer owns the context functions: it can read the keys and the
-- materialized scope, and nothing else.
-- Grant before the ownership change: afterwards fair_owner may not grant, and
-- existing grants carry over to the new owner.
GRANT EXECUTE ON FUNCTION authz.visible_bus(text, text) TO app_rw, app_engine;
GRANT CREATE ON SCHEMA authz TO authz_definer;
GRANT SELECT ON authz.user_scope TO authz_definer;
GRANT EXECUTE ON FUNCTION authz.hmac(bytea, bytea, text), authz.ctx_max_ttl() TO authz_definer;
ALTER FUNCTION authz.ctx_scope() OWNER TO authz_definer;
ALTER FUNCTION authz.visible_bus(text, text) OWNER TO authz_definer;
REVOKE CREATE ON SCHEMA authz FROM authz_definer;

-- Registry of BU-owned tables (AC-24); T-31's archive guard reads it.
CREATE TABLE iam.bu_owned_tables (
  table_name     regclass    PRIMARY KEY,
  resource_type  text        NOT NULL,
  registered_at  timestamptz NOT NULL DEFAULT now()
);

-- Makes a table BU-owned: bu_id must exist (uuid, NOT NULL); adds the foreign
-- key and index, enables and forces RLS, and installs one policy per
-- operation. Reads use read_bus; writes use write_bus (USING and WITH CHECK),
-- so rows can be neither written outside nor moved out of write scope.
-- Refuses tables that already carry other policies, since permissive
-- policies are OR-ed and could widen access. Run by migrations (fair_owner).
CREATE FUNCTION authz.apply_bu_rls(tbl regclass, resource_type text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  rel text := (SELECT c.relname FROM pg_class c WHERE c.oid = tbl);
  rt text := quote_literal(resource_type);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.permission p WHERE p.resource_type = apply_bu_rls.resource_type) THEN
    RAISE EXCEPTION 'apply_bu_rls: unknown resource type %', resource_type USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = 'bu_id'
                 AND a.atttypid = 'uuid'::regtype AND a.attnotnull AND NOT a.attisdropped) THEN
    RAISE EXCEPTION 'apply_bu_rls: % needs a NOT NULL uuid column bu_id (AC-24)', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = tbl AND p.polname NOT IN ('bu_select', 'bu_insert', 'bu_update', 'bu_delete')) THEN
    RAISE EXCEPTION 'apply_bu_rls: % has other policies; BU tables carry only the BU policies', tbl USING ERRCODE = 'invalid_table_definition';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid = tbl AND c.contype = 'f' AND c.confrelid = 'iam.bu'::regclass) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (bu_id) REFERENCES iam.bu (id)', tbl, rel || '_bu_fk');
  END IF;
  EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %s (bu_id)', rel || '_bu_id', tbl);
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);

  EXECUTE format('DROP POLICY IF EXISTS bu_select ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_insert ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_update ON %s', tbl);
  EXECUTE format('DROP POLICY IF EXISTS bu_delete ON %s', tbl);
  -- (SELECT ...) makes each call an InitPlan, evaluated once per statement; the
  -- ::uuid[] cast makes ANY take it as an array rather than a subquery.
  EXECUTE format('CREATE POLICY bu_select ON %s FOR SELECT USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''read''))::uuid[]))', tbl, rt);
  EXECUTE format('CREATE POLICY bu_insert ON %s FOR INSERT WITH CHECK (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt);
  EXECUTE format('CREATE POLICY bu_update ON %s FOR UPDATE USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))'
                 ' WITH CHECK (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt, rt);
  EXECUTE format('CREATE POLICY bu_delete ON %s FOR DELETE USING (bu_id = ANY ((SELECT authz.visible_bus(%s, ''write''))::uuid[]))', tbl, rt);

  INSERT INTO iam.bu_owned_tables (table_name, resource_type) VALUES (tbl, resource_type)
  ON CONFLICT (table_name) DO UPDATE SET resource_type = EXCLUDED.resource_type;
END $$;
