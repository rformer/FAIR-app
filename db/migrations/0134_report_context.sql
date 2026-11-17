-- F-010 T-04 (ADR-007 amendment 6; F-010-AC-11, AC-20; design §3.3): a
-- delegated, read-only DB context for report jobs.
--
--   * authz.ctx_key.purpose: 'session' (the gateway's keys, as before) or
--     'report' (the risk service's risk/report-context key).
--   * authz.ctx_user() accepts a token signed with a 'report' key only
--     inside a read-only transaction, and only while a report.run of the
--     token's user is running with the token's nonce. Otherwise it answers
--     no user, so RLS returns nothing and every write function refuses. A
--     session key's tokens are unchanged.
--   * authz.add_ctx_key(id, secret, purpose); the two-argument form keeps
--     adding session keys.

ALTER TABLE authz.ctx_key ADD COLUMN purpose text NOT NULL DEFAULT 'session' CHECK (purpose IN ('session', 'report'));

CREATE FUNCTION authz.add_ctx_key(new_key_id text, new_secret bytea, key_purpose text) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO authz.ctx_key (key_id, secret, purpose) VALUES (new_key_id, new_secret, key_purpose);
$$;
REVOKE ALL ON FUNCTION authz.add_ctx_key(text, bytea, text) FROM PUBLIC;

GRANT USAGE ON SCHEMA report TO authz_definer;
GRANT SELECT (requested_by, state, context_nonce) ON report.run TO authz_definer;

GRANT CREATE ON SCHEMA authz TO authz_definer;
SET ROLE authz_definer;

-- As 0062, with the report purpose's two further conditions.
CREATE OR REPLACE FUNCTION authz.ctx_user(OUT user_id uuid, OUT scope_version bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  tok text := current_setting('authz.ctx', true);
  parts text[];
  k bytea;
  purpose text;
  uid uuid;
  ver bigint;
  exp bigint;
BEGIN
  IF tok IS NULL OR tok = '' THEN
    RETURN;
  END IF;
  parts := string_to_array(tok, '.');
  IF cardinality(parts) <> 7 OR parts[1] <> 'v1' THEN
    RETURN;
  END IF;
  SELECT c.secret, c.purpose INTO k, purpose FROM authz.ctx_key c
  WHERE c.key_id = parts[2] AND (c.retired_at IS NULL OR c.retired_at > now());
  IF k IS NULL THEN
    RETURN;
  END IF;
  IF encode(authz.hmac(convert_to(array_to_string(parts[1:6], '.'), 'UTF8'), k, 'sha256'), 'hex') <> parts[7] THEN
    RETURN;
  END IF;
  BEGIN
    uid := parts[3]::uuid;
    ver := parts[4]::bigint;
    exp := parts[5]::bigint;
  EXCEPTION WHEN others THEN
    RETURN;
  END;
  IF exp <= extract(epoch FROM now()) OR exp > extract(epoch FROM now()) + authz.ctx_max_ttl() THEN
    RETURN;
  END IF;
  IF purpose = 'report' THEN
    -- Delegated: reads only, for the run it was minted for (amendment 6).
    IF current_setting('transaction_read_only') <> 'on' THEN
      RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM report.run r WHERE r.requested_by = uid AND r.state = 'running' AND r.context_nonce = parts[6]) THEN
      RETURN;
    END IF;
  ELSIF purpose <> 'session' THEN
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM authz.user_scope u WHERE u.user_id = uid AND u.scope_version = ver) THEN
    RETURN;  -- no access, or a stale token
  END IF;
  user_id := uid;
  scope_version := ver;
END $$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA authz FROM authz_definer;
