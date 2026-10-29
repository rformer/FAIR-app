-- F-001 T-16 (AC-01, AC-04; design §5.1): OIDC login (authorization code +
-- PKCE, state and nonce).
--
-- iam.oidc_state holds each started login until its callback: the state
-- (the key; a 256-bit random value), the nonce the ID token must carry, the
-- PKCE code verifier, and the path to return to; consumed once, 10 minutes
-- at most. The iam service (app_rw) reaches it through definer functions.
-- An OIDC IdP's configuration is iam.idp.metadata (kind 'oidc'): issuer,
-- authorization_endpoint, token_endpoint, jwks_uri or jwks (inline, for
-- air-gapped installs), client_id, client_secret_file (a mounted file, never
-- the secret itself), scopes and subject_claim.

CREATE TABLE iam.oidc_state (
  idp_id         uuid        NOT NULL REFERENCES iam.idp (id),
  state          text        NOT NULL CHECK (length(state) BETWEEN 32 AND 128),
  nonce          text        NOT NULL CHECK (length(nonce) BETWEEN 32 AND 128),
  code_verifier  text        NOT NULL CHECK (length(code_verifier) BETWEEN 43 AND 128),
  return_to      text        NOT NULL CHECK (return_to ~ '^/' AND return_to !~ '^//' AND length(return_to) <= 2048),
  expires_at     timestamptz NOT NULL,
  PRIMARY KEY (idp_id, state)
);
REVOKE ALL ON iam.oidc_state FROM PUBLIC;

CREATE FUNCTION iam.oidc_state_save(idp uuid, login_state text, login_nonce text, verifier text, return_path text, expires timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF expires > now() + interval '10 minutes' THEN
    RAISE EXCEPTION 'a login lives at most 10 minutes' USING ERRCODE = '22023';
  END IF;
  DELETE FROM iam.oidc_state s WHERE s.expires_at < now();
  INSERT INTO iam.oidc_state (idp_id, state, nonce, code_verifier, return_to, expires_at)
  VALUES (idp, login_state, login_nonce, verifier, return_path, expires);
END $$;

-- The started login, deleted; no row when unknown, used or expired.
CREATE FUNCTION iam.oidc_state_consume(idp uuid, login_state text)
RETURNS TABLE (nonce text, code_verifier text, return_to text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM iam.oidc_state s WHERE s.idp_id = idp AND s.state = login_state AND s.expires_at > now()
  RETURNING s.nonce, s.code_verifier, s.return_to;
$$;

REVOKE ALL ON FUNCTION iam.oidc_state_save(uuid, text, text, text, text, timestamptz), iam.oidc_state_consume(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.oidc_state_save(uuid, text, text, text, text, timestamptz), iam.oidc_state_consume(uuid, text) TO app_rw;
