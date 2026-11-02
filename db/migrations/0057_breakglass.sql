-- F-001 T-34 (AC-39 to AC-45, AC-47; design §5.7): break-glass.
--
--   * Off by default (breakglass.enabled false in every profile; AC-39). It
--     changes only here: the posture change workflow refuses the key. Every
--     profile fixes it at false, so enabling records a posture exception
--     (time-bound, renewable, auto-reverted; F-015), and whenever the value
--     turns false the accounts are disabled.
--   * Enabling at install (AC-40): iam.breakglass_install_enable, run by the
--     installer as fair_owner (`iam breakglass enable`) before anyone has
--     signed in, with a reason; audited and printed to the install log.
--     After install (AC-41): iam.breakglass_request_enable asks for a
--     breakglass.enable approval (T-26: a second holder of
--     breakglass.manage), applied by iam.breakglass_apply_enable; audited
--     high. Either way: one or two holders (AC-42), each a local account
--     (source breakglass) holding Platform Admin at the root, which carries
--     no risk data (AC-44), with a one-time enrollment code (24 hours,
--     stored as SHA-256) to register a WebAuthn credential; never a
--     password.
--   * Disabling (AC-45): iam.breakglass_disable, no approval: the setting
--     goes off and the accounts are disabled, which revokes their sessions
--     in the same transaction (0045).
--   * Login is WebAuthn only (internal/authn/breakglass): a credential the
--     account enrolled, user verification required. Every login is audited
--     high, announced on iam.breakglass.login, queued for every notification
--     channel (iam.notice_outbox, F-009) and, in SaaS mode, for the SecOps
--     webhook (AC-43).
--   * Lockout (AC-47): auth.lockout_threshold failures within
--     auth.lockout_window lock the account (unlock: user administration).
--   * AC-44: no assignment or role version may give a break-glass account
--     a risk-data permission.

CREATE TABLE iam.webauthn_credential (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid        NOT NULL REFERENCES iam.app_user (id),
  credential_id  bytea       NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 16 AND 1023),
  credential     jsonb       NOT NULL,  -- the verified credential record (public key, flags, authenticator)
  sign_count     bigint      NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_used_at   timestamptz
);
CREATE INDEX webauthn_credential_user ON iam.webauthn_credential (user_id);
REVOKE ALL ON iam.webauthn_credential FROM PUBLIC;

CREATE TABLE iam.breakglass_enrollment (
  user_id     uuid        PRIMARY KEY REFERENCES iam.app_user (id),
  code_hash   bytea       NOT NULL UNIQUE CHECK (length(code_hash) = 32),
  created_by  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL CHECK (expires_at > created_at)
);
REVOKE ALL ON iam.breakglass_enrollment FROM PUBLIC;

-- A WebAuthn ceremony between its two requests (single use, 5 minutes).
CREATE TABLE iam.webauthn_ceremony (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        text        NOT NULL CHECK (kind IN ('enroll', 'login')),
  user_id     uuid        REFERENCES iam.app_user (id),
  session     jsonb       NOT NULL,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX webauthn_ceremony_expiry ON iam.webauthn_ceremony (expires_at);
REVOKE ALL ON iam.webauthn_ceremony FROM PUBLIC;

CREATE TABLE iam.login_failure (
  user_id  uuid        NOT NULL REFERENCES iam.app_user (id),
  at       timestamptz NOT NULL DEFAULT now(),
  reason   text        NOT NULL
);
CREATE INDEX login_failure_user ON iam.login_failure (user_id, at);
REVOKE ALL ON iam.login_failure FROM PUBLIC;

-- Notifications for every configured channel, delivered by F-009.
CREATE TABLE iam.notice_outbox (
  id            bigserial   PRIMARY KEY,
  kind          text        NOT NULL,
  channels      text        NOT NULL DEFAULT 'all',
  payload       jsonb       NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz
);
REVOKE ALL ON iam.notice_outbox FROM PUBLIC;

-- Posture: breakglass.enabled changes only through break-glass; the SecOps
-- outbox takes break-glass events in SaaS mode.
GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- Sets breakglass.enabled with a recorded, applied change. Every profile
-- fixes it at false (default = bound), so enabling is an exception (owner:
-- the requester; approver: the second administrator, or the installer at
-- install), time-bound by exception.max_duration, renewable and
-- auto-reverted like any other (F-015). Disabling supersedes it.
CREATE FUNCTION posture.breakglass_set(enabled boolean, owner uuid, approver uuid, reason text, approval uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  b   record := posture.active_binding('breakglass.enabled');
  cid uuid;
  exc uuid;
BEGIN
  INSERT INTO posture.change (key, bu_id, old_value, new_value, direction, explanation, requested_by, approval_request_id, state, applied_at)
  VALUES ('breakglass.enabled', NULL, posture.current_value('breakglass.enabled', NULL), to_jsonb(enabled),
          CASE WHEN enabled THEN 'loosen' ELSE 'tighten' END, reason, owner, approval, 'applied', now())
  RETURNING posture.change.id INTO cid;
  UPDATE posture.exception e SET state = 'superseded'
  WHERE e.key = 'breakglass.enabled' AND e.bu_id IS NULL AND NOT e.overlay AND e.state IN ('active', 'revert_failed');
  IF NOT enabled THEN
    PERFORM posture.write_value('breakglass.enabled', NULL, 'false', 'change', cid, NULL);
    RETURN NULL;
  END IF;
  INSERT INTO posture.exception AS e (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, expires_at, state)
  VALUES ('breakglass.enabled', NULL, 'true', coalesce(b.bound, 'false'), reason, owner, approver,
          now() + posture.exception_duration(NULL), 'active')
  RETURNING e.id INTO exc;
  PERFORM posture.write_value('breakglass.enabled', NULL, 'true', 'exception', NULL, exc);
  RETURN exc;
END $$;

CREATE FUNCTION posture.breakglass_secops(event jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF posture.deployment_mode() = 'saas' THEN
    INSERT INTO posture.secops_outbox (event) VALUES (event);
  END IF;
END $$;

REVOKE ALL ON FUNCTION posture.breakglass_set(boolean, uuid, uuid, text, uuid), posture.breakglass_secops(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.breakglass_set(boolean, uuid, uuid, text, uuid), posture.breakglass_secops(jsonb) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

CREATE FUNCTION posture.change_not_breakglass() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  -- The request workflow inserts requested or pending changes; break-glass
  -- records its own, applied ones.
  IF NEW.key = 'breakglass.enabled' AND NEW.state <> 'applied' THEN
    RAISE EXCEPTION 'breakglass.enabled changes only by enabling or disabling break-glass (F-001 T-34)' USING ERRCODE = 'PF003';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER change_not_breakglass BEFORE INSERT ON posture.change
  FOR EACH ROW EXECUTE FUNCTION posture.change_not_breakglass();

REVOKE ALL ON FUNCTION posture.change_not_breakglass() FROM PUBLIC;

-- AC-44: a break-glass account never holds a risk-data permission.
CREATE FUNCTION iam.breakglass_no_risk_data(perms text[], users uuid[]) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  bad text;
BEGIN
  IF EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = ANY (users) AND u.source = 'breakglass') THEN
    SELECT p.key INTO bad FROM iam.permission p WHERE p.key = ANY (perms) AND p.risk_data ORDER BY p.key LIMIT 1;
    IF bad IS NOT NULL THEN
      RAISE EXCEPTION 'break-glass accounts may not hold risk-data permission % (AC-44)', bad USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
END $$;

CREATE FUNCTION iam.assignment_breakglass() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.breakglass_no_risk_data(
    (SELECT v.permissions FROM iam.role r JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version WHERE r.id = NEW.role_id),
    ARRAY(SELECT iam.principal_users(NEW.principal_kind, NEW.principal_id)));
  RETURN NEW;
END $$;
CREATE TRIGGER assignment_breakglass BEFORE INSERT ON iam.assignment
  FOR EACH ROW EXECUTE FUNCTION iam.assignment_breakglass();

CREATE FUNCTION iam.role_version_breakglass() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.breakglass_no_risk_data(NEW.permissions, ARRAY(
    SELECT DISTINCT u FROM iam.assignment a, LATERAL iam.principal_users(a.principal_kind, a.principal_id) u
    WHERE a.role_id = NEW.role_id AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())));
  RETURN NEW;
END $$;
CREATE TRIGGER role_version_breakglass BEFORE INSERT ON iam.role_version
  FOR EACH ROW EXECUTE FUNCTION iam.role_version_breakglass();

-- A break-glass account in a group would receive the group's roles.
CREATE FUNCTION iam.grp_member_breakglass() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = NEW.user_id AND u.source = 'breakglass') THEN
    RAISE EXCEPTION 'break-glass accounts are in no group (AC-44)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER grp_member_breakglass BEFORE INSERT OR UPDATE ON iam.grp_member
  FOR EACH ROW EXECUTE FUNCTION iam.grp_member_breakglass();

-- Unlocking (or re-enabling) starts the failure count afresh.
CREATE FUNCTION iam.login_failures_reset() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  DELETE FROM iam.login_failure f WHERE f.user_id = NEW.id;
  RETURN NULL;
END $$;
CREATE TRIGGER login_failures_reset AFTER UPDATE OF status ON iam.app_user
  FOR EACH ROW WHEN (NEW.status = 'active' AND OLD.status <> 'active') EXECUTE FUNCTION iam.login_failures_reset();

-- breakglass.enabled in force (false when unreadable: fail closed).
CREATE FUNCTION iam.breakglass_enabled() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce((iam.instance_setting('breakglass.enabled'))::boolean, false);
$$;

CREATE FUNCTION iam.breakglass_event(event text, actor text, target text, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', event, 'severity', 'high', 'actor', actor, 'target', target, 'reason', reason,
                                      'attributes', coalesce(attrs, '{}')));
$$;

-- The signed-context user holding breakglass.manage at the root.
CREATE FUNCTION iam.breakglass_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'break-glass administration needs a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, 'breakglass.manage', NULL) THEN
    RAISE EXCEPTION 'breakglass.manage is required' USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

-- The installer, as the owner and approver of install-time configuration in
-- posture's records: a fixed, disabled, non-human account (never signs in).
CREATE FUNCTION iam.installer_user() RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  id constant uuid := '00000000-0000-4000-8000-00000000f001';
BEGIN
  INSERT INTO iam.app_user (id, email, display_name, source, status, disabled_reason)
  VALUES (id, 'installer@system.invalid', 'Installer (install-time configuration)', 'service', 'disabled', 'system')
  ON CONFLICT DO NOTHING;
  RETURN id;
END $$;

-- Whenever breakglass.enabled turns false (disabling, or its exception
-- expiring and being reverted), the accounts are disabled, which ends their
-- sessions (0045).
CREATE FUNCTION iam.breakglass_setting_off() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  n integer;
BEGIN
  UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'breakglass_disabled'
  WHERE x.source = 'breakglass' AND x.status = 'active';
  GET DIAGNOSTICS n = ROW_COUNT;
  DELETE FROM iam.breakglass_enrollment;
  IF n > 0 THEN
    PERFORM iam.breakglass_event('breakglass.accounts_disabled', 'system:iam', 'breakglass', 'breakglass.enabled is off (' || NEW.source || ')',
      jsonb_build_object('accounts_disabled', n));
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER breakglass_setting_off AFTER INSERT OR UPDATE ON posture.setting_value
  FOR EACH ROW WHEN (NEW.key = 'breakglass.enabled' AND NEW.bu_id IS NULL AND NEW.value = 'false')
  EXECUTE FUNCTION iam.breakglass_setting_off();

-- Holders: a JSON array of one or two {email, name}.
CREATE FUNCTION iam.breakglass_holders(holders jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h jsonb;
  out jsonb := '[]';
BEGIN
  IF jsonb_typeof(holders) IS DISTINCT FROM 'array' OR jsonb_array_length(holders) NOT BETWEEN 1 AND 2 THEN
    RAISE EXCEPTION 'one or two break-glass holders (AC-42)' USING ERRCODE = 'PF004';
  END IF;
  FOR h IN SELECT * FROM jsonb_array_elements(holders) LOOP
    IF coalesce(h->>'email', '') !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' OR char_length(btrim(coalesce(h->>'name', ''))) NOT BETWEEN 1 AND 200 THEN
      RAISE EXCEPTION 'each holder needs an email address and a name' USING ERRCODE = 'PF004';
    END IF;
    out := out || jsonb_build_array(jsonb_build_object('email', lower(btrim(h->>'email')), 'name', btrim(h->>'name')));
  END LOOP;
  IF jsonb_array_length(out) = 2 AND out->0->>'email' = out->1->>'email' THEN
    RAISE EXCEPTION 'the holders need distinct email addresses' USING ERRCODE = 'PF004';
  END IF;
  RETURN out;
END $$;

-- Enables break-glass for holders, each with a one-time enrollment code
-- (hashes[i] for holder i). Returns [{user_id, email}].
CREATE FUNCTION iam.breakglass_enable_now(actor text, owner uuid, approver uuid, approval uuid, holders jsonb, hashes bytea[], reason text, extra jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  hs    jsonb := iam.breakglass_holders(holders);
  h     jsonb;
  i     integer := 0;
  u     iam.app_user;
  out   jsonb := '[]';
  keep  uuid[] := '{}';
  exc   uuid;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required (AC-40, AC-41)' USING ERRCODE = 'PF004';
  END IF;
  IF iam.breakglass_enabled() THEN
    RAISE EXCEPTION 'break-glass is enabled already' USING ERRCODE = 'PF003';
  END IF;
  IF hashes IS NULL OR cardinality(hashes) < jsonb_array_length(hs) THEN
    RAISE EXCEPTION 'one enrollment code per holder' USING ERRCODE = '22023';
  END IF;
  exc := posture.breakglass_set(true, owner, approver, btrim(reason), approval);
  FOR h IN SELECT * FROM jsonb_array_elements(hs) LOOP
    i := i + 1;
    SELECT * INTO u FROM iam.app_user x WHERE lower(x.email) = h->>'email' FOR UPDATE;
    IF FOUND AND u.source <> 'breakglass' THEN
      RAISE EXCEPTION '% is an existing account; a break-glass account needs an address of its own', h->>'email' USING ERRCODE = 'PF003';
    END IF;
    IF NOT FOUND THEN
      INSERT INTO iam.app_user (email, display_name, source) VALUES (h->>'email', h->>'name', 'breakglass') RETURNING * INTO u;
    ELSE
      UPDATE iam.app_user x SET display_name = h->>'name', status = 'active', disabled_reason = NULL, reactivated_at = now()
      WHERE x.id = u.id RETURNING * INTO u;
    END IF;
    -- A fresh enrollment each time break-glass is enabled.
    DELETE FROM iam.webauthn_credential c WHERE c.user_id = u.id;
    DELETE FROM iam.login_failure f WHERE f.user_id = u.id;
    INSERT INTO iam.breakglass_enrollment (user_id, code_hash, created_by, expires_at)
    VALUES (u.id, hashes[i], actor, now() + interval '24 hours')
    ON CONFLICT (user_id) DO UPDATE SET code_hash = EXCLUDED.code_hash, created_by = EXCLUDED.created_by,
      created_at = now(), expires_at = EXCLUDED.expires_at;
    IF NOT EXISTS (SELECT 1 FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id
                   WHERE a.principal_kind = 'user' AND a.principal_id = u.id AND r.name = 'Platform Admin' AND r.builtin
                     AND a.bu_id = (SELECT b.id FROM iam.bu b WHERE b.parent_id IS NULL) AND a.revoked_at IS NULL) THEN
      PERFORM set_config('iam.assignment_bootstrap', 'on', true);
      INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id)
      SELECT 'user', u.id, r.id, b.id FROM iam.role r, iam.bu b WHERE r.name = 'Platform Admin' AND r.builtin AND b.parent_id IS NULL;
      PERFORM set_config('iam.assignment_bootstrap', 'off', true);
    END IF;
    keep := keep || u.id;
    out := out || jsonb_build_array(jsonb_build_object('user_id', u.id, 'email', u.email));
  END LOOP;
  -- At most two accounts (AC-42): earlier holders not named again stay off.
  UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'breakglass_disabled'
  WHERE x.source = 'breakglass' AND x.status = 'active' AND x.id <> ALL (keep);
  PERFORM iam.breakglass_event('breakglass.enabled', actor, 'breakglass', btrim(reason),
    jsonb_build_object('holders', out, 'exception', exc) || coalesce(extra, '{}'));
  RETURN out;
END $$;

CREATE FUNCTION iam.breakglass_disable_now(actor text, owner uuid, reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  n integer;
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  -- The status trigger (0045) revokes their sessions in this transaction.
  UPDATE iam.app_user x SET status = 'disabled', disabled_reason = 'breakglass_disabled'
  WHERE x.source = 'breakglass' AND x.status <> 'disabled';
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM posture.breakglass_set(false, owner, NULL, btrim(reason), NULL);
  DELETE FROM iam.breakglass_enrollment;
  DELETE FROM iam.webauthn_ceremony;
  PERFORM iam.breakglass_event('breakglass.disabled', actor, 'breakglass', btrim(reason), jsonb_build_object('accounts_disabled', n));
  RETURN n;
END $$;

-- Installer (fair_owner): only before anyone has signed in and before any
-- break-glass account exists.
CREATE FUNCTION iam.breakglass_install_enable(holders jsonb, hashes bytea[], reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM iam.session) OR EXISTS (SELECT 1 FROM iam.app_user u WHERE u.source = 'breakglass') THEN
    RAISE EXCEPTION 'the installation is in use; enable break-glass with POST /api/v1/breakglass/enable and a second approval (AC-41)'
      USING ERRCODE = 'PF003';
  END IF;
  RETURN iam.breakglass_enable_now('system:installer', iam.installer_user(), iam.installer_user(), NULL, holders, hashes, reason,
    jsonb_build_object('at_install', true));
END $$;

CREATE FUNCTION iam.breakglass_install_disable(reason text) RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT iam.breakglass_disable_now('system:installer', iam.installer_user(), reason);
$$;

-- The API (signed context, breakglass.manage) --------------------------------

CREATE FUNCTION iam.breakglass_status()
RETURNS TABLE (enabled boolean, accounts jsonb, pending_approval uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.breakglass_actor();
  RETURN QUERY SELECT iam.breakglass_enabled(),
    coalesce((SELECT jsonb_agg(jsonb_build_object('id', u.id, 'email', u.email, 'name', u.display_name, 'status', u.status,
        'disabled_reason', u.disabled_reason, 'last_login_at', u.last_login_at,
        'credentials', (SELECT count(*) FROM iam.webauthn_credential c WHERE c.user_id = u.id),
        'enrollment_expires_at', (SELECT e.expires_at FROM iam.breakglass_enrollment e WHERE e.user_id = u.id AND e.expires_at > now()))
      ORDER BY u.email) FROM iam.app_user u WHERE u.source = 'breakglass'), '[]'),
    (SELECT a.id FROM iam.approval_request a WHERE a.kind = 'breakglass.enable' AND a.status IN ('pending', 'approved')
       AND a.consumed_at IS NULL AND a.expires_at > now() ORDER BY a.created_at DESC LIMIT 1);
END $$;

CREATE FUNCTION iam.breakglass_request_enable(holders jsonb, reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.breakglass_actor();
  hs    jsonb := iam.breakglass_holders(holders);
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required (AC-41)' USING ERRCODE = 'PF004';
  END IF;
  IF iam.breakglass_enabled() THEN
    RAISE EXCEPTION 'break-glass is enabled already' USING ERRCODE = 'PF003';
  END IF;
  IF EXISTS (SELECT 1 FROM iam.app_user x, jsonb_array_elements(hs) h WHERE lower(x.email) = h->>'email' AND x.source <> 'breakglass') THEN
    RAISE EXCEPTION 'a holder''s address belongs to an existing account; a break-glass account needs an address of its own' USING ERRCODE = 'PF003';
  END IF;
  RETURN iam.request_approval('breakglass.enable', 'breakglass:enable:' || encode(sha256(convert_to(hs::text, 'UTF8')), 'hex'), btrim(reason), jsonb_build_object('holders', hs), NULL);
END $$;

-- The holders of an approval (for the caller to make one code each).
CREATE FUNCTION iam.breakglass_approval_holders(approval uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM iam.breakglass_actor();
  RETURN (SELECT a.payload->'holders' FROM iam.approval_request a WHERE a.id = approval AND a.kind = 'breakglass.enable');
END $$;

CREATE FUNCTION iam.breakglass_apply_enable(approval uuid, hashes bytea[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.breakglass_actor();
  req   iam.approval_request;
  used  jsonb;
BEGIN
  SELECT * INTO req FROM iam.approval_request a WHERE a.id = approval AND a.kind = 'breakglass.enable';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no break-glass approval %', approval USING ERRCODE = 'P0002';
  END IF;
  used := iam.consume_approval(approval, req.kind, req.target_ref);  -- {payload, requested_by, decided_by} (0018)
  RETURN iam.breakglass_enable_now(actor::text, (used->>'requested_by')::uuid, (used->>'decided_by')::uuid, approval,
    used->'payload'->'holders', hashes, req.reason,
    jsonb_build_object('approval', approval, 'requested_by', used->>'requested_by', 'approved_by', used->>'decided_by'));
END $$;

CREATE FUNCTION iam.breakglass_disable(reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.breakglass_actor();
BEGIN
  IF NOT iam.breakglass_enabled() THEN
    RAISE EXCEPTION 'break-glass is disabled already' USING ERRCODE = 'PF003';
  END IF;
  RETURN iam.breakglass_disable_now(actor::text, actor, reason);
END $$;

-- A new enrollment code for an account (a lost or replaced key): its
-- credentials are removed, so the old key no longer signs in.
CREATE FUNCTION iam.breakglass_new_code(account uuid, hash bytea, reason text) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  actor uuid := iam.breakglass_actor();
  u     iam.app_user;
  exp   timestamptz := now() + interval '24 hours';
BEGIN
  IF btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'a reason is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO u FROM iam.app_user x WHERE x.id = account AND x.source = 'breakglass' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no break-glass account %', account USING ERRCODE = 'P0002';
  END IF;
  IF NOT iam.breakglass_enabled() OR u.status <> 'active' THEN
    RAISE EXCEPTION 'the account is not in use (break-glass off, or the account disabled or locked)' USING ERRCODE = 'PF003';
  END IF;
  DELETE FROM iam.webauthn_credential c WHERE c.user_id = account;
  INSERT INTO iam.breakglass_enrollment (user_id, code_hash, created_by, expires_at) VALUES (account, hash, actor::text, exp)
  ON CONFLICT (user_id) DO UPDATE SET code_hash = EXCLUDED.code_hash, created_by = EXCLUDED.created_by, created_at = now(),
    expires_at = EXCLUDED.expires_at;
  PERFORM iam.breakglass_event('breakglass.enrollment_reset', actor::text, 'user:' || account, btrim(reason), jsonb_build_object('email', u.email));
  RETURN exp;
END $$;

-- WebAuthn ceremonies (the iam service, no session) ---------------------------

-- The account an unexpired enrollment code belongs to, while break-glass is
-- on and the account active.
CREATE FUNCTION iam.breakglass_enrollee(hash bytea) RETURNS TABLE (user_id uuid, email text, display_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.id, u.email, u.display_name FROM iam.breakglass_enrollment e JOIN iam.app_user u ON u.id = e.user_id
  WHERE e.code_hash = hash AND e.expires_at > now() AND u.status = 'active' AND u.source = 'breakglass' AND iam.breakglass_enabled();
$$;

CREATE FUNCTION iam.webauthn_ceremony_put(ceremony_kind text, account uuid, data jsonb) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  id uuid;
BEGIN
  DELETE FROM iam.webauthn_ceremony c WHERE c.expires_at <= now();
  INSERT INTO iam.webauthn_ceremony (kind, user_id, session, expires_at) VALUES (ceremony_kind, account, data, now() + interval '5 minutes')
  RETURNING iam.webauthn_ceremony.id INTO id;
  RETURN id;
END $$;

-- Takes a ceremony once (NULL when unknown, expired or of another kind).
CREATE FUNCTION iam.webauthn_ceremony_take(ceremony uuid, ceremony_kind text) RETURNS TABLE (user_id uuid, session jsonb)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  DELETE FROM iam.webauthn_ceremony c WHERE c.id = ceremony AND c.kind = ceremony_kind AND c.expires_at > now()
  RETURNING c.user_id, c.session;
$$;

-- Registers the verified credential and spends the code.
CREATE FUNCTION iam.breakglass_enroll(hash bytea, cred_id bytea, cred jsonb, count bigint, client text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid;
BEGIN
  SELECT e.user_id INTO u FROM iam.breakglass_enrollee(hash) e;
  IF u IS NULL THEN
    RAISE EXCEPTION 'invalid enrollment code' USING ERRCODE = 'PF007';
  END IF;
  DELETE FROM iam.breakglass_enrollment e WHERE e.user_id = u;
  INSERT INTO iam.webauthn_credential (user_id, credential_id, credential, sign_count) VALUES (u, cred_id, cred, count);
  PERFORM iam.breakglass_event('breakglass.enrolled', u::text, 'user:' || u, NULL,
    jsonb_build_object('credential_id', encode(cred_id, 'base64'), 'ip', client));
  RETURN u;
END $$;

-- The account a discoverable login names (its user handle), with its
-- credentials.
CREATE FUNCTION iam.breakglass_login_account(account uuid)
RETURNS TABLE (user_id uuid, email text, display_name text, status text, credentials jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.id, u.email, u.display_name, u.status::text,
    coalesce((SELECT jsonb_agg(c.credential || jsonb_build_object('fair_sign_count', c.sign_count) ORDER BY c.created_at)
              FROM iam.webauthn_credential c WHERE c.user_id = u.id), '[]')
  FROM iam.app_user u WHERE u.id = account AND u.source = 'breakglass';
$$;

-- A failed break-glass login of a known account; locks it at
-- auth.lockout_threshold failures within auth.lockout_window (AC-47).
-- Returns whether the account is now locked.
CREATE FUNCTION iam.breakglass_login_failed(account uuid, why text, client text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  threshold integer := coalesce((iam.instance_setting('auth.lockout_threshold'))::integer, 3);
  win       interval := coalesce((iam.instance_setting('auth.lockout_window') #>> '{}')::interval, interval '15 minutes');
  n         integer;
  locked    boolean := false;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = account AND u.source = 'breakglass') THEN
    RETURN false;
  END IF;
  INSERT INTO iam.login_failure (user_id, reason) VALUES (account, why);
  SELECT count(*) INTO n FROM iam.login_failure f WHERE f.user_id = account AND f.at > now() - win;
  PERFORM iam.breakglass_event('breakglass.login_failed', 'anonymous', 'user:' || account, why,
    jsonb_build_object('ip', client, 'failures', n, 'threshold', threshold));
  IF n >= threshold THEN
    UPDATE iam.app_user x SET status = 'locked', disabled_reason = 'lockout' WHERE x.id = account AND x.status = 'active';
    IF FOUND THEN
      locked := true;
      PERFORM iam.breakglass_event('user.locked', 'system:iam', 'user:' || account, 'lockout',
        jsonb_build_object('failures', n, 'window', win::text));
    END IF;
  END IF;
  RETURN locked;
END $$;

-- A verified break-glass login: the account must still be usable and the
-- signature counter must advance (a counter that does not suggests a
-- cloned key). Audited high and announced everywhere (AC-43). Returns NULL
-- on success, else the reason it was refused (counted as a failure).
CREATE FUNCTION iam.breakglass_login_succeeded(account uuid, cred_id bytea, count bigint, client text, agent text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u   iam.app_user;
  c   iam.webauthn_credential;
  evt jsonb;
BEGIN
  SELECT * INTO u FROM iam.app_user x WHERE x.id = account AND x.source = 'breakglass' FOR UPDATE;
  SELECT * INTO c FROM iam.webauthn_credential x WHERE x.credential_id = cred_id AND x.user_id = account FOR UPDATE;
  IF u.id IS NULL OR c.id IS NULL THEN
    RETURN 'unknown credential';
  END IF;
  IF NOT iam.breakglass_enabled() THEN
    RETURN 'break-glass disabled';
  END IF;
  IF u.status <> 'active' THEN
    RETURN 'account ' || u.status;
  END IF;
  IF (count <> 0 OR c.sign_count <> 0) AND count <= c.sign_count THEN
    PERFORM iam.breakglass_login_failed(account, 'signature counter did not advance (cloned key?)', client);
    RETURN 'signature counter did not advance';
  END IF;
  UPDATE iam.webauthn_credential x SET sign_count = count, last_used_at = now() WHERE x.id = c.id;
  UPDATE iam.app_user x SET last_login_at = now() WHERE x.id = account;
  DELETE FROM iam.login_failure f WHERE f.user_id = account;
  evt := jsonb_build_object('type', 'breakglass.login', 'user_id', account, 'email', u.email, 'ip', client, 'user_agent', agent, 'at', now());
  PERFORM iam.breakglass_event('breakglass.login', account::text, 'user:' || account, NULL,
    jsonb_build_object('email', u.email, 'ip', client, 'user_agent', agent, 'credential_id', encode(cred_id, 'base64')));
  INSERT INTO iam.event_outbox (topic, payload) VALUES ('iam.breakglass.login', evt);
  INSERT INTO iam.notice_outbox (kind, payload) VALUES ('breakglass.login', evt);
  PERFORM posture.breakglass_secops(evt);
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION iam.login_failures_reset(), iam.breakglass_no_risk_data(text[], uuid[]), iam.assignment_breakglass(), iam.role_version_breakglass(),
  iam.grp_member_breakglass(), iam.breakglass_enabled(), iam.breakglass_event(text, text, text, text, jsonb), iam.breakglass_actor(),
  iam.installer_user(), iam.breakglass_setting_off(), iam.breakglass_holders(jsonb),
  iam.breakglass_enable_now(text, uuid, uuid, uuid, jsonb, bytea[], text, jsonb), iam.breakglass_disable_now(text, uuid, text),
  iam.breakglass_install_enable(jsonb, bytea[], text), iam.breakglass_install_disable(text), iam.breakglass_status(),
  iam.breakglass_request_enable(jsonb, text), iam.breakglass_approval_holders(uuid), iam.breakglass_apply_enable(uuid, bytea[]),
  iam.breakglass_disable(text), iam.breakglass_new_code(uuid, bytea, text), iam.breakglass_enrollee(bytea),
  iam.webauthn_ceremony_put(text, uuid, jsonb), iam.webauthn_ceremony_take(uuid, text), iam.breakglass_enroll(bytea, bytea, jsonb, bigint, text),
  iam.breakglass_login_account(uuid), iam.breakglass_login_failed(uuid, text, text),
  iam.breakglass_login_succeeded(uuid, bytea, bigint, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.breakglass_enabled(), iam.breakglass_status(), iam.breakglass_request_enable(jsonb, text),
  iam.breakglass_approval_holders(uuid), iam.breakglass_apply_enable(uuid, bytea[]), iam.breakglass_disable(text),
  iam.breakglass_new_code(uuid, bytea, text), iam.breakglass_enrollee(bytea), iam.webauthn_ceremony_put(text, uuid, jsonb),
  iam.webauthn_ceremony_take(uuid, text), iam.breakglass_enroll(bytea, bytea, jsonb, bigint, text), iam.breakglass_login_account(uuid),
  iam.breakglass_login_failed(uuid, text, text), iam.breakglass_login_succeeded(uuid, bytea, bigint, text, text) TO app_rw;
