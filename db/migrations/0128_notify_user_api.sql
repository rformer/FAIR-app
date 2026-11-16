-- F-009 T-06 (F-009-AC-02, AC-18, AC-19, AC-21; design §3.8, §6): each
-- user's notifications and preferences, for the notifications API.
--
-- The functions take the user from the signed database context
-- (authz.ctx_user) and touch only that user's rows:
--   * notify.my_notifications(unread, before, lim): newest first, with the
--     envelope (the link the page opens), the kind's label, read state;
--   * notify.unread_count();
--   * notify.mark_read(ids, every): the given ones, or all;
--   * notify.my_preferences() and notify.set_preferences(mutes, digest,
--     digest_hour): mutes by kind (email only; mandatory kinds refused,
--     PF028 mandatory), the digest and its hour (UTC). A change records
--     notification.preferences_changed in its transaction (AC-21).
-- app_notify also takes the platform's idempotency store (iam.idempotency_*,
-- as every API) and checks permissions at the root (iam.root_bu).

GRANT USAGE ON SCHEMA iam TO app_notify;
GRANT EXECUTE ON FUNCTION iam.idempotency_begin(uuid, text, text), iam.idempotency_complete(uuid, text, integer, text, bytea),
  iam.idempotency_abandon(uuid, text), iam.root_bu() TO app_notify;
GRANT INSERT ON iam.event_outbox TO notify_definer;
GRANT USAGE ON SEQUENCE iam.event_outbox_id_seq TO notify_definer;
SET ROLE authz_definer;
GRANT EXECUTE ON FUNCTION authz.ctx_user() TO notify_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;

GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;

CREATE FUNCTION notify.me() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (authz.ctx_user()).user_id;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'notifications need a valid signed database context' USING ERRCODE = 'PF028', HINT = 'no_context';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION notify.my_notifications(unread boolean, before bigint, lim integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.me();
BEGIN
  IF lim IS NULL OR lim < 1 OR lim > 200 THEN
    RAISE EXCEPTION 'notify: limit is 1 to 200' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  RETURN coalesce((SELECT jsonb_agg(x.o ORDER BY x.id DESC) FROM (
    SELECT i.id, jsonb_build_object('id', i.id, 'created_at', i.created_at, 'read_at', i.read_at, 'kind', n.kind, 'label', k.label,
      'mandatory', k.mandatory, 'envelope', n.envelope) AS o
    FROM notify.inbox i JOIN notify.notice n ON n.id = i.notice_id JOIN notify.kind k ON k.kind = n.kind
    WHERE i.user_id = u AND (NOT unread OR i.read_at IS NULL) AND (before IS NULL OR i.id < before)
    ORDER BY i.id DESC LIMIT lim) x), '[]');
END $$;

CREATE FUNCTION notify.unread_count() RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT count(*)::integer FROM notify.inbox i WHERE i.user_id = notify.me() AND i.read_at IS NULL
$$;

CREATE FUNCTION notify.mark_read(ids bigint[], every boolean) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.me(); n integer;
BEGIN
  IF NOT coalesce(every, false) AND (ids IS NULL OR cardinality(ids) = 0 OR cardinality(ids) > 500) THEN
    RAISE EXCEPTION 'notify: name 1 to 500 notifications, or all' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  UPDATE notify.inbox i SET read_at = now()
  WHERE i.user_id = u AND i.read_at IS NULL AND (coalesce(every, false) OR i.id = ANY (ids));
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

CREATE FUNCTION notify.my_preferences() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object(
    'kinds', coalesce((SELECT jsonb_agg(jsonb_build_object('kind', k.kind, 'label', k.label, 'mandatory', k.mandatory, 'security', k.security,
        'email_muted', coalesce(p.email_muted, false)) ORDER BY k.kind)
      FROM notify.kind k LEFT JOIN notify.preference p ON p.kind = k.kind AND p.user_id = notify.me()
      WHERE k.retired_at IS NULL AND k.kind <> 'notify.test'), '[]'),
    'digest', coalesce((SELECT o.digest FROM notify.user_option o WHERE o.user_id = notify.me()), false),
    'digest_hour', coalesce((SELECT o.digest_hour FROM notify.user_option o WHERE o.user_id = notify.me()), 7))
$$;

CREATE FUNCTION notify.set_preferences(mutes jsonb, digest boolean, digest_hour integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u      uuid := notify.me();
  kv     record;
  k      notify.kind;
  before jsonb := notify.my_preferences();
  after  jsonb;
BEGIN
  IF jsonb_typeof(mutes) IS DISTINCT FROM 'object' OR digest IS NULL OR digest_hour IS NULL OR digest_hour NOT BETWEEN 0 AND 23 THEN
    RAISE EXCEPTION 'notify: mutes (kind to true or false), digest and digest_hour (0 to 23) are required' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  FOR kv IN SELECT * FROM jsonb_each(mutes) LOOP
    SELECT * INTO k FROM notify.kind x WHERE x.kind = kv.key AND x.retired_at IS NULL AND x.kind <> 'notify.test';
    IF NOT FOUND OR jsonb_typeof(kv.value) <> 'boolean' THEN
      RAISE EXCEPTION 'notify: % is not a notice kind to mute (true or false)', kv.key USING ERRCODE = 'PF028', HINT = 'invalid_request';
    END IF;
    IF k.mandatory AND (kv.value)::text::boolean THEN
      RAISE EXCEPTION 'notify: % cannot be muted', k.kind USING ERRCODE = 'PF028', HINT = 'mandatory';
    END IF;
    IF (kv.value)::text::boolean THEN
      INSERT INTO notify.preference (user_id, kind, email_muted) VALUES (u, k.kind, true)
      ON CONFLICT (user_id, kind) DO UPDATE SET email_muted = true;
    ELSE
      DELETE FROM notify.preference p WHERE p.user_id = u AND p.kind = k.kind;
    END IF;
  END LOOP;
  INSERT INTO notify.user_option (user_id, digest, digest_hour) VALUES (u, digest, digest_hour)
  ON CONFLICT (user_id) DO UPDATE SET digest = EXCLUDED.digest, digest_hour = EXCLUDED.digest_hour;
  after := notify.my_preferences();
  IF after IS DISTINCT FROM before THEN
    INSERT INTO iam.event_outbox (topic, payload) VALUES ('audit', jsonb_build_object('type', 'notification.preferences_changed', 'severity', 'low',
      'actor', u::text, 'target', 'user:' || u, 'attributes', jsonb_build_object(
        'muted', coalesce((SELECT string_agg(x ->> 'kind', ',' ORDER BY x ->> 'kind') FROM jsonb_array_elements(after -> 'kinds') x WHERE (x ->> 'email_muted')::boolean), ''),
        'digest', (after ->> 'digest'), 'digest_hour', (after ->> 'digest_hour'))));
  END IF;
  RETURN after;
END $$;

REVOKE ALL ON FUNCTION notify.me(), notify.my_notifications(boolean, bigint, integer), notify.unread_count(), notify.mark_read(bigint[], boolean),
  notify.my_preferences(), notify.set_preferences(jsonb, boolean, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notify.my_notifications(boolean, bigint, integer), notify.unread_count(), notify.mark_read(bigint[], boolean),
  notify.my_preferences(), notify.set_preferences(jsonb, boolean, integer) TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;
