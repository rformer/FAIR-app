-- F-009 T-11 (F-009-AC-08 to AC-12, AC-17, AC-21; design §3.4, §6, §8):
-- administering the channels, and their status and delivery log.
--
-- The caller comes from the signed context and must hold notification.manage
-- (changes) or notification.view (reads; manage also reads) at the root.
-- Every change needs a reason and records its event in its transaction:
-- notification.channel_created, channel_changed (with what changed),
-- channel_disabled, channel_enabled, channel_removed, secret_rotated,
-- test_sent. Webhook secrets arrive sealed (notify.Keyring) and are never
-- returned; a rotation keeps the previous secret for 24 hours. Versions are
-- checked (expected_version, PF028 stale_version). The configuration's
-- shape is the service's (internal/notify SMTPConfig.Check, the guard);
-- the database keeps the rules: one live relay, webhooks with a BU, kinds
-- the release knows and a secret.

GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;

-- The caller, holding perm at the root (42501 otherwise).
CREATE FUNCTION notify.require(perm text) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.me(); root uuid := (SELECT b.id FROM iam.bu b WHERE b.parent_id IS NULL);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.permission_holders(perm, root, 100000) h WHERE h.id = u)
     AND NOT (perm = 'notification.view' AND EXISTS (SELECT 1 FROM iam.permission_holders('notification.manage', root, 100000) h WHERE h.id = u)) THEN
    RAISE EXCEPTION 'notify: % at the root is needed', perm USING ERRCODE = '42501', HINT = 'forbidden';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION notify.reason_ok(reason text) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'notify: a reason of 1 to 1,000 characters is required' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  RETURN btrim(reason);
END $$;

CREATE FUNCTION notify.channel_event(type text, severity text, actor uuid, c notify.channel, reason text, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', severity, 'actor', actor::text, 'target', 'notification_channel:' || c.id,
    'attributes', attrs || jsonb_build_object('channel', c.id::text, 'channel_kind', c.kind, 'name', c.name, 'reason', reason)));
$$;

CREATE FUNCTION notify.channel_json(c notify.channel) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('id', c.id, 'kind', c.kind, 'name', c.name, 'config', c.config, 'bu_id', c.bu_id,
    'bu_name', (SELECT b.name FROM iam.bu b WHERE b.id = c.bu_id), 'kinds', to_jsonb(c.kinds), 'enabled', c.enabled, 'version', c.version,
    'created_at', c.created_at, 'removed_at', c.removed_at, 'rotation_until', c.previous_until,
    'last_success', c.last_success, 'last_failure', c.last_failure, 'last_error', c.last_error,
    'backlog', (SELECT count(*) FROM notify.delivery d WHERE d.channel_id = c.id AND d.state IN ('pending', 'sending')),
    'failed_24h', (SELECT count(*) FROM notify.delivery d WHERE d.channel_id = c.id AND d.state = 'failed' AND d.created_at > now() - interval '24 hours'))
$$;

CREATE FUNCTION notify.channels() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM notify.require('notification.view');
  RETURN coalesce((SELECT jsonb_agg(notify.channel_json(c) ORDER BY c.kind DESC, lower(c.name)) FROM notify.channel c WHERE c.removed_at IS NULL), '[]');
END $$;

CREATE FUNCTION notify.check_kinds(kinds text[]) RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE bad text;
BEGIN
  IF kinds IS NULL OR cardinality(kinds) = 0 OR cardinality(kinds) > 64 THEN
    RAISE EXCEPTION 'notify: a webhook takes 1 to 64 notice kinds' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  SELECT x INTO bad FROM unnest(kinds) x WHERE NOT EXISTS (SELECT 1 FROM notify.kind k WHERE k.kind = x AND k.retired_at IS NULL AND k.kind <> 'notify.test') LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'notify: % is not a notice kind', bad USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  RETURN ARRAY(SELECT DISTINCT x FROM unnest(kinds) x ORDER BY 1);
END $$;

CREATE FUNCTION notify.check_name(name text) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF name IS NULL OR char_length(btrim(name)) NOT BETWEEN 1 AND 100 OR name ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'notify: a name of 1 to 100 characters is required' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  RETURN btrim(name);
END $$;

-- The relay: created, or replaced at expected_version.
CREATE FUNCTION notify.put_smtp(config jsonb, expected_version integer, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.require('notification.manage'); c notify.channel; why text := notify.reason_ok(reason); changed text;
BEGIN
  IF jsonb_typeof(config) IS DISTINCT FROM 'object' OR config ? 'password' THEN
    RAISE EXCEPTION 'notify: the relay''s configuration is an object, without a password (password_file names a file)' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  SELECT * INTO c FROM notify.channel x WHERE x.kind = 'smtp' AND x.removed_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    IF coalesce(expected_version, 0) <> 0 THEN
      RAISE EXCEPTION 'notify: there is no relay to change' USING ERRCODE = 'PF028', HINT = 'stale_version';
    END IF;
    INSERT INTO notify.channel (kind, name, config, created_by) VALUES ('smtp', 'SMTP relay', config, u) RETURNING * INTO c;
    PERFORM notify.channel_event('notification.channel_created', 'high', u, c, why, jsonb_build_object('host', config ->> 'host'));
    RETURN notify.channel_json(c);
  END IF;
  IF expected_version IS DISTINCT FROM c.version THEN
    RAISE EXCEPTION 'notify: the relay changed meanwhile (version %)', c.version USING ERRCODE = 'PF028', HINT = 'stale_version';
  END IF;
  SELECT string_agg(k, ',' ORDER BY k) INTO changed FROM (
    SELECT k FROM jsonb_object_keys(config || c.config) k WHERE (config -> k) IS DISTINCT FROM (c.config -> k)) x;
  UPDATE notify.channel x SET config = put_smtp.config, version = x.version + 1 WHERE x.id = c.id RETURNING * INTO c;
  PERFORM notify.channel_event('notification.channel_changed', 'high', u, c, why, jsonb_build_object('changed', coalesce(changed, ''), 'host', config ->> 'host'));
  RETURN notify.channel_json(c);
END $$;

CREATE FUNCTION notify.create_webhook(name text, config jsonb, bu uuid, kinds text[], secret_ct bytea, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.require('notification.manage'); c notify.channel; why text := notify.reason_ok(reason);
BEGIN
  IF jsonb_typeof(config) IS DISTINCT FROM 'object' OR NOT config ? 'url' OR secret_ct IS NULL THEN
    RAISE EXCEPTION 'notify: a webhook needs a url and a secret' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  IF bu IS NULL OR NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = bu AND b.archived_at IS NULL) THEN
    RAISE EXCEPTION 'notify: no such business unit' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  INSERT INTO notify.channel (kind, name, config, bu_id, kinds, secret_ct, created_by)
  VALUES ('webhook', notify.check_name(name), config, bu, notify.check_kinds(kinds), secret_ct, u) RETURNING * INTO c;
  PERFORM notify.channel_event('notification.channel_created', 'high', u, c, why,
    jsonb_build_object('host', config ->> 'host', 'bu', bu::text, 'kinds', array_to_string(c.kinds, ',')));
  RETURN notify.channel_json(c);
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION 'notify: a channel named % exists', name USING ERRCODE = 'PF028', HINT = 'name_taken';
END $$;

CREATE FUNCTION notify.update_webhook(id uuid, name text, config jsonb, bu uuid, kinds text[], expected_version integer, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.require('notification.manage'); c notify.channel; why text := notify.reason_ok(reason); nk text[]; changed text[] := '{}';
BEGIN
  SELECT * INTO c FROM notify.channel x WHERE x.id = update_webhook.id AND x.kind = 'webhook' AND x.removed_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notify: no such webhook' USING ERRCODE = 'P0002';
  END IF;
  IF expected_version IS DISTINCT FROM c.version THEN
    RAISE EXCEPTION 'notify: the webhook changed meanwhile (version %)', c.version USING ERRCODE = 'PF028', HINT = 'stale_version';
  END IF;
  IF jsonb_typeof(config) IS DISTINCT FROM 'object' OR NOT config ? 'url' THEN
    RAISE EXCEPTION 'notify: a webhook needs a url' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  IF bu IS NULL OR NOT EXISTS (SELECT 1 FROM iam.bu b WHERE b.id = bu AND b.archived_at IS NULL) THEN
    RAISE EXCEPTION 'notify: no such business unit' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  nk := notify.check_kinds(kinds);
  IF notify.check_name(name) IS DISTINCT FROM c.name THEN changed := changed || 'name'::text; END IF;
  IF config IS DISTINCT FROM c.config THEN changed := changed || 'url'::text; END IF;
  IF bu IS DISTINCT FROM c.bu_id THEN changed := changed || 'bu'::text; END IF;
  IF nk IS DISTINCT FROM c.kinds THEN changed := changed || 'kinds'::text; END IF;
  UPDATE notify.channel x SET name = notify.check_name(update_webhook.name), config = update_webhook.config, bu_id = bu, kinds = nk, version = x.version + 1
  WHERE x.id = c.id RETURNING * INTO c;
  PERFORM notify.channel_event('notification.channel_changed', 'high', u, c, why, jsonb_build_object('changed', array_to_string(changed, ','),
    'host', config ->> 'host', 'bu', bu::text, 'kinds', array_to_string(nk, ',')));
  RETURN notify.channel_json(c);
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION 'notify: a channel named % exists', name USING ERRCODE = 'PF028', HINT = 'name_taken';
END $$;

-- enable, disable or remove a channel (the relay or a webhook).
CREATE FUNCTION notify.set_channel(id uuid, action text, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.require('notification.manage'); c notify.channel; why text := notify.reason_ok(reason);
BEGIN
  SELECT * INTO c FROM notify.channel x WHERE x.id = set_channel.id AND x.removed_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notify: no such channel' USING ERRCODE = 'P0002';
  END IF;
  CASE action
    WHEN 'disable' THEN
      IF NOT c.enabled THEN RAISE EXCEPTION 'notify: already disabled' USING ERRCODE = 'PF028', HINT = 'unchanged'; END IF;
      UPDATE notify.channel x SET enabled = false, version = x.version + 1 WHERE x.id = c.id RETURNING * INTO c;
      PERFORM notify.channel_event('notification.channel_disabled', 'high', u, c, why, '{}');
    WHEN 'enable' THEN
      IF c.enabled THEN RAISE EXCEPTION 'notify: already enabled' USING ERRCODE = 'PF028', HINT = 'unchanged'; END IF;
      UPDATE notify.channel x SET enabled = true, version = x.version + 1 WHERE x.id = c.id RETURNING * INTO c;
      PERFORM notify.channel_event('notification.channel_enabled', 'high', u, c, why, '{}');
    WHEN 'remove' THEN
      UPDATE notify.channel x SET removed_at = now(), enabled = false, version = x.version + 1, secret_ct = CASE WHEN x.kind = 'webhook' THEN '\x00'::bytea END,
        previous_ct = NULL, previous_until = NULL
      WHERE x.id = c.id RETURNING * INTO c;
      PERFORM notify.channel_event('notification.channel_removed', 'high', u, c, why, '{}');
    ELSE
      RAISE EXCEPTION 'notify: action is enable, disable or remove' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END CASE;
  RETURN notify.channel_json(c);
END $$;

CREATE FUNCTION notify.rotate_secret(id uuid, secret_ct bytea, reason text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.require('notification.manage'); c notify.channel; why text := notify.reason_ok(reason);
BEGIN
  SELECT * INTO c FROM notify.channel x WHERE x.id = rotate_secret.id AND x.kind = 'webhook' AND x.removed_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notify: no such webhook' USING ERRCODE = 'P0002';
  END IF;
  IF secret_ct IS NULL THEN
    RAISE EXCEPTION 'notify: a new secret is required' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  UPDATE notify.channel x SET previous_ct = x.secret_ct, previous_until = now() + interval '24 hours', secret_ct = rotate_secret.secret_ct,
    version = x.version + 1 WHERE x.id = c.id RETURNING * INTO c;
  PERFORM notify.channel_event('notification.secret_rotated', 'high', u, c, why, jsonb_build_object('previous_until', c.previous_until::text));
  RETURN notify.channel_json(c);
END $$;

-- What the service needs to send a test message on channel id.
CREATE FUNCTION notify.test_target(id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.require('notification.manage'); c notify.channel;
BEGIN
  SELECT * INTO c FROM notify.channel x WHERE x.id = test_target.id AND x.removed_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notify: no such channel' USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object('kind', c.kind, 'config', c.config, 'secret', encode(c.secret_ct, 'base64'),
    'email', (SELECT a.email FROM iam.app_user a WHERE a.id = u), 'bu_name', (SELECT b.name FROM iam.bu b WHERE b.id = coalesce(c.bu_id,
      (SELECT r.id FROM iam.bu r WHERE r.parent_id IS NULL))));
END $$;

CREATE FUNCTION notify.record_test(id uuid, ok boolean, detail text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := notify.require('notification.manage'); c notify.channel;
BEGIN
  SELECT * INTO c FROM notify.channel x WHERE x.id = record_test.id AND x.removed_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notify: no such channel' USING ERRCODE = 'P0002';
  END IF;
  PERFORM notify.channel_event('notification.test_sent', 'low', u, c, 'test message',
    jsonb_build_object('outcome', CASE WHEN ok THEN 'sent' ELSE 'failed' END, 'detail', left(coalesce(detail, ''), 500)));
END $$;

-- The delivery log (AC-17): kinds, links, recipients, outcomes; no content.
CREATE FUNCTION notify.deliveries(channel uuid, state text, kind text, before timestamptz, lim integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM notify.require('notification.view');
  IF lim IS NULL OR lim < 1 OR lim > 201 THEN
    RAISE EXCEPTION 'notify: limit is 1 to 200' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  RETURN coalesce((SELECT jsonb_agg(x.o ORDER BY x.created_at DESC, x.id) FROM (
    SELECT d.created_at, d.id, jsonb_build_object('id', d.id, 'created_at', d.created_at, 'kind', n.kind, 'link', n.envelope #>> '{item,link}',
      'bu_name', n.envelope #>> '{bu,name}', 'channel', d.channel_id, 'channel_kind', c.kind, 'channel_name', c.name,
      'recipient', CASE WHEN d.user_id IS NULL THEN NULL ELSE (SELECT coalesce(nullif(btrim(a.display_name), ''), a.email) FROM iam.app_user a WHERE a.id = d.user_id) END,
      'state', d.state, 'attempts', d.attempts, 'outcome', d.outcome, 'reason', d.reason, 'sent_at', d.sent_at, 'digest', d.digest) AS o
    FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id JOIN notify.channel c ON c.id = d.channel_id
    WHERE (deliveries.channel IS NULL OR d.channel_id = deliveries.channel) AND (deliveries.state IS NULL OR d.state = deliveries.state)
      AND (deliveries.kind IS NULL OR n.kind = deliveries.kind) AND (before IS NULL OR d.created_at < before)
    ORDER BY d.created_at DESC, d.id LIMIT lim) x), '[]');
END $$;

REVOKE ALL ON FUNCTION notify.require(text), notify.reason_ok(text), notify.channel_event(text, text, uuid, notify.channel, text, jsonb),
  notify.channel_json(notify.channel), notify.check_kinds(text[]), notify.check_name(text), notify.channels(), notify.put_smtp(jsonb, integer, text),
  notify.create_webhook(text, jsonb, uuid, text[], bytea, text), notify.update_webhook(uuid, text, jsonb, uuid, text[], integer, text),
  notify.set_channel(uuid, text, text), notify.rotate_secret(uuid, bytea, text), notify.test_target(uuid), notify.record_test(uuid, boolean, text),
  notify.deliveries(uuid, text, text, timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notify.channels(), notify.put_smtp(jsonb, integer, text), notify.create_webhook(text, jsonb, uuid, text[], bytea, text),
  notify.update_webhook(uuid, text, jsonb, uuid, text[], integer, text), notify.set_channel(uuid, text, text), notify.rotate_secret(uuid, bytea, text),
  notify.test_target(uuid), notify.record_test(uuid, boolean, text), notify.deliveries(uuid, text, text, timestamptz, integer) TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;
