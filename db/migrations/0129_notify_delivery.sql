-- F-009 T-10 (F-009-AC-13 to AC-16, AC-19; design §3.5, §3.8, §3.9):
-- delivering, by every replica.
--
--   * notify.claim(batch, token): due deliveries (not held for a digest),
--     each claimed once (FOR UPDATE SKIP LOCKED) with the caller's token;
--     email recipients are re-checked first and dropped with their reason.
--   * notify.settle(id, token, outcome, detail, retry_hours): sent; retry
--     (30 seconds doubling to 30 minutes, until retry_hours from the
--     delivery's creation, then failed as retries_exhausted); failed
--     (permanent or refused). A failure is recorded (notification.
--     delivery_failed, high for security kinds; a refused destination also
--     notification.destination_refused); the channel keeps its last success
--     and failure.
--   * The finding notification_undelivered (high) opens when a security
--     notice fails and no email or webhook delivery of it was sent, and
--     resolves when a security notice is next sent (posture.
--     notification_finding).
--   * notify.reclaim(): a claim older than 2 minutes is uncertain: back to
--     pending, the same id (the receiver drops duplicates).
--   * notify.claim_digest(token): one user whose digest hour (UTC) has come
--     today, with their held deliveries, claimed together.
--   * notify.purge(log_days): deliveries past the log's retention, notices
--     (with their in-app notifications and recipients) past 180 days.
--   * notify.banner(): the system-use banner's first sentence, for emails.

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;
CREATE FUNCTION posture.notification_finding(open boolean, detail jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE inserted boolean;
BEGIN
  IF NOT open THEN
    UPDATE posture.drift_finding f SET status = 'resolved', resolved_at = now(), last_seen = now()
    WHERE f.check_id = 'notification_undelivered' AND f.subject = 'notifications' AND f.status <> 'resolved';
    RETURN CASE WHEN FOUND THEN 'resolved' ELSE 'unchanged' END;
  END IF;
  INSERT INTO posture.drift_finding AS d (kind, check_id, severity, controls, subject, detail, remediation)
  VALUES ('app', 'notification_undelivered', 'high', ARRAY['IR-6', 'SI-4'], 'notifications', coalesce(detail, '{}'),
          'A security notice reached nobody outside the platform: its email and webhook deliveries failed. It is in the recipients'' '
          || 'notifications in the app. Check the relay and webhooks (Notifications, Delivery status), then the security notice itself. '
          || 'The finding resolves when a security notice is next delivered by email or webhook.')
  ON CONFLICT (check_id, subject) WHERE status <> 'resolved' DO UPDATE SET last_seen = now(), detail = EXCLUDED.detail
  RETURNING (d.xmax = 0) INTO inserted;
  RETURN CASE WHEN inserted THEN 'opened' ELSE 'refreshed' END;
END $$;
REVOKE ALL ON FUNCTION posture.notification_finding(boolean, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.notification_finding(boolean, jsonb) TO notify_definer;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;

GRANT SELECT (text) ON iam.banner TO notify_definer;

GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;

CREATE FUNCTION notify.emit(type text, severity text, d notify.delivery, attrs jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', type, 'severity', severity, 'actor', 'system:notify', 'target', 'notification_channel:' || d.channel_id,
    'attributes', attrs || jsonb_build_object('delivery', d.id::text, 'notice', d.notice_id::text, 'channel', d.channel_id::text)));
$$;

CREATE FUNCTION notify.claim(batch integer, token uuid) RETURNS SETOF jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d   notify.delivery;
  n   notify.notice;
  ch  notify.channel;
  k   notify.kind;
  why text;
BEGIN
  IF batch IS NULL OR batch < 1 OR batch > 1000 OR token IS NULL THEN
    RAISE EXCEPTION 'notify.claim: batch is 1 to 1,000, with a token' USING ERRCODE = 'PF028', HINT = 'invalid_batch';
  END IF;
  FOR d IN SELECT * FROM notify.delivery x WHERE x.state = 'pending' AND NOT x.digest AND x.next_attempt_at <= now()
           ORDER BY x.next_attempt_at, x.created_at LIMIT batch FOR UPDATE SKIP LOCKED LOOP
    SELECT * INTO n FROM notify.notice x WHERE x.id = d.notice_id;
    SELECT * INTO ch FROM notify.channel x WHERE x.id = d.channel_id;
    SELECT * INTO k FROM notify.kind x WHERE x.kind = n.kind;
    IF ch.removed_at IS NOT NULL OR NOT ch.enabled THEN
      UPDATE notify.delivery x SET state = 'dropped', reason = 'channel_removed' WHERE x.id = d.id;
      CONTINUE;
    END IF;
    -- An email's recipient, re-checked before each attempt (design §3.2).
    IF d.user_id IS NOT NULL THEN
      why := notify.recheck(n, d.user_id, (SELECT CASE WHEN r.via = 'acceptance.approve' THEN NULL ELSE r.via END
                                           FROM notify.recipient r WHERE r.notice_id = n.id AND r.user_id = d.user_id));
      IF why IS NOT NULL THEN
        UPDATE notify.delivery x SET state = 'dropped', reason = why WHERE x.id = d.id;
        CONTINUE;
      END IF;
    END IF;
    UPDATE notify.delivery x SET state = 'sending', token = claim.token, claimed_at = now(), attempts = x.attempts + 1 WHERE x.id = d.id;
    RETURN NEXT jsonb_build_object('id', d.id, 'notice', n.id, 'channel', ch.id, 'channel_kind', ch.kind, 'config', ch.config,
      'secret', encode(ch.secret_ct, 'base64'),
      'previous', CASE WHEN ch.previous_until > now() THEN encode(ch.previous_ct, 'base64') END,
      'email', (SELECT u.email FROM iam.app_user u WHERE u.id = d.user_id),
      'envelope', n.envelope, 'label', k.label, 'security', k.security, 'attempts', d.attempts + 1);
  END LOOP;
END $$;

CREATE FUNCTION notify.settle(id uuid, token uuid, outcome text, detail text, retry_hours integer) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d     notify.delivery;
  k     notify.kind;
  final text;
  err   text := left(coalesce(nullif(btrim(detail), ''), outcome), 1000);
BEGIN
  SELECT * INTO d FROM notify.delivery x WHERE x.id = settle.id FOR UPDATE;
  IF NOT FOUND OR d.state <> 'sending' OR d.token IS DISTINCT FROM settle.token THEN
    RAISE EXCEPTION 'notify.settle: not this claim' USING ERRCODE = 'PF028', HINT = 'stale_claim';
  END IF;
  IF outcome NOT IN ('sent', 'retry', 'permanent', 'refused') OR retry_hours IS NULL OR retry_hours NOT BETWEEN 1 AND 72 THEN
    RAISE EXCEPTION 'notify.settle: outcome is sent, retry, permanent or refused; retry_hours 1 to 72' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  SELECT x.* INTO k FROM notify.kind x JOIN notify.notice n ON n.kind = x.kind WHERE n.id = d.notice_id;
  IF outcome = 'sent' THEN
    UPDATE notify.delivery x SET state = 'sent', token = NULL, claimed_at = NULL, sent_at = now(), outcome = left(detail, 1000) WHERE x.id = d.id;
    UPDATE notify.channel c SET last_success = now() WHERE c.id = d.channel_id;
    IF k.security THEN
      PERFORM posture.notification_finding(false, NULL);
    END IF;
    RETURN 'sent';
  END IF;
  UPDATE notify.channel c SET last_failure = now(), last_error = err WHERE c.id = d.channel_id;
  IF outcome = 'retry' AND d.created_at + make_interval(hours => retry_hours) > now() THEN
    UPDATE notify.delivery x SET state = 'pending', token = NULL, claimed_at = NULL, outcome = err,
      next_attempt_at = now() + make_interval(secs => least(1800, 30 * power(2, greatest(d.attempts - 1, 0)))) WHERE x.id = d.id;
    RETURN 'retry';
  END IF;
  final := CASE outcome WHEN 'retry' THEN 'retries_exhausted' ELSE outcome END;
  UPDATE notify.delivery x SET state = 'failed', token = NULL, claimed_at = NULL, outcome = err, reason = final WHERE x.id = d.id;
  PERFORM notify.emit('notification.delivery_failed', CASE WHEN k.security THEN 'high' ELSE 'low' END, d,
    jsonb_build_object('kind', k.kind, 'reason', final, 'attempts', d.attempts::text));
  IF final = 'refused' THEN
    PERFORM notify.emit('notification.destination_refused', 'high', d, jsonb_build_object('kind', k.kind, 'detail', err));
  END IF;
  -- A security notice that reached nobody outside the app (AC-15).
  IF k.security AND NOT EXISTS (SELECT 1 FROM notify.delivery x WHERE x.notice_id = d.notice_id AND x.state IN ('sent', 'pending', 'sending')) THEN
    PERFORM posture.notification_finding(true, jsonb_build_object('notice', d.notice_id, 'kind', k.kind, 'reason', final));
  END IF;
  RETURN final;
END $$;

CREATE FUNCTION notify.reclaim() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n integer;
BEGIN
  UPDATE notify.delivery x SET state = 'pending', token = NULL, claimed_at = NULL, next_attempt_at = now()
  WHERE x.state = 'sending' AND x.claimed_at < now() - interval '2 minutes';
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

-- One user whose digest is due (their hour has come today and no digest
-- went today), with every delivery held for it, claimed with token.
CREATE FUNCTION notify.claim_digest(token uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  o     notify.user_option;
  items jsonb;
  smtp  notify.channel;
BEGIN
  SELECT * INTO smtp FROM notify.channel x WHERE x.kind = 'smtp' AND x.removed_at IS NULL AND x.enabled;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT * INTO o FROM notify.user_option x
  WHERE x.digest AND extract(hour FROM now() AT TIME ZONE 'UTC') >= x.digest_hour
    AND (x.last_digest_at IS NULL OR x.last_digest_at < date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
    AND EXISTS (SELECT 1 FROM notify.delivery d WHERE d.user_id = x.user_id AND d.digest AND d.state = 'pending')
  ORDER BY x.digest_hour, x.user_id LIMIT 1 FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  WITH c AS (
    UPDATE notify.delivery d SET state = 'sending', token = claim_digest.token, claimed_at = now(), attempts = d.attempts + 1
    WHERE d.user_id = o.user_id AND d.digest AND d.state = 'pending' AND d.channel_id = smtp.id RETURNING d.id, d.notice_id
  )
  SELECT jsonb_agg(jsonb_build_object('id', c.id, 'envelope', n.envelope, 'label', k.label) ORDER BY n.seq) INTO items
  FROM c JOIN notify.notice n ON n.id = c.notice_id JOIN notify.kind k ON k.kind = n.kind;
  UPDATE notify.user_option x SET last_digest_at = now() WHERE x.user_id = o.user_id;
  IF items IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object('user', o.user_id, 'email', (SELECT u.email FROM iam.app_user u WHERE u.id = o.user_id), 'config', smtp.config,
    'channel', smtp.id, 'items', items);
END $$;

CREATE FUNCTION notify.purge(log_days integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE deliveries integer; notices integer;
BEGIN
  IF log_days IS NULL OR log_days NOT BETWEEN 30 AND 365 THEN
    RAISE EXCEPTION 'notify.purge: log_days is 30 to 365' USING ERRCODE = 'PF028', HINT = 'invalid_request';
  END IF;
  DELETE FROM notify.delivery d WHERE d.state IN ('sent', 'failed', 'dropped') AND d.created_at < now() - make_interval(days => log_days);
  GET DIAGNOSTICS deliveries = ROW_COUNT;
  DELETE FROM notify.notice n WHERE n.collected_at < now() - interval '180 days'
    AND NOT EXISTS (SELECT 1 FROM notify.delivery d WHERE d.notice_id = n.id AND d.state IN ('pending', 'sending'));
  GET DIAGNOSTICS notices = ROW_COUNT;
  RETURN jsonb_build_object('deliveries', deliveries, 'notices', notices);
END $$;

CREATE FUNCTION notify.banner() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT left(coalesce(substring(btrim(b.text) FROM '^[^.!?]*[.!?]'), btrim(b.text)), 300) FROM iam.banner b
$$;

REVOKE ALL ON FUNCTION notify.emit(text, text, notify.delivery, jsonb), notify.claim(integer, uuid), notify.settle(uuid, uuid, text, text, integer),
  notify.reclaim(), notify.claim_digest(uuid), notify.purge(integer), notify.banner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notify.claim(integer, uuid), notify.settle(uuid, uuid, text, text, integer), notify.reclaim(), notify.claim_digest(uuid),
  notify.purge(integer), notify.banner() TO app_notify;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;
