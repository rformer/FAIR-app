-- F-002 T-16 (F-002-AC-22, AC-23, AC-24; design §6.4): forwarding the trail
-- to a syslog destination.
--
-- The leader's forwarder reads the destination from the F-015 setting
-- audit.syslog_destination (AC-24: changes are settings changes) and keeps
-- one row per destination in audit.destination: its address, its cursor
-- (last_seq, the last record sent) and whether its backlog alert is raised.
-- Decisions of 2026-11-05 (Robert Former):
--   * A destination configured for the first time, or again after being
--     cleared, starts at the beginning of the online trail (every record,
--     AC-22). A changed address keeps the cursor (the same feed, moved).
--   * Clearing the setting stops forwarding; the row stays (address NULL)
--     so the Posture page shows what was sent.
-- The cursor only moves forward. Records are read with audit.verify_records
-- (body, chain hash, segment). audit.status reports each destination's
-- address, backlog, the receipt time of the oldest record waiting and the
-- alert state (the Posture page's Audit trail tile, AC-23).

ALTER TABLE audit.destination
  ADD COLUMN address text CHECK (address IS NULL OR btrim(address) <> ''),
  ADD COLUMN backlog_alerted boolean NOT NULL DEFAULT false;

SET ROLE audit_definer;

-- The destination dname of kind dkind now has address addr: created, or
-- re-added after being cleared, at the start of the online trail; an
-- address change keeps the cursor. Returns the cursor.
CREATE FUNCTION audit.forward_destination(dname text, dkind text, addr text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d     audit.destination;
  start bigint := coalesce((SELECT min(r.seq) FROM audit.record r), 1) - 1;
BEGIN
  IF addr IS NULL OR btrim(addr) = '' THEN
    RAISE EXCEPTION 'audit: a destination address is required' USING ERRCODE = 'PF004';
  END IF;
  SELECT * INTO d FROM audit.destination x WHERE x.name = dname FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO audit.destination (name, kind, last_seq, address) VALUES (dname, dkind, start, addr) RETURNING * INTO d;
  ELSIF d.kind <> dkind THEN
    RAISE EXCEPTION 'audit: destination % is of kind %', dname, d.kind USING ERRCODE = 'PF004';
  ELSIF d.address IS NULL THEN
    UPDATE audit.destination x SET address = addr, last_seq = start, last_error = NULL, backlog_alerted = false
    WHERE x.name = dname RETURNING * INTO d;
  ELSIF d.address <> addr THEN
    UPDATE audit.destination x SET address = addr, last_error = NULL WHERE x.name = dname RETURNING * INTO d;
  END IF;
  RETURN d.last_seq;
END $$;

-- The destination's setting was cleared: forwarding stops.
CREATE FUNCTION audit.forward_clear(dname text) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (UPDATE audit.destination x SET address = NULL, backlog_alerted = false
             WHERE x.name = dname AND x.address IS NOT NULL RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM u);
$$;

-- Records up to to_seq were sent: the cursor moves forward only.
CREATE FUNCTION audit.forward_advance(dname text, to_seq bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  UPDATE audit.destination x SET last_seq = to_seq, last_sent_at = clock_timestamp(), last_error = NULL
  WHERE x.name = dname AND x.address IS NOT NULL AND to_seq > x.last_seq AND to_seq <= (SELECT h.seq FROM audit.head h);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit: destination % cannot advance to %', dname, to_seq USING ERRCODE = 'PF003';
  END IF;
END $$;

-- Sending failed.
CREATE FUNCTION audit.forward_error(dname text, err text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE audit.destination x SET last_error = left(coalesce(nullif(btrim(err), ''), 'failed'), 1000) WHERE x.name = dname;
$$;

-- The destination's backlog: records waiting, the receipt time of the
-- oldest of them (NULL: none), whether its alert is raised, and its last
-- sending error.
CREATE FUNCTION audit.forward_backlog(dname text, OUT waiting bigint, OUT oldest_at timestamptz, OUT alerted boolean, OUT last_error text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  d audit.destination;
BEGIN
  SELECT * INTO d FROM audit.destination x WHERE x.name = dname;
  IF NOT FOUND OR d.address IS NULL THEN
    waiting := 0; alerted := false;
    RETURN;
  END IF;
  waiting := greatest(coalesce((SELECT h.seq FROM audit.head h), 0) - d.last_seq, 0);
  oldest_at := (SELECT r.received_at FROM audit.record r WHERE r.seq > d.last_seq ORDER BY r.seq LIMIT 1);
  alerted := d.backlog_alerted;
  last_error := d.last_error;
END $$;

-- Raises or clears the backlog alert; true when it changed (the caller
-- records audit.forward_backlog or audit.forward_recovered in the same
-- transaction, once per crossing).
CREATE FUNCTION audit.forward_set_alert(dname text, raised boolean) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (UPDATE audit.destination x SET backlog_alerted = raised
             WHERE x.name = dname AND x.backlog_alerted IS DISTINCT FROM raised RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM u);
$$;

-- The status (as in 0073), with each destination's address, oldest waiting
-- record and alert.
CREATE OR REPLACE FUNCTION audit.status() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  last_run  audit.verification;
  last_full audit.verification;
  last_ok   audit.verification;
  good_full timestamptz;
  failed    boolean;
  st        text;
  h         audit.head;
BEGIN
  SELECT * INTO last_run FROM audit.verification v WHERE v.finished_at IS NOT NULL ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT * INTO last_full FROM audit.verification v WHERE v.finished_at IS NOT NULL AND v.kind = 'full' ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT * INTO last_ok FROM audit.verification v WHERE v.ok ORDER BY v.finished_at DESC, v.id DESC LIMIT 1;
  SELECT max(v.finished_at) INTO good_full FROM audit.verification v WHERE v.kind = 'full' AND v.ok;
  SELECT EXISTS (SELECT 1 FROM audit.verification v WHERE v.ok IS FALSE AND (good_full IS NULL OR v.finished_at > good_full)) INTO failed;
  SELECT * INTO h FROM audit.head;
  st := CASE
    WHEN last_run.id IS NULL THEN 'never'
    WHEN failed THEN 'failed'
    WHEN NOT EXISTS (SELECT 1 FROM audit.verification v WHERE v.ok AND v.finished_at > now() - interval '30 minutes')
      OR good_full IS NULL OR good_full < now() - interval '26 hours' THEN 'overdue'
    ELSE 'ok' END;
  RETURN jsonb_build_object(
    'state', st,
    'last_run', CASE WHEN last_run.id IS NULL THEN NULL ELSE jsonb_build_object('id', last_run.id, 'kind', last_run.kind,
      'finished_at', last_run.finished_at, 'ok', last_run.ok, 'to_seq', last_run.to_seq, 'to_segment', last_run.to_segment,
      'failed_at_seq', last_run.failed_at_seq, 'failed_at_segment', last_run.failed_at_segment, 'detail', last_run.detail) END,
    'last_full', CASE WHEN last_full.id IS NULL THEN NULL ELSE jsonb_build_object('id', last_full.id, 'finished_at', last_full.finished_at,
      'ok', last_full.ok, 'to_seq', last_full.to_seq, 'to_segment', last_full.to_segment) END,
    'last_verified_at', last_ok.finished_at,
    'verified_through_seq', last_ok.to_seq,
    'head_seq', coalesce(h.seq, 0),
    'open_segment', h.open_segment,
    'intake_waiting', (SELECT count(*) FROM audit.intake),
    'checkpoint_copies_waiting', (SELECT count(*) FROM audit.checkpoint c WHERE c.worm_key IS NULL),
    'destinations', coalesce((SELECT jsonb_agg(jsonb_build_object('name', d.name, 'kind', d.kind, 'address', d.address,
      'last_seq', d.last_seq,
      'backlog', CASE WHEN d.address IS NULL THEN 0 ELSE greatest(coalesce(h.seq, 0) - d.last_seq, 0) END,
      'oldest_waiting_at', CASE WHEN d.address IS NULL THEN NULL ELSE
        (SELECT r.received_at FROM audit.record r WHERE r.seq > d.last_seq ORDER BY r.seq LIMIT 1) END,
      'backlog_alert', d.backlog_alerted,
      'last_sent_at', d.last_sent_at, 'last_error', d.last_error) ORDER BY d.name)
      FROM audit.destination d), '[]'::jsonb),
    'storage', NULL);
END $$;

REVOKE ALL ON FUNCTION audit.forward_destination(text, text, text), audit.forward_clear(text), audit.forward_advance(text, bigint),
  audit.forward_error(text, text), audit.forward_backlog(text), audit.forward_set_alert(text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.forward_destination(text, text, text), audit.forward_clear(text), audit.forward_advance(text, bigint),
  audit.forward_error(text, text), audit.forward_backlog(text), audit.forward_set_alert(text, boolean) TO app_audit;
RESET ROLE;
SET LOCAL ROLE fair_owner;
