-- F-002 T-06 (F-002-AC-01, AC-02, AC-36; design §4.3, §6.1): the
-- database's own audit events go to the trail, in the producer's
-- transaction.
--
-- Every SQL producer writes its events to iam.event_outbox with topic
-- 'audit'. A BEFORE INSERT trigger now hands each such row to audit.submit
-- and skips the outbox insert, so the event commits or rolls back with the
-- change that produced it, and a refused event (PF011) fails that change
-- (AC-02). The iam worker no longer relays audit rows (scope.Worker).
--
-- audit.outbox_event converts an outbox payload to the envelope as
-- pkg/audit.FromOutbox did: top-level nulls are dropped (never nested ones,
-- which before/after keep), null attributes are dropped, and non-string
-- attribute values become their JSON text. The row's created_at is the
-- event time. Pending audit rows are moved to the trail here.

CREATE FUNCTION audit.outbox_event(payload jsonb, created timestamptz) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  ev    jsonb;
  attrs jsonb := '{}';
  k     text;
  v     jsonb;
BEGIN
  IF payload IS NULL OR jsonb_typeof(payload) <> 'object' THEN
    RETURN payload; -- audit.submit refuses it
  END IF;
  SELECT coalesce(jsonb_object_agg(e.key, e.value), '{}') INTO ev
  FROM jsonb_each(payload) e WHERE jsonb_typeof(e.value) <> 'null' AND e.key <> 'attributes';
  IF jsonb_typeof(payload->'attributes') = 'object' THEN
    FOR k, v IN SELECT * FROM jsonb_each(payload->'attributes') LOOP
      CONTINUE WHEN jsonb_typeof(v) = 'null';
      attrs := attrs || jsonb_build_object(k, CASE jsonb_typeof(v) WHEN 'string' THEN v #>> '{}' ELSE v::text END);
    END LOOP;
  ELSIF payload ? 'attributes' AND jsonb_typeof(payload->'attributes') <> 'null' THEN
    ev := ev || jsonb_build_object('attributes', payload->'attributes'); -- audit.submit refuses it
  END IF;
  IF attrs <> '{}' THEN
    ev := ev || jsonb_build_object('attributes', attrs);
  END IF;
  IF NOT ev ? 'time' AND created IS NOT NULL THEN
    ev := ev || jsonb_build_object('time', to_char(created AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  END IF;
  RETURN ev;
END $$;

CREATE FUNCTION audit.from_outbox() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM audit.submit(audit.outbox_event(NEW.payload, coalesce(NEW.created_at, clock_timestamp())));
  RETURN NULL; -- recorded in the trail, not the outbox
END $$;

REVOKE ALL ON FUNCTION audit.outbox_event(jsonb, timestamptz), audit.from_outbox() FROM PUBLIC;
-- Created by fair_owner (iam.event_outbox's owner), then handed to audit_definer.
CREATE TRIGGER event_outbox_audit BEFORE INSERT ON iam.event_outbox
  FOR EACH ROW WHEN (NEW.topic = 'audit') EXECUTE FUNCTION audit.from_outbox();
ALTER FUNCTION audit.outbox_event(jsonb, timestamptz) OWNER TO audit_definer;
ALTER FUNCTION audit.from_outbox() OWNER TO audit_definer;

-- The installer's commands (iam migrate, keys, breakglass) connect as
-- app_migrator and record their events as fair_owner, in the transaction
-- that makes the change (pkg/audit.Trail with Role fair_owner).
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.submit(jsonb) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- Pending audit rows (not yet relayed) move to the trail. audit_definer
-- reads the outbox for this step only.
GRANT SELECT ON iam.event_outbox TO audit_definer;
SET ROLE audit_definer;
SELECT count(audit.submit(audit.outbox_event(o.payload, o.created_at)))
FROM iam.event_outbox o WHERE o.topic = 'audit' AND o.published_at IS NULL;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE SELECT ON iam.event_outbox FROM audit_definer;
DELETE FROM iam.event_outbox WHERE topic = 'audit' AND published_at IS NULL;
