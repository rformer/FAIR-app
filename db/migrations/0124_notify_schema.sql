-- F-009 T-02 (F-009-AC-01, AC-13; design §5): the notify schema.
--
--   * Owned through notify_definer (bootstrap role; re-run
--     scripts/db-bootstrap.sh); app_notify, the notify service, reaches it
--     only through notify_definer's functions (from T-04 on). No table is
--     BU-owned and no application role reads or writes any of them.
--   * notify.kind: the release's notice kinds, synced by iam migrate
--     (notify.sync_kinds); a kind leaving the release is retired, never
--     deleted.
--   * notify.notice: a notice collected from an outbox, once per source row;
--     its envelope never changes once written, only when it was fanned out.
--   * notify.inbox: a user's in-app notification; only read_at changes,
--     once.
--   * notify.channel: the SMTP relay (at most one live) and webhooks.
--   * notify.delivery: one notice to one recipient by one channel, at most
--     once (unique); sent, failed and dropped are final.
--   * notify.preference, notify.user_option: each user's mutes and digest.
--   * PF028: refusals of notify's rules (the hint names the rule).
--   * notify_definer reads the features' outboxes and marks them delivered
--     (SELECT, UPDATE of delivered_at), and reads users and their scopes for
--     recipients and re-checks.

CREATE SCHEMA notify;
REVOKE ALL ON SCHEMA notify FROM PUBLIC;
GRANT USAGE ON SCHEMA notify TO notify_definer, app_notify;

CREATE TABLE notify.kind (
  kind        text        PRIMARY KEY CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' AND char_length(kind) <= 64),
  source      text        NOT NULL CHECK (source IN ('estimate', 'acceptance', 'posture', 'iam', 'finding', 'register', 'notify')),
  source_kind text        NOT NULL,
  mandatory   boolean     NOT NULL,
  security    boolean     NOT NULL,
  label       text        NOT NULL CHECK (char_length(label) BETWEEN 1 AND 200),
  retired_at  timestamptz,
  synced_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source, source_kind),
  CHECK (mandatory OR NOT security)
);

CREATE TABLE notify.notice (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          text        NOT NULL REFERENCES notify.kind (kind),
  source        text        NOT NULL,
  source_id     text        NOT NULL,
  envelope      jsonb       NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
  item_type     text,
  item_id       text,
  bu_id         uuid        REFERENCES iam.bu (id),
  restricted    boolean     NOT NULL DEFAULT false,
  recipients    jsonb       NOT NULL CHECK (jsonb_typeof(recipients) = 'object'),
  left_out      integer     NOT NULL DEFAULT 0 CHECK (left_out >= 0),
  queued_at     timestamptz NOT NULL,
  collected_at  timestamptz NOT NULL DEFAULT now(),
  fanned_out_at timestamptz,
  seq           bigint      GENERATED ALWAYS AS IDENTITY UNIQUE,
  UNIQUE (source, source_id)
);
CREATE INDEX notice_to_fan_out ON notify.notice (seq) WHERE fanned_out_at IS NULL;

CREATE TABLE notify.inbox (
  id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  notice_id  uuid        NOT NULL REFERENCES notify.notice (id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL REFERENCES iam.app_user (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  read_at    timestamptz,
  UNIQUE (notice_id, user_id)
);
CREATE INDEX inbox_user ON notify.inbox (user_id, id DESC);
CREATE INDEX inbox_unread ON notify.inbox (user_id) WHERE read_at IS NULL;

CREATE TABLE notify.channel (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  kind           text        NOT NULL CHECK (kind IN ('smtp', 'webhook')),
  name           text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  config         jsonb       NOT NULL CHECK (jsonb_typeof(config) = 'object'),
  bu_id          uuid        REFERENCES iam.bu (id),
  kinds          text[]      NOT NULL DEFAULT '{}',
  secret_ct      bytea,
  previous_ct    bytea,
  previous_until timestamptz,
  enabled        boolean     NOT NULL DEFAULT true,
  version        integer     NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at     timestamptz NOT NULL DEFAULT now(),
  created_by     uuid        REFERENCES iam.app_user (id),
  removed_at     timestamptz,
  last_success   timestamptz,
  last_failure   timestamptz,
  last_error     text        CHECK (char_length(last_error) <= 1000),
  -- An SMTP relay has no BU, kinds or secret; a webhook has all three.
  CHECK ((kind = 'smtp' AND bu_id IS NULL AND secret_ct IS NULL AND cardinality(kinds) = 0)
      OR (kind = 'webhook' AND bu_id IS NOT NULL AND secret_ct IS NOT NULL AND cardinality(kinds) > 0)),
  CHECK ((previous_ct IS NULL) = (previous_until IS NULL))
);
CREATE UNIQUE INDEX channel_one_smtp ON notify.channel (kind) WHERE kind = 'smtp' AND removed_at IS NULL;
CREATE UNIQUE INDEX channel_name ON notify.channel (lower(name)) WHERE removed_at IS NULL;

CREATE TABLE notify.delivery (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  notice_id       uuid        NOT NULL REFERENCES notify.notice (id) ON DELETE CASCADE,
  channel_id      uuid        NOT NULL REFERENCES notify.channel (id),
  user_id         uuid        REFERENCES iam.app_user (id),
  state           text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sending', 'sent', 'failed', 'dropped')),
  attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  token           uuid,
  claimed_at      timestamptz,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  digest          boolean     NOT NULL DEFAULT false,
  outcome         text        CHECK (char_length(outcome) <= 1000),
  reason          text        CHECK (reason IN ('inactive', 'no_permission', 'not_visible', 'no_email', 'muted', 'channel_removed', 'refused',
                                                'permanent', 'retries_exhausted')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz,
  UNIQUE NULLS NOT DISTINCT (notice_id, channel_id, user_id),
  CHECK ((state = 'sending') = (token IS NOT NULL AND claimed_at IS NOT NULL)),
  CHECK ((state = 'sent') = (sent_at IS NOT NULL)),
  CHECK (state NOT IN ('failed', 'dropped') OR reason IS NOT NULL)
);
CREATE INDEX delivery_due ON notify.delivery (next_attempt_at) WHERE state = 'pending';
CREATE INDEX delivery_sending ON notify.delivery (claimed_at) WHERE state = 'sending';
CREATE INDEX delivery_log ON notify.delivery (created_at DESC);
CREATE INDEX delivery_channel ON notify.delivery (channel_id, created_at DESC);

CREATE TABLE notify.preference (
  user_id     uuid    NOT NULL REFERENCES iam.app_user (id),
  kind        text    NOT NULL REFERENCES notify.kind (kind),
  email_muted boolean NOT NULL,
  PRIMARY KEY (user_id, kind)
);

CREATE TABLE notify.user_option (
  user_id        uuid        PRIMARY KEY REFERENCES iam.app_user (id),
  digest         boolean     NOT NULL DEFAULT false,
  digest_hour    integer     NOT NULL DEFAULT 7 CHECK (digest_hour BETWEEN 0 AND 23),
  last_digest_at timestamptz
);

REVOKE ALL ON notify.kind, notify.notice, notify.inbox, notify.channel, notify.delivery, notify.preference, notify.user_option FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON notify.kind TO notify_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON notify.notice, notify.inbox, notify.channel, notify.delivery, notify.preference, notify.user_option TO notify_definer;

-- State rules (PF028), for every role: a notice's envelope is fixed once
-- written; an in-app notification is read once; a delivery's final states
-- are final, and a delivery keeps its notice, channel and recipient.
CREATE FUNCTION notify.notice_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.kind, NEW.source, NEW.source_id, NEW.envelope, NEW.item_type, NEW.item_id, NEW.bu_id, NEW.restricted, NEW.recipients, NEW.left_out,
      NEW.queued_at, NEW.collected_at)
     IS DISTINCT FROM (OLD.kind, OLD.source, OLD.source_id, OLD.envelope, OLD.item_type, OLD.item_id, OLD.bu_id, OLD.restricted, OLD.recipients,
      OLD.left_out, OLD.queued_at, OLD.collected_at)
     OR (OLD.fanned_out_at IS NOT NULL AND NEW.fanned_out_at IS DISTINCT FROM OLD.fanned_out_at) THEN
    RAISE EXCEPTION 'notify: a notice does not change once collected' USING ERRCODE = 'PF028', HINT = 'notice_fixed';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER fixed BEFORE UPDATE ON notify.notice FOR EACH ROW EXECUTE FUNCTION notify.notice_before_update();

CREATE FUNCTION notify.inbox_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.notice_id, NEW.user_id, NEW.created_at) IS DISTINCT FROM (OLD.notice_id, OLD.user_id, OLD.created_at)
     OR (OLD.read_at IS NOT NULL AND NEW.read_at IS DISTINCT FROM OLD.read_at) OR NEW.read_at IS NULL THEN
    RAISE EXCEPTION 'notify: an in-app notification is only marked read, once' USING ERRCODE = 'PF028', HINT = 'read_once';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER read_once BEFORE UPDATE ON notify.inbox FOR EACH ROW EXECUTE FUNCTION notify.inbox_before_update();

CREATE FUNCTION notify.delivery_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.notice_id, NEW.channel_id, NEW.user_id, NEW.created_at) IS DISTINCT FROM (OLD.id, OLD.notice_id, OLD.channel_id, OLD.user_id, OLD.created_at) THEN
    RAISE EXCEPTION 'notify: a delivery keeps its notice, channel and recipient' USING ERRCODE = 'PF028', HINT = 'delivery_fixed';
  END IF;
  IF OLD.state IN ('sent', 'failed', 'dropped') THEN
    RAISE EXCEPTION 'notify: a delivery that is % is final', OLD.state USING ERRCODE = 'PF028', HINT = 'delivery_final';
  END IF;
  IF NEW.attempts < OLD.attempts THEN
    RAISE EXCEPTION 'notify: attempts only grow' USING ERRCODE = 'PF028', HINT = 'delivery_fixed';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER final BEFORE UPDATE ON notify.delivery FOR EACH ROW EXECUTE FUNCTION notify.delivery_before_update();

-- The features' outboxes, for notify.collect (T-04).
GRANT USAGE ON SCHEMA iam, posture, estimate, acceptance TO notify_definer;
GRANT SELECT, UPDATE (delivered_at) ON iam.notice_outbox, posture.notice_outbox, estimate.notice_outbox, acceptance.notice_outbox TO notify_definer;
-- Users, their scopes and the BU tree, for recipients and re-checks (T-05).
GRANT SELECT (id, email, display_name, status) ON iam.app_user TO notify_definer;
GRANT SELECT ON iam.bu, iam.bu_closure, authz.user_scope TO notify_definer;
GRANT USAGE ON SCHEMA authz TO notify_definer;

-- notify.sync_kinds: the release's kinds (internal/notify.SyncPayload).
-- Added, changed (mandatory, security, label) or retired (no longer in the
-- release); a retired kind returns when a release has it again.
GRANT CREATE ON SCHEMA notify TO notify_definer;
SET ROLE notify_definer;
CREATE FUNCTION notify.sync_kinds(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  k       jsonb;
  old     notify.kind;
  added   text[] := '{}';
  changed text[] := '{}';
  retired text[] := '{}';
  names   text[] := '{}';
BEGIN
  IF jsonb_typeof(payload -> 'kinds') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'notify.sync_kinds: the payload has no kinds' USING ERRCODE = 'PF028', HINT = 'invalid_kinds';
  END IF;
  FOR k IN SELECT * FROM jsonb_array_elements(payload -> 'kinds') LOOP
    names := names || (k ->> 'kind');
    SELECT * INTO old FROM notify.kind x WHERE x.kind = k ->> 'kind' FOR UPDATE;
    IF NOT FOUND THEN
      INSERT INTO notify.kind (kind, source, source_kind, mandatory, security, label)
      VALUES (k ->> 'kind', k ->> 'source', k ->> 'source_kind', (k ->> 'mandatory')::boolean, (k ->> 'security')::boolean, k ->> 'label');
      added := added || (k ->> 'kind');
    ELSIF (old.source, old.source_kind) IS DISTINCT FROM (k ->> 'source', k ->> 'source_kind') THEN
      RAISE EXCEPTION 'notify.sync_kinds: % changes its source; a new kind is needed', k ->> 'kind' USING ERRCODE = 'PF028', HINT = 'invalid_kinds';
    ELSIF (old.mandatory, old.security, old.label, old.retired_at IS NULL)
          IS DISTINCT FROM ((k ->> 'mandatory')::boolean, (k ->> 'security')::boolean, k ->> 'label', true) THEN
      UPDATE notify.kind x SET mandatory = (k ->> 'mandatory')::boolean, security = (k ->> 'security')::boolean, label = k ->> 'label',
        retired_at = NULL, synced_at = now() WHERE x.kind = old.kind;
      changed := changed || old.kind;
    END IF;
  END LOOP;
  WITH r AS (UPDATE notify.kind x SET retired_at = now(), synced_at = now() WHERE x.retired_at IS NULL AND NOT x.kind = ANY (names) RETURNING x.kind)
  SELECT coalesce(array_agg(kind ORDER BY kind), '{}') INTO retired FROM r;
  -- A mandatory kind cannot stay muted.
  DELETE FROM notify.preference p USING notify.kind x WHERE x.kind = p.kind AND x.mandatory;
  RETURN jsonb_build_object('added', to_jsonb(added), 'changed', to_jsonb(changed), 'retired', to_jsonb(retired));
END $$;
REVOKE ALL ON FUNCTION notify.sync_kinds(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notify.sync_kinds(jsonb) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA notify FROM notify_definer;
