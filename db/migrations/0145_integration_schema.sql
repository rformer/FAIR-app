-- F-011 T-03 (F-011-AC-02, AC-03, AC-08, AC-19; design §5): the integration
-- schema.
--
--   * Owned through integration_definer (bootstrap role; re-run
--     scripts/db-bootstrap.sh with FAIR_INTEGRATE_PASSWORD_FILE). Every
--     table but loss_event is the definer's alone: no application role reads
--     or writes them directly; app_rw (the risk service) and app_integrate
--     (the integrate service) reach them through integration_definer's
--     functions (T-07 on).
--   * integration.integration: a source of records at a BU, of one input
--     kind (assets, loss_events, risks, control_status) and one delivery
--     (push, file, connector); deleted ones are kept, marked, for their
--     provenance. At most 50 not deleted (PF032).
--   * integration.secret: a connector's sealed credentials (AES-256-GCM
--     under integrate/secrets, design §3.1): replaced or removed, never read
--     but by the integrate service's function.
--   * integration.run: a batch received; running, then succeeded or failed,
--     final.
--   * integration.record: a run's staged records, purged after
--     integration.records_retention_days; never changed.
--   * integration.link: a source record's platform record, per integration
--     and external ID.
--   * integration.proposal: a proposed change; pending, then accepted,
--     rejected or superseded, final.
--   * integration.applied: an accepted proposal's version; append-only.
--   * integration.loss_event: BU-owned, RLS type library (shared down, as
--     library entries), inserted and updated only by integration_definer
--     (ADR-007 amendments 3 and 5); app_rw reads under RLS (F-011-AC-19).
--   * integration.derivation: a reference class's filter over loss events.
--   * integration.notice_outbox: notices for F-009 (collected from T-10 on).
--   * PF031: refusals of integration's state rules (the hint names the
--     rule); PF032: the integration limit.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_integrate') OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'integration_definer') THEN
    RAISE EXCEPTION 'roles app_integrate and integration_definer are missing: re-run scripts/db-bootstrap.sh with FAIR_INTEGRATE_PASSWORD_FILE (F-011 T-03)';
  END IF;
END $$;

CREATE SCHEMA integration;
REVOKE ALL ON SCHEMA integration FROM PUBLIC;
GRANT USAGE ON SCHEMA integration TO integration_definer, app_rw, app_integrate;

CREATE TABLE integration.integration (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id              uuid        NOT NULL REFERENCES iam.bu (id),
  name               text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  kind               text        NOT NULL CHECK (kind IN ('assets', 'loss_events', 'risks', 'control_status')),
  delivery           text        NOT NULL CHECK (delivery IN ('push', 'file', 'connector')),
  mapping            jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(mapping) = 'object' AND length(mapping::text) <= 65536),
  connector          jsonb       CHECK (jsonb_typeof(connector) = 'object' AND length(connector::text) <= 8192),
  service_account_id uuid        REFERENCES iam.app_user (id),
  auto_accept        boolean     NOT NULL DEFAULT false,
  state              text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'paused', 'deleted')),
  version            integer     NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_by         uuid        NOT NULL REFERENCES iam.app_user (id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  changed_by         uuid        REFERENCES iam.app_user (id),
  changed_at         timestamptz,
  deleted_at         timestamptz,
  next_run_at        timestamptz,
  last_run_at        timestamptz,
  failures           integer     NOT NULL DEFAULT 0 CHECK (failures >= 0),
  CHECK ((delivery = 'connector') = (connector IS NOT NULL)),
  CHECK ((state = 'deleted') = (deleted_at IS NOT NULL)),
  CHECK (delivery = 'connector' OR next_run_at IS NULL)
);
CREATE UNIQUE INDEX integration_name ON integration.integration (bu_id, lower(name)) WHERE state <> 'deleted';
CREATE INDEX integration_due ON integration.integration (next_run_at) WHERE state = 'active' AND delivery = 'connector';

CREATE TABLE integration.secret (
  integration_id uuid        NOT NULL REFERENCES integration.integration (id),
  purpose        text        NOT NULL CHECK (purpose IN ('source', 'client')),
  key_id         text        NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
  nonce          bytea       NOT NULL CHECK (length(nonce) = 12),
  ciphertext     bytea       NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 8192),
  set_by         uuid        NOT NULL REFERENCES iam.app_user (id),
  set_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (integration_id, purpose)
);

CREATE TABLE integration.run (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id uuid        NOT NULL REFERENCES integration.integration (id),
  trigger        text        NOT NULL CHECK (trigger IN ('push', 'upload', 'schedule', 'manual')),
  actor          uuid        REFERENCES iam.app_user (id),
  dry_run        boolean     NOT NULL DEFAULT false,
  complete       boolean     NOT NULL DEFAULT false,
  state          text        NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'succeeded', 'failed')),
  counts         jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(counts) = 'object'),
  refusals       jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(refusals) = 'array' AND jsonb_array_length(refusals) <= 1000),
  failure        text        CHECK (char_length(failure) <= 500),
  started_at     timestamptz NOT NULL DEFAULT now(),
  finished_at    timestamptz,
  CHECK ((state = 'running') = (finished_at IS NULL)),
  CHECK (state <> 'failed' OR failure IS NOT NULL)
);
CREATE INDEX run_integration ON integration.run (integration_id, started_at DESC);
CREATE INDEX run_hour ON integration.run (integration_id, started_at) WHERE NOT dry_run;

CREATE TABLE integration.record (
  run_id      uuid    NOT NULL REFERENCES integration.run (id) ON DELETE CASCADE,
  n           integer NOT NULL CHECK (n >= 1 AND n <= 10000),
  kind        text    NOT NULL CHECK (kind IN ('asset', 'asset_group', 'loss_event', 'risk', 'control_status')),
  external_id text    NOT NULL CHECK (char_length(external_id) BETWEEN 1 AND 256),
  data        jsonb   NOT NULL CHECK (jsonb_typeof(data) = 'object'),
  digest      text    NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (run_id, n)
);

CREATE TABLE integration.link (
  integration_id  uuid        NOT NULL REFERENCES integration.integration (id),
  external_id     text        NOT NULL CHECK (char_length(external_id) BETWEEN 1 AND 256),
  target_type     text        NOT NULL CHECK (target_type IN ('asset', 'asset_group', 'loss_event', 'risk', 'control')),
  target_id       uuid        NOT NULL,
  last_digest     text        CHECK (last_digest ~ '^[0-9a-f]{64}$'),
  rejected_digest text        CHECK (rejected_digest ~ '^[0-9a-f]{64}$'),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (integration_id, external_id)
);
CREATE INDEX link_target ON integration.link (target_type, target_id);

CREATE TABLE integration.proposal (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id   uuid        NOT NULL REFERENCES integration.integration (id),
  run_id           uuid        NOT NULL REFERENCES integration.run (id),
  bu_id            uuid        NOT NULL REFERENCES iam.bu (id),
  target_type      text        NOT NULL CHECK (target_type IN ('asset', 'asset_group', 'risk', 'control', 'reference_class')),
  target_id        uuid,
  external_id      text        CHECK (char_length(external_id) BETWEEN 1 AND 256),
  action           text        NOT NULL CHECK (action IN ('create', 'update', 'archive')),
  base_version     integer     CHECK (base_version >= 1),
  document         jsonb       CHECK (jsonb_typeof(document) = 'object'),
  digest           text        CHECK (digest ~ '^[0-9a-f]{64}$'),
  descriptive_only boolean     NOT NULL DEFAULT false,
  state            text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'accepted', 'rejected', 'superseded')),
  decided_by       uuid        REFERENCES iam.app_user (id),
  decided_at       timestamptz,
  reason           text        CHECK (char_length(reason) BETWEEN 1 AND 500),
  created_at       timestamptz NOT NULL DEFAULT now(),
  seq              bigint      GENERATED ALWAYS AS IDENTITY,
  CHECK ((action = 'create') = (target_id IS NULL)),
  CHECK ((action = 'create') = (base_version IS NULL)),
  CHECK ((action = 'archive') = (document IS NULL)),
  CHECK ((document IS NULL) = (digest IS NULL)),
  CHECK ((state IN ('accepted', 'rejected')) = (decided_by IS NOT NULL AND decided_at IS NOT NULL)),
  CHECK (state <> 'rejected' OR reason IS NOT NULL)
);
CREATE INDEX proposal_pending ON integration.proposal (bu_id, target_type, seq) WHERE state = 'pending';
CREATE INDEX proposal_run ON integration.proposal (run_id);
CREATE UNIQUE INDEX proposal_one_pending ON integration.proposal (integration_id, external_id) WHERE state = 'pending' AND external_id IS NOT NULL;

CREATE TABLE integration.applied (
  proposal_id uuid        PRIMARY KEY REFERENCES integration.proposal (id),
  target_type text        NOT NULL CHECK (target_type IN ('asset', 'asset_group', 'risk', 'control', 'reference_class')),
  target_id   uuid        NOT NULL,
  version     integer     NOT NULL CHECK (version >= 1),
  accepted_by uuid        NOT NULL REFERENCES iam.app_user (id),
  accepted_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (target_type, target_id, version)
);

-- Amounts by FAIR form of loss (model.FormsOfLoss), canonical decimals in
-- the installation currency (F-003 canon.Decimal).
CREATE FUNCTION integration.valid_amounts(a jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_typeof(a) = 'object' AND NOT EXISTS (
    SELECT 1 FROM jsonb_each(a) x
    WHERE x.key NOT IN ('productivity', 'response', 'replacement', 'fines_judgments', 'competitive_advantage', 'reputation')
       OR jsonb_typeof(x.value) <> 'string' OR NOT (x.value #>> '{}') ~ '^(0|[1-9][0-9]{0,17})(\.[0-9]{1,6})?$')
$$;

CREATE TABLE integration.loss_event (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id          uuid        NOT NULL REFERENCES iam.bu (id),
  integration_id uuid        NOT NULL REFERENCES integration.integration (id),
  external_id    text        NOT NULL CHECK (char_length(external_id) BETWEEN 1 AND 256),
  occurred_on    date        NOT NULL,
  event_type     text        NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 100),
  description    text        CHECK (char_length(description) <= 2000),
  amounts        jsonb       NOT NULL DEFAULT '{}' CHECK (integration.valid_amounts(amounts)),
  archived_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  seq            bigint      GENERATED ALWAYS AS IDENTITY,
  UNIQUE (integration_id, external_id)
);
CREATE INDEX loss_event_bu ON integration.loss_event (bu_id, occurred_on);
CREATE INDEX loss_event_type ON integration.loss_event (event_type, occurred_on) WHERE archived_at IS NULL;

CREATE TABLE integration.derivation (
  reference_class_id uuid        PRIMARY KEY REFERENCES risk.library_entry (id),
  bu_id              uuid        NOT NULL REFERENCES iam.bu (id),
  filter             jsonb       NOT NULL CHECK (jsonb_typeof(filter) = 'object' AND length(filter::text) <= 8192),
  data_kind          text        NOT NULL CHECK (data_kind IN ('counts', 'losses')),
  digest             text        CHECK (digest ~ '^[0-9a-f]{64}$'),
  set_by             uuid        NOT NULL REFERENCES iam.app_user (id),
  set_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE integration.notice_outbox (
  id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind           text        NOT NULL CHECK (kind IN ('integration.run_failed', 'integration.proposals_waiting', 'control.lapsed')),
  user_id        uuid        NOT NULL REFERENCES iam.app_user (id),
  integration_id uuid        REFERENCES integration.integration (id),
  run_id         uuid        REFERENCES integration.run (id),
  control_id     uuid,
  scenario_id    uuid,
  created_at     timestamptz NOT NULL DEFAULT now(),
  delivered_at   timestamptz,
  CHECK ((kind = 'control.lapsed') = (control_id IS NOT NULL AND scenario_id IS NOT NULL AND integration_id IS NULL)),
  CHECK (kind = 'control.lapsed' OR integration_id IS NOT NULL)
);
CREATE INDEX integration_notice_outbox_pending ON integration.notice_outbox (id) WHERE delivered_at IS NULL;

-- Loss events: BU-owned, read under RLS as library records (shared down);
-- written only by integration_definer (amendments 3 and 5).
SELECT authz.apply_bu_rls('integration.loss_event', 'library', 'archived_at', shared_down => true);
SELECT authz.allow_definer('integration.loss_event', 'integration_definer');
SELECT authz.allow_definer_insert('integration.loss_event', 'integration_definer');

REVOKE ALL ON integration.integration, integration.secret, integration.run, integration.record, integration.link, integration.proposal,
  integration.applied, integration.loss_event, integration.derivation, integration.notice_outbox FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON integration.integration, integration.run, integration.link, integration.proposal, integration.derivation TO integration_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON integration.secret TO integration_definer;
GRANT SELECT, INSERT, DELETE ON integration.record TO integration_definer;
GRANT SELECT, INSERT ON integration.applied, integration.notice_outbox TO integration_definer;
GRANT INSERT ON integration.loss_event TO integration_definer;
GRANT SELECT ON integration.loss_event TO app_rw;
GRANT USAGE ON SEQUENCE integration.notice_outbox_id_seq, integration.proposal_seq_seq, integration.loss_event_seq_seq TO integration_definer;
GRANT EXECUTE ON FUNCTION integration.valid_amounts(jsonb) TO integration_definer, app_rw;

-- State rules (PF031), for every role.
CREATE FUNCTION integration.integration_before() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.bu_id, NEW.kind, NEW.delivery, NEW.created_by, NEW.created_at) IS DISTINCT FROM (OLD.id, OLD.bu_id, OLD.kind, OLD.delivery, OLD.created_by, OLD.created_at) THEN
      RAISE EXCEPTION 'integration: an integration keeps its business unit, kind and delivery' USING ERRCODE = 'PF031', HINT = 'integration_fixed';
    END IF;
    IF OLD.state = 'deleted' THEN
      RAISE EXCEPTION 'integration: a deleted integration does not change' USING ERRCODE = 'PF031', HINT = 'integration_deleted';
    END IF;
    IF NEW.state = 'deleted' OR OLD.state = NEW.state THEN
      RETURN NEW;
    END IF;
  END IF;
  IF NEW.state <> 'deleted' AND (SELECT count(*) FROM integration.integration i WHERE i.state <> 'deleted' AND i.id <> NEW.id) >= 50 THEN
    RAISE EXCEPTION 'integration: at most 50 integrations' USING ERRCODE = 'PF032', HINT = 'too_many_integrations';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER rules BEFORE INSERT OR UPDATE ON integration.integration FOR EACH ROW EXECUTE FUNCTION integration.integration_before();

CREATE FUNCTION integration.run_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.integration_id, NEW.trigger, NEW.actor, NEW.dry_run, NEW.complete, NEW.started_at)
     IS DISTINCT FROM (OLD.id, OLD.integration_id, OLD.trigger, OLD.actor, OLD.dry_run, OLD.complete, OLD.started_at) THEN
    RAISE EXCEPTION 'integration: a run keeps what it received' USING ERRCODE = 'PF031', HINT = 'run_fixed';
  END IF;
  IF OLD.state <> 'running' THEN
    RAISE EXCEPTION 'integration: a finished run does not change' USING ERRCODE = 'PF031', HINT = 'run_finished';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER state BEFORE UPDATE ON integration.run FOR EACH ROW EXECUTE FUNCTION integration.run_before_update();

CREATE FUNCTION integration.proposal_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.integration_id, NEW.run_id, NEW.bu_id, NEW.target_type, NEW.target_id, NEW.external_id, NEW.action, NEW.base_version,
      NEW.document, NEW.digest, NEW.descriptive_only, NEW.created_at, NEW.seq)
     IS DISTINCT FROM (OLD.id, OLD.integration_id, OLD.run_id, OLD.bu_id, OLD.target_type, OLD.target_id, OLD.external_id, OLD.action, OLD.base_version,
      OLD.document, OLD.digest, OLD.descriptive_only, OLD.created_at, OLD.seq) THEN
    RAISE EXCEPTION 'integration: a proposal keeps what it proposes' USING ERRCODE = 'PF031', HINT = 'proposal_fixed';
  END IF;
  IF OLD.state <> 'pending' THEN
    RAISE EXCEPTION 'integration: a decided proposal does not change' USING ERRCODE = 'PF031', HINT = 'proposal_decided';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER state BEFORE UPDATE ON integration.proposal FOR EACH ROW EXECUTE FUNCTION integration.proposal_before_update();

CREATE FUNCTION integration.link_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.integration_id, NEW.external_id, NEW.target_type, NEW.target_id, NEW.created_at)
     IS DISTINCT FROM (OLD.integration_id, OLD.external_id, OLD.target_type, OLD.target_id, OLD.created_at) THEN
    RAISE EXCEPTION 'integration: a link keeps its source record and target' USING ERRCODE = 'PF031', HINT = 'link_fixed';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER fixed BEFORE UPDATE ON integration.link FOR EACH ROW EXECUTE FUNCTION integration.link_before_update();

CREATE FUNCTION integration.loss_event_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.integration_id, NEW.external_id, NEW.created_at, NEW.seq) IS DISTINCT FROM (OLD.id, OLD.integration_id, OLD.external_id, OLD.created_at, OLD.seq) THEN
    RAISE EXCEPTION 'integration: a loss event keeps its source' USING ERRCODE = 'PF031', HINT = 'loss_event_fixed';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER fixed BEFORE UPDATE ON integration.loss_event FOR EACH ROW EXECUTE FUNCTION integration.loss_event_before_update();

CREATE FUNCTION integration.no_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'integration: % rows do not change', TG_TABLE_NAME USING ERRCODE = 'PF031', HINT = 'append_only';
END $$;
CREATE TRIGGER fixed BEFORE UPDATE ON integration.record FOR EACH ROW EXECUTE FUNCTION integration.no_change();
CREATE TRIGGER fixed BEFORE UPDATE OR DELETE ON integration.applied FOR EACH ROW EXECUTE FUNCTION integration.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON integration.run FOR EACH ROW EXECUTE FUNCTION integration.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON integration.proposal FOR EACH ROW EXECUTE FUNCTION integration.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON integration.loss_event FOR EACH ROW EXECUTE FUNCTION integration.no_change();
CREATE TRIGGER no_delete BEFORE DELETE ON integration.integration FOR EACH ROW EXECUTE FUNCTION integration.no_change();

CREATE FUNCTION integration.refuse_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'integration: % is not truncated', TG_TABLE_NAME USING ERRCODE = 'PF031', HINT = 'append_only';
END $$;
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON integration.run FOR EACH STATEMENT EXECUTE FUNCTION integration.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON integration.proposal FOR EACH STATEMENT EXECUTE FUNCTION integration.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON integration.applied FOR EACH STATEMENT EXECUTE FUNCTION integration.refuse_truncate();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON integration.loss_event FOR EACH STATEMENT EXECUTE FUNCTION integration.refuse_truncate();
