-- F-010 T-03 (F-010-AC-06, AC-15, AC-19; design §5, amended 2026-11-16):
-- the report schema.
--
--   * Owned through report_definer (bootstrap role; re-run
--     scripts/db-bootstrap.sh). Every table is the definer's alone: no
--     application role reads or writes any of them directly. Reads go
--     through report_definer's functions, which take the caller from the
--     signed DB context (T-09 on): a report run, its files and a schedule
--     belong to one user; snapshots are returned only as the caller may see
--     them (design §3.2 as amended: scoped reads, so the purge is a plain
--     delete). No table is BU-owned, so none is registered with the RLS
--     harness.
--   * report.run: one report requested or scheduled; queued, running
--     (again queued for a retry), then succeeded or failed, final.
--   * report.file: a run's file per format, in the report store; only its
--     purge (purged_at, once) changes it.
--   * report.schedule: a person's scheduled report (at most 20 live per
--     owner, PF030); deleted schedules are kept, marked, so their runs
--     still name them.
--   * report.snapshot, snapshot_bu, snapshot_rollup: the portfolio trend
--     (design §3.2): never changed; purged whole past the retention.
--   * report.notice_outbox: notices for F-009 (collected from T-16 on).
--   * PF029: refusals of report's state rules (the hint names the rule).

CREATE SCHEMA report;
REVOKE ALL ON SCHEMA report FROM PUBLIC;
GRANT USAGE ON SCHEMA report TO report_definer, app_rw;

CREATE TABLE report.schedule (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner           uuid        NOT NULL REFERENCES iam.app_user (id),
  bu_id           uuid        NOT NULL REFERENCES iam.bu (id),
  kind            text        NOT NULL CHECK (kind IN ('register', 'portfolio', 'acceptances', 'treatment', 'risk')),
  params          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object' AND length(params::text) <= 4096),
  formats         text[]      NOT NULL CHECK (cardinality(formats) BETWEEN 1 AND 3 AND formats <@ ARRAY['pdf', 'csv', 'json']),
  cadence         text        NOT NULL CHECK (cadence IN ('daily', 'weekly', 'monthly')),
  weekday         integer     CHECK (weekday BETWEEN 0 AND 6),
  monthday        integer     CHECK (monthday BETWEEN 1 AND 28),
  hour            integer     NOT NULL CHECK (hour BETWEEN 0 AND 23),
  next_at         timestamptz NOT NULL,
  state           text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended')),
  suspended_reason text       CHECK (suspended_reason IN ('inactive', 'no_permission')),
  version         integer     NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz,
  CHECK ((cadence = 'weekly') = (weekday IS NOT NULL)),
  CHECK ((cadence = 'monthly') = (monthday IS NOT NULL)),
  CHECK ((state = 'suspended') = (suspended_reason IS NOT NULL))
);
CREATE INDEX schedule_due ON report.schedule (next_at) WHERE state = 'active' AND deleted_at IS NULL;
CREATE INDEX schedule_owner ON report.schedule (owner) WHERE deleted_at IS NULL;

CREATE TABLE report.run (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  requested_by  uuid        NOT NULL REFERENCES iam.app_user (id),
  bu_id         uuid        NOT NULL REFERENCES iam.bu (id),
  kind          text        NOT NULL CHECK (kind IN ('register', 'portfolio', 'acceptances', 'treatment', 'risk')),
  params        jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object' AND length(params::text) <= 4096),
  formats       text[]      NOT NULL CHECK (cardinality(formats) BETWEEN 1 AND 3 AND formats <@ ARRAY['pdf', 'csv', 'json']),
  reason        text        CHECK (char_length(reason) BETWEEN 1 AND 500),
  schedule_id   uuid        REFERENCES report.schedule (id),
  state         text        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
  progress      integer     NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  attempts      integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  context_nonce text        CHECK (context_nonce ~ '^[0-9a-f]{32}$'),
  data_as_of    timestamptz,
  risk_count    integer     CHECK (risk_count >= 0),
  left_out      jsonb       CHECK (jsonb_typeof(left_out) = 'object'),
  failure       text        CHECK (char_length(failure) <= 500),
  requested_at  timestamptz NOT NULL DEFAULT now(),
  started_at    timestamptz,
  finished_at   timestamptz,
  CHECK ((state = 'running') = (context_nonce IS NOT NULL)),
  CHECK ((state IN ('succeeded', 'failed')) = (finished_at IS NOT NULL)),
  CHECK (state <> 'failed' OR failure IS NOT NULL)
);
CREATE INDEX run_requester ON report.run (requested_by, requested_at DESC);
CREATE INDEX run_active ON report.run (requested_by) WHERE state IN ('queued', 'running');

CREATE TABLE report.file (
  run_id     uuid        NOT NULL REFERENCES report.run (id),
  format     text        NOT NULL CHECK (format IN ('pdf', 'csv', 'json')),
  object_key text        NOT NULL CHECK (char_length(object_key) BETWEEN 1 AND 512),
  version_id text        CHECK (char_length(version_id) <= 1024),
  size       bigint      NOT NULL CHECK (size BETWEEN 0 AND 104857600),
  sha256     text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  purged_at  timestamptz,
  PRIMARY KEY (run_id, format)
);
CREATE INDEX file_live ON report.file (created_at) WHERE purged_at IS NULL;

CREATE TABLE report.snapshot (
  id       bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  taken_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX snapshot_taken ON report.snapshot (taken_at);

-- One row per BU per snapshot: that BU's own risks (not its subtree).
CREATE TABLE report.snapshot_bu (
  snapshot_id     bigint  NOT NULL REFERENCES report.snapshot (id) ON DELETE CASCADE,
  bu_id           uuid    NOT NULL REFERENCES iam.bu (id),
  open_risks      integer NOT NULL CHECK (open_risks >= 0),
  current_risks   integer NOT NULL CHECK (current_risks >= 0),
  stale_risks     integer NOT NULL CHECK (stale_risks >= 0),
  unquantified    integer NOT NULL CHECK (unquantified >= 0),
  mean_sum        numeric NOT NULL CHECK (mean_sum >= 0),
  acceptances     jsonb   NOT NULL CHECK (jsonb_typeof(acceptances) = 'object'),
  open_actions    integer NOT NULL CHECK (open_actions >= 0),
  overdue_actions integer NOT NULL CHECK (overdue_actions >= 0),
  PRIMARY KEY (snapshot_id, bu_id),
  CHECK (current_risks + stale_risks + unquantified = open_risks)
);
CREATE INDEX snapshot_bu_bu ON report.snapshot_bu (bu_id, snapshot_id);

-- The latest succeeded roll-up of a BU since the previous snapshot, with
-- the BUs of every risk it included and the aggregate-only BUs it summed.
CREATE TABLE report.snapshot_rollup (
  snapshot_id        bigint      NOT NULL REFERENCES report.snapshot (id) ON DELETE CASCADE,
  bu_id              uuid        NOT NULL REFERENCES iam.bu (id),
  rollup_id          uuid        NOT NULL REFERENCES register.rollup (id),
  rollup_finished_at timestamptz NOT NULL,
  summary            jsonb       NOT NULL CHECK (jsonb_typeof(summary) = 'object'),
  risk_bus           uuid[]      NOT NULL,
  aggregate_only_bus uuid[]      NOT NULL DEFAULT '{}',
  PRIMARY KEY (snapshot_id, bu_id)
);

CREATE TABLE report.notice_outbox (
  id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind         text        NOT NULL CHECK (kind IN ('report.ready', 'report.failed', 'report.schedule_suspended')),
  user_id      uuid        NOT NULL REFERENCES iam.app_user (id),
  run_id       uuid        REFERENCES report.run (id),
  schedule_id  uuid        REFERENCES report.schedule (id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  CHECK ((kind = 'report.schedule_suspended') = (schedule_id IS NOT NULL AND run_id IS NULL)),
  CHECK (kind = 'report.schedule_suspended' OR run_id IS NOT NULL)
);
CREATE INDEX report_notice_outbox_pending ON report.notice_outbox (id) WHERE delivered_at IS NULL;

REVOKE ALL ON report.schedule, report.run, report.file, report.snapshot, report.snapshot_bu, report.snapshot_rollup, report.notice_outbox FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON report.schedule, report.run, report.file TO report_definer;
GRANT SELECT, INSERT, DELETE ON report.snapshot, report.snapshot_bu, report.snapshot_rollup TO report_definer;
GRANT SELECT, INSERT ON report.notice_outbox TO report_definer;
GRANT USAGE ON SEQUENCE report.snapshot_id_seq, report.notice_outbox_id_seq TO report_definer;

-- State rules (PF029), for every role.
CREATE FUNCTION report.run_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.id, NEW.requested_by, NEW.bu_id, NEW.kind, NEW.params, NEW.formats, NEW.reason, NEW.schedule_id, NEW.requested_at)
     IS DISTINCT FROM (OLD.id, OLD.requested_by, OLD.bu_id, OLD.kind, OLD.params, OLD.formats, OLD.reason, OLD.schedule_id, OLD.requested_at) THEN
    RAISE EXCEPTION 'report: a run keeps what was requested' USING ERRCODE = 'PF029', HINT = 'run_request_fixed';
  END IF;
  IF OLD.state IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'report: a finished run does not change' USING ERRCODE = 'PF029', HINT = 'run_finished';
  END IF;
  IF NOT ((OLD.state = 'queued' AND NEW.state IN ('queued', 'running', 'failed'))
       OR (OLD.state = 'running' AND NEW.state IN ('running', 'queued', 'succeeded', 'failed'))) THEN
    RAISE EXCEPTION 'report: a run moves queued, running, then succeeded or failed' USING ERRCODE = 'PF029', HINT = 'run_state';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER state BEFORE UPDATE ON report.run FOR EACH ROW EXECUTE FUNCTION report.run_before_update();

CREATE FUNCTION report.file_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (NEW.run_id, NEW.format, NEW.object_key, NEW.version_id, NEW.size, NEW.sha256, NEW.created_at)
     IS DISTINCT FROM (OLD.run_id, OLD.format, OLD.object_key, OLD.version_id, OLD.size, OLD.sha256, OLD.created_at)
     OR OLD.purged_at IS NOT NULL OR NEW.purged_at IS NULL THEN
    RAISE EXCEPTION 'report: a file is only marked purged, once' USING ERRCODE = 'PF029', HINT = 'file_fixed';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER fixed BEFORE UPDATE ON report.file FOR EACH ROW EXECUTE FUNCTION report.file_before_update();

CREATE FUNCTION report.no_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'report: % rows do not change', TG_TABLE_NAME USING ERRCODE = 'PF029', HINT = 'append_only';
END $$;
CREATE TRIGGER fixed BEFORE UPDATE ON report.snapshot FOR EACH ROW EXECUTE FUNCTION report.no_change();
CREATE TRIGGER fixed BEFORE UPDATE ON report.snapshot_bu FOR EACH ROW EXECUTE FUNCTION report.no_change();
CREATE TRIGGER fixed BEFORE UPDATE ON report.snapshot_rollup FOR EACH ROW EXECUTE FUNCTION report.no_change();

CREATE FUNCTION report.schedule_before() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.owner, NEW.created_at) IS DISTINCT FROM (OLD.id, OLD.owner, OLD.created_at) OR OLD.deleted_at IS NOT NULL THEN
      RAISE EXCEPTION 'report: a schedule keeps its owner, and a deleted one does not change' USING ERRCODE = 'PF029', HINT = 'schedule_fixed';
    END IF;
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
      RETURN NEW;
    END IF;
  END IF;
  IF (SELECT count(*) FROM report.schedule s WHERE s.owner = NEW.owner AND s.deleted_at IS NULL AND s.id <> NEW.id) >= 20 THEN
    RAISE EXCEPTION 'report: at most 20 schedules per person' USING ERRCODE = 'PF030', HINT = 'too_many_schedules';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER rules BEFORE INSERT OR UPDATE ON report.schedule FOR EACH ROW EXECUTE FUNCTION report.schedule_before();
