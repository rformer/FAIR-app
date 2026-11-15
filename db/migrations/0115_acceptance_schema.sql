-- F-008 T-02 (F-008-AC-16, AC-17; design §3.1, §5): the acceptance schema.
--
--   * acceptance.acceptance (type 'acceptance', the risk's BU): an
--     acceptance's head: its state (pending, active, suspended, expired,
--     ended with a reason), tier, the BU its approvers must hold
--     acceptance.approve at, the approvals it needs, the mean annualized
--     loss it was placed on, its expiry date. One open acceptance per risk
--     (active, suspended, or pending other than a renewal), and one pending
--     renewal per risk beside it.
--   * acceptance.step (type 'acceptance'): the history, append-only for
--     every role (PF027); the first step holds the request's evidence. Only
--     acceptance_definer moves a step (bu_id) with its risk.
--   * acceptance.notice_outbox: notices for F-009 (design §3.6).
--   * Writes only by acceptance_definer's functions (T-04, T-06): approvers
--     hold acceptance.approve, not write scope, so the definer reads,
--     updates and inserts every row (ADR-007 amendments 3 and 5) and checks
--     the caller itself. app_rw reads under RLS (acceptance.view).

CREATE SCHEMA acceptance;
REVOKE ALL ON SCHEMA acceptance FROM PUBLIC;
GRANT USAGE ON SCHEMA acceptance TO app_rw, acceptance_definer;

CREATE TABLE acceptance.acceptance (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  bu_id            uuid        NOT NULL,
  risk_id          uuid        NOT NULL REFERENCES register.risk (id),
  renews           uuid        REFERENCES acceptance.acceptance (id),
  state            text        NOT NULL CHECK (state IN ('pending', 'active', 'suspended', 'expired', 'ended')),
  end_reason       text        CHECK (end_reason IN ('rejected', 'withdrawn', 'revoked', 'replaced', 'risk_closed')),
  tier             integer     NOT NULL CHECK (tier BETWEEN 1 AND 3),
  tier_bu_id       uuid        NOT NULL REFERENCES iam.bu (id),
  approvals_needed integer     NOT NULL CHECK (approvals_needed BETWEEN 1 AND 2),
  mean             numeric     NOT NULL CHECK (mean >= 0),
  expires_on       date        NOT NULL,
  approved_bu_id   uuid        REFERENCES iam.bu (id),
  requested_by     uuid        NOT NULL REFERENCES iam.app_user (id),
  requested_at     timestamptz NOT NULL DEFAULT now(),
  activated_at     timestamptz,
  ended_at         timestamptz,
  steps            integer     NOT NULL DEFAULT 0,
  seq              bigint      GENERATED ALWAYS AS IDENTITY UNIQUE,
  CHECK ((state = 'ended') = (end_reason IS NOT NULL)),
  CHECK ((state IN ('ended', 'expired')) = (ended_at IS NOT NULL))
);
-- One open acceptance per risk: an active or suspended one, or a pending
-- request that is not a renewal; and one pending renewal beside it.
CREATE UNIQUE INDEX acceptance_open ON acceptance.acceptance (risk_id)
  WHERE state IN ('active', 'suspended') OR (state = 'pending' AND renews IS NULL);
CREATE UNIQUE INDEX acceptance_renewal ON acceptance.acceptance (risk_id) WHERE state = 'pending' AND renews IS NOT NULL;
CREATE INDEX acceptance_bu ON acceptance.acceptance (bu_id, seq);
CREATE INDEX acceptance_state ON acceptance.acceptance (state, expires_on);
CREATE INDEX acceptance_tier_bu ON acceptance.acceptance (tier_bu_id) WHERE state IN ('pending', 'suspended');

CREATE TABLE acceptance.step (
  acceptance_id uuid        NOT NULL REFERENCES acceptance.acceptance (id),
  n             integer     NOT NULL CHECK (n >= 1),
  bu_id         uuid        NOT NULL,
  kind          text        NOT NULL CHECK (kind IN ('requested', 'approved', 'rejected', 'withdrawn', 'activated', 'suspended', 'review_requested',
                                                     'reactivated', 'revoked', 'expired', 'replaced', 'ended')),
  actor         uuid        REFERENCES iam.app_user (id), -- null: the system (the job)
  at            timestamptz NOT NULL DEFAULT now(),
  reason        text        CHECK (char_length(reason) BETWEEN 1 AND 1000),
  data          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(data) = 'object'),
  PRIMARY KEY (acceptance_id, n)
);

CREATE TABLE acceptance.notice_outbox (
  id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind          text        NOT NULL CHECK (kind IN ('expiring', 'expired', 'decision_needed', 'decided', 'suspended')),
  user_id       uuid        REFERENCES iam.app_user (id),
  acceptance_id uuid        NOT NULL REFERENCES acceptance.acceptance (id),
  lead_days     integer,
  created_at    timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz,
  UNIQUE NULLS NOT DISTINCT (acceptance_id, kind, user_id, lead_days)
);
CREATE INDEX notice_outbox_pending ON acceptance.notice_outbox (id) WHERE delivered_at IS NULL;

SELECT authz.apply_bu_rls('acceptance.acceptance', 'acceptance');
SELECT authz.apply_bu_rls('acceptance.step', 'acceptance');
SELECT authz.allow_definer('acceptance.acceptance', 'acceptance_definer');
SELECT authz.allow_definer('acceptance.step', 'acceptance_definer');
SELECT authz.allow_definer_insert('acceptance.acceptance', 'acceptance_definer');
SELECT authz.allow_definer_insert('acceptance.step', 'acceptance_definer');

GRANT SELECT ON acceptance.acceptance, acceptance.step TO app_rw;
GRANT INSERT ON acceptance.acceptance, acceptance.step TO acceptance_definer;
GRANT SELECT, INSERT, UPDATE ON acceptance.notice_outbox TO acceptance_definer;

GRANT CREATE ON SCHEMA acceptance TO acceptance_definer;
SET ROLE acceptance_definer;

-- Steps never change, but for the definer moving them with their risk.
CREATE FUNCTION acceptance.step_before_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND current_user = 'acceptance_definer' AND (to_jsonb(NEW) - 'bu_id') = (to_jsonb(OLD) - 'bu_id') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'acceptance.step: % refused; an acceptance''s history is append-only', TG_OP USING ERRCODE = 'PF027';
END $$;

-- Heads change only through the acceptance functions and are never deleted.
CREATE FUNCTION acceptance.head_before_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND current_user = 'acceptance_definer' THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'acceptance.acceptance: % refused; acceptances change only through their lifecycle and are never deleted', TG_OP
    USING ERRCODE = 'PF027';
END $$;

-- Truncation, for every role.
CREATE FUNCTION acceptance.refuse_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'acceptance.%: TRUNCATE refused', TG_TABLE_NAME USING ERRCODE = 'PF027';
END $$;

REVOKE ALL ON FUNCTION acceptance.step_before_change(), acceptance.head_before_change(), acceptance.refuse_truncate() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acceptance.step_before_change(), acceptance.head_before_change(), acceptance.refuse_truncate() TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA acceptance FROM acceptance_definer;

CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON acceptance.step FOR EACH ROW EXECUTE FUNCTION acceptance.step_before_change();
CREATE TRIGGER definer_only BEFORE UPDATE OR DELETE ON acceptance.acceptance FOR EACH ROW EXECUTE FUNCTION acceptance.head_before_change();
CREATE TRIGGER never_truncated BEFORE TRUNCATE ON acceptance.step FOR EACH STATEMENT EXECUTE FUNCTION acceptance.refuse_truncate();
CREATE TRIGGER never_truncated BEFORE TRUNCATE ON acceptance.acceptance FOR EACH STATEMENT EXECUTE FUNCTION acceptance.refuse_truncate();
