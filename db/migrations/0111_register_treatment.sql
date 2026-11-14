-- F-007 T-06 (F-007-AC-15 to AC-17; design §3.2): treatment.
--
--   * register.treatment.next_due: the earliest due date of the plan's open
--     actions (planned or in progress), kept by the treatment version
--     trigger, so the register lists risks with overdue actions without
--     reading every plan (AC-17, AC-19). An action is overdue when its due
--     date has passed (next_due < the current date) and it is neither done
--     nor cancelled; computed on read.
--   * Otherwise the trigger is 0108's.

ALTER TABLE register.treatment ADD COLUMN next_due date;
CREATE INDEX treatment_next_due ON register.treatment (next_due) WHERE next_due IS NOT NULL;
CREATE INDEX treatment_decision ON register.treatment (decision);
GRANT UPDATE (next_due) ON register.treatment TO register_definer;

GRANT CREATE ON SCHEMA register TO register_definer;
SET ROLE register_definer;

CREATE OR REPLACE FUNCTION register.treatment_version_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  h register.treatment;
  d jsonb;
  problems text[];
BEGIN
  NEW.author := register.actor();
  NEW.created_at := now();
  SELECT * INTO h FROM register.treatment x WHERE x.risk_id = NEW.risk_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'register.treatment_version: no treatment for risk %', NEW.risk_id USING ERRCODE = 'PF026';
  END IF;
  IF (SELECT r.state FROM register.risk r WHERE r.id = NEW.risk_id) = 'closed' THEN
    RAISE EXCEPTION 'register.treatment_version: the risk is closed; reopen it to change its treatment' USING ERRCODE = 'PF026', HINT = 'closed';
  END IF;
  IF NEW.version IS DISTINCT FROM h.current_version + 1 THEN
    RAISE EXCEPTION 'register.treatment_version: version % is stale; the current version is %', NEW.version, h.current_version
      USING ERRCODE = 'PF026', HINT = 'stale_version';
  END IF;
  NEW.bu_id := h.bu_id;
  IF NEW.digest IS DISTINCT FROM encode(sha256(NEW.document), 'hex') THEN
    RAISE EXCEPTION 'register.treatment_version: the digest does not match the document' USING ERRCODE = 'PF026';
  END IF;
  BEGIN
    d := convert_from(NEW.document, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'register.treatment_version: the document is not JSON' USING ERRCODE = 'PF026', DETAIL = '/: is not JSON';
  END;
  problems := register.check_treatment(d, NEW.risk_id);
  IF cardinality(problems) > 0 THEN
    RAISE EXCEPTION 'register.treatment_version: invalid treatment document' USING ERRCODE = 'PF026', DETAIL = array_to_string(problems, E'\n');
  END IF;
  UPDATE register.treatment x SET current_version = NEW.version, decision = d ->> 'decision',
    next_due = (SELECT min((a ->> 'due')::date) FROM jsonb_array_elements(coalesce(d -> 'actions', '[]')) a WHERE a ->> 'state' IN ('planned', 'in_progress'))
  WHERE x.risk_id = h.risk_id;
  RETURN NEW;
END $$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA register FROM register_definer;
