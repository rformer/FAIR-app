-- F-003 T-05 (F-003-AC-01, AC-26; requirements NFR: lists of 10,000
-- scenarios in a BU subtree in 500 ms p95): what lists need on the heads.
--
--   * seq: a unique, increasing number per head, the keyset order of
--     authz.NewestQuery (newest first), indexed with bu_id.
--   * Summary columns kept by the version trigger from the current
--     version's document, so lists filter and show without parsing
--     documents: every head's name; a scenario's owner, asset (or asset
--     group) and threat community.
--
-- Heads still change only through archived_at (app_rw) and the version
-- trigger, which now advances current_version and the summary together.

ALTER TABLE risk.scenario
  ADD COLUMN seq bigint GENERATED ALWAYS AS IDENTITY,
  ADD COLUMN name text,
  ADD COLUMN owner uuid,
  ADD COLUMN asset_id uuid,
  ADD COLUMN threat_community_id uuid;
ALTER TABLE risk.library_entry
  ADD COLUMN seq bigint GENERATED ALWAYS AS IDENTITY,
  ADD COLUMN name text;
ALTER TABLE risk.control
  ADD COLUMN seq bigint GENERATED ALWAYS AS IDENTITY,
  ADD COLUMN name text;
CREATE UNIQUE INDEX scenario_seq ON risk.scenario (seq);
CREATE UNIQUE INDEX library_entry_seq ON risk.library_entry (seq);
CREATE UNIQUE INDEX control_seq ON risk.control (seq);
CREATE INDEX scenario_bu_seq ON risk.scenario (bu_id, seq);
CREATE INDEX library_entry_bu_seq ON risk.library_entry (bu_id, seq);
CREATE INDEX control_bu_seq ON risk.control (bu_id, seq);
CREATE INDEX scenario_owner ON risk.scenario (owner, seq);
CREATE INDEX scenario_asset ON risk.scenario (asset_id, seq);
CREATE INDEX scenario_threat_community ON risk.scenario (threat_community_id, seq);

GRANT UPDATE (name, owner, asset_id, threat_community_id) ON risk.scenario TO risk_definer;
GRANT UPDATE (name) ON risk.library_entry, risk.control TO risk_definer;

-- Heads: archived_at changes alone; current_version advances by one, with
-- the summary, only from the version trigger (column grants keep app_rw to
-- archived_at).
CREATE OR REPLACE FUNCTION risk.head_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  summary text[] := ARRAY['name', 'owner', 'asset_id', 'threat_community_id'];
BEGIN
  IF (to_jsonb(NEW) - 'archived_at' - 'current_version' - summary) IS DISTINCT FROM (to_jsonb(OLD) - 'archived_at' - 'current_version' - summary)
     OR (NEW.current_version IS DISTINCT FROM OLD.current_version AND NEW.current_version IS DISTINCT FROM OLD.current_version + 1)
     OR ((to_jsonb(NEW) -> 'name', to_jsonb(NEW) -> 'owner', to_jsonb(NEW) -> 'asset_id', to_jsonb(NEW) -> 'threat_community_id')
         IS DISTINCT FROM (to_jsonb(OLD) -> 'name', to_jsonb(OLD) -> 'owner', to_jsonb(OLD) -> 'asset_id', to_jsonb(OLD) -> 'threat_community_id')
         AND NEW.current_version IS NOT DISTINCT FROM OLD.current_version) THEN
    RAISE EXCEPTION 'risk.%: only archived_at changes, and current_version and the summary only by a new version', TG_TABLE_NAME USING ERRCODE = 'PF018';
  END IF;
  RETURN NEW;
END $$;

GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;

-- As in 0085, and the head's summary follows the new version.
CREATE OR REPLACE FUNCTION risk.version_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  head_id uuid;
  h record;
  problems text[];
  d jsonb;
BEGIN
  NEW.author := risk.actor();
  NEW.created_at := now();
  CASE TG_TABLE_NAME
  WHEN 'scenario_version' THEN
    head_id := NEW.scenario_id;
    SELECT s.bu_id, s.current_version, s.archived_at, 'scenario' AS kind INTO h FROM risk.scenario s WHERE s.id = head_id FOR UPDATE;
  WHEN 'library_version' THEN
    head_id := NEW.entry_id;
    SELECT e.bu_id, e.current_version, e.archived_at, e.kind INTO h FROM risk.library_entry e WHERE e.id = head_id FOR UPDATE;
  WHEN 'control_version' THEN
    head_id := NEW.control_id;
    SELECT c.bu_id, c.current_version, c.archived_at, 'control' AS kind INTO h FROM risk.control c WHERE c.id = head_id FOR UPDATE;
  END CASE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'risk.%: no such head %', TG_TABLE_NAME, head_id USING ERRCODE = 'PF017';
  END IF;
  IF h.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'risk.%: % is archived; restore it before changing it', TG_TABLE_NAME, head_id USING ERRCODE = 'PF017';
  END IF;
  IF NEW.version IS DISTINCT FROM h.current_version + 1 THEN
    RAISE EXCEPTION 'risk.%: version % of % is stale; the current version is %', TG_TABLE_NAME, NEW.version, head_id, h.current_version
      USING ERRCODE = 'PF017';
  END IF;
  NEW.bu_id := h.bu_id;
  IF NEW.digest IS DISTINCT FROM encode(sha256(NEW.document), 'hex') THEN
    RAISE EXCEPTION 'risk.%: the digest does not match the document', TG_TABLE_NAME USING ERRCODE = 'PF016';
  END IF;
  problems := risk.check_document(h.kind, NEW.document);
  IF cardinality(problems) > 0 THEN
    RAISE EXCEPTION 'risk.%: invalid % document', TG_TABLE_NAME, h.kind
      USING ERRCODE = 'PF016', DETAIL = array_to_string(problems, E'\n');
  END IF;
  d := convert_from(NEW.document, 'UTF8')::jsonb;
  CASE TG_TABLE_NAME
  WHEN 'scenario_version' THEN
    UPDATE risk.scenario SET current_version = NEW.version, name = d ->> 'name', owner = (d ->> 'owner')::uuid,
      asset_id = (d #>> '{asset,id}')::uuid, threat_community_id = (d #>> '{threat_community,id}')::uuid
    WHERE id = head_id;
  WHEN 'library_version' THEN UPDATE risk.library_entry SET current_version = NEW.version, name = d ->> 'name' WHERE id = head_id;
  WHEN 'control_version' THEN UPDATE risk.control SET current_version = NEW.version, name = d ->> 'name' WHERE id = head_id;
  END CASE;
  RETURN NEW;
END $$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;
