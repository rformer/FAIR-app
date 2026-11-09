-- F-003 T-08 (F-003-AC-16, AC-20; design §1, §4.4): a scenario's pins are
-- self-contained. When a scenario version pins an asset group, the group
-- version's members (its library_pin rows) are copied into the scenario's
-- pins too, at the group pin's pointer plus the member's ("/asset" +
-- "/members/0"), marked member_of the group pin. The input bundle (F-005)
-- and any reader of the scenario then have every document the scenario
-- uses, under the scenario's own policy, even without library.view.
-- Members are not pins of the scenario's own document: adopting moves the
-- group pin, and the new version copies that group version's members.

ALTER TABLE risk.scenario_pin ADD COLUMN member_of text;
ALTER TABLE risk.scenario_pin ADD CONSTRAINT scenario_pin_member CHECK (member_of IS NULL OR (to_kind = 'asset' AND pointer LIKE member_of || '/%'));

GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;

-- As in 0085, and asset group pins bring their members.
CREATE OR REPLACE FUNCTION risk.version_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  pin record;
  kind text;
  d jsonb := convert_from(NEW.document, 'UTF8')::jsonb;
  v record;
  members integer;
BEGIN
  kind := d ->> 'kind';
  FOR pin IN SELECT * FROM risk.document_pins(kind, d) LOOP
    IF pin.to_kind = 'control' THEN
      SELECT cv.digest, cv.document INTO v FROM risk.control_version cv WHERE cv.control_id = pin.to_id AND cv.version = pin.to_version;
    ELSE
      SELECT lv.digest, lv.document INTO v FROM risk.library_version lv JOIN risk.library_entry e ON e.id = lv.entry_id
      WHERE lv.entry_id = pin.to_id AND lv.version = pin.to_version AND e.kind = pin.to_kind;
    END IF;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'risk.%: % pins %s % version %, which does not exist or is not visible', TG_TABLE_NAME, pin.pointer,
        pin.to_kind, pin.to_id, pin.to_version USING ERRCODE = 'PF016';
    END IF;
    IF TG_TABLE_NAME = 'scenario_version' THEN
      INSERT INTO risk.scenario_pin (scenario_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document)
      VALUES (NEW.scenario_id, NEW.version, NEW.bu_id, pin.pointer, pin.to_kind, pin.to_id, pin.to_version, v.digest, v.document);
      IF pin.to_kind = 'asset_group' THEN
        -- The group version's members, as its own pins hold them (visible
        -- wherever the group is: same BU, shared down).
        INSERT INTO risk.scenario_pin (scenario_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document, member_of)
        SELECT NEW.scenario_id, NEW.version, NEW.bu_id, pin.pointer || lp.pointer, lp.to_kind, lp.to_id, lp.to_version, lp.to_digest, lp.to_document, pin.pointer
        FROM risk.library_pin lp WHERE lp.entry_id = pin.to_id AND lp.version = pin.to_version;
        GET DIAGNOSTICS members = ROW_COUNT;
        IF members = 0 THEN
          RAISE EXCEPTION 'risk.%: the members of asset group % version % are not visible', TG_TABLE_NAME, pin.to_id, pin.to_version
            USING ERRCODE = 'PF016';
        END IF;
      END IF;
    ELSE
      INSERT INTO risk.library_pin (entry_id, version, bu_id, pointer, to_kind, to_id, to_version, to_digest, to_document)
      VALUES (NEW.entry_id, NEW.version, NEW.bu_id, pin.pointer, pin.to_kind, pin.to_id, pin.to_version, v.digest, v.document);
    END IF;
  END LOOP;
  RETURN NULL;
END $$;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;
