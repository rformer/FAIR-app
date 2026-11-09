-- F-003 T-10 (F-003-AC-11; design §6.6): the starter library.
--
-- iam migrate syncs the release's starter library (internal/risk/starter)
-- into risk.starter_entry, as it syncs the event catalog: entries are
-- added, changed or removed to match the release. Each document is checked
-- like any library version (risk.check_document, its digest). Starter
-- entries are read by the service (library.view somewhere) and never
-- edited: no application role writes the table.
--
-- risk.copy_starter copies an entry into a BU as an ordinary library entry
-- (version 1, the starter document), recording its origin (key@release);
-- the copy is the caller's to edit. It runs under the caller's RLS context
-- (library write scope at the BU).

CREATE TABLE risk.starter_entry (
  key          text    PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
  release      text    NOT NULL CHECK (char_length(release) BETWEEN 1 AND 64),
  kind         text    NOT NULL CHECK (kind IN ('asset', 'asset_group', 'threat_community', 'loss_profile')),
  illustrative boolean NOT NULL,
  guidance     text    NOT NULL CHECK (char_length(btrim(guidance)) BETWEEN 1 AND 10000),
  document     bytea   NOT NULL,
  digest       text    NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$')
);
GRANT SELECT ON risk.starter_entry TO app_rw, risk_definer;

-- The sync checks documents as fair_owner, which needs the secrets check.
SET ROLE audit_definer;
GRANT EXECUTE ON FUNCTION audit.looks_secret(text) TO fair_owner;
RESET ROLE;
SET LOCAL ROLE fair_owner;

-- Syncs the release's starter library; returns what changed.
CREATE FUNCTION risk.sync_starter(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  e jsonb;
  doc bytea;
  problems text[];
  old risk.starter_entry;
  added text[] := '{}';
  changed text[] := '{}';
  removed text[];
  keys text[] := '{}';
  rel text := payload ->> 'release';
BEGIN
  IF rel IS NULL OR jsonb_typeof(payload -> 'entries') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'risk.sync_starter: a release and entries are required' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  FOR e IN SELECT * FROM jsonb_array_elements(payload -> 'entries') LOOP
    doc := convert_to(e ->> 'document', 'UTF8');
    IF encode(sha256(doc), 'hex') IS DISTINCT FROM e ->> 'digest' THEN
      RAISE EXCEPTION 'risk.sync_starter: % does not match its digest', e ->> 'key' USING ERRCODE = 'PF016';
    END IF;
    problems := risk.check_document(e ->> 'kind', doc);
    IF cardinality(problems) > 0 THEN
      RAISE EXCEPTION 'risk.sync_starter: % is invalid', e ->> 'key' USING ERRCODE = 'PF016', DETAIL = array_to_string(problems, E'\n');
    END IF;
    keys := keys || (e ->> 'key');
    SELECT * INTO old FROM risk.starter_entry s WHERE s.key = e ->> 'key';
    IF NOT FOUND THEN
      added := added || (e ->> 'key');
    ELSIF (old.release, old.kind, old.illustrative, old.guidance, old.digest)
          IS DISTINCT FROM (rel, e ->> 'kind', (e -> 'illustrative')::boolean, e ->> 'guidance', e ->> 'digest') THEN
      changed := changed || (e ->> 'key');
    END IF;
    INSERT INTO risk.starter_entry (key, release, kind, illustrative, guidance, document, digest)
    VALUES (e ->> 'key', rel, e ->> 'kind', (e -> 'illustrative')::boolean, e ->> 'guidance', doc, e ->> 'digest')
    ON CONFLICT (key) DO UPDATE SET release = EXCLUDED.release, kind = EXCLUDED.kind, illustrative = EXCLUDED.illustrative,
      guidance = EXCLUDED.guidance, document = EXCLUDED.document, digest = EXCLUDED.digest;
  END LOOP;
  WITH gone AS (DELETE FROM risk.starter_entry s WHERE NOT s.key = ANY (keys) RETURNING s.key)
  SELECT coalesce(array_agg(key ORDER BY key), '{}') INTO removed FROM gone;
  RETURN jsonb_build_object('added', to_jsonb(added), 'changed', to_jsonb(changed), 'removed', to_jsonb(removed));
END $$;
REVOKE ALL ON FUNCTION risk.sync_starter(jsonb) FROM PUBLIC;

GRANT INSERT (bu_id, kind, origin) ON risk.library_entry TO risk_definer;
GRANT INSERT (entry_id, version, document, digest, change_note) ON risk.library_version TO risk_definer;

GRANT CREATE ON SCHEMA risk TO risk_definer;
SET ROLE risk_definer;

-- Copies a starter entry into a BU; returns the new entry's id.
CREATE FUNCTION risk.copy_starter(key text, bu uuid, note text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  s risk.starter_entry;
  id uuid;
BEGIN
  PERFORM risk.actor();
  SELECT * INTO s FROM risk.starter_entry e WHERE e.key = copy_starter.key;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'risk: no starter entry %', key USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO risk.library_entry (bu_id, kind, origin) VALUES (bu, s.kind, s.key || '@' || s.release) RETURNING library_entry.id INTO id;
  INSERT INTO risk.library_version (entry_id, version, document, digest, change_note) VALUES (id, 1, s.document, s.digest, note);
  RETURN id;
END $$;
REVOKE ALL ON FUNCTION risk.copy_starter(text, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION risk.copy_starter(text, uuid, text) TO app_rw;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA risk FROM risk_definer;
