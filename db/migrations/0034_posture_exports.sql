-- F-015 T-35 (AC-47; design §6.9 integrity): export records.
--
-- Each OSCAL export (Assessment Results or POA&M, T-33/T-34) is recorded
-- with the snapshot it was built from, the SHA-256 of the document and of
-- the snapshot, and a detached ECDSA P-256 signature over a signed statement
-- {kind, export id, as_of, created_at, digests, key id}, which is what makes
-- the export timestamped. The service regenerates the document from the
-- stored snapshot whenever it is fetched or reproduced and refuses it if the
-- digest differs. Records are append-only: posture_definer may insert and
-- read them, never update or delete them. PostgreSQL cannot verify ECDSA, so
-- the database checks what it can: the permission (posture.export, from the
-- signed context), the snapshot digest, that the statement names exactly the
-- recorded values, and a created_at within a minute of its own clock.

CREATE TABLE posture.export_record (
  id               uuid        PRIMARY KEY,
  kind             text        NOT NULL CHECK (kind IN ('assessment_results', 'poam')),
  as_of            timestamptz NOT NULL,
  created_at       timestamptz NOT NULL,
  created_by       uuid        NOT NULL REFERENCES iam.app_user (id),
  snapshot         bytea       NOT NULL,
  snapshot_digest  text        NOT NULL CHECK (snapshot_digest ~ '^[0-9a-f]{64}$'),
  document_digest  text        NOT NULL CHECK (document_digest ~ '^[0-9a-f]{64}$'),
  statement        bytea       NOT NULL,
  signature        text        NOT NULL CHECK (signature ~ '^[A-Za-z0-9+/]+=*$'),
  key_id           text        NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$'),
  UNIQUE (kind, as_of)
);
REVOKE ALL ON posture.export_record FROM PUBLIC;
ALTER TABLE posture.export_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.export_record FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.export_record TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON posture.export_record TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The caller from the signed context, who must hold posture.export.
CREATE FUNCTION posture.export_actor() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := (SELECT s.user_id FROM authz.ctx_scope() s);
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'exports need a valid signed database context' USING ERRCODE = 'PF007';
  END IF;
  IF NOT iam.holds_permission(u, 'posture.export', NULL) THEN
    RAISE EXCEPTION 'posture.export is required' USING ERRCODE = 'PF008';
  END IF;
  RETURN u;
END $$;

CREATE FUNCTION posture.record_export(export_id uuid, export_kind text, export_as_of timestamptz, export_created_at timestamptz,
  snapshot bytea, snapshot_digest text, document_digest text, statement bytea, signature text, key_id text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u uuid := posture.export_actor();
  st jsonb;
BEGIN
  IF encode(sha256(snapshot), 'hex') IS DISTINCT FROM snapshot_digest THEN
    RAISE EXCEPTION 'the snapshot digest does not match the snapshot' USING ERRCODE = 'PF004';
  END IF;
  IF abs(extract(epoch FROM (export_created_at - clock_timestamp()))) > 60 THEN
    RAISE EXCEPTION 'created_at % is not the current time', export_created_at USING ERRCODE = 'PF004';
  END IF;
  IF export_as_of > export_created_at THEN
    RAISE EXCEPTION 'as_of is after created_at' USING ERRCODE = 'PF004';
  END IF;
  BEGIN
    st := convert_from(statement, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'the statement is not JSON' USING ERRCODE = 'PF004';
  END;
  IF st ->> 'type' IS DISTINCT FROM 'fair-posture-export'
     OR st ->> 'export_id' IS DISTINCT FROM export_id::text
     OR st ->> 'kind' IS DISTINCT FROM export_kind
     OR (st ->> 'as_of')::timestamptz IS DISTINCT FROM export_as_of
     OR (st ->> 'created_at')::timestamptz IS DISTINCT FROM export_created_at
     OR st ->> 'created_by' IS DISTINCT FROM u::text
     OR st ->> 'snapshot_sha256' IS DISTINCT FROM snapshot_digest
     OR st ->> 'document_sha256' IS DISTINCT FROM document_digest
     OR st ->> 'key_id' IS DISTINCT FROM key_id THEN
    RAISE EXCEPTION 'the signed statement does not match the export' USING ERRCODE = 'PF004';
  END IF;
  INSERT INTO posture.export_record AS r (id, kind, as_of, created_at, created_by, snapshot, snapshot_digest, document_digest,
    statement, signature, key_id)
  VALUES (export_id, export_kind, export_as_of, export_created_at, u, snapshot, snapshot_digest, document_digest,
    statement, signature, key_id);
  RETURN export_id;
END $$;

-- One export with its snapshot (posture.export).
CREATE FUNCTION posture.export_get(export_id uuid)
RETURNS TABLE (id uuid, kind text, as_of timestamptz, created_at timestamptz, created_by uuid, snapshot bytea,
               snapshot_digest text, document_digest text, statement bytea, signature text, key_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  PERFORM posture.export_actor();
  RETURN QUERY SELECT r.id, r.kind, r.as_of, r.created_at, r.created_by, r.snapshot, r.snapshot_digest, r.document_digest,
    r.statement, r.signature, r.key_id FROM posture.export_record r WHERE r.id = export_get.export_id;
END $$;

-- The export of a kind at an as_of, for reproduction (posture.export).
CREATE FUNCTION posture.export_at(export_kind text, export_as_of timestamptz) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM posture.export_actor();
  RETURN (SELECT r.id FROM posture.export_record r WHERE r.kind = export_kind AND r.as_of = export_as_of);
END $$;

-- The export history without snapshots, newest first (the Posture API
-- shows it to posture.view holders).
CREATE FUNCTION posture.export_records(max_rows integer DEFAULT 100)
RETURNS TABLE (id uuid, kind text, as_of timestamptz, created_at timestamptz, created_by uuid, snapshot_digest text,
               document_digest text, key_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT r.id, r.kind, r.as_of, r.created_at, r.created_by, r.snapshot_digest, r.document_digest, r.key_id
  FROM posture.export_record r ORDER BY r.created_at DESC, r.id LIMIT greatest(1, least(max_rows, 1000));
$$;

REVOKE ALL ON FUNCTION posture.export_actor(), posture.record_export(uuid, text, timestamptz, timestamptz, bytea, text, text, bytea, text, text),
  posture.export_get(uuid), posture.export_at(text, timestamptz), posture.export_records(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.record_export(uuid, text, timestamptz, timestamptz, bytea, text, text, bytea, text, text),
  posture.export_get(uuid), posture.export_at(text, timestamptz), posture.export_records(integer) TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
