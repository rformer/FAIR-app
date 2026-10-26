-- F-015 T-08: posture schema (design §5 and its access model).
--
-- Posture rows are configuration, not BU-owned business records: bu_id is
-- nullable (NULL = instance-wide) and the main readers are system processes.
-- Application roles therefore get NO privileges on these tables, reads
-- included; every read and write goes through SECURITY DEFINER functions
-- owned by posture_definer (T-09 onward). RLS is enabled and forced with a
-- single posture_definer policy, so a mistaken grant still exposes no rows.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'posture_definer')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_posture') THEN
    RAISE EXCEPTION 'roles posture_definer and app_posture are missing: re-run scripts/db-bootstrap.sh (F-015 T-08)';
  END IF;
END $$;

CREATE SCHEMA posture AUTHORIZATION fair_owner;
REVOKE ALL ON SCHEMA posture FROM PUBLIC;
-- The posture service reaches its definer functions through the schema; it
-- gets no table privileges. Other services' read access arrives with T-11.
GRANT USAGE ON SCHEMA posture TO app_posture, posture_definer;
ALTER DEFAULT PRIVILEGES FOR ROLE fair_owner IN SCHEMA posture REVOKE ALL ON TABLES FROM PUBLIC;

-- Registered settings (§6.1). Rows come from service registration (T-12) and
-- package import (T-10).
CREATE TABLE posture.setting_def (
  key                  text        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  type                 text        NOT NULL CHECK (type IN ('duration', 'int', 'bool', 'enum', 'set')),
  direction            text        NOT NULL,
  enum_order           text[],     -- enum: weakest -> strictest
  bu_scopable          boolean     NOT NULL DEFAULT false,
  hard_floor           jsonb,      -- NULL: no floor
  hard_floor_families  text[]      NOT NULL DEFAULT '{}', -- empty: every family
  params               text[]      NOT NULL DEFAULT '{}', -- OSCAL parameter ids
  owner_feature        text        NOT NULL CHECK (owner_feature ~ '^F-[0-9]{3}$'),
  registered_version   text        NOT NULL,
  registered_at        timestamptz NOT NULL DEFAULT now(),
  CHECK ((type IN ('duration', 'int') AND direction IN ('lower_is_stricter', 'higher_is_stricter'))
      OR (type = 'bool' AND direction IN ('true_is_stricter', 'false_is_stricter'))
      OR (type = 'enum' AND direction = 'ordered')
      OR (type = 'set' AND direction = 'subset_is_stricter')),
  CHECK ((type = 'enum') = (enum_order IS NOT NULL)),
  CHECK (enum_order IS NULL OR cardinality(enum_order) >= 2),
  CHECK (hard_floor_families <@ ARRAY['fedramp', 'cmmc', 'enterprise'])
);

-- Profiles, one row per version (built-in packages and custom profiles).
CREATE TABLE posture.profile (
  id              text        NOT NULL CHECK (id ~ '^[a-z0-9][a-z0-9.-]*$'),
  version         text        NOT NULL CHECK (version ~ '^[a-z0-9][a-z0-9.-]*$'),
  name            text        NOT NULL CHECK (btrim(name) <> ''),
  family          text        NOT NULL CHECK (family IN ('fedramp', 'cmmc', 'enterprise')), -- hard floors apply per family
  kind            text        NOT NULL CHECK (kind IN ('builtin', 'custom')),
  base_profile_id text,
  base_version    text,
  package_digest  text        CHECK (package_digest ~ '^[0-9a-f]{64}$'), -- built-in: the signed package's SHA-256
  status          text        NOT NULL CHECK (status IN ('draft', 'pending_approval', 'approved', 'active', 'retired')),
  label_deviates  boolean     NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  created_by      uuid        REFERENCES iam.app_user (id), -- NULL: package import
  PRIMARY KEY (id, version),
  FOREIGN KEY (base_profile_id, base_version) REFERENCES posture.profile (id, version),
  CHECK ((kind = 'builtin') = (package_digest IS NOT NULL)),
  CHECK ((kind = 'custom') = (base_profile_id IS NOT NULL AND base_version IS NOT NULL)),
  CHECK (kind = 'custom' OR NOT label_deviates)
);

-- Each profile version's default and bound per setting. No foreign key to
-- setting_def: a package may bind keys of features not yet registered.
CREATE TABLE posture.profile_value (
  profile_id     text    NOT NULL,
  version        text    NOT NULL,
  key            text    NOT NULL,
  default_value  jsonb   NOT NULL,
  bound          jsonb   NOT NULL, -- the weakest value allowed without an exception
  justification  text,
  loosened       boolean NOT NULL DEFAULT false, -- weaker than the base profile (custom)
  PRIMARY KEY (profile_id, version, key),
  FOREIGN KEY (profile_id, version) REFERENCES posture.profile (id, version),
  CHECK (NOT loosened OR btrim(coalesce(justification, '')) <> '')
);

-- The active profile (singleton).
CREATE TABLE posture.active_profile (
  singleton     boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  profile_id    text        NOT NULL,
  version       text        NOT NULL,
  activated_at  timestamptz NOT NULL DEFAULT now(),
  activated_by  uuid        REFERENCES iam.app_user (id), -- NULL: install-time seed (T-10)
  switch_id     uuid,       -- profile_switch (Phase C)
  FOREIGN KEY (profile_id, version) REFERENCES posture.profile (id, version)
);

-- Requested setting changes (§6.2).
CREATE TABLE posture.change (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  key                  text        NOT NULL REFERENCES posture.setting_def (key),
  bu_id                uuid        REFERENCES iam.bu (id), -- NULL: instance-wide
  old_value            jsonb,
  new_value            jsonb       NOT NULL,
  direction            text        NOT NULL CHECK (direction IN ('tighten', 'neutral', 'loosen')),
  explanation          text,
  requested_by         uuid        NOT NULL REFERENCES iam.app_user (id),
  approval_request_id  uuid,       -- F-001 approvals
  state                text        NOT NULL CHECK (state IN ('applied', 'pending_approval', 'rejected')),
  created_at           timestamptz NOT NULL DEFAULT now(),
  applied_at           timestamptz,
  CHECK ((state = 'applied') = (applied_at IS NOT NULL)),
  CHECK (state <> 'pending_approval' OR approval_request_id IS NOT NULL)
);
CREATE INDEX change_key_bu ON posture.change (key, bu_id);

-- Time-bound exceptions (§6.3).
CREATE TABLE posture.exception (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  key                text        NOT NULL REFERENCES posture.setting_def (key),
  bu_id              uuid        REFERENCES iam.bu (id), -- NULL: instance-wide
  value              jsonb       NOT NULL,
  bound_at_creation  jsonb       NOT NULL,
  justification      text        NOT NULL CHECK (btrim(justification) <> ''),
  owner_id           uuid        NOT NULL REFERENCES iam.app_user (id),
  approved_by        uuid        NOT NULL REFERENCES iam.app_user (id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  renewed_from       uuid        REFERENCES posture.exception (id),
  state              text        NOT NULL CHECK (state IN ('active', 'renewed', 'expired', 'reverted', 'revert_failed')),
  CHECK (expires_at > created_at)
);
CREATE INDEX exception_due ON posture.exception (expires_at) WHERE state = 'active';

-- Current values: one per key, instance-wide (bu_id NULL) or per BU.
-- row_mac (T-09) is an HMAC over (key, bu_id, value, source, ref id) keyed by
-- a posture key application roles cannot read.
CREATE TABLE posture.setting_value (
  key           text        NOT NULL,
  bu_id         uuid        REFERENCES iam.bu (id),
  value         jsonb       NOT NULL,
  source        text        NOT NULL CHECK (source IN ('profile', 'change', 'exception', 'overlay', 'revert')),
  change_id     uuid        REFERENCES posture.change (id),
  exception_id  uuid        REFERENCES posture.exception (id),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  row_mac       bytea       NOT NULL CHECK (octet_length(row_mac) = 32),
  UNIQUE NULLS NOT DISTINCT (key, bu_id),
  CHECK ((source = 'change') = (change_id IS NOT NULL)),
  CHECK ((source IN ('exception', 'revert')) = (exception_id IS NOT NULL))
);

-- Defence in depth (design §5 access model): RLS enabled and forced, with a
-- single policy for posture_definer.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['setting_def', 'profile', 'profile_value', 'active_profile', 'change', 'exception', 'setting_value'] LOOP
    EXECUTE format('REVOKE ALL ON posture.%I FROM PUBLIC', t);
    EXECUTE format('ALTER TABLE posture.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE posture.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY definer_only ON posture.%I TO posture_definer USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;
