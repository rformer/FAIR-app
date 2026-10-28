-- F-015 T-30 (AC-39, AC-40; design §6.8 access model): consent to the
-- deployment scanner's Kubernetes access.
--
--   (none) -> granted | declined      the install-time decision (installer)
--   granted -> revoked                 access withdrawn later (installer; reason)
--   declined | revoked -> requested    the scanner enabled later (installer)
--   requested -> granted               an admin acknowledges it (settings.change)
--   requested -> declined              the request withdrawn (installer)
--   granted -> granted                 re-consent to a release's new permissions
-- Each decision records the digest of the permission manifest consented to.
-- In SaaS mode deployment drift detection is always on (AC-38): declining or
-- revoking is refused, and an undecided SaaS install counts as granted.
-- While access is not granted, posture refuses scanner reports and every
-- deployment check is "Not assessed" (AC-40). The service audits each
-- decision (declines and revocations high).

CREATE TABLE posture.k8s_access (
  singleton           boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  state               text        NOT NULL CHECK (state IN ('requested', 'granted', 'declined', 'revoked')),
  permissions_digest  text        NOT NULL CHECK (permissions_digest ~ '^[0-9a-f]{64}$'),
  decided_by          uuid        REFERENCES iam.app_user (id), -- an admin's acknowledgement
  decided_actor       text        NOT NULL,                     -- system:installer or the admin
  decided_at          timestamptz NOT NULL DEFAULT now(),
  reason              text,
  CHECK (state NOT IN ('declined', 'revoked') OR btrim(coalesce(reason, '')) <> '')
);
REVOKE ALL ON posture.k8s_access FROM PUBLIC;
ALTER TABLE posture.k8s_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture.k8s_access FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_only ON posture.k8s_access TO posture_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON posture.k8s_access TO posture_definer;

GRANT CREATE ON SCHEMA posture TO posture_definer;
SET ROLE posture_definer;

-- The installer's decisions (posture k8s-access ...). Returns the previous
-- state ('' when undecided).
CREATE FUNCTION posture.decide_k8s_access(new_state text, reason text, digest text, actor text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  cur  posture.k8s_access;
  prev text;
BEGIN
  IF new_state NOT IN ('granted', 'declined', 'requested', 'revoked') THEN
    RAISE EXCEPTION 'unknown Kubernetes access state %', new_state USING ERRCODE = 'PF004';
  END IF;
  IF btrim(coalesce(actor, '')) = '' OR digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'an actor and the permission manifest digest are required' USING ERRCODE = 'PF004';
  END IF;
  IF posture.deployment_mode() = 'saas' AND new_state IN ('declined', 'revoked') THEN
    RAISE EXCEPTION 'deployment drift detection is always on in SaaS mode' USING ERRCODE = 'PF003';
  END IF;
  IF new_state IN ('declined', 'revoked') AND btrim(coalesce(reason, '')) = '' THEN
    RAISE EXCEPTION 'declining or revoking Kubernetes access needs a stated reason' USING ERRCODE = 'PF002';
  END IF;
  SELECT * INTO cur FROM posture.k8s_access FOR UPDATE;
  prev := coalesce(cur.state, '');
  IF NOT ((prev = '' AND new_state IN ('granted', 'declined'))
       OR (prev = 'granted' AND new_state IN ('revoked', 'granted'))
       OR (prev IN ('declined', 'revoked') AND new_state = 'requested')
       OR (prev = 'requested' AND new_state = 'declined')) THEN
    RAISE EXCEPTION 'Kubernetes access cannot go from % to % (a later grant is requested here and acknowledged by an admin)',
      coalesce(nullif(prev, ''), 'undecided'), new_state USING ERRCODE = 'PF003';
  END IF;
  INSERT INTO posture.k8s_access AS k (singleton, state, permissions_digest, decided_by, decided_actor, decided_at, reason)
  VALUES (true, new_state, digest, NULL, actor, now(), nullif(btrim(coalesce(reason, '')), ''))
  ON CONFLICT (singleton) DO UPDATE SET state = EXCLUDED.state, permissions_digest = EXCLUDED.permissions_digest,
    decided_by = NULL, decided_actor = EXCLUDED.decided_actor, decided_at = now(), reason = EXCLUDED.reason;
  RETURN prev;
END $$;

-- An admin acknowledges a requested grant, as the signed-context user with
-- settings.change at the root, for the permission manifest digest shown.
CREATE FUNCTION posture.acknowledge_k8s_access(digest text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  u   uuid := posture.change_actor(NULL);
  cur posture.k8s_access;
BEGIN
  SELECT * INTO cur FROM posture.k8s_access FOR UPDATE;
  IF NOT FOUND OR cur.state <> 'requested' THEN
    RAISE EXCEPTION 'no Kubernetes access request to acknowledge (state %)', coalesce(cur.state, 'undecided') USING ERRCODE = 'PF003';
  END IF;
  IF digest IS DISTINCT FROM cur.permissions_digest THEN
    RAISE EXCEPTION 'the permissions acknowledged are not those requested' USING ERRCODE = 'PF004';
  END IF;
  UPDATE posture.k8s_access SET state = 'granted', decided_by = u, decided_actor = u::text, decided_at = now(), reason = NULL;
END $$;

-- The current state, for the Posture page banner and the scanner gate.
-- An undecided SaaS install counts as granted (AC-38).
CREATE FUNCTION posture.k8s_access_status(OUT state text, OUT permissions_digest text, OUT decided_actor text,
  OUT decided_at timestamptz, OUT reason text, OUT deployment_mode text, OUT last_report timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(k.state, CASE WHEN posture.deployment_mode() = 'saas' THEN 'granted' ELSE 'undecided' END),
         k.permissions_digest, k.decided_actor, k.decided_at, k.reason, posture.deployment_mode(),
         (SELECT max(r.received_at) FROM posture.scanner_report r)
  FROM (SELECT 1) one LEFT JOIN posture.k8s_access k ON true;
$$;

REVOKE ALL ON FUNCTION posture.decide_k8s_access(text, text, text, text), posture.acknowledge_k8s_access(text),
  posture.k8s_access_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION posture.decide_k8s_access(text, text, text, text), posture.acknowledge_k8s_access(text),
  posture.k8s_access_status() TO app_posture;

RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA posture FROM posture_definer;
