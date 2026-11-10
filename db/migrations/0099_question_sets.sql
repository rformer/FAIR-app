-- F-004 T-11 (F-004-AC-24 to AC-26; design §6.6): calibration question sets.
--
-- The shipped set comes with each release (internal/estimate/bank) and is
-- synced by iam migrate (estimate.sync_bank, as fair_owner): a question
-- whose text, unit, answer or source changed gains a version; one no longer
-- shipped is retired; the set is read-only to everyone else.
--
-- Holders of calibration.manage (at the root) keep custom sets: create one
-- (a draft), add questions, edit them (a new version), retire them, then
-- activate the set, and retire it when it is done. Only active sets are
-- drawn from (estimate.start_exercise), and only questions not retired.
-- A question's answer is shown to managers here, and to a person only after
-- they submit an exercise holding it (0098). Every change is recorded in
-- the trail (calibration.question_set_changed).

GRANT CREATE ON SCHEMA estimate TO estimate_definer;
SET ROLE estimate_definer;

-- The release's shipped set (iam migrate).
CREATE FUNCTION estimate.sync_bank(payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  sid uuid := (payload ->> 'set_id')::uuid;
  q jsonb; cur estimate.question; added text[] := '{}'; changed text[] := '{}'; retired text[] := '{}'; r record;
BEGIN
  INSERT INTO estimate.question_set (id, origin, name, description, status, release)
  VALUES (sid, 'shipped', payload ->> 'name', coalesce(payload ->> 'description', ''), 'active', payload ->> 'release')
  ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, release = EXCLUDED.release, status = 'active';
  FOR q IN SELECT x FROM jsonb_array_elements(payload -> 'questions') x LOOP
    SELECT * INTO cur FROM estimate.question y WHERE y.id = (q ->> 'id')::uuid ORDER BY y.version DESC LIMIT 1;
    IF NOT FOUND THEN
      INSERT INTO estimate.question (id, version, set_id, kind, text, unit, answer, source)
      VALUES ((q ->> 'id')::uuid, 1, sid, q ->> 'kind', q ->> 'text', q ->> 'unit', q ->> 'answer', q ->> 'source');
      added := added || (q ->> 'key');
    ELSIF cur.retired_at IS NOT NULL OR (cur.kind, cur.text, cur.unit, cur.answer, cur.source)
          IS DISTINCT FROM (q ->> 'kind', q ->> 'text', q ->> 'unit', q ->> 'answer', q ->> 'source') THEN
      INSERT INTO estimate.question (id, version, set_id, kind, text, unit, answer, source)
      VALUES (cur.id, cur.version + 1, sid, q ->> 'kind', q ->> 'text', q ->> 'unit', q ->> 'answer', q ->> 'source');
      UPDATE estimate.question y SET retired_at = now() WHERE y.id = cur.id AND y.version <= cur.version AND y.retired_at IS NULL;
      changed := changed || (q ->> 'key');
    END IF;
  END LOOP;
  FOR r IN SELECT DISTINCT y.id FROM estimate.question y
           WHERE y.set_id = sid AND y.retired_at IS NULL
             AND NOT y.id::text = ANY (ARRAY(SELECT x ->> 'id' FROM jsonb_array_elements(payload -> 'questions') x)) LOOP
    UPDATE estimate.question y SET retired_at = now() WHERE y.id = r.id AND y.retired_at IS NULL;
    retired := retired || r.id::text;
  END LOOP;
  RETURN jsonb_build_object('added', to_jsonb(added), 'changed', to_jsonb(changed), 'retired', to_jsonb(retired));
END $$;

-- The caller holds calibration.manage (at the root).
CREATE FUNCTION estimate.manager() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.actor();
BEGIN
  IF NOT iam.holds_permission(u, 'calibration.manage', NULL) THEN
    RAISE EXCEPTION 'estimate: managing question sets needs calibration.manage' USING ERRCODE = '42501';
  END IF;
  RETURN u;
END $$;

-- A custom set the caller may change.
CREATE FUNCTION estimate.custom_set(id uuid) RETURNS estimate.question_set
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s estimate.question_set;
BEGIN
  SELECT * INTO s FROM estimate.question_set x WHERE x.id = custom_set.id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: no such question set %', id USING ERRCODE = 'P0002';
  END IF;
  IF s.origin = 'shipped' THEN
    RAISE EXCEPTION 'estimate: the shipped question set is read-only' USING ERRCODE = 'PF022';
  END IF;
  IF s.status = 'retired' THEN
    RAISE EXCEPTION 'estimate: the question set is retired' USING ERRCODE = 'PF022';
  END IF;
  RETURN s;
END $$;

-- Record a change.
CREATE FUNCTION estimate.set_changed(u uuid, set_id uuid, action text, question uuid) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO iam.event_outbox (topic, payload)
  VALUES ('audit', jsonb_build_object('type', 'calibration.question_set_changed', 'severity', 'low', 'actor', u::text,
    'target', 'question_set:' || set_id, 'attributes', jsonb_build_object('action', action, 'question', question)));
$$;

-- A question's fields, checked as text is everywhere (lengths, a single
-- line, no secrets); the table's checks hold the rest.
CREATE FUNCTION estimate.check_question(qkind text, qtext text, qunit text, qanswer text, qsource text) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE p text[];
BEGIN
  p := risk.text(to_jsonb(qtext), '/text', 1000, true, false) || risk.text(to_jsonb(qsource), '/source', 1000, true, false)
    || CASE WHEN qkind = 'range' THEN risk.text(to_jsonb(qunit), '/unit', 100, true, false) ELSE '{}' END;
  IF qkind NOT IN ('range', 'binary') THEN p := p || '/kind: is range or binary'::text; END IF;
  IF qkind = 'range' AND (qanswer IS NULL OR qanswer !~ '^-?[0-9]{1,30}(\.[0-9]{1,30})?$') THEN p := p || '/answer: a range question''s answer is a decimal'::text; END IF;
  IF qkind = 'binary' AND (qanswer IS NULL OR qanswer NOT IN ('true', 'false')) THEN p := p || '/answer: is true or false'::text; END IF;
  IF qkind = 'binary' AND qunit IS NOT NULL THEN p := p || '/unit: a true-or-false question has no unit'::text; END IF;
  IF cardinality(p) > 0 THEN
    RAISE EXCEPTION 'estimate: invalid question' USING ERRCODE = 'PF016', DETAIL = array_to_string(p, E'\n');
  END IF;
END $$;

CREATE FUNCTION estimate.question_sets() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM estimate.manager();
  RETURN coalesce((SELECT jsonb_agg(jsonb_build_object('id', s.id, 'origin', s.origin, 'name', s.name, 'description', s.description,
      'status', s.status, 'release', s.release, 'created_at', s.created_at,
      'questions', (SELECT count(DISTINCT q.id) FROM estimate.question q WHERE q.set_id = s.id AND q.retired_at IS NULL))
    ORDER BY s.origin DESC, s.name) FROM estimate.question_set s), '[]');
END $$;

-- A set with each question's latest version, answer and source included.
CREATE FUNCTION estimate.question_set(id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s estimate.question_set;
BEGIN
  PERFORM estimate.manager();
  SELECT * INTO s FROM estimate.question_set x WHERE x.id = question_set.id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: no such question set %', id USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object('id', s.id, 'origin', s.origin, 'name', s.name, 'description', s.description, 'status', s.status, 'release', s.release,
    'questions', coalesce((SELECT jsonb_agg(jsonb_build_object('id', q.id, 'version', q.version, 'kind', q.kind, 'text', q.text, 'unit', q.unit,
        'answer', q.answer, 'source', q.source, 'retired', q.retired_at IS NOT NULL) ORDER BY q.created_at, q.id)
      FROM (SELECT DISTINCT ON (y.id) y.* FROM estimate.question y WHERE y.set_id = s.id ORDER BY y.id, y.version DESC) q), '[]'));
END $$;

CREATE FUNCTION estimate.create_set(name text, description text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.manager(); id uuid; p text[];
BEGIN
  p := risk.text(to_jsonb(name), '/name', 200, true, false) || risk.text(to_jsonb(coalesce(description, '')), '/description', 10000, false, true);
  IF cardinality(p) > 0 THEN
    RAISE EXCEPTION 'estimate: invalid question set' USING ERRCODE = 'PF016', DETAIL = array_to_string(p, E'\n');
  END IF;
  INSERT INTO estimate.question_set (origin, name, description, status, created_by) VALUES ('custom', btrim(name), coalesce(description, ''), 'draft', u)
  RETURNING question_set.id INTO id;
  PERFORM estimate.set_changed(u, id, 'created', NULL);
  RETURN id;
END $$;

CREATE FUNCTION estimate.add_question(set_id uuid, qkind text, qtext text, qunit text, qanswer text, qsource text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.manager(); s estimate.question_set := estimate.custom_set(set_id); id uuid := gen_random_uuid();
BEGIN
  PERFORM estimate.check_question(qkind, qtext, qunit, qanswer, qsource);
  INSERT INTO estimate.question (id, version, set_id, kind, text, unit, answer, source)
  VALUES (id, 1, s.id, qkind, btrim(qtext), btrim(qunit), CASE WHEN qkind = 'range' THEN estimate.num(qanswer::numeric) ELSE qanswer END, btrim(qsource));
  PERFORM estimate.set_changed(u, s.id, 'question_added', id);
  RETURN id;
END $$;

CREATE FUNCTION estimate.edit_question(id uuid, qtext text, qunit text, qanswer text, qsource text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.manager(); cur estimate.question; s estimate.question_set;
BEGIN
  SELECT * INTO cur FROM estimate.question y WHERE y.id = edit_question.id ORDER BY y.version DESC LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: no such question %', id USING ERRCODE = 'P0002';
  END IF;
  s := estimate.custom_set(cur.set_id);
  IF cur.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'estimate: the question is retired' USING ERRCODE = 'PF022';
  END IF;
  PERFORM estimate.check_question(cur.kind, qtext, qunit, qanswer, qsource);
  INSERT INTO estimate.question (id, version, set_id, kind, text, unit, answer, source)
  VALUES (cur.id, cur.version + 1, s.id, cur.kind, btrim(qtext), btrim(qunit), CASE WHEN cur.kind = 'range' THEN estimate.num(qanswer::numeric) ELSE qanswer END, btrim(qsource));
  PERFORM estimate.set_changed(u, s.id, 'question_edited', cur.id);
  RETURN cur.version + 1;
END $$;

CREATE FUNCTION estimate.retire_question(id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.manager(); s uuid;
BEGIN
  SELECT y.set_id INTO s FROM estimate.question y WHERE y.id = retire_question.id LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: no such question %', id USING ERRCODE = 'P0002';
  END IF;
  PERFORM estimate.custom_set(s);
  UPDATE estimate.question y SET retired_at = now() WHERE y.id = retire_question.id AND y.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'estimate: the question is retired' USING ERRCODE = 'PF022';
  END IF;
  PERFORM estimate.set_changed(u, s, 'question_retired', id);
END $$;

-- draft → active (with a question at least), active or draft → retired.
CREATE FUNCTION estimate.set_set_status(id uuid, to_status text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := estimate.manager(); s estimate.question_set := estimate.custom_set(id);
BEGIN
  IF to_status = 'active' THEN
    IF s.status <> 'draft' THEN
      RAISE EXCEPTION 'estimate: only a draft set is activated' USING ERRCODE = 'PF022';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM estimate.question q WHERE q.set_id = s.id AND q.retired_at IS NULL) THEN
      RAISE EXCEPTION 'estimate: a set needs a question before it is activated' USING ERRCODE = 'PF022';
    END IF;
  ELSIF to_status IS DISTINCT FROM 'retired' THEN
    RAISE EXCEPTION 'estimate: a set is activated or retired' USING ERRCODE = 'PF022';
  END IF;
  UPDATE estimate.question_set x SET status = to_status WHERE x.id = s.id;
  PERFORM estimate.set_changed(u, s.id, CASE to_status WHEN 'active' THEN 'activated' ELSE 'retired' END, NULL);
END $$;

REVOKE ALL ON FUNCTION estimate.sync_bank(jsonb), estimate.manager(), estimate.custom_set(uuid), estimate.set_changed(uuid, uuid, text, uuid),
  estimate.check_question(text, text, text, text, text), estimate.question_sets(), estimate.question_set(uuid), estimate.create_set(text, text),
  estimate.add_question(uuid, text, text, text, text, text), estimate.edit_question(uuid, text, text, text, text), estimate.retire_question(uuid),
  estimate.set_set_status(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION estimate.sync_bank(jsonb) TO fair_owner;
GRANT EXECUTE ON FUNCTION estimate.question_sets(), estimate.question_set(uuid), estimate.create_set(text, text),
  estimate.add_question(uuid, text, text, text, text, text), estimate.edit_question(uuid, text, text, text, text), estimate.retire_question(uuid),
  estimate.set_set_status(uuid, text) TO app_rw;
RESET ROLE;
SET LOCAL ROLE fair_owner;
REVOKE CREATE ON SCHEMA estimate FROM estimate_definer;
