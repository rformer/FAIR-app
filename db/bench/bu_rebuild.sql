-- F-001 T-05: closure rebuild cost for BU move / restrict / unrestrict
-- (design §12 R1). Run as a superuser against a scratch database that has
-- db/migrations applied:
--   psql -d <scratch> -v n1=10 -v n2=10 -v n3=19 -f db/bench/bu_rebuild.sql
-- Builds a root with n1 children, n2 under each and n3 under each of those.
-- T-11 folds this into the benchmark gate.
\set ON_ERROR_STOP on
CREATE FUNCTION pg_temp.build(n1 int, n2 int, n3 int) RETURNS void LANGUAGE plpgsql AS $$
DECLARE r uuid; a uuid; b uuid; i int; j int; k int;
BEGIN
  SELECT id INTO r FROM iam.bu WHERE parent_id IS NULL;
  FOR i IN 1..n1 LOOP
    INSERT INTO iam.bu(name, code, parent_id, restricted) VALUES ('a', 'A'||i, r, false) RETURNING id INTO a;
    FOR j IN 1..n2 LOOP
      INSERT INTO iam.bu(name, code, parent_id, restricted) VALUES ('b', 'B'||i||'_'||j, a, false) RETURNING id INTO b;
      FOR k IN 1..n3 LOOP
        INSERT INTO iam.bu(name, code, parent_id, restricted) VALUES ('c', 'C'||i||'_'||j||'_'||k, b, false);
      END LOOP;
    END LOOP;
  END LOOP;
END $$;
SELECT pg_temp.build(:n1, :n2, :n3);
ANALYZE iam.bu; ANALYZE iam.bu_closure;
SELECT count(*) AS bus FROM iam.bu;
\timing on
-- Largest single subtree moves under a sibling (A1 -> under A2): subtree = 1 + n2 + n2*n3 nodes
UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code='A2') WHERE code='A1';
-- Restrict and unrestrict the node at the top of the largest subtree (A2 now holds two subtrees)
UPDATE iam.bu SET restricted = true  WHERE code='A2';
UPDATE iam.bu SET restricted = false WHERE code='A2';
