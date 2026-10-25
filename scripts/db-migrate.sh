#!/usr/bin/env bash
# Applies db/migrations/*.sql in order as app_migrator, each inside one
# transaction under SET ROLE fair_owner. Records version + SHA-256 in
# fair_meta.schema_migrations and refuses to continue if an applied
# migration file has changed (tamper/drift detection).
#
# Connection: libpq env vars (PGHOST, PGPORT, PGDATABASE, PGSSLMODE).
# User is always app_migrator; password from FAIR_MIGRATOR_PASSWORD_FILE.
# MIGRATIONS_DIR may override the migrations directory (used by tests).
#
# Phase 1 replaces this with an embedded Go runner with identical semantics.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
dir="${MIGRATIONS_DIR:-$root/db/migrations}"

: "${PGDATABASE:?PGDATABASE must be set}"
: "${FAIR_MIGRATOR_PASSWORD_FILE:?FAIR_MIGRATOR_PASSWORD_FILE must be set}"
export PGUSER=app_migrator
PGPASSWORD="$(tr -d '\r\n' < "$FAIR_MIGRATOR_PASSWORD_FILE")"
export PGPASSWORD

run_psql() { psql --no-psqlrc -v ON_ERROR_STOP=1 -q -X "$@"; }

# Ensure the bookkeeping schema exists (owned by fair_owner, invisible to app roles).
run_psql <<'SQL'
SET ROLE fair_owner;
CREATE SCHEMA IF NOT EXISTS fair_meta AUTHORIZATION fair_owner;
REVOKE ALL ON SCHEMA fair_meta FROM PUBLIC;
CREATE TABLE IF NOT EXISTS fair_meta.schema_migrations (
  version    text        PRIMARY KEY,
  sha256     text        NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON fair_meta.schema_migrations FROM PUBLIC;
SQL

shopt -s nullglob
files=("$dir"/*.sql)
[[ ${#files[@]} -gt 0 ]] || { echo "migrate: no migrations in $dir" >&2; exit 1; }

applied=0
for f in "${files[@]}"; do
  version="$(basename "$f" .sql)"
  [[ "$version" =~ ^[0-9]{4}_[a-z0-9_]+$ ]] || { echo "migrate: bad file name $f" >&2; exit 1; }
  sum="$(sha256sum "$f" | cut -d' ' -f1)"

  recorded="$(run_psql -tA -c "SET ROLE fair_owner; SELECT sha256 FROM fair_meta.schema_migrations WHERE version = '$version'" | tail -n1)"
  if [[ -n "$recorded" ]]; then
    if [[ "$recorded" != "$sum" ]]; then
      echo "migrate: CHECKSUM MISMATCH for $version (applied $recorded, file $sum). Refusing to continue." >&2
      exit 3
    fi
    continue
  fi

  {
    echo "BEGIN;"
    echo "SET LOCAL ROLE fair_owner;"
    cat "$f"
    echo
    echo "INSERT INTO fair_meta.schema_migrations(version, sha256) VALUES ('$version', '$sum');"
    echo "COMMIT;"
  } | run_psql
  echo "migrate: applied $version"
  applied=$((applied + 1))
done

echo "migrate: done ($applied applied)"
