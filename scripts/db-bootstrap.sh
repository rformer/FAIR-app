#!/usr/bin/env bash
# Creates/asserts database roles (db/bootstrap/0001_roles.sql).
# Run by the installer or platform DBA with an administrative connection.
#
# Connection: standard libpq env vars for the ADMIN account (PGHOST, PGPORT,
# PGUSER, PGPASSWORD or PGPASSFILE, PGSSLMODE). Target database: PGDATABASE.
# Role passwords are read from files (mounted secrets), never from literals:
#   FAIR_MIGRATOR_PASSWORD_FILE, FAIR_RW_PASSWORD_FILE, FAIR_ENGINE_PASSWORD_FILE
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

: "${PGDATABASE:?PGDATABASE must name the target database}"
for v in FAIR_MIGRATOR_PASSWORD_FILE FAIR_RW_PASSWORD_FILE FAIR_ENGINE_PASSWORD_FILE; do
  f="${!v:-}"
  [[ -n "$f" && -s "$f" ]] || { echo "error: $v must point to a non-empty file" >&2; exit 2; }
done

read_secret() { tr -d '\r\n' < "$1"; }

psql --no-psqlrc -v ON_ERROR_STOP=1 -q \
  -v dbname="$PGDATABASE" \
  -v migrator_password="$(read_secret "$FAIR_MIGRATOR_PASSWORD_FILE")" \
  -v rw_password="$(read_secret "$FAIR_RW_PASSWORD_FILE")" \
  -v engine_password="$(read_secret "$FAIR_ENGINE_PASSWORD_FILE")" \
  -f "$root/db/bootstrap/0001_roles.sql"

echo "bootstrap: roles asserted for database $PGDATABASE"
