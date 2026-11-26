#!/usr/bin/env bash
# F-012 T-14 (F-012-AC-14, AC-16, AC-17; design §3.5; ADR-016): the instance
# pipeline's steps, run by .github/workflows/infra-instances.yml (the
# sandbox apply runs the same workflow from a copy of the repository,
# docs/operations/sandbox-apply.md).
#
#   scripts/infra-instance.sh list
#       every instance: the names of infra/instances/*.tfvars
#   scripts/infra-instance.sh changed BASE
#       the instances a change since BASE touches (every instance when
#       infra/instance, infra/instance-account or infra/modules changed)
#   scripts/infra-instance.sh plan NAME OUT
#       plans both roots read-only (fair-instances-plan, fair-instance-plan)
#       into OUT/<root>.{exitcode,json,txt,digest}; tofu plan
#       -detailed-exitcode: 0 no changes, 2 changes, 1 error. The stack is
#       planned once the account exists (OUT/instance.skipped otherwise).
#   scripts/infra-instance.sh apply NAME APPROVED
#       after approval (fair-instances-apply): the account (created through
#       the commercial pair), its invitation and acceptance, its import and
#       placement under the instances OU, the stack, then the secrets'
#       values (only entries without one). Each root applies only a plan
#       whose digest equals the approved plan's (APPROVED/<root>.digest,
#       from the plan on main); a new instance's first stack plan, which no
#       one could see before its account existed, must only create.
#
# Environment (the workflow's, from repository variables; nothing secret):
#   FAIR_INSTANCES_CONFIG  JSON: management_account_id, commercial_account_id,
#                          region, state_bucket, instances_ou_id, roles
#                          {plan, apply, commercial_plan, commercial_apply},
#                          log_archive {bucket, kms_key_arn}, dns
#                          {account_id, zone_id, domain, read_role_arn,
#                          delegate_role_arn}, ops_telemetry (or null),
#                          access_controller_role_arn (or absent; T-18)
#   ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN
#                          GitHub's OIDC token request (id-token: write);
#                          or FAIR_OIDC_TOKEN_FILE, a token file kept fresh
# Needs docker, jq, the AWS CLI v2 and Go. Every AWS call uses FIPS
# endpoints. Nothing here deletes a retained store, closes an account or
# removes one from the organization (docs/operations/decommissioning.md).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
export MSYS_NO_PATHCONV=1

TOFU_IMAGE=ghcr.io/opentofu/opentofu:1.13.9@sha256:f5aef7f2632b490e3c289a239d7974497d0583f3df6bfa35e8eb31a367ee5ec0
NAME_RE='^[a-z][a-z0-9-]{1,19}[a-z0-9]$'

die() { echo "infra-instance: $*" >&2; exit 1; }

list() {
  local f
  for f in infra/instances/*.tfvars; do
    [ -e "$f" ] || continue
    basename "$f" .tfvars
  done
}

changed() { # BASE
  local base="$1"
  if git diff --name-only "$base" HEAD -- infra/instance infra/instance-account infra/modules | grep -q .; then
    list
    return
  fi
  git diff --name-only --diff-filter=d "$base" HEAD -- 'infra/instances/*.tfvars' | sed -n 's#^infra/instances/\([^/]*\)\.tfvars$#\1#p'
}

case "${1:-}" in
  list) list; exit 0 ;;
  changed) [ $# -eq 2 ] || die "usage: changed BASE"; changed "$2"; exit 0 ;;
  plan | apply) ;;
  *) die "usage: list | changed BASE | plan NAME OUT | apply NAME APPROVED" ;;
esac
[ $# -eq 3 ] || die "usage: $1 NAME DIR"
CMD="$1" NAME="$2" DIR="$3"
[[ "$NAME" =~ $NAME_RE ]] || die "not an instance name: $NAME"
SPEC="infra/instances/$NAME.tfvars"
[ -f "$SPEC" ] || die "no $SPEC"
# A spec sets only spec fields (infra/instance/variables.tf), never the
# pipeline's (pipeline.tf: the account, the mode, the roles), and names
# itself; tofu fmt keeps every field at the start of its line.
docker run --rm -v "$REPO/infra:/infra:ro" -w /infra "$TOFU_IMAGE" fmt -check -no-color "instances/$NAME.tfvars" >/dev/null \
  || die "$SPEC is not formatted (tofu fmt)"
spec_fields="$(sed -n 's/^variable "\([a-z_]*\)" {$/\1/p' infra/instance/variables.tf)"
while IFS= read -r k; do
  grep -qxF "$k" <<<"$spec_fields" || die "$SPEC sets $k, which is not a spec field"
done < <(sed -n 's/^\([a-z_][a-z0-9_]*\) *=.*/\1/p' "$SPEC")
grep -qx "instance *= *\"$NAME\"" "$SPEC" || die "$SPEC must set instance = \"$NAME\""
mkdir -p "$DIR"
DIR="$(cd "$DIR" && pwd)"

: "${FAIR_INSTANCES_CONFIG:?FAIR_INSTANCES_CONFIG (the pipeline configuration) is required}"
cfg() { jq -er "$1" <<<"$FAIR_INSTANCES_CONFIG"; }
cfg_json() { jq -ec "$1" <<<"$FAIR_INSTANCES_CONFIG"; }
MGMT="$(cfg .management_account_id)"
REGION="$(cfg .region)"
BUCKET="$(cfg .state_bucket)"
export AWS_REGION="$REGION" AWS_USE_FIPS_ENDPOINT=true AWS_PAGER=""
if [ "$CMD" = plan ]; then
  MODE=plan ROLE="$(cfg .roles.plan)" COMMERCIAL_ROLE="$(cfg .roles.commercial_plan)"
else
  MODE=apply ROLE="$(cfg .roles.apply)" COMMERCIAL_ROLE="$(cfg .roles.commercial_apply)"
fi

# The workflow's OIDC token, refreshed while the run lasts (GitHub's tokens
# are short-lived; the providers re-read the file when they renew).
TOKEN_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"
cleanup() {
  [ -n "${REFRESH_PID:-}" ] && kill "$REFRESH_PID" 2>/dev/null || true
  rm -rf "$TOKEN_DIR" "$WORK"
}
trap cleanup EXIT
fetch_token() {
  curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -er .value >"$TOKEN_DIR/token.new"
  mv "$TOKEN_DIR/token.new" "$TOKEN_DIR/token"
}
if [ -n "${FAIR_OIDC_TOKEN_FILE:-}" ]; then
  cp "$FAIR_OIDC_TOKEN_FILE" "$TOKEN_DIR/token"
  ( while sleep 60; do cp "$FAIR_OIDC_TOKEN_FILE" "$TOKEN_DIR/token" 2>/dev/null || true; done ) &
  REFRESH_PID=$!
else
  : "${ACTIONS_ID_TOKEN_REQUEST_URL:?the workflow needs id-token: write}"
  fetch_token
  ( while sleep 240; do fetch_token || true; done ) &
  REFRESH_PID=$!
fi
chmod 0644 "$TOKEN_DIR/token"
export AWS_ROLE_ARN="$ROLE" AWS_WEB_IDENTITY_TOKEN_FILE="$TOKEN_DIR/token" AWS_ROLE_SESSION_NAME="fair-instance-$NAME-$MODE"

ACCOUNT_VARS=(
  -e "TF_VAR_instance=$NAME"
  -e "TF_VAR_account_id=$MGMT"
  -e "TF_VAR_commercial_account_id=$(cfg .commercial_account_id)"
  -e "TF_VAR_commercial_role_arn=$COMMERCIAL_ROLE"
  -e "TF_VAR_instances_ou_id=$(cfg .instances_ou_id)"
  -e "TF_VAR_region=$REGION"
  -e "TF_VAR_web_identity_token_file=/run/oidc/token"
)

tofu() { # root args...
  local root="$1"
  shift
  local extra=()
  [ "$root" = instance-account ] && extra=("${ACCOUNT_VARS[@]}")
  [ "$root" = instance ] && extra=("${STACK_VARS[@]}")
  docker run --rm --user "$(id -u):$(id -g)" -v "$REPO:/src" -v "$TOKEN_DIR:/run/oidc:ro" -v "$WORK:/work" -w "/src/infra/$root" \
    -e HOME=/work -e TF_IN_AUTOMATION=1 -e TF_DATA_DIR="/work/$root.terraform" \
    -e AWS_REGION -e AWS_USE_FIPS_ENDPOINT -e AWS_ROLE_ARN -e AWS_ROLE_SESSION_NAME \
    -e AWS_WEB_IDENTITY_TOKEN_FILE=/run/oidc/token \
    "${extra[@]}" "$TOFU_IMAGE" "$@"
}

init() { # root key
  tofu "$1" init -input=false -no-color -lockfile=readonly -reconfigure \
    -backend-config="$1.s3.tfbackend" -backend-config="bucket=$BUCKET" -backend-config="key=instances/$NAME/$2" >/dev/null
}

# plan_root ROOT OUT_PREFIX [args]: plan into /work, record exit code, JSON
# and text; prints the exit code.
plan_root() {
  local root="$1" out="$2"
  shift 2
  local code=0
  local lock=()
  [ "$MODE" = plan ] && lock=(-lock=false)
  tofu "$root" plan -input=false -no-color -detailed-exitcode "${lock[@]}" -out="/work/$root.tfplan" "$@" >"$out.txt" 2>&1 || code=$?
  echo "$code" >"$out.exitcode"
  if [ "$code" = 0 ] || [ "$code" = 2 ]; then
    # Only addresses and actions leave this step: the full JSON carries
    # the state's values, which never go into artifacts or comments.
    tofu "$root" show -json -no-color "/work/$root.tfplan" | jq -c '{
      format_version, terraform_version, errored: (.errored // false),
      resource_changes: [(.resource_changes // [])[] | {address, mode, type, change: {actions: .change.actions}}],
      resource_drift: [(.resource_drift // [])[] | {address, mode, type, change: {actions: .change.actions}}]
    }' >"$out.json"
    go run ./cmd/infraplan digest "$out.json" >"$out.digest"
  fi
  echo "$code"
}

joined() { # in the account root's state?
  tofu instance-account state list -no-color 2>/dev/null | grep -qxF 'aws_organizations_account.member[0]'
}

# --- the account ---------------------------------------------------------
init instance-account account.tfstate
JOINED=false
joined && JOINED=true
ACCOUNT_VARS+=(-e "TF_VAR_joined=$JOINED")

if [ "$MODE" = plan ]; then
  code="$(plan_root instance-account "$DIR/account")"
  [ "$code" = 1 ] && { cat "$DIR/account.txt" >&2; die "the account plan failed"; }
else
  code="$(plan_root instance-account "$WORK/account")"
  [ "$code" = 1 ] && { cat "$WORK/account.txt" >&2; die "the account plan failed"; }
  if [ "$code" = 2 ]; then
    if [ -f "$DIR/account.digest" ]; then
      [ "$(cat "$WORK/account.digest")" = "$(cat "$DIR/account.digest")" ] \
        || die "the account plan differs from the approved one (re-run the plan on main)"
    fi
    tofu instance-account apply -input=false -no-color /work/instance-account.tfplan
  fi
fi

ACCOUNT_ID="$(tofu instance-account output -raw -no-color account_id 2>/dev/null || true)"
if ! [[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]]; then
  [ "$MODE" = plan ] || die "the account was not created"
  echo "account not created yet: the stack is planned in the apply job, after the account exists (it may only create)" >"$DIR/instance.skipped"
  exit 0
fi

# --- joining the organization (apply only) --------------------------------
if [ "$MODE" = apply ] && [ "$JOINED" = false ]; then
  if ! aws organizations describe-account --account-id "$ACCOUNT_ID" >/dev/null 2>&1; then
    hs="$(aws organizations list-handshakes-for-organization --filter ActionType=INVITE --output json |
      jq -r --arg id "$ACCOUNT_ID" '[.Handshakes[] | select(.State == "OPEN" or .State == "REQUESTED") | select(any(.Parties[]; .Type == "ACCOUNT" and .Id == $id))][0].Id // empty')"
    if [ -z "$hs" ]; then
      hs="$(aws organizations invite-account-to-organization --target "Id=$ACCOUNT_ID,Type=ACCOUNT" \
        --notes "FAIR instance $NAME (F-012 T-14)" --output json | jq -er .Handshake.Id)"
    fi
    # Accept inside the new account, as its infrastructure role (it trusts
    # this management account; the apply role may assume it only while the
    # account belongs to no organization).
    creds="$(aws sts assume-role --role-arn "arn:aws-us-gov:iam::$ACCOUNT_ID:role/OrganizationAccountAccessRole" \
      --role-session-name "fair-instance-$NAME-join" --output json)"
    AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId <<<"$creds")" \
      AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretAccessKey <<<"$creds")" \
      AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken <<<"$creds")" \
      AWS_ROLE_ARN="" AWS_WEB_IDENTITY_TOKEN_FILE="" \
      aws organizations accept-handshake --handshake-id "$hs" >/dev/null
    for _ in $(seq 30); do
      aws organizations describe-account --account-id "$ACCOUNT_ID" >/dev/null 2>&1 && break
      sleep 10
    done
    aws organizations describe-account --account-id "$ACCOUNT_ID" >/dev/null || die "the account did not join"
  fi
  # Import the member and place it under the instances OU: the only change
  # that plan may make.
  ACCOUNT_VARS=("${ACCOUNT_VARS[@]/TF_VAR_joined=false/TF_VAR_joined=true}")
  tofu instance-account import -input=false -no-color 'aws_organizations_account.member[0]' "$ACCOUNT_ID"
  code="$(plan_root instance-account "$WORK/account-join")"
  [ "$code" = 1 ] && { cat "$WORK/account-join.txt" >&2; die "the placement plan failed"; }
  if [ "$code" = 2 ]; then
    jq -e '[.resource_changes[] | select(.change.actions != ["no-op"]) | select(.address != "aws_organizations_account.member[0]" or .change.actions != ["update"])] | length == 0' \
      "$WORK/account-join.json" >/dev/null || die "placing the joined account would change more than its OU and tags"
    tofu instance-account apply -input=false -no-color /work/instance-account.tfplan
  fi
fi

# --- the stack -----------------------------------------------------------
STACK_VARS=(
  -e "TF_VAR_account_id=$ACCOUNT_ID"
  -e "TF_VAR_mode=$MODE"
  -e "TF_VAR_management_account_id=$MGMT"
  -e "TF_VAR_log_archive=$(cfg_json .log_archive)"
  -e "TF_VAR_dns=$(cfg_json .dns)"
  -e "TF_VAR_ops_telemetry=$(jq -c '.ops_telemetry // null' <<<"$FAIR_INSTANCES_CONFIG")"
)
# accessctl's role (T-18), once just-in-time access is configured.
ACCESS_ROLE="$(jq -r '.access_controller_role_arn // empty' <<<"$FAIR_INSTANCES_CONFIG")"
[ -z "$ACCESS_ROLE" ] || STACK_VARS+=(-e "TF_VAR_access_controller_role_arn=$ACCESS_ROLE")
init instance terraform.tfstate
VARFILE="-var-file=/src/infra/instances/$NAME.tfvars"

if [ "$MODE" = plan ]; then
  if [ "$JOINED" = false ]; then
    echo "the account has not joined the organization yet: the stack is planned in the apply job (it may only create)" >"$DIR/instance.skipped"
    exit 0
  fi
  code="$(plan_root instance "$DIR/instance" "$VARFILE")"
  [ "$code" = 1 ] && { cat "$DIR/instance.txt" >&2; die "the stack plan failed"; }
  exit 0
fi

code="$(plan_root instance "$WORK/instance" "$VARFILE")"
[ "$code" = 1 ] && { cat "$WORK/instance.txt" >&2; die "the stack plan failed"; }
if [ "$code" = 2 ]; then
  if [ -f "$DIR/instance.digest" ]; then
    [ "$(cat "$WORK/instance.digest")" = "$(cat "$DIR/instance.digest")" ] \
      || die "the stack plan differs from the approved one (re-run the plan on main)"
  else
    go run ./cmd/infraplan create-only "$WORK/instance.json" \
      || die "no approved stack plan, and this one does more than create"
  fi
  tofu instance apply -input=false -no-color /work/instance.tfplan
fi

# --- the secrets' values (onboarding) --------------------------------------
# Only entries without a value, and the key files only as a whole set: a
# partial set is refused (the services' keys pair with each other; add
# missing directories with `iam keys upgrade`, docs/install/keys.md).
status="$(tofu instance output -raw -no-color status)"
[ "$status" = active ] || exit 0
creds="$(aws sts assume-role --role-arn "arn:aws-us-gov:iam::$ACCOUNT_ID:role/OrganizationAccountAccessRole" \
  --role-session-name "fair-instance-$NAME-secrets" --output json)"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId <<<"$creds")"
AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretAccessKey <<<"$creds")"
AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken <<<"$creds")"
unset AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE

has_value() { [ "$(aws secretsmanager list-secret-version-ids --secret-id "$1" --output json | jq '[.Versions[] | select(.VersionStages | index("AWSCURRENT"))] | length')" != 0 ]; }
mapfile -t names < <(tofu instance output -json -no-color secret_names | jq -r '.[]')
prefix="fair/$NAME/"
keys_missing=() keys_present=0
for s in "${names[@]}"; do
  case "$s" in "${prefix}database/"*) continue ;; esac
  if has_value "$s"; then keys_present=$((keys_present + 1)); else keys_missing+=("$s"); fi
done
umask 077
KEYS="$(mktemp -d /dev/shm/fair-keys.XXXXXX 2>/dev/null || mktemp -d)"
trap 'rm -rf "$KEYS"; cleanup' EXIT
if [ "${#keys_missing[@]}" -gt 0 ]; then
  [ "$keys_present" = 0 ] || die "${#keys_missing[@]} key entries without a value beside $keys_present with one: add them with iam keys upgrade (docs/install/keys.md), not here"
  GOFIPS140=v1.0.0 go run ./cmd/iam keys init -dir "$KEYS/set" >/dev/null
  for s in "${keys_missing[@]}"; do
    d="$KEYS/set/${s#"$prefix"}"
    [ -d "$d" ] || die "iam keys init made no ${s#"$prefix"}"
    (cd "$d" && for f in *; do jq -Rs --arg k "$f" '{($k): .}' <"$f"; done) | jq -s 'add' >"$KEYS/value.json"
    aws secretsmanager put-secret-value --secret-id "$s" --secret-string "file://$KEYS/value.json" >/dev/null
    echo "loaded $s"
  done
fi
for s in "${names[@]}"; do
  case "$s" in "${prefix}database/"*) ;; *) continue ;; esac
  has_value "$s" && continue
  openssl rand -base64 33 | tr -d '\n' | jq -Rs '{password: .}' >"$KEYS/value.json"
  aws secretsmanager put-secret-value --secret-id "$s" --secret-string "file://$KEYS/value.json" >/dev/null
  echo "loaded $s"
done
rm -rf "$KEYS"
echo "infra-instance: $NAME applied"
