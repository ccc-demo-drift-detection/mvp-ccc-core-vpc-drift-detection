#!/usr/bin/env bash
# Tool: Privateer (IaC)
# Purpose: Evaluate CCC controls against Terraform intent/state (no AWS API),
#          produce CCC-mapped results, and optionally gate CI. See docs/drift-detection.md.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

echo "🔍 Running Privateer check for VPC CCC alignment..."

# 1) Load environment for plugin vars (region/toggles) — no AWS calls here

# Load env for plugin variables (REGION, ENABLE_VPC_FLOW_LOGS) if present
ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true
export REGION ENABLE_VPC_FLOW_LOGS APPROVED_DEPLOYMENT_REGIONS_CSV \
       ENABLE_SAMPLE_ENCRYPTED_BUCKET ENABLE_UNENCRYPTED_BUCKET \
       ALLOWED_INGRESS_CIDRS_CSV ALLOWED_INGRESS_IPV6_CIDRS_CSV \
       ALLOWED_INGRESS_SECURITY_GROUPS_CSV \
       ALLOWED_REPLICATION_ACCOUNTS_CSV ALLOWED_REPLICATION_BUCKETS_CSV \
       ALLOWED_REPLICATION_REGIONS_CSV AWS_PROFILE || true

# Harmonise control-filter env vars for Privateer + summaries
CONTROL_FILTER_RAW=${CONTROL_FILTER:-${CONTROLS_FILTER_CSV:-}}
if [ -n "${CONTROL_FILTER_RAW:-}" ] && [ -z "${CONTROLS_FILTER_CSV:-}" ]; then
  export CONTROLS_FILTER_CSV="$CONTROL_FILTER_RAW"
fi

if command -v jq >/dev/null 2>&1; then
  if [ -n "${CONTROL_FILTER_RAW:-}" ]; then
    FILTER_JSON=$(printf '%s' "$CONTROL_FILTER_RAW" | jq -Rc 'split(",") | map(gsub("^\\s+|\\s+$"; "") | ascii_upcase) | map(select(. != ""))')
  else
    FILTER_JSON='[]'
  fi
else
  FILTER_JSON='[]'
fi

mkdir -p output

# 2) Primary path: Privateer via go-plugin RPC
if ! OUT=$(privateer run \
  --config ./plugins/plugin-ccc-vpc/ccc-yaml/config.yml \
  --write \
  --silent \
  --loglevel error \
  --test-suites default 2>&1); then
  echo "$OUT" | tee output/iac-guard-report.txt
  # 3) Fallback for sandboxed environments that block plugin RPC sockets
  if echo "$OUT" | grep -qiE "setsockopt: operation not permitted|Unrecognized remote plugin message|failed to negotiate"; then
    echo "⚠️  RPC blocked; falling back to direct plugin debug mode..."
    if command -v vpc >/dev/null 2>&1; then
      vpc debug \
        --config ./plugins/plugin-ccc-vpc/ccc-yaml/config.yml \
        --service ccc-vpc \
        --write \
        --silent \
        --loglevel error \
        --test-suites default \
        | tee output/iac-guard-report.txt || true
    else
      if [ -x "$HOME/.privateer/bin/vpc" ]; then
        "$HOME/.privateer/bin/vpc" debug \
          --config ./plugins/plugin-ccc-vpc/ccc-yaml/config.yml \
          --service ccc-vpc \
          --write \
          --silent \
          --loglevel error \
          --test-suites default \
          | tee output/iac-guard-report.txt || true
      else
        echo "❌ vpc plugin binary not found in PATH or ~/.privateer/bin" | tee -a output/iac-guard-report.txt
      fi
    fi
  else
    echo "❌ Privateer run failed; see above output" | tee -a output/iac-guard-report.txt
  fi
else
  echo "$OUT" | tee output/iac-guard-report.txt
fi

echo "✅ Privateer check complete. Output saved to output/iac-guard-report.txt"

# 4) Simple human summary for Flow Logs (CCC.VPC.C04)
if [ -f output/ccc-vpc/ccc-vpc.log ] || [ -f output/ccc-vpc/ccc-vpc.yaml ] || [ -f output/ccc-vpc/ccc-vpc.json ]; then
  if command -v rg >/dev/null 2>&1; then
    SEARCH_CMD="rg -q"
  else
    SEARCH_CMD="grep -R -q"
  fi
  if ${SEARCH_CMD} "VPC Flow Logs detected" output/ccc-vpc/* 2>/dev/null || \
     ${SEARCH_CMD} "present in Terraform plan" output/ccc-vpc/* 2>/dev/null; then
    echo "✅ CCC.VPC.C04: Flow Logs ENABLED (detected in Terraform state)"
  elif ${SEARCH_CMD} "aws_flow_log resource" output/ccc-vpc/* 2>/dev/null; then
    echo "❌ CCC.VPC.C04: Flow Logs MISSING (no aws_flow_log in Terraform state)"
  else
    echo "ℹ️  CCC.VPC.C04: No flow-logs signal found; see output/ccc-vpc/ for details"
  fi
fi

# 5) Detailed per-test summary and optional CI gate (IAC_GUARD_STRICT)
STRICT=${IAC_GUARD_STRICT:-true}
RESULT_DIR=output/ccc-vpc
RESULT_JSON="$RESULT_DIR/ccc-vpc.json"
RESULT_YAML="$RESULT_DIR/ccc-vpc.yaml"

if [ -f "$RESULT_JSON" ] && command -v jq >/dev/null 2>&1; then
  echo "\n=== Per-test results (from JSON) ==="
  jq --argjson filter_ids "$FILTER_JSON" -r '
    def include_control($id):
      ( $filter_ids | length ) == 0
      or (
        ($id // "") as $raw
        | ($raw | ascii_upcase) as $upper
        | ($upper != "" and ($filter_ids | index($upper)) != null)
      );
    def suites: (.evaluation_suites // .Evaluation_Suites // []);
    def ctrls(x): (x.control_evaluations // x.Control_Evaluations // []);
    def asmt(x): (x.assessments // x.Assessments // []);
    def cid(x): (x.control_id // x.Control_Id // "");
    def rid(x): (x.requirement_id // x.Requirement_Id // "");
    def res(x): (x.result // x.Result // "");
    def msg(x): (x.message // x.Message // "");
    suites[]? | . as $s | ctrls($s)[]? as $c |
    select(include_control(cid($c))) |
    asmt($c)[]? as $a |
    "\(cid($c)) \(rid($a)): \(res($a)) - \(msg($a))"
  ' "$RESULT_JSON" || true
  FAILS=$(jq --argjson filter_ids "$FILTER_JSON" -r '
    def include_control($id):
      ( $filter_ids | length ) == 0
      or (
        ($id // "") as $raw
        | ($raw | ascii_upcase) as $upper
        | ($upper != "" and ($filter_ids | index($upper)) != null)
      );
    def suites: (.evaluation_suites // .Evaluation_Suites // []);
    def ctrls(x): (x.control_evaluations // x.Control_Evaluations // []);
    def asmt(x): (x.assessments // x.Assessments // []);
    def res(x): (x.result // x.Result // "");
    [ suites[]? | ctrls(.)[]? | select(include_control((.control_id // .Control_Id // ""))) | asmt(.)[]? | select(res(.)=="Failed") ] | length
  ' "$RESULT_JSON" 2>/dev/null || echo 0)
  WARNS=$(jq --argjson filter_ids "$FILTER_JSON" -r '
    def include_control($id):
      ( $filter_ids | length ) == 0
      or (
        ($id // "") as $raw
        | ($raw | ascii_upcase) as $upper
        | ($upper != "" and ($filter_ids | index($upper)) != null)
      );
    def suites: (.evaluation_suites // .Evaluation_Suites // []);
    def ctrls(x): (x.control_evaluations // x.Control_Evaluations // []);
    def asmt(x): (x.assessments // x.Assessments // []);
    def res(x): (x.result // x.Result // "");
    [ suites[]? | ctrls(.)[]? | select(include_control((.control_id // .Control_Id // ""))) | asmt(.)[]? | select(res(.)=="Warning") ] | length
  ' "$RESULT_JSON" 2>/dev/null || echo 0)
  echo "Summary: Failed=$FAILS Warning=$WARNS"
  if [ "$STRICT" = true ] && [ "$FAILS" -gt 0 ]; then
    echo "❌ One or more controls Failed — exiting 1 (IAC_GUARD_STRICT=true)"
    exit 1
  fi
elif [ -f "$RESULT_YAML" ]; then
  echo "\n=== Per-test results (from YAML; simple grep) ==="
  # Fallback: print requirement/result/message lines grouped
  awk '/control_id:/{cid=$2} /requirement_id:/{rid=$2} /result:/{res=$2} /message:/{msg=substr($0,index($0,$2)); printf("%s %s: %s - %s\n", cid, rid, res, msg)}' "$RESULT_YAML" || true
  FAILS=$(grep -c "result: Failed" "$RESULT_YAML" || true)
  WARNS=$(grep -c "result: Warning" "$RESULT_YAML" || true)
  echo "Summary: Failed=$FAILS Warning=$WARNS"
  if [ "$STRICT" = true ] && [ "$FAILS" -gt 0 ]; then
    echo "❌ One or more controls Failed — exiting 1 (IAC_GUARD_STRICT=true)"
    exit 1
  fi
fi
