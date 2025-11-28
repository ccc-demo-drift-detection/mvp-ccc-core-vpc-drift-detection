#!/usr/bin/env bash
# Tool: Privateer (IaC)
# Purpose: Convenience wrapper to run the Privateer plugin and write results
#          mapped to CCC controls from Terraform state/plan. See docs/drift-detection.md.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

CONTROL_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--control)
      if [[ $# -lt 2 ]]; then
        echo "--control flag requires a value" >&2
        exit 1
      fi
      CONTROL_FILTER="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

export CONTROL_FILTER

echo "=== 🔍 Privateer Guard Check ==="
echo "🔍 Running Privateer check for VPC CCC alignment..."

# Source ENV_FILE for plugin variables (mirrors iac-guard.sh)
ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true
export REGION ENABLE_VPC_FLOW_LOGS APPROVED_DEPLOYMENT_REGIONS_CSV \
       ENABLE_SAMPLE_ENCRYPTED_BUCKET ENABLE_UNENCRYPTED_BUCKET \
       ENFORCE_MFA_DEMO_ADMIN_ROLE ENABLE_CORE_AUDIT_LOGS \
       ALLOWED_INGRESS_CIDRS_CSV ALLOWED_INGRESS_IPV6_CIDRS_CSV \
       ALLOWED_INGRESS_SECURITY_GROUPS_CSV AWS_PROFILE \
       ENABLE_REPLICATION_DEMO REPLICATION_DESTINATION_REGION \
       ALLOWED_REPLICATION_ACCOUNTS_CSV ALLOWED_REPLICATION_BUCKETS_CSV \
       ALLOWED_REPLICATION_REGIONS_CSV ENABLE_CMEK_DEMO \
       ENFORCE_CMEK_ROTATION REQUIRE_KMS_ENCRYPTION REQUIRE_CMEK_ROTATION \
       CCC_C01_ALLOW_WORLD_TLS_INGRESS CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS || true

if [[ -n "$CONTROL_FILTER" ]]; then
  echo "🎯 Control filter: $CONTROL_FILTER"
fi

# Forward run to Privateer (writes CCC-mapped results to output/ccc-vpc)
CMD=(privateer run \
  --config ./plugins/plugin-ccc-vpc/ccc-yaml/config.yml \
  --write \
  --silent \
  --loglevel error \
  --test-suites default)

RUN_CMD=("${CMD[@]}")
if [[ -n "$CONTROL_FILTER" ]]; then
  RUN_CMD=(env CONTROLS_FILTER_CSV="$CONTROL_FILTER" "${RUN_CMD[@]}")
fi

OUT=$("${RUN_CMD[@]}" 2>&1 || true)

echo "$OUT" | tee output/iac-guard-report.txt

RESULT_JSON=output/ccc-vpc/ccc-vpc.json
if [[ -f "$RESULT_JSON" ]]; then
  PYTHON=${PYTHON:-python3}
SUMMARY=$($PYTHON - <<'PY'
import json, os
from pathlib import Path

path = Path('output/ccc-vpc/ccc-vpc.json')
data = json.loads(path.read_text()) if path.exists() else {}
suites = data.get('Evaluation_Suites') or data.get('evaluation_suites') or []

filter_raw = os.environ.get('CONTROL_FILTER', '') or os.environ.get('CONTROLS_FILTER_CSV', '')
filter_set = {item.strip().upper() for item in filter_raw.split(',') if item.strip()}

failed = []
needs_review = []

def should_check(control_id: str) -> bool:
    if not control_id:
        return False
    if not filter_set:
        return True
    return control_id.upper() in filter_set

for suite in suites:
    evaluations = suite.get('Control_Evaluations') or suite.get('control_evaluations') or []
    for ctrl in evaluations:
        cid = (ctrl.get('Control_Id') or ctrl.get('control_id') or '').strip()
        if not should_check(cid):
            continue
        result = (ctrl.get('Result') or ctrl.get('result') or '').strip()
        if result in ('Not Run', ''):
            continue
        message = ctrl.get('Message') or ctrl.get('message') or ''
        if result == 'Failed':
            failed.append((cid, message))
        elif result in ('Needs Review', 'Unknown'):
            needs_review.append((cid, message))

if failed:
    print('FAIL')
    for cid, msg in failed:
        print(f"{cid}: {msg}")
elif needs_review:
    print('WARN')
    for cid, msg in needs_review:
        print(f"{cid}: {msg}")
else:
    print('PASS')
PY
  )
  STATUS=$(echo "$SUMMARY" | head -n1)
  DETAILS=$(echo "$SUMMARY" | tail -n +2)
  case "$STATUS" in
    FAIL)
      echo "❌ Control failures detected:"; echo "$DETAILS"
      ;;
    WARN)
      echo "⚠️ Controls need review:"; echo "$DETAILS"
      ;;
    PASS)
      echo "✅ All required guardrails passed."
      ;;
    *)
      echo "ℹ️ Privateer run complete; check $RESULT_JSON for details."
      ;;
  esac
else
  # Heuristic summary when structured output is missing (e.g., run failed early)
  if echo "$OUT" | grep -q "missing.*aws_flow_log"; then
    echo "❌ Flow logs missing (as expected if disabled)"
  elif echo "$OUT" | grep -q "no plugins were requested"; then
    echo "❌ Privateer failed: No plugin was requested or configured properly"
  else
    echo "ℹ️ Privateer run complete; structured results not found."
  fi
fi
