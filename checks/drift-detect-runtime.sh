#!/usr/bin/env bash
# Tool: Drift Detect (Runtime)
# Purpose: Run runtime guard (and optional Prowler), snapshot artifacts, and
#          print a concise drift line comparing runtime vs intended toggles.
#          See docs/drift-detection.md.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

echo "=== 🔁 Detect Runtime Drift (runtime guard + snapshot) ==="

# 1) Load environment for region/toggles
ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true
export REGION=${REGION:-${TF_VAR_REGION:-}}
export ENABLE_VPC_FLOW_LOGS=${ENABLE_VPC_FLOW_LOGS:-${TF_VAR_ENABLE_VPC_FLOW_LOGS:-}}
export USE_LOCALSTACK=${USE_LOCALSTACK:-${TF_VAR_USE_LOCALSTACK:-}}
AWS_PROFILE=${AWS_PROFILE:-${TF_VAR_AWS_PROFILE:-}}

# 2) Timestamped snapshot directory for evidence
ts() { date +"%Y%m%d-%H%M%S"; }
snap_dir="output/drift/$(ts)"
mkdir -p "$snap_dir"

# 3) Run runtime guard (Flow Logs) — tolerate non-zero to continue snapshotting
./checks/runtime-guard.sh || true

# 4) Snapshot artifacts (runtime JSON, tfstate; prowler if present)
cp -f output/runtime/runtime-guard.json "$snap_dir/" 2>/dev/null || true
cp -f iac/terraform.tfstate "$snap_dir/" 2>/dev/null || true
if [[ -d output/terraform ]]; then
  cp -rf output/terraform "$snap_dir/" 2>/dev/null || true
fi

# If prowler is available, run a focused check and snapshot
if command -v prowler >/dev/null 2>&1; then
  mkdir -p output/prowler
  PROWLER_ARGS=(aws --region "${REGION}" --check vpc_flow_logs_enabled --output-formats html json-asff --output-directory ./output/prowler)
  if [[ -n "$AWS_PROFILE" ]]; then
    PROWLER_ARGS+=(--profile "${AWS_PROFILE}")
  fi
  prowler "${PROWLER_ARGS[@]}" >/dev/null 2>&1 || true
  if [[ -d output/prowler ]]; then
    cp -rf output/prowler "$snap_dir/" 2>/dev/null || true
  fi
fi

# 5) Print concise drift summary from the guard JSON
if [[ -f output/runtime/runtime-guard.json ]] && command -v jq >/dev/null 2>&1; then
  FLOW_EXPECT=$(jq -r '.checks["CCC.VPC.C04"].expected.enable_flow_logs // .expected_enable_flow_logs // "unknown"' output/runtime/runtime-guard.json 2>/dev/null || echo unknown)
  FLOW_HAS=$(jq -r '.checks["CCC.VPC.C04"].observed.has_flow_logs // .has_flow_logs // false' output/runtime/runtime-guard.json 2>/dev/null || echo false)
  FLOW_STATUS=$(jq -r '.checks["CCC.VPC.C04"].status // .flow_logs_status // "Unknown"' output/runtime/runtime-guard.json 2>/dev/null || echo Unknown)
  VPC=$(jq -r '.vpc_id // ""' output/runtime/runtime-guard.json 2>/dev/null || echo "")

  if [[ "$FLOW_STATUS" == "Unknown" ]]; then
    echo "⚠️  Flow Logs status unknown (expected=$FLOW_EXPECT, message=$(jq -r '.checks[\"CCC.VPC.C04\"].message // .flow_logs_message // ""' output/runtime/runtime-guard.json))"
  elif [[ "$FLOW_EXPECT" == "true" && "$FLOW_HAS" != "true" ]]; then
    echo "❗ Drift: Flow Logs expected=true but missing at runtime (VPC=$VPC)"
  elif [[ "$FLOW_EXPECT" == "false" && "$FLOW_HAS" == "true" ]]; then
    echo "❗ Drift: Flow Logs disabled in intent but enabled at runtime (VPC=$VPC)"
  else
    echo "No Flow Logs drift detected (expected=$FLOW_EXPECT, has_flow_logs=$FLOW_HAS, status=$FLOW_STATUS, VPC=$VPC)"
  fi

  ENC_EXPECT=$(jq -r '.checks["CCC.C02"].expected.enable_sample_encrypted_bucket // "false"' output/runtime/runtime-guard.json 2>/dev/null || echo false)
  ENC_STATUS=$(jq -r '.checks["CCC.C02"].status // "Unknown"' output/runtime/runtime-guard.json 2>/dev/null || echo Unknown)
  ENC_MESSAGE=$(jq -r '.checks["CCC.C02"].message // ""' output/runtime/runtime-guard.json 2>/dev/null || echo "")
  ENC_FAILED_BUCKETS=$(jq -r '[.checks["CCC.C02"].observed.buckets[]? | select(.status=="Fail") | .bucket | select(length>0)] | join(",")' output/runtime/runtime-guard.json 2>/dev/null || echo "")

  if [[ "$ENC_EXPECT" == "true" ]]; then
    if [[ "$ENC_STATUS" == "Unknown" ]]; then
      echo "⚠️  Unable to confirm S3 encryption (message=$ENC_MESSAGE)"
    elif [[ "$ENC_STATUS" == "Fail" ]]; then
      if [[ -n "$ENC_FAILED_BUCKETS" ]]; then
        echo "❗ Drift: Required S3 encryption missing for bucket(s): $ENC_FAILED_BUCKETS"
      else
        echo "❗ Drift: $ENC_MESSAGE"
      fi
    else
      echo "No S3 encryption drift detected (status=$ENC_STATUS, message=$ENC_MESSAGE)"
    fi
  else
    echo "S3 encryption drift check skipped (enable_sample_encrypted_bucket=$ENC_EXPECT)"
  fi

  SUBNET_STATUS=$(jq -r '.checks["CCC.VPC.C02"].status // .public_subnet_status // "Unknown"' output/runtime/runtime-guard.json 2>/dev/null || echo Unknown)
  SUBNET_MESSAGE=$(jq -r '.checks["CCC.VPC.C02"].message // .public_subnet_message // ""' output/runtime/runtime-guard.json 2>/dev/null || echo "")
  SUBNET_EXPECT=$(jq -r '.expected_map_public_ip_on_launch // "unknown"' output/runtime/runtime-guard.json 2>/dev/null || echo unknown)
  SUBNET_ID=$(jq -r '.public_subnet_id // ""' output/runtime/runtime-guard.json 2>/dev/null || echo "")

  if [[ "$SUBNET_STATUS" == "Unknown" ]]; then
    echo "⚠️  Public subnet status unknown (message=$SUBNET_MESSAGE)"
  elif [[ "$SUBNET_STATUS" == "Fail" ]]; then
    actual=$(jq -r '.map_public_ip_on_launch' output/runtime/runtime-guard.json 2>/dev/null || echo null)
    if [[ "$actual" != "true" && "$actual" != "false" ]]; then
      actual="unknown"
    fi
    echo "❗ Drift: MapPublicIpOnLaunch=$actual (expected $SUBNET_EXPECT) [${SUBNET_ID:-unknown}]"
  else
    echo "No public subnet drift detected (status=$SUBNET_STATUS, message=$SUBNET_MESSAGE)"
  fi
else
  echo "ℹ️  No runtime artifact found to summarize."
fi

echo "📦 Snapshot: $snap_dir"
