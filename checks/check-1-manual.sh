#!/usr/bin/env bash
# Tool: Manual AWS CLI
# Purpose: Quick baseline check for CCC.VPC.C04 (VPC CIDR + Flow Logs) using AWS CLI
#          with tfstate fallback; helpful for demos and debugging. See docs/drift-detection.md.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

echo "=== 🔍 Manual VPC CIDR and Flow Logs Check (CCC.VPC.C04) ==="

# 1) Load env and map creds for AWS CLI
ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true
export REGION ENABLE_VPC_FLOW_LOGS USE_LOCALSTACK
export AWS_PROFILE=${AWS_PROFILE:-}

# Map Make/Terraform-style creds to AWS CLI env var names when a profile is not supplied
if [[ -z "${AWS_PROFILE:-}" ]]; then
  export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-${AWS_ACCESS_KEY:-}}
  export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-${AWS_SECRET_KEY:-}}
  SESSION_TOKEN=${AWS_SESSION_TOKEN_ID:-${AWS_SESSION_TOKEN:-}}
  if [[ -n "$SESSION_TOKEN" ]]; then
    export AWS_SESSION_TOKEN="$SESSION_TOKEN"
  fi
fi
# 2) Optional LocalStack endpoint (auto-detect if provider uses it)
AWS_ENDPOINT=${AWS_ENDPOINT:-}
if [[ -z "$AWS_ENDPOINT" ]]; then
  if [[ "${USE_LOCALSTACK:-}" == "true" ]]; then
    AWS_ENDPOINT="http://localhost:4566"
  elif [[ -z "${USE_LOCALSTACK:-}" ]] && grep -q "localhost:4566" iac/main.tf 2>/dev/null; then
    AWS_ENDPOINT="http://localhost:4566"
  fi
fi
EP_ARG=()
if [[ -n "$AWS_ENDPOINT" ]]; then
  EP_ARG=(--endpoint-url "$AWS_ENDPOINT")
fi
AWS_ARGS=()
if [[ -n "${AWS_PROFILE:-}" ]]; then
  AWS_ARGS=(--profile "$AWS_PROFILE")
fi
# 3) Resolve VPC ID (tfstate → AWS search)
VPC_ID=""
# 1) Prefer Terraform state output if available
if [[ -f iac/terraform.tfstate ]]; then
  VPC_ID=$(jq -r '.outputs.vpc_id.value // empty' iac/terraform.tfstate 2>/dev/null || true)
  if [[ -z "$VPC_ID" ]]; then
    # Fallback to resource lookup in state
    VPC_ID=$(jq -r '.resources[] | select(.type=="aws_vpc" and .name=="demo") | .instances[0].attributes.id // empty' iac/terraform.tfstate 2>/dev/null || true)
  fi
fi
# 2) If still empty, query AWS by expected CIDR
if [[ -z "$VPC_ID" ]]; then
  VPC_ID=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" \
    --region "$REGION" ec2 describe-vpcs \
    --query "Vpcs[?CidrBlock=='10.42.0.0/16'].VpcId" \
    --output text 2>/dev/null || true)
  [[ "$VPC_ID" == "None" ]] && VPC_ID=""
fi

if [[ -n "$VPC_ID" ]]; then
  echo "✅ VPC with CIDR 10.42.0.0/16 found: $VPC_ID"

  # 4) Check if flow logs exist for this VPC
  FLOW_LOGS=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" \
    --region "$REGION" ec2 describe-flow-logs \
    --query "FlowLogs[?ResourceId=='$VPC_ID']" \
    --output json 2>/dev/null)

  HAS_FLOW_LOGS=false
  if echo "$FLOW_LOGS" | grep -q '"FlowLogId"'; then
    HAS_FLOW_LOGS=true
  fi

  # 5) Fallback: if CLI could not determine, peek Terraform state for aws_flow_log
  if [[ "$HAS_FLOW_LOGS" == false && -f iac/terraform.tfstate ]]; then
    if grep -q '"type":\s*"aws_flow_log"' iac/terraform.tfstate; then
      HAS_FLOW_LOGS=true
    fi
  fi

  # 6) Equivalent CCC.VPC.C04 decision and summary
  if [[ "$HAS_FLOW_LOGS" == true ]]; then
    echo "✅ CCC.VPC.C04: Passed — VPC Flow Logs detected for VPC $VPC_ID"
  else
    # include intent if available
    if [[ -n "${ENABLE_VPC_FLOW_LOGS:-}" ]]; then
      echo "❌ CCC.VPC.C04: Failed — Flow Logs not found for VPC $VPC_ID (intent: ENABLE_VPC_FLOW_LOGS=${ENABLE_VPC_FLOW_LOGS})"
    else
      echo "❌ CCC.VPC.C04: Failed — Flow Logs not found for VPC $VPC_ID"
    fi
  fi

else
  echo "❌ VPC not found. Checked state and AWS (region=$REGION endpoint=${AWS_ENDPOINT:-none})"
fi
