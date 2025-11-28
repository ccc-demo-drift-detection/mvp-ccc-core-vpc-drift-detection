#!/usr/bin/env bash
# Tool: Drift Simulation (Runtime)
# Purpose: Simulate drift for selected CCC controls by mutating AWS resources out-of-band.
#          Default control is CCC.VPC.C04 (Flow Logs), but additional controls can be
#          specified via CONTROLS=CCC.C02,CCC.C03,CCC.VPC.C02,...
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true
AWS_ENDPOINT=${AWS_ENDPOINT:-}
REGION=${REGION:-${TF_VAR_REGION:-}}
USE_LOCALSTACK=${USE_LOCALSTACK:-${TF_VAR_USE_LOCALSTACK:-}}
AWS_PROFILE=${AWS_PROFILE:-${TF_VAR_AWS_PROFILE:-}}
export REGION USE_LOCALSTACK AWS_PROFILE

if [[ -z "${AWS_PROFILE:-}" ]]; then
  export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-${AWS_ACCESS_KEY:-}}
  export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-${AWS_SECRET_KEY:-}}
  SESSION_TOKEN=${AWS_SESSION_TOKEN_ID:-${AWS_SESSION_TOKEN:-}}
  if [[ -n "$SESSION_TOKEN" ]]; then
    export AWS_SESSION_TOKEN="$SESSION_TOKEN"
  fi
fi

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

require_tool() {
  local cmd=$1
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "❌ Required command '$cmd' not found." >&2
    exit 1
  fi
}

require_tool jq

resolve_vpc_id() {
  local vpc=""
  if [[ -f iac/terraform.tfstate ]]; then
    vpc=$(jq -r '.outputs.vpc_id.value // empty' iac/terraform.tfstate 2>/dev/null || true)
  fi
  if [[ -z "$vpc" ]]; then
    vpc=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" --region "$REGION" ec2 describe-vpcs \
      --query "Vpcs[?CidrBlock=='10.42.0.0/16'].VpcId" --output text 2>/dev/null || true)
    [[ "$vpc" == "None" ]] && vpc=""
  fi
  echo "$vpc"
}

resolve_encrypted_bucket() {
  if [[ -f iac/terraform.tfstate ]]; then
    jq -r '.resources[]? | select(.type=="aws_s3_bucket" and .name=="encrypted") |
      .instances[0].attributes.bucket // empty' iac/terraform.tfstate 2>/dev/null | head -n1
  fi
}

resolve_demo_admin_role() {
  if [[ -f iac/terraform.tfstate ]]; then
    jq -r '.resources[]? | select(.type=="aws_iam_role" and .name=="demo_admin") |
      .instances[0].attributes.name // "ccc-demo-admin"' iac/terraform.tfstate 2>/dev/null | head -n1
  fi
}

resolve_public_subnet() {
  if [[ -f iac/terraform.tfstate ]]; then
    jq -r '.resources[]? | select(.type=="aws_subnet" and .name=="public") |
      .instances[0].attributes.id // empty' iac/terraform.tfstate 2>/dev/null | head -n1
  fi
}

simulate_flow_logs() {
  echo "=== 🔧 Simulate Drift: CCC.VPC.C04 (remove Flow Logs) ==="
  local vpc_id
  vpc_id=$(resolve_vpc_id)
  if [[ -z "$vpc_id" ]]; then
    echo "❌ VPC not found; cannot remove Flow Logs." >&2
    return 1
  fi
  local flow_ids
  flow_ids=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" --region "$REGION" ec2 describe-flow-logs \
    --query "FlowLogs[?ResourceId=='$vpc_id'].FlowLogId" --output text 2>/dev/null || true)
  if [[ -z "$flow_ids" || "$flow_ids" == "None" ]]; then
    echo "ℹ️  No Flow Logs found for $vpc_id; nothing to delete."
    return 0
  fi
  for fid in $flow_ids; do
    [[ -z "$fid" ]] && continue
    echo " - Deleting Flow Log $fid"
    aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" --region "$REGION" ec2 delete-flow-logs --flow-log-ids "$fid" >/dev/null 2>&1 || true
  done
  echo "✅ Drift simulated for CCC.VPC.C04 (Flow Logs removed)."
}

simulate_s3_encryption() {
  echo "=== 🔧 Simulate Drift: CCC.C02 (remove S3 bucket encryption) ==="
  local bucket
  bucket=$(resolve_encrypted_bucket)
  if [[ -z "$bucket" ]]; then
    echo "❌ Encrypted bucket not found in state; cannot simulate." >&2
    return 1
  fi
  local tmp
  tmp=$(mktemp)
  cat >"$tmp" <<'JSON'
{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }
  ]
}
JSON
  echo " - Overwriting encryption configuration for bucket $bucket (forcing AES256)"
  aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" --region "$REGION" \
    s3api put-bucket-encryption \
    --bucket "$bucket" \
    --server-side-encryption-configuration "file://$tmp" >/dev/null 2>&1 || true
  rm -f "$tmp"
  echo "✅ Drift simulated for CCC.C02 (bucket encryption downgraded to AES256)."
}

simulate_iam_mfa() {
  echo "=== 🔧 Simulate Drift: CCC.C03 (remove MFA enforcement) ==="
  local role policy current document temp_file
  role=$(resolve_demo_admin_role)
  [[ -z "$role" ]] && role="ccc-demo-admin"
  policy="ccc-demo-admin-policy"
  temp_file=$(mktemp)
  if ! aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" iam get-role-policy --role-name "$role" --policy-name "$policy" >/dev/null 2>&1; then
    echo "❌ Unable to retrieve inline policy for role $role; skipping CCC.C03." >&2
    rm -f "$temp_file"
    return 1
  fi
  current=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" iam get-role-policy --role-name "$role" --policy-name "$policy" \
    --query 'PolicyDocument' --output text 2>/dev/null || true)
  if [[ -z "$current" ]]; then
    echo "ℹ️  Policy document empty; nothing to modify."
    rm -f "$temp_file"
    return 0
  fi
  require_tool jq
  printf '%s\n' "$current" | jq '
    .Statement |= (
      if type=="array" then
        [ .[] | select(.Sid != "DenyWithoutMFA") ]
      else
        .
      end
    )
  ' > "$temp_file"
  echo " - Updating role policy for $role (removing DenyWithoutMFA)"
  aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" iam put-role-policy --role-name "$role" --policy-name "$policy" \
    --policy-document "file://$temp_file" >/dev/null 2>&1 || true
  rm -f "$temp_file"
  echo "✅ Drift simulated for CCC.C03 (MFA enforcement removed)."
}

simulate_public_ip() {
  echo "=== 🔧 Simulate Drift: CCC.VPC.C02 (enable public IP assignment) ==="
  local subnet
  subnet=$(resolve_public_subnet)
  if [[ -z "$subnet" ]]; then
    echo "❌ Public subnet not found; cannot toggle MapPublicIpOnLaunch." >&2
    return 1
  fi
  echo " - Enabling auto public IP assignment on subnet $subnet"
  aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" --region "$REGION" ec2 modify-subnet-attribute \
    --subnet-id "$subnet" --map-public-ip-on-launch >/dev/null 2>&1 || true
  echo "✅ Drift simulated for CCC.VPC.C02 (public IP auto-assign enabled)."
}

CONTROLS_RAW=${CONTROLS:-${CONTROL:-CCC.VPC.C04}}
IFS=',' read -r -a CONTROL_LIST <<<"$(printf '%s' "$CONTROLS_RAW" | tr -d ' ')"

if [[ ${#CONTROL_LIST[@]} -eq 0 ]]; then
  CONTROL_LIST=("CCC.VPC.C04")
fi

for ctrl in "${CONTROL_LIST[@]}"; do
  case "$(printf '%s' "$ctrl" | tr '[:lower:]' '[:upper:]')" in
    "CCC.VPC.C04")
      simulate_flow_logs
      ;;
    "CCC.C02")
      simulate_s3_encryption
      ;;
    "CCC.C03")
      simulate_iam_mfa
      ;;
    "CCC.VPC.C02")
      simulate_public_ip
      ;;
    *)
      echo "⚠️  Control $ctrl not supported for drift simulation; skipping."
      ;;
  esac
done
