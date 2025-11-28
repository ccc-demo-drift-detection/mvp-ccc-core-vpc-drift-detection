#!/usr/bin/env bash
# Tool: Runtime Guard (Custom AWS CLI)
# Purpose: Targeted runtime check tied to CCC (e.g., CCC.VPC.C04 Flow Logs).
#          Compares runtime to intended IaC/env toggles and emits drift JSON.
#          See docs/drift-detection.md.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

echo "=== 🔎 Runtime Guard (Flow Logs drift) ==="

# 1) Load environment (REGION, toggles) for intent comparison
ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true

export REGION=${REGION:-${TF_VAR_REGION:-}}
export ENABLE_VPC_FLOW_LOGS=${ENABLE_VPC_FLOW_LOGS:-${TF_VAR_ENABLE_VPC_FLOW_LOGS:-}}
export USE_LOCALSTACK=${USE_LOCALSTACK:-${TF_VAR_USE_LOCALSTACK:-}}
PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP=${PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP:-${TF_VAR_PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP:-}}
AWS_PROFILE=${AWS_PROFILE:-${TF_VAR_AWS_PROFILE:-}}

# 2) Map Make/Terraform-style creds to AWS CLI env var names if a profile is not used
if [[ -z "$AWS_PROFILE" ]]; then
  export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-${AWS_ACCESS_KEY:-}}
  export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-${AWS_SECRET_KEY:-}}
  SESSION_TOKEN=${AWS_SESSION_TOKEN_ID:-${AWS_SESSION_TOKEN:-}}
  if [[ -n "$SESSION_TOKEN" ]]; then
    export AWS_SESSION_TOKEN="$SESSION_TOKEN"
  fi
else
  export AWS_PROFILE
fi

# 3) Optional LocalStack endpoint detection for local demos
AWS_ENDPOINT=${AWS_ENDPOINT:-}
if [[ -z "$AWS_ENDPOINT" && "${USE_LOCALSTACK:-}" == "true" ]]; then
  AWS_ENDPOINT="http://localhost:4566"
fi

declare -a EP_ARG=()
if [[ -n "$AWS_ENDPOINT" ]]; then
  EP_ARG=(--endpoint-url "$AWS_ENDPOINT")
fi

declare -a AWS_ARGS=()
if [[ -n "$AWS_PROFILE" ]]; then
  AWS_ARGS=(--profile "$AWS_PROFILE")
fi
mkdir -p output/runtime

# 4) Resolve target VPC ID (prefer Terraform state; fallback to AWS query)
VPC_ID=""
if [[ -f iac/terraform.tfstate ]]; then
  VPC_ID=$(jq -r '.outputs.vpc_id.value // empty' iac/terraform.tfstate 2>/dev/null || true)
  if [[ -z "$VPC_ID" ]]; then
    VPC_ID=$(jq -r '.resources[] | select(.type=="aws_vpc" and .name=="demo") | .instances[0].attributes.id // empty' iac/terraform.tfstate 2>/dev/null || true)
  fi
fi
if [[ -z "$VPC_ID" ]]; then
  VPC_ID=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" \
    --region "$REGION" ec2 describe-vpcs \
    --query "Vpcs[?CidrBlock=='10.42.0.0/16'].VpcId" \
    --output text 2>/dev/null || true)
  [[ "$VPC_ID" == "None" ]] && VPC_ID=""
fi

if [[ -z "$VPC_ID" ]]; then
  echo "❌ VPC not found. Cannot run runtime guard." >&2
  exit 1
fi

# Resolve public subnet ID (if available)
PUBLIC_SUBNET_ID=""
if [[ -f iac/terraform.tfstate ]]; then
  PUBLIC_SUBNET_ID=$(jq -r '.outputs.public_subnet_id.value // empty' iac/terraform.tfstate 2>/dev/null || true)
  if [[ -z "$PUBLIC_SUBNET_ID" ]]; then
    PUBLIC_SUBNET_ID=$(jq -r '.resources[]? | select(.type=="aws_subnet" and .name=="public") | .instances[0].attributes.id // empty' iac/terraform.tfstate 2>/dev/null || true)
  fi
fi

# 5) Check Flow Logs attachment at runtime (AWS is source of truth)
LOCALSTACK_MODE=false
if [[ "${USE_LOCALSTACK:-}" == "true" || "$AWS_ENDPOINT" == http://localhost:4566* ]]; then
  LOCALSTACK_MODE=true
fi

FLOW_JSON=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" \
  --region "$REGION" ec2 describe-flow-logs \
  --query "FlowLogs[?ResourceId=='$VPC_ID']" \
  --output json 2>/dev/null || echo '[]')

HAS_FLOW=false
if echo "$FLOW_JSON" | grep -q '"FlowLogId"'; then
  HAS_FLOW=true
fi

# 6) Intent from config (toggle) for simple drift logic
FLOW_EXPECT=${ENABLE_VPC_FLOW_LOGS:-}
if [[ -z "$FLOW_EXPECT" ]]; then FLOW_EXPECT="unknown"; fi

FLOW_STATUS="Unknown"
FLOW_MSG=""
if [[ "$LOCALSTACK_MODE" == true ]]; then
  FLOW_STATUS="Unknown"
  FLOW_MSG="Flow Log APIs not supported in LocalStack demo"
else
  case "$(printf '%s' "$FLOW_EXPECT" | tr '[:upper:]' '[:lower:]')" in
    "true")
      if [[ "$HAS_FLOW" == true ]]; then
        FLOW_STATUS="Pass"
        FLOW_MSG="Flow Logs present for $VPC_ID"
      else
        FLOW_STATUS="Fail"
        FLOW_MSG="Flow Logs NOT present for $VPC_ID (drift: expected enabled)"
      fi
      ;;
    "false")
      if [[ "$HAS_FLOW" == true ]]; then
        FLOW_STATUS="Fail"
        FLOW_MSG="Flow Logs present for $VPC_ID (drift: expected disabled)"
      else
        FLOW_STATUS="Pass"
        FLOW_MSG="Flow Logs disabled for $VPC_ID as intended"
      fi
      ;;
    *)
      if [[ "$HAS_FLOW" == true ]]; then
        FLOW_STATUS="Pass"
        FLOW_MSG="Flow Logs present for $VPC_ID (no expectation set)"
      else
        FLOW_STATUS="Unknown"
        FLOW_MSG="Flow Logs status unknown for $VPC_ID (no expectation set)"
      fi
      ;;
  esac
fi

echo "VPC: $VPC_ID (region=$REGION endpoint=${AWS_ENDPOINT:-none})"
echo "Expected (ENABLE_VPC_FLOW_LOGS): $FLOW_EXPECT"
echo "Result: $FLOW_STATUS - $FLOW_MSG"

# 6b) Check public subnet auto-assign (CCC.VPC.C02)
PUBLIC_SUBNET_EXPECT=$(printf '%s' "${PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP:-}" | tr '[:upper:]' '[:lower:]')
if [[ "$PUBLIC_SUBNET_EXPECT" != "true" && "$PUBLIC_SUBNET_EXPECT" != "false" ]]; then
  PUBLIC_SUBNET_EXPECT="unknown"
fi

SUBNET_STATUS="Unknown"
SUBNET_MSG=""
SUBNET_ACTUAL_VALUE="unknown"
if [[ "$LOCALSTACK_MODE" == true ]]; then
  SUBNET_STATUS="Unknown"
  SUBNET_MSG="Subnet APIs not supported in LocalStack demo"
elif [[ -z "$PUBLIC_SUBNET_ID" ]]; then
  SUBNET_STATUS="Unknown"
  SUBNET_MSG="Public subnet ID not found in Terraform state"
else
  set +e
  SUBNET_ACTUAL=$(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}" \
    --region "$REGION" ec2 describe-subnets \
    --subnet-ids "$PUBLIC_SUBNET_ID" \
    --query "Subnets[0].MapPublicIpOnLaunch" \
    --output text 2>/dev/null)
  rc=$?
  set -e
  if [[ $rc -ne 0 || -z "$SUBNET_ACTUAL" || "$SUBNET_ACTUAL" == "None" ]]; then
    SUBNET_STATUS="Unknown"
    SUBNET_MSG="Unable to query MapPublicIpOnLaunch for subnet $PUBLIC_SUBNET_ID"
  else
    SUBNET_ACTUAL_VALUE=$(printf '%s' "$SUBNET_ACTUAL" | tr '[:upper:]' '[:lower:]')
    if [[ "$SUBNET_ACTUAL_VALUE" != "true" && "$SUBNET_ACTUAL_VALUE" != "false" ]]; then
      SUBNET_STATUS="Unknown"
      SUBNET_MSG="Unexpected MapPublicIpOnLaunch value: $SUBNET_ACTUAL (subnet $PUBLIC_SUBNET_ID)"
    elif [[ "$PUBLIC_SUBNET_EXPECT" == "unknown" ]]; then
      SUBNET_STATUS="Unknown"
      SUBNET_MSG="MapPublicIpOnLaunch=$SUBNET_ACTUAL_VALUE for subnet $PUBLIC_SUBNET_ID (no intent set)"
    elif [[ "$SUBNET_ACTUAL_VALUE" == "$PUBLIC_SUBNET_EXPECT" ]]; then
      SUBNET_STATUS="Pass"
      SUBNET_MSG="MapPublicIpOnLaunch=$SUBNET_ACTUAL_VALUE for subnet $PUBLIC_SUBNET_ID"
    else
      SUBNET_STATUS="Fail"
      SUBNET_MSG="MapPublicIpOnLaunch=$SUBNET_ACTUAL_VALUE (expected $PUBLIC_SUBNET_EXPECT) for subnet $PUBLIC_SUBNET_ID"
    fi
  fi
fi

echo "Public Subnet: ${PUBLIC_SUBNET_ID:-unknown}"
echo "Expected (PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP): $PUBLIC_SUBNET_EXPECT"
echo "Result (CCC.VPC.C02): $SUBNET_STATUS - $SUBNET_MSG"

# 7) Runtime checks for CCC.C02 (S3 encryption)
ENABLE_SAMPLE_ENCRYPTED_BUCKET=${ENABLE_SAMPLE_ENCRYPTED_BUCKET:-${TF_VAR_ENABLE_SAMPLE_ENCRYPTED_BUCKET:-false}}
REQUIRE_KMS_ENCRYPTION=${REQUIRE_KMS_ENCRYPTION:-${TF_VAR_REQUIRE_KMS_ENCRYPTION:-true}}

declare -a encrypted_bucket_names=()
if [[ -f iac/terraform.tfstate ]]; then
  mapfile -t encrypted_bucket_names < <(
    jq -r '.resources[] | select(.type=="aws_s3_bucket" and .name=="encrypted") |
      (.instances[]? | .attributes.bucket // empty)' iac/terraform.tfstate 2>/dev/null | sed '/^$/d'
  ) || true
fi

declare -a bucket_entries=()
declare -a bucket_failures=()
declare -i bucket_pass_count=0
declare -i bucket_total=0

evaluate_encrypted_bucket() {
  local bucket_name=$1
  local require_kms=$2

  bucket_total+=1
  local status="Unknown"
  local message=""
  local algorithm=""
  local kms_key=""

  if [[ -z "$bucket_name" ]]; then
    status="Unknown"
    message="Bucket name not found in Terraform state"
  else
    local enc_output
    local cmd=(aws "${AWS_ARGS[@]}" "${EP_ARG[@]}")
    if [[ -n "${REGION:-}" ]]; then
      cmd+=(--region "$REGION")
    fi
    cmd+=(s3api get-bucket-encryption --bucket "$bucket_name")
    set +e
    enc_output=$("${cmd[@]}" 2>&1)
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      if [[ "$LOCALSTACK_MODE" == true ]]; then
        status="Unknown"
        message="Skipped (LocalStack does not report bucket encryption reliably)"
      elif grep -qi "Could not connect" <<<"$enc_output" || grep -qi "RequestError" <<<"$enc_output" || grep -qi "connection" <<<"$enc_output"; then
        status="Unknown"
        message="Unable to reach S3 API to confirm encryption (network/endpoint unavailable)"
      else
        status="Fail"
        message="Failed to query bucket encryption: ${enc_output:-unknown error}"
      fi
    else
      local enc_json="$enc_output"
      algorithm=$(echo "$enc_json" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // empty')
      kms_key=$(echo "$enc_json" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID // empty')
      if [[ -z "$algorithm" ]]; then
        status="Fail"
        message="Encryption configuration missing algorithm"
      elif [[ "$require_kms" == "true" && "$algorithm" != "aws:kms" ]]; then
        status="Fail"
        message="Expected aws:kms encryption but found $algorithm"
      elif [[ "$require_kms" == "true" && -z "$kms_key" ]]; then
        status="Fail"
        message="Expected KMS CMK but none reported"
      else
        status="Pass"
        message="Server-side encryption enforced (${algorithm})"
      fi
    fi
  fi

  if [[ "$status" == "Fail" ]]; then
    bucket_failures+=("$bucket_name")
  elif [[ "$status" == "Pass" ]]; then
    bucket_pass_count+=1
  fi

  bucket_entries+=(
    "$(jq -n --arg bucket "$bucket_name" --arg status "$status" --arg message "$message" \
             --arg algorithm "$algorithm" --arg kms "$kms_key" '{bucket: $bucket, status: $status, message: $message, algorithm: ($algorithm // ""), kms_key: ($kms // "")}')"
  )
}

if [[ "$ENABLE_SAMPLE_ENCRYPTED_BUCKET" == "true" ]]; then
  if [[ ${#encrypted_bucket_names[@]} -eq 0 ]]; then
    evaluate_encrypted_bucket "" "$REQUIRE_KMS_ENCRYPTION"
  else
    for bucket in "${encrypted_bucket_names[@]}"; do
      evaluate_encrypted_bucket "$bucket" "$REQUIRE_KMS_ENCRYPTION"
    done
  fi
fi

ENCRYPTION_STATUS="Unknown"
ENCRYPTION_MSG="No encrypted bucket expectations to evaluate"

if [[ $bucket_total -gt 0 ]]; then
  if [[ ${#bucket_failures[@]} -gt 0 ]]; then
    ENCRYPTION_STATUS="Fail"
    ENCRYPTION_MSG="Buckets missing required encryption: $(IFS=,; echo "${bucket_failures[*]}")"
  elif [[ $bucket_pass_count -gt 0 && $bucket_pass_count -eq $bucket_total ]]; then
    ENCRYPTION_STATUS="Pass"
    ENCRYPTION_MSG="All expected buckets enforce required encryption"
  else
    ENCRYPTION_STATUS="Unknown"
    ENCRYPTION_MSG="Unable to confirm encryption for expected buckets"
  fi
fi

bucket_results_json="[]"
if [[ ${#bucket_entries[@]} -gt 0 ]]; then
  bucket_results_json=$(printf '%s\n' "${bucket_entries[@]}" | jq -s '.')
fi

# 8) Write machine-readable artifact for summarizers/diff tools
flow_has_json=$([[ "$HAS_FLOW" == true ]] && echo true || echo false)
if [[ "$SUBNET_ACTUAL_VALUE" == "true" ]]; then
  subnet_actual_json=true
elif [[ "$SUBNET_ACTUAL_VALUE" == "false" ]]; then
  subnet_actual_json=false
else
  subnet_actual_json=null
fi

jq -n \
  --arg region "$REGION" \
  --arg endpoint "${AWS_ENDPOINT:-}" \
  --arg vpc "$VPC_ID" \
  --arg expected_flow "$FLOW_EXPECT" \
  --arg flow_status "$FLOW_STATUS" \
  --arg flow_message "$FLOW_MSG" \
  --arg encryption_status "$ENCRYPTION_STATUS" \
  --arg encryption_message "$ENCRYPTION_MSG" \
  --arg enable_sample_encrypted_bucket "$ENABLE_SAMPLE_ENCRYPTED_BUCKET" \
  --arg require_kms "$REQUIRE_KMS_ENCRYPTION" \
  --argjson has_flow "$flow_has_json" \
  --arg public_subnet_id "${PUBLIC_SUBNET_ID:-}" \
  --arg public_subnet_expect "$PUBLIC_SUBNET_EXPECT" \
  --arg public_subnet_status "$SUBNET_STATUS" \
  --arg public_subnet_message "$SUBNET_MSG" \
  --argjson public_subnet_actual "$subnet_actual_json" \
  --argjson buckets "$bucket_results_json" \
  '"ccc-runtime-guard" as $schema |
   {
     schema: $schema,
     region: $region,
     endpoint: $endpoint,
     vpc_id: $vpc,
     expected_enable_flow_logs: $expected_flow,
     has_flow_logs: $has_flow,
     flow_logs_status: $flow_status,
     flow_logs_message: $flow_message,
     encryption_status: $encryption_status,
     encryption_message: $encryption_message,
     enable_sample_encrypted_bucket: $enable_sample_encrypted_bucket,
     require_kms_encryption: $require_kms,
     public_subnet_id: $public_subnet_id,
     expected_map_public_ip_on_launch: $public_subnet_expect,
     map_public_ip_on_launch: $public_subnet_actual,
     public_subnet_status: $public_subnet_status,
     public_subnet_message: $public_subnet_message,
     checks: {
       "CCC.VPC.C04": {
         control_id: "CCC.VPC.C04",
         status: $flow_status,
         message: $flow_message,
         expected: { enable_flow_logs: $expected_flow },
         observed: { has_flow_logs: $has_flow, vpc_id: $vpc }
       },
       "CCC.C02": {
         control_id: "CCC.C02",
         status: $encryption_status,
         message: $encryption_message,
         expected: {
           enable_sample_encrypted_bucket: ($enable_sample_encrypted_bucket == "true"),
           require_kms_encryption: ($require_kms == "true")
         },
         observed: {
           buckets: $buckets
         }
        },
        "CCC.VPC.C02": {
          control_id: "CCC.VPC.C02",
          status: $public_subnet_status,
          message: $public_subnet_message,
          expected: {
            map_public_ip_on_launch:
              (if $public_subnet_expect == "true" then true
               elif $public_subnet_expect == "false" then false
               else null end)
          },
          observed: {
            subnet_id: $public_subnet_id,
            map_public_ip_on_launch: $public_subnet_actual
          }
        }
     }
   }
' > output/runtime/runtime-guard.json

echo "✅ Runtime guard complete. See output/runtime/runtime-guard.json"
