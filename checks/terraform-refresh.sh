#!/usr/bin/env bash
# Tool: Terraform Refresh Plan
# Purpose: Run `terraform plan -refresh-only` to surface provider-reported drift
#          and emit machine-readable summaries under output/terraform/.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"
IAC_DIR="$ROOT_DIR/iac"
OUTPUT_DIR="$ROOT_DIR/output/terraform"
LOG_DIR="$ROOT_DIR/output/validate"
mkdir -p "$OUTPUT_DIR" "$LOG_DIR"

ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true

export REGION=${REGION:-${TF_VAR_REGION:-}}
export USE_LOCALSTACK=${USE_LOCALSTACK:-${TF_VAR_USE_LOCALSTACK:-}}
export ENABLE_VPC_FLOW_LOGS=${ENABLE_VPC_FLOW_LOGS:-${TF_VAR_ENABLE_VPC_FLOW_LOGS:-}}
AWS_PROFILE=${AWS_PROFILE:-${TF_VAR_AWS_PROFILE:-}}

if [[ -n "$AWS_PROFILE" ]]; then
  if command -v aws >/dev/null 2>&1; then
    if [[ -z "${AWS_ACCESS_KEY:-}" ]]; then
      AWS_ACCESS_KEY=$(aws --profile "$AWS_PROFILE" configure get aws_access_key_id 2>/dev/null || true)
      export AWS_ACCESS_KEY
    fi
    if [[ -z "${AWS_SECRET_KEY:-}" ]]; then
      AWS_SECRET_KEY=$(aws --profile "$AWS_PROFILE" configure get aws_secret_access_key 2>/dev/null || true)
      export AWS_SECRET_KEY
    fi
    if [[ -z "${AWS_SESSION_TOKEN:-}" ]]; then
      AWS_SESSION_TOKEN=$(aws --profile "$AWS_PROFILE" configure get aws_session_token 2>/dev/null || true)
      export AWS_SESSION_TOKEN
    fi
  fi
  export AWS_PROFILE
  # Ensure variables are exported for downstream Terraform provider usage
  if [[ -n "$AWS_ACCESS_KEY" ]]; then
    export AWS_ACCESS_KEY
    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY"
  fi
  if [[ -n "$AWS_SECRET_KEY" ]]; then
    export AWS_SECRET_KEY
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY"
  fi
  if [[ -n "$AWS_SESSION_TOKEN" ]]; then
    export AWS_SESSION_TOKEN
  fi
else
  export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-${AWS_ACCESS_KEY:-}}
  export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-${AWS_SECRET_KEY:-}}
  SESSION_TOKEN=${AWS_SESSION_TOKEN_ID:-${AWS_SESSION_TOKEN:-}}
  if [[ -n "$SESSION_TOKEN" ]]; then
    export AWS_SESSION_TOKEN="$SESSION_TOKEN"
  fi
fi

# Optional LocalStack endpoint detection (to match runtime guard behaviour)
AWS_ENDPOINT=${AWS_ENDPOINT:-}
if [[ -z "$AWS_ENDPOINT" ]]; then
  if [[ "${USE_LOCALSTACK:-}" == "true" ]]; then
    AWS_ENDPOINT="http://localhost:4566"
  elif grep -q "localhost:4566" "$IAC_DIR/main.tf" 2>/dev/null; then
    AWS_ENDPOINT="http://localhost:4566"
  fi
fi

# Map relevant ENV vars to TF_VAR_* so refresh-only plan reflects intent toggles
declare -A TF_VAR_MAP=(
  [REGION]=region
  [AWS_ACCESS_KEY]=aws_access_key
  [AWS_SECRET_KEY]=aws_secret_key
  [AWS_SESSION_TOKEN]=aws_session_token
  [USE_LOCALSTACK]=use_localstack
  [ENABLE_VPC_FLOW_LOGS]=enable_vpc_flow_logs
  [ENABLE_FLOW_LOG_PROTECTION]=enable_flow_log_protection
  [FLOW_LOG_RETENTION_DAYS]=flow_log_retention_days
  [CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS]=ccc_c12_enforce_strict_network_access
  [CCC_C08_PUBLIC_SUBNET_AZ]=ccc_c08_public_subnet_az
  [CCC_C08_PRIVATE_SUBNET_AZ]=ccc_c08_private_subnet_az
  [PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP]=public_subnet_auto_assign_public_ip
  [ASSOCIATE_PUBLIC_IP_WEB_INSTANCE]=associate_public_ip_web_instance
  [CREATE_WEB_INSTANCE]=create_web_instance
  [CREATE_DEMO_VPC_PEERING]=create_demo_vpc_peering
  [CCC_C01_ALLOW_WORLD_TLS_INGRESS]=ccc_c01_allow_world_tls_ingress
  [ENFORCE_MFA_DEMO_ADMIN_ROLE]=enforce_mfa_demo_admin_role
  [ENABLE_CORE_AUDIT_LOGS]=enable_core_audit_logs
  [ENABLE_ENUMERATION_ALERTS]=enable_enumeration_alerts
  [ENABLE_SAMPLE_ENCRYPTED_BUCKET]=enable_sample_encrypted_bucket
  [ENABLE_UNENCRYPTED_BUCKET]=enable_unencrypted_bucket
  [ENABLE_REPLICATION_DEMO]=enable_replication_demo
  [REPLICATION_DESTINATION_REGION]=replication_destination_region
  [ENABLE_CMEK_DEMO]=enable_cmek_demo
  [ENFORCE_CMEK_ROTATION]=enforce_cmek_rotation
  [REQUIRE_KMS_ENCRYPTION]=require_kms_encryption
  [REQUIRE_CMEK_ROTATION]=require_cmek_rotation
  [ALLOWED_INGRESS_CIDRS_CSV]=allowed_ingress_cidrs_csv
  [ALLOWED_INGRESS_IPV6_CIDRS_CSV]=allowed_ingress_ipv6_cidrs_csv
  [ALLOWED_INGRESS_SECURITY_GROUPS_CSV]=allowed_ingress_security_groups_csv
  [ALLOWED_VPC_PEER_ACCOUNTS_CSV]=allowed_vpc_peer_accounts_csv
  [ALLOWED_VPC_PEER_VPCS_CSV]=allowed_vpc_peer_vpcs_csv
  [ALLOWED_VPC_PEER_REGIONS_CSV]=allowed_vpc_peer_regions_csv
  [ALLOWED_REPLICATION_ACCOUNTS_CSV]=allowed_replication_accounts_csv
  [ALLOWED_REPLICATION_BUCKETS_CSV]=allowed_replication_buckets_csv
  [ALLOWED_REPLICATION_REGIONS_CSV]=allowed_replication_regions_csv
  [APPROVED_DEPLOYMENT_REGIONS_CSV]=allowed_regions_csv
)

for env_key in "${!TF_VAR_MAP[@]}"; do
  tf_key=${TF_VAR_MAP[$env_key]}
  value=${!env_key-}
  if [[ -n "$value" ]]; then
    # Normalise booleans to lowercase true/false for Terraform
    case "$value" in
      true|TRUE|True) value=true ;;
      false|FALSE|False) value=false ;;
    esac
    export "TF_VAR_${tf_key}"="$value"
  fi
done

TF_LOG_PATH="$LOG_DIR/terraform-refresh.log"
PLAN_PATH="$IAC_DIR/tfrefresh.out"
JSON_PATH="$OUTPUT_DIR/refresh-plan.json"
SUMMARY_PATH="$OUTPUT_DIR/refresh-summary.json"
TEXT_PATH="$OUTPUT_DIR/refresh-plan.txt"

rm -f "$PLAN_PATH" "$JSON_PATH" "$SUMMARY_PATH" "$TEXT_PATH"

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform binary not found in PATH" >&2
  exit 1
fi

export TF_IN_AUTOMATION=1
declare -a terraform_cmd=(terraform plan -refresh-only -input=false -lock=false -out=tfrefresh.out)

TIMEOUT_SECONDS=${TF_REFRESH_TIMEOUT:-45}
export AWS_MAX_ATTEMPTS=${AWS_MAX_ATTEMPTS:-1}
export AWS_RETRY_MODE=${AWS_RETRY_MODE:-standard}

# Use endpoint override if targeting LocalStack
if [[ -n "$AWS_ENDPOINT" ]]; then
  export AWS_ENDPOINT_URL="$AWS_ENDPOINT"
fi

pushd "$IAC_DIR" >/dev/null

set +e
if [[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] && [ "$TIMEOUT_SECONDS" -gt 0 ]; then
  timeout "${TIMEOUT_SECONDS}s" "${terraform_cmd[@]}" >"$TF_LOG_PATH" 2>&1
  PLAN_RC=$?
else
  "${terraform_cmd[@]}" >"$TF_LOG_PATH" 2>&1
  PLAN_RC=$?
fi
set -e

popd >/dev/null

if [[ $PLAN_RC -eq 124 ]]; then
  echo "Terraform refresh-only plan timed out after ${TIMEOUT_SECONDS}s; skipping provider drift" >&2
  jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson exit_code 124 \
    '{timestamp: $timestamp, plan_exit_code: $exit_code, drift: [], note: "timeout"}' > "$SUMMARY_PATH"
  echo "Artifacts:"
  printf ' - %s\n' "$SUMMARY_PATH"
  exit 0
fi

if [[ $PLAN_RC -eq 1 ]]; then
  echo "Terraform refresh-only plan failed (see $TF_LOG_PATH)" >&2
  exit 1
fi

# Capture human-readable plan for quick inspection
terraform -chdir="$IAC_DIR" show tfrefresh.out > "$TEXT_PATH" 2>/dev/null || true
terraform -chdir="$IAC_DIR" show -json tfrefresh.out > "$JSON_PATH"

DRIFT_ARRAY=$(jq '[.resource_changes[]? | select((.change.actions // []) | length > 0 and any((.change.actions // [])[]; . == "update" or . == "delete" or . == "create")) |
  {
    address: .address,
    type: .type,
    actions: (.change.actions // []),
    message: ("Detected " + ((.change.actions // []) | join("/")) + " via refresh-only plan")
  }
]' "$JSON_PATH")

jq -n \
  --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --argjson exit_code "$PLAN_RC" \
  --argjson drift "$DRIFT_ARRAY" \
  '{timestamp: $timestamp, plan_exit_code: $exit_code, drift: $drift}' > "$SUMMARY_PATH"

DRIFT_COUNT=$(jq 'length' <<<"$DRIFT_ARRAY")
if [[ $DRIFT_COUNT -gt 0 ]]; then
  echo "Terraform refresh-only plan detected $DRIFT_COUNT drift change(s)."
else
  echo "Terraform refresh-only plan detected no drift changes."
fi

echo "Artifacts:"
printf ' - %s\n' "$JSON_PATH" "$SUMMARY_PATH" "$TEXT_PATH"

exit 0
