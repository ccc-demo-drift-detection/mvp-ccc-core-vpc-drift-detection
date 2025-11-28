#!/usr/bin/env bash
# Tool: Prowler (Runtime)
# Purpose: Runtime corroboration for CCC VPC controls (C02, C03, C04).
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

echo "=== 🔍 Prowler CCC VPC Runtime Checks ==="

ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true

REGION=${1:-${REGION:-"ap-northeast-1"}}
AWS_PROFILE=${AWS_PROFILE:-}

if ! command -v prowler >/dev/null 2>&1; then
  echo "❌ prowler not found (install via pipx, brew, docker, or docker image)." >&2
  exit 1
fi

PROWLER_OUTPUT_DIR=output/prowler
mkdir -p "$PROWLER_OUTPUT_DIR"

PROWLER_CHECKS=(
  vpc_flow_logs_enabled
  vpc_subnet_no_public_ip_by_default
  vpc_peering_routing_tables_with_least_privilege
  vpc_endpoint_connections_trust_boundaries
  vpc_endpoint_services_allowed_principals_trust_boundaries
)

printf "Running checks: %s\n" "${PROWLER_CHECKS[*]}"

PROWLER_ARGS=(aws --region "$REGION" --output-formats html json-asff --output-directory "./$PROWLER_OUTPUT_DIR" --ignore-exit-code-3 --no-banner --log-level ERROR)
PROWLER_ARGS+=(--check)
PROWLER_ARGS+=("${PROWLER_CHECKS[@]}")
if [[ -n "$AWS_PROFILE" ]]; then
  PROWLER_ARGS+=(--profile "$AWS_PROFILE")
fi

# Ignore non-zero return so demos continue even when AWS endpoints are unreachable.
prowler "${PROWLER_ARGS[@]}" || true

# Produce a small map linking the executed checks to CCC controls and frameworks.
if command -v python3 >/dev/null 2>&1; then
  export PROWLER_CHECKS_CSV=$(IFS=,; echo "${PROWLER_CHECKS[*]}")
  python3 <<'PY'
import json
import os
from pathlib import Path

checks = [c for c in os.environ.get("PROWLER_CHECKS_CSV", "").split(",") if c]

ccc_map = {
    "vpc_flow_logs_enabled": {
        "ccc_controls": ["CCC.VPC.C04"],
        "frameworks": ["aws_foundational_security_best_practices_aws", "cis_1.4_aws", "nist_800_53_revision_5_aws", "pci_4.0_aws"],
    },
    "vpc_subnet_no_public_ip_by_default": {
        "ccc_controls": ["CCC.VPC.C02"],
        "frameworks": ["aws_foundational_security_best_practices_aws", "cis_1.5_aws", "nist_800_53_revision_5_aws"],
    },
    "vpc_peering_routing_tables_with_least_privilege": {
        "ccc_controls": ["CCC.VPC.C03"],
        "frameworks": ["aws_foundational_security_best_practices_aws", "cis_1.4_aws", "nist_800_53_revision_5_aws"],
    },
    "vpc_endpoint_connections_trust_boundaries": {
        "ccc_controls": ["CCC.VPC.C03"],
        "frameworks": ["aws_foundational_security_best_practices_aws", "cis_1.4_aws", "nist_800_53_revision_5_aws"],
    },
    "vpc_endpoint_services_allowed_principals_trust_boundaries": {
        "ccc_controls": ["CCC.VPC.C03"],
        "frameworks": ["aws_foundational_security_best_practices_aws", "cis_1.4_aws", "nist_800_53_revision_5_aws"],
    },
}

summary = {}
for check in checks:
    summary[check] = ccc_map.get(check, {"ccc_controls": [], "frameworks": []})

output_path = Path("output/prowler/ccc-vpc-runtime-map.json")
output_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"Compliance map written to {output_path}")
PY
else
  echo "⚠️  python3 not found; skipping CCC map generation." >&2
fi

{
  echo "Executed Prowler checks (CCC runtime corroboration):"
  for chk in "${PROWLER_CHECKS[@]}"; do
    echo " - $chk"
  done
} > output/prowler/ccc-vpc-runtime-checks.txt

echo "✅ Prowler runtime scan complete (artifacts under output/prowler)."
