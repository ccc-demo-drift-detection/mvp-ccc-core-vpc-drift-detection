#!/usr/bin/env bash
set -euo pipefail

echo "=== ✅ CCC-VPC-MVP Environment Check ==="

check_cmd() {
  local cmd="$1"
  local version_arg="${2:---version}"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "✅ $cmd: $($cmd $version_arg 2>&1 | head -n 1)"
  else
    echo "❌ $cmd not found — please install it."
  fi
}

# Check required tools
check_cmd terraform -version
check_cmd aws --version
check_cmd jq --version
check_cmd privateer --help || true
check_cmd prowler --version || echo "❌ prowler not found (via pipx, git, or docker)"
check_cmd make -v
check_cmd git --version

echo
echo "=== ✅ .env.basic Variables Check ==="
if [ -f .env.basic ]; then
  source .env.basic
  echo "✅ Loaded .env.basic"
  echo "  REGION=$REGION"
  echo "  ENABLE_VPC_FLOW_LOGS=$ENABLE_VPC_FLOW_LOGS"
else
  echo "❌ .env.basic not found"
fi

echo
echo "=== ✅ Terraform validation ==="
if [ -d "iac" ]; then
  pushd iac >/dev/null
  terraform init -upgrade -input=false >/dev/null 2>&1 || true
  terraform validate || echo "❌ Terraform validation failed"
  popd >/dev/null
else
  echo "⚠️  No iac/ folder found"
fi

echo
echo "=== ✅ All checks complete ==="


# lsb_release -a
# uname -m
