#!/usr/bin/env bash
# Wrapper to run validate.sh with provider drift enabled (long-running live scan).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

ENV_FILE=${ENV_FILE:-.env.basic}
TF_REFRESH_TIMEOUT=${TF_REFRESH_TIMEOUT:-0}

VALIDATE_REFRESH=true \
ENV_FILE="$ENV_FILE" \
TF_REFRESH_TIMEOUT="$TF_REFRESH_TIMEOUT" \
"$SCRIPT_DIR/validate.sh"
