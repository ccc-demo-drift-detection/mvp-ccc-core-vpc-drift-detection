#!/usr/bin/env bash
# Create a timestamped snapshot of key readiness outputs.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"
OUTPUT_DIR="$ROOT_DIR/output"
SNAPSHOT_DIR="$OUTPUT_DIR/snapshots"

if [[ ! -d "$OUTPUT_DIR" ]]; then
  echo "No output directory found at $OUTPUT_DIR. Run validation first." >&2
  exit 1
fi

ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
TARGET="$SNAPSHOT_DIR/$TIMESTAMP"

# Determine previous snapshot for deduplication
PREVIOUS=""
if compgen -G "$SNAPSHOT_DIR/[0-9]*" >/dev/null; then
  PREVIOUS=$(ls -1dt "$SNAPSHOT_DIR"/[0-9]* 2>/dev/null | grep -v "/diffs$" | head -n1 || true)
  [[ "$PREVIOUS" == "$TARGET" ]] && PREVIOUS=""
fi

# Skip if nothing changed since last snapshot
if [[ -n "$PREVIOUS" && -f "$PREVIOUS/metadata.txt" ]]; then
  reference="$PREVIOUS/metadata.txt"
  changed=0
  for dir in ccc-vpc runtime reports prowler drift; do
    if [[ -d "$OUTPUT_DIR/$dir" ]] && find "$OUTPUT_DIR/$dir" -type f -newer "$reference" -print -quit | grep -q .; then
      changed=1
      break
    fi
  done
  if [[ $changed -eq 0 ]]; then
    echo "No new outputs since snapshot $(basename "$PREVIOUS"); skipping."
    exit 0
  fi
fi

mkdir -p "$TARGET"

# Record metadata for traceability
cat > "$TARGET/metadata.txt" <<META
snapshot_ts=$TIMESTAMP
region=${REGION:-${TF_VAR_REGION:-unknown}}
aws_profile=${AWS_PROFILE:-${TF_VAR_AWS_PROFILE:-}}
flow_logs_intent=${ENABLE_VPC_FLOW_LOGS:-${TF_VAR_ENABLE_VPC_FLOW_LOGS:-unknown}}
META

copy_dir() {
  local src=$1
  local name=$2
  if [[ -d "$OUTPUT_DIR/$src" ]]; then
    local args=(-a)
    if [[ -n "$PREVIOUS" && -d "$PREVIOUS/$name" ]]; then
      args+=(--link-dest="$PREVIOUS/$name")
    fi
    rsync "${args[@]}" "$OUTPUT_DIR/$src/" "$TARGET/$name/"
  fi
}

copy_dir ccc-vpc ccc-vpc
copy_dir runtime runtime
copy_dir reports reports
copy_dir prowler prowler
copy_dir terraform terraform

if [[ -d "$OUTPUT_DIR/drift" ]]; then
  rsync_args=(-a)
  if [[ -n "$PREVIOUS" && -d "$PREVIOUS/drift" ]]; then
    rsync_args+=(--link-dest="$PREVIOUS/drift")
  fi
  rsync "${rsync_args[@]}" "$OUTPUT_DIR/drift/" "$TARGET/drift/" || true
fi

echo "Snapshot created at $TARGET"
