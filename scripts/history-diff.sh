#!/usr/bin/env bash
# Compare two readiness snapshots and emit a human-readable Markdown diff.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SNAPSHOT_DIR="$ROOT_DIR/output/snapshots"

FROM=${1:-${FROM:-}}
TO=${2:-${TO:-}}

if [[ -z "$FROM" || -z "$TO" ]]; then
  echo "Usage: make history-diff FROM=<timestamp> TO=<timestamp>" >&2
  exit 1
fi

FROM_PATH="$SNAPSHOT_DIR/$FROM"
TO_PATH="$SNAPSHOT_DIR/$TO"

if [[ ! -d "$FROM_PATH" ]]; then
  echo "Snapshot $FROM not found at $FROM_PATH" >&2
  exit 1
fi
if [[ ! -d "$TO_PATH" ]]; then
  echo "Snapshot $TO not found at $TO_PATH" >&2
  exit 1
fi

DIFF_DIR="$SNAPSHOT_DIR/diffs"
mkdir -p "$DIFF_DIR"
DIFF_FILE="$DIFF_DIR/diff-$FROM-to-$TO.md"

python3 - "$FROM_PATH" "$TO_PATH" "$DIFF_FILE" <<'PY'
import json
import os
import sys
from pathlib import Path

from_path = Path(sys.argv[1])
to_path = Path(sys.argv[2])
diff_file = Path(sys.argv[3])


def load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None


def privateer_summary(snapshot):
    result_path = snapshot / "ccc-vpc" / "ccc-vpc.json"
    data = load_json(result_path)
    if not data:
        return {}
    suites = data.get("evaluation_suites") or data.get("Evaluation_Suites") or []
    summary = {}
    for suite in suites:
        controls = suite.get("control_evaluations") or suite.get("Control_Evaluations") or []
        for ctrl in controls:
            cid = ctrl.get("control_id") or ctrl.get("Control_Id")
            res = ctrl.get("result") or ctrl.get("Result")
            msg = ctrl.get("message") or ctrl.get("Message") or ""
            if cid:
                summary[cid] = (res, msg)
    return summary


def runtime_guard_summary(snapshot):
    runtime_path = snapshot / "runtime" / "runtime-guard.json"
    data = load_json(runtime_path)
    if not data:
        return None
    return {
        "vpc_id": data.get("vpc_id"),
        "expected": data.get("expected_enable_flow_logs"),
        "has_flow_logs": data.get("has_flow_logs"),
        "status": data.get("status"),
        "message": data.get("message"),
    }


def prowler_summary(snapshot):
    prowler_dir = snapshot / "prowler"
    if not prowler_dir.exists():
        return {}
    # Prefer ASFF / JSON outputs
    files = sorted(prowler_dir.glob("*.json"))
    if not files:
        files = sorted(prowler_dir.glob("*.asff"))
    findings = {}
    for file in files:
        data = load_json(file)
        if not data:
            continue
        if isinstance(data, dict):
            entries = data.get("Findings") or []
        else:
            entries = data
        for entry in entries:
            resources = entry.get("Resources") or []
            if not resources:
                continue
            rid = resources[0].get("Id")
            status = (entry.get("Compliance", {}) or {}).get("Status", "UNKNOWN")
            title = entry.get("Title", "")
            if rid:
                findings[rid] = (status.upper(), title)
    return findings


def metadata(snapshot):
    meta_path = snapshot / "metadata.txt"
    if not meta_path.exists():
        return {}
    data = {}
    for line in meta_path.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


old_priv = privateer_summary(from_path)
new_priv = privateer_summary(to_path)
old_guard = runtime_guard_summary(from_path)
new_guard = runtime_guard_summary(to_path)
old_prowler = prowler_summary(from_path)
new_prowler = prowler_summary(to_path)
old_meta = metadata(from_path)
new_meta = metadata(to_path)

lines = []
lines.append("# Snapshot Diff\n")
lines.append(f"- From: {from_path.name}\n")
lines.append(f"- To: {to_path.name}\n\n")

changes = 0

# Privateer differences
priv_keys = sorted(set(old_priv.keys()) | set(new_priv.keys()))
priv_rows = []
for key in priv_keys:
    old = old_priv.get(key)
    new = new_priv.get(key)
    if old == new:
        continue
    changes += 1
    old_display = old[0] if old else "(missing)"
    new_display = new[0] if new else "(missing)"
    priv_rows.append((key, old_display, new_display))

if priv_rows:
    lines.append("## IaC (Privateer)\n\n")
    lines.append("| Control | Previous | Current |\n")
    lines.append("|---------|----------|---------|\n")
    for key, old_display, new_display in priv_rows:
        lines.append(f"| {key} | {old_display} | {new_display} |\n")
    lines.append("\n")

# Runtime guard diff
if old_guard or new_guard:
    guard_changed = False
    guard_lines = []
    for field in ("vpc_id", "expected", "has_flow_logs", "status", "message"):
        old = old_guard.get(field) if old_guard else None
        new = new_guard.get(field) if new_guard else None
        if old != new:
            guard_changed = True
            changes += 1
            guard_lines.append((field, old, new))
    if guard_changed:
        lines.append("## Runtime Guard\n\n")
        lines.append("| Field | Previous | Current |\n")
        lines.append("|-------|----------|---------|\n")
        for field, old, new in guard_lines:
            lines.append(f"| {field} | {old} | {new} |\n")
        lines.append("\n")

# Prowler diff
prowler_keys = sorted(set(old_prowler.keys()) | set(new_prowler.keys()))
prowler_rows = []
for rid in prowler_keys:
    old = old_prowler.get(rid)
    new = new_prowler.get(rid)
    if old == new:
        continue
    changes += 1
    old_status = old[0] if old else "(missing)"
    new_status = new[0] if new else "(missing)"
    prowler_rows.append((rid, old_status, new_status))

if prowler_rows:
    lines.append("## Runtime Scan (Prowler)\n\n")
    lines.append("| Resource | Previous | Current |\n")
    lines.append("|----------|----------|---------|\n")
    for rid, old_status, new_status in prowler_rows:
        lines.append(f"| {rid} | {old_status} | {new_status} |\n")
    lines.append("\n")

# Metadata differences (e.g., snapshot time, profile)
meta_keys = sorted(set(old_meta.keys()) | set(new_meta.keys()))
meta_rows = []
for key in meta_keys:
    old = old_meta.get(key)
    new = new_meta.get(key)
    if old != new:
        meta_rows.append((key, old, new))

if meta_rows:
    lines.append("## Metadata\n\n")
    lines.append("| Field | Previous | Current |\n")
    lines.append("|-------|----------|---------|\n")
    for key, old, new in meta_rows:
        lines.append(f"| {key} | {old} | {new} |\n")
    lines.append("\n")

if changes == 0:
    lines.append("No readiness changes detected between these snapshots.\n")
else:
    # Also append a compact file-level diff summary for auditing
    summary = os.popen(f"git --no-pager diff --no-index --stat '{from_path}' '{to_path}'").read().strip()
    if summary:
        lines.append("## File Summary\n\n")
        lines.append("```\n")
        lines.append(summary.strip() + "\n")
        lines.append("```\n")

with open(diff_file, "w") as fh:
    fh.write("".join(lines))
PY

echo "Diff written to $DIFF_FILE"
