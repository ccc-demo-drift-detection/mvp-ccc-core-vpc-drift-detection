#!/usr/bin/env bash
# Tool: Unified Validator
# Purpose: Orchestrate manual, IaC, and runtime checks, then summarize CCC drift.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"

printf "=== 🧪 Unified Validation (Manual → IaC → Runtime) ===\n"

ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || exit 1
export REGION ENABLE_VPC_FLOW_LOGS USE_LOCALSTACK
export AWS_PROFILE=${AWS_PROFILE:-}

# Harmonise control-filter env vars for downstream scripts and summaries
CONTROL_FILTER_RAW=${CONTROL_FILTER:-${CONTROLS_FILTER_CSV:-}}
if [ -n "${CONTROL_FILTER_RAW:-}" ] && [ -z "${CONTROLS_FILTER_CSV:-}" ]; then
  export CONTROLS_FILTER_CSV="$CONTROL_FILTER_RAW"
fi

if command -v jq >/dev/null 2>&1; then
  if [ -n "${CONTROL_FILTER_RAW:-}" ]; then
    FILTER_JSON=$(printf '%s' "$CONTROL_FILTER_RAW" | jq -Rc 'split(",") | map(gsub("^\\s+|\\s+$"; "") | ascii_upcase) | map(select(. != ""))')
  else
    FILTER_JSON='[]'
  fi
  CONTROL_FILTER_SET=$(printf '%s' "$FILTER_JSON" | jq -r '.[]')
else
  FILTER_JSON='[]'
  CONTROL_FILTER_SET=""
fi

control_in_filter() {
  local needle="${1:-}"
  if [ -z "$needle" ]; then
    return 1
  fi
  if [ -z "${CONTROL_FILTER_SET:-}" ]; then
    return 0
  fi
  local upper
  upper=$(printf '%s' "$needle" | tr '[:lower:]' '[:upper:]')
  while IFS= read -r item; do
    if [ -n "$item" ] && [ "$item" = "$upper" ]; then
      return 0
    fi
  done <<EOF
$CONTROL_FILTER_SET
EOF
  return 1
}

mkdir -p output/validate

MANUAL_LOG="output/validate/manual.log"
IAC_LOG="output/validate/iac.log"
RUNTIME_LOG="output/validate/runtime.log"
CI_OUTPUT_DIR=${VALIDATE_CI_DIR:-output/ci}
mkdir -p "$CI_OUTPUT_DIR"
SUMMARY_JSON_PATH="$CI_OUTPUT_DIR/validate-summary.json"
JUNIT_XML_PATH="$CI_OUTPUT_DIR/validate-junit.xml"
MODE=${VALIDATE_MODE:-standard}
STRICT=${VALIDATE_STRICT:-false}

# Manual check (best-effort)
man_rc=0
set +e
("$PWD"/checks/check-1-manual.sh) >"$MANUAL_LOG" 2>&1
man_rc=$?
set -e
# printf "\n=== Manual Checks ===\n"
if [ $man_rc -ne 0 ]; then
  printf "⚠️  Manual check exited with %d (see %s).\n" "$man_rc" "$MANUAL_LOG"
else
  printf "✅ Manual check complete (details: %s).\n" "$MANUAL_LOG"
fi

# Privateer (IaC) guard
IAC_GUARD_STRICT=${IAC_GUARD_STRICT:-false}
set +e
ENV_FILE="$ENV_FILE_PATH" IAC_GUARD_STRICT="$IAC_GUARD_STRICT" "$PWD"/checks/iac-guard.sh >"$IAC_LOG" 2>&1
IAC_RC=$?
set -e
# printf "\n=== IaC Guard ===\n"
if [ $IAC_RC -ne 0 ]; then
  printf "⚠️  IaC guard exited with %d (see %s).\n" "$IAC_RC" "$IAC_LOG"
else
  printf "✅ IaC guard complete (details: %s).\n" "$IAC_LOG"
fi

# Runtime guard
set +e
ENV_FILE="$ENV_FILE_PATH" "$PWD"/checks/runtime-guard.sh >"$RUNTIME_LOG" 2>&1
RUNTIME_RC=$?
set -e
# printf "\n=== Runtime Guard ===\n"
if [ $RUNTIME_RC -ne 0 ]; then
  printf "⚠️  Runtime guard exited with %d (see %s).\n" "$RUNTIME_RC" "$RUNTIME_LOG"
else
  printf "✅ Runtime guard complete (details: %s).\n" "$RUNTIME_LOG"
fi

RESULT_JSON="output/ccc-vpc/ccc-vpc.json"
RUNTIME_JSON="output/runtime/runtime-guard.json"
SUMMARY_LINES=()

if [ -f "$RESULT_JSON" ] && command -v jq >/dev/null 2>&1; then
  readarray -t SUMMARY_LINES < <(jq --argjson filter_ids "$FILTER_JSON" -r '
    def include_control($id):
      ( $filter_ids | length ) == 0
      or (
        ($id // "") as $raw
        | ($raw | ascii_upcase) as $upper
        | ($upper != "" and ($filter_ids | index($upper)) != null)
      );
    def short(msg):
      (msg // "" | tostring) as $original
      | ($original | gsub("\\n"; " ")) as $clean
      | if ($clean | length) > 90 then ($clean[:75] + "...") else $clean end;
    def suites: (.Evaluation_Suites // .evaluation_suites // []);
    [ suites[]? | (.Control_Evaluations // .control_evaluations // [])[]? |
      select(include_control(.Control_Id // .control_id // "")) |
      { id: (.Control_Id // .control_id // ""),
        result: (.Result // .result // "Unknown"),
        message: short(.Message // .message // "") }
    ]
    | sort_by(.id)
    | unique_by(.id)
    | map("\(.id) — IaC: \(.result) (\(.message))" )
    | .[]
  ' "$RESULT_JSON")
else
  SUMMARY_LINES+=("IaC results unavailable (missing output/ccc-vpc/ccc-vpc.json)")
fi

printf "\n=== CCC Control Summary (IaC) ===\n"
for line in "${SUMMARY_LINES[@]}"; do
  printf "%s\n" "$line"
done

DRIFT_NOTES=()
printf "\n=== CCC Control Summary (Runtime) ===\n"
RUNTIME_SUMMARY=()
if [ -f "$RUNTIME_JSON" ] && command -v jq >/dev/null 2>&1; then
  FLOW_EXPECT=$(jq -r '.checks["CCC.VPC.C04"].expected.enable_flow_logs // .expected_enable_flow_logs // "unknown"' "$RUNTIME_JSON")
  FLOW_HAS=$(jq -r '.checks["CCC.VPC.C04"].observed.has_flow_logs // .has_flow_logs // false' "$RUNTIME_JSON")
  FLOW_STATUS=$(jq -r '.checks["CCC.VPC.C04"].status // .flow_logs_status // "Unknown"' "$RUNTIME_JSON")
  FLOW_MSG=$(jq -r '.checks["CCC.VPC.C04"].message // .flow_logs_message // ""' "$RUNTIME_JSON")
  VPC=$(jq -r '.vpc_id // ""' "$RUNTIME_JSON")

  SUBNET_STATUS_JQ='.checks["CCC.VPC.C02"].status // .public_subnet_status // "Unknown"'
  SUBNET_MSG_JQ='.checks["CCC.VPC.C02"].message // .public_subnet_message // ""'
  SUBNET_STATUS=$(jq -r "$SUBNET_STATUS_JQ" "$RUNTIME_JSON")
  SUBNET_MSG=$(jq -r "$SUBNET_MSG_JQ" "$RUNTIME_JSON")
  PUBLIC_SUBNET_EXPECT=$(jq -r '.expected_map_public_ip_on_launch // "unknown"' "$RUNTIME_JSON")
  PUBLIC_SUBNET_ID=$(jq -r '.public_subnet_id // ""' "$RUNTIME_JSON")
  SUBNET_ACTUAL_RAW=$(jq -r '.map_public_ip_on_launch // ""' "$RUNTIME_JSON")
  if [[ "$SUBNET_ACTUAL_RAW" == "true" || "$SUBNET_ACTUAL_RAW" == "false" ]]; then
    SUBNET_ACTUAL_VALUE="$SUBNET_ACTUAL_RAW"
  else
    SUBNET_ACTUAL_VALUE="unknown"
  fi

  if control_in_filter "CCC.VPC.C04" || control_in_filter "CCC.C04"; then
    RUNTIME_SUMMARY+=("CCC.VPC.C04 — Runtime: $FLOW_STATUS ($FLOW_MSG)")

    FLOW_STATUS_LOWER=${FLOW_STATUS,,}
    if [[ "$FLOW_STATUS_LOWER" == "unknown" ]]; then
      DRIFT_NOTES+=("⚠️  CCC.VPC.C04 runtime status unknown: $FLOW_MSG")
    elif [[ "$FLOW_STATUS_LOWER" == "fail" || "$FLOW_STATUS_LOWER" == "failed" ]]; then
      if [[ "$FLOW_EXPECT" == "true" && "$FLOW_HAS" != "true" ]]; then
        DRIFT_NOTES+=("❗ Drift (CCC.VPC.C04): expected enable_flow_logs=true, observed has_flow_logs=false (VPC=$VPC)")
      elif [[ "$FLOW_EXPECT" == "false" && "$FLOW_HAS" == "true" ]]; then
        DRIFT_NOTES+=("❗ Drift (CCC.VPC.C04): expected enable_flow_logs=false, observed has_flow_logs=true (VPC=$VPC)")
      else
        DRIFT_NOTES+=("⚠️  CCC.VPC.C04 runtime failure: $FLOW_MSG")
      fi
    else
      DRIFT_NOTES+=("✅ Flow Logs aligned (expected=$FLOW_EXPECT, has_flow_logs=$FLOW_HAS).")
    fi
  fi

  ENC_EXPECT=$(jq -r '.checks["CCC.C02"].expected.enable_sample_encrypted_bucket // "false"' "$RUNTIME_JSON")
  ENC_EXPECT_LOWER=$(printf '%s' "$ENC_EXPECT" | tr '[:upper:]' '[:lower:]')
  ENC_STATUS=$(jq -r '.checks["CCC.C02"].status // "Unknown"' "$RUNTIME_JSON")
  ENC_STATUS_LOWER=${ENC_STATUS,,}
  ENC_MSG=$(jq -r '.checks["CCC.C02"].message // ""' "$RUNTIME_JSON")

  if control_in_filter "CCC.C02"; then
    RUNTIME_SUMMARY+=("CCC.C02 — Runtime: $ENC_STATUS ($ENC_MSG)")

    if [[ "$ENC_EXPECT_LOWER" == "true" ]]; then
      if [[ "$ENC_STATUS_LOWER" == "unknown" ]]; then
        DRIFT_NOTES+=("⚠️  S3 encryption runtime status unknown: $ENC_MSG")
      elif [[ "$ENC_STATUS_LOWER" == "fail" ]]; then
        FAILED_DETAILS=$(jq -r '.checks["CCC.C02"].observed.buckets[]? | select(.status=="Fail") | "\(.bucket) (algorithm=\(.algorithm // \"unknown\"))"' "$RUNTIME_JSON" 2>/dev/null | paste -sd ", " - || true)
        if [[ -n "$FAILED_DETAILS" ]]; then
          DRIFT_NOTES+=("❗ Drift (CCC.C02): expected aws:kms but observed $FAILED_DETAILS")
        else
          DRIFT_NOTES+=("❗ Drift (CCC.C02): $ENC_MSG")
        fi
      else
        DRIFT_NOTES+=("✅ S3 encryption aligned (status=$ENC_STATUS).")
      fi
    else
      DRIFT_NOTES+=("ℹ️  S3 encryption runtime check skipped (enable_sample_encrypted_bucket=$ENC_EXPECT).")
    fi
  fi
  if control_in_filter "CCC.VPC.C02"; then
    RUNTIME_SUMMARY+=("CCC.VPC.C02 — Runtime: $SUBNET_STATUS ($SUBNET_MSG)")
    if [[ "$PUBLIC_SUBNET_EXPECT" == "true" || "$PUBLIC_SUBNET_EXPECT" == "false" ]]; then
      if [[ "$SUBNET_STATUS" == "Fail" ]]; then
        actual_display="$SUBNET_ACTUAL_VALUE"
        if [[ "$actual_display" != "true" && "$actual_display" != "false" ]]; then
          actual_display="unknown"
        fi
        DRIFT_NOTES+=("❗ Drift (CCC.VPC.C02): MapPublicIpOnLaunch=$actual_display (expected $PUBLIC_SUBNET_EXPECT) [$PUBLIC_SUBNET_ID]")
      fi
    fi
  fi

else
  printf "CCC.VPC.C04 — Runtime: Unknown (runtime artifact missing).\n"
  printf "CCC.C02 — Runtime: Unknown (runtime artifact missing).\n"
  printf "CCC.VPC.C02 — Runtime: Unknown (runtime artifact missing).\n"
  DRIFT_NOTES+=("⚠️  Unable to confirm runtime drift without runtime JSON.")
fi

for line in "${RUNTIME_SUMMARY[@]}"; do
  printf "%s\n" "$line"
done

printf "\n========= Info ============\n"
# Terraform refresh-only drift (provider view)
REFRESH_ENABLED=${VALIDATE_REFRESH:-false}
if [[ "$REFRESH_ENABLED" == "true" ]]; then
  REFRESH_SUMMARY="$PWD/output/terraform/refresh-summary.json"
  REFRESH_RUN_LOG="$PWD/output/validate/terraform-refresh-run.log"

  mkdir -p "$(dirname "$REFRESH_RUN_LOG")"

  set +e
  ENV_FILE="$ENV_FILE_PATH" "$PWD"/checks/terraform-refresh.sh | tee "$REFRESH_RUN_LOG"
  REFRESH_RC=${PIPESTATUS[0]}
  set -e

  if [[ $REFRESH_RC -ne 0 ]]; then
    printf "Terraform refresh-only plan: failed (see %s).\n" "$REFRESH_RUN_LOG"
    DRIFT_NOTES+=("⚠️  Terraform refresh-only plan failed (see validate log).")
  elif [[ -f "$REFRESH_SUMMARY" ]]; then
    REFRESH_COUNT=$(jq -r '.drift | length' "$REFRESH_SUMMARY")
    REFRESH_NOTE=$(jq -r '.note // ""' "$REFRESH_SUMMARY")
    if [[ "$REFRESH_COUNT" -gt 0 ]]; then
      printf "Terraform refresh-only drift findings (%s):\n" "$REFRESH_COUNT"
      jq -r '.drift[] | " - \(.address): \(.message)"' "$REFRESH_SUMMARY"
      mapfile -t REFRESH_LINES < <(jq -r '.drift[] | "❗ Drift (Terraform): " + .message + " [" + .address + "]"' "$REFRESH_SUMMARY")
      if [[ ${#REFRESH_LINES[@]} -gt 0 ]]; then
        DRIFT_NOTES+=( "${REFRESH_LINES[@]}" )
      fi
    else
      if [[ "$REFRESH_NOTE" == "timeout" ]]; then
        printf "Terraform refresh-only plan skipped (timed out after configured limit).\n"
        DRIFT_NOTES+=("⚠️  Terraform refresh-only plan timed out; provider drift not evaluated.")
      else
        printf "Terraform refresh-only plan detected no drift changes.\n"
        DRIFT_NOTES+=("✅ Terraform refresh-only plan detected no drift changes.")
      fi
    fi
  else
    printf "Terraform refresh-only plan summary missing (expected at %s).\n" "$REFRESH_SUMMARY"
    DRIFT_NOTES+=("⚠️  Terraform refresh-only summary missing (expected at output/terraform/refresh-summary.json).")
  fi
else
  printf "Terraform refresh-only plan skipped (VALIDATE_REFRESH=false).\n"
  DRIFT_NOTES+=("ℹ️  Terraform refresh-only plan skipped (VALIDATE_REFRESH=false).")
fi

DRIFT_NOTE=$(printf '%s\n' "${DRIFT_NOTES[@]}")
printf "%s\n" "$DRIFT_NOTE"

if command -v python3 >/dev/null 2>&1; then
  export MANUAL_LOG IAC_LOG RUNTIME_LOG RESULT_JSON RUNTIME_JSON
  export SUMMARY_JSON_PATH JUNIT_XML_PATH MODE DRIFT_NOTE
  export MANUAL_EXIT="$man_rc" IAC_EXIT="$IAC_RC" RUNTIME_EXIT="$RUNTIME_RC"
  export VALIDATE_STRICT_FLAG="$STRICT"
  python3 <<'PY'
import datetime
import json
import os
import re
import sys
import xml.etree.ElementTree as ET


def getenv(name, default=""):
  return os.environ.get(name, default)


SUMMARY_PATH = getenv("SUMMARY_JSON_PATH")
JUNIT_PATH = getenv("JUNIT_XML_PATH")
MANUAL_LOG = getenv("MANUAL_LOG")
IAC_LOG = getenv("IAC_LOG")
RUNTIME_LOG = getenv("RUNTIME_LOG")
RESULT_JSON = getenv("RESULT_JSON")
RUNTIME_JSON = getenv("RUNTIME_JSON")
DRIFT_NOTE = getenv("DRIFT_NOTE")
MODE = getenv("MODE", "standard")
STRICT_FLAG = getenv("VALIDATE_STRICT_FLAG", "false").lower() == "true"


def utc_now(truncate=True):
  now = datetime.datetime.now(datetime.timezone.utc)
  if truncate:
    now = now.replace(microsecond=0)
  iso = now.isoformat().replace("+00:00", "Z")
  return iso


def to_int(value):
  try:
    return int(str(value).strip())
  except Exception:  # noqa: BLE001
    return 0


MANUAL_EXIT = to_int(getenv("MANUAL_EXIT", "0"))
IAC_EXIT = to_int(getenv("IAC_EXIT", "0"))
RUNTIME_EXIT = to_int(getenv("RUNTIME_EXIT", "0"))


def read_text(path):
  if not path:
    return ""
  try:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
      return handle.read()
  except Exception:  # noqa: BLE001
    return ""


def load_json(path):
  if not path or not os.path.exists(path):
    return None
  try:
    with open(path, "r", encoding="utf-8") as handle:
      return json.load(handle)
  except Exception:  # noqa: BLE001
    return None


def classify(result):
  if result is None:
    return "unknown"
  value = str(result).strip().lower()
  mapping = {
      "pass": "passed",
      "passed": "passed",
      "success": "passed",
      "succeeded": "passed",
      "true": "passed",
      "fail": "failed",
      "failed": "failed",
      "error": "failed",
      "critical": "failed",
      "false": "failed",
      "warning": "warning",
      "warn": "warning",
      "partial": "warning",
      "skipped": "skipped",
      "not_applicable": "skipped",
      "n/a": "skipped",
      "unknown": "unknown",
  }
  return mapping.get(value, "unknown")


def get_field(obj, *candidates, default=None):
  for name in candidates:
    if isinstance(name, (tuple, list)):
      for nested in name:
        if isinstance(obj, dict) and nested in obj:
          return obj[nested]
    elif isinstance(obj, dict) and name in obj:
      return obj[name]
  return default


def ensure_list(value):
  if isinstance(value, list):
    return value
  if value is None:
    return []
  return [value]


def last_nonempty_line(text):
  for line in reversed([ln.strip() for ln in text.splitlines()]):
    if line:
      return line
  return ""


manual_content = read_text(MANUAL_LOG)
manual_status = "passed"
manual_message = last_nonempty_line(manual_content) or "Manual check executed."
if MANUAL_EXIT != 0:
  manual_status = "failed"
  manual_message = f"Manual check exited with code {MANUAL_EXIT}."
elif "❌" in manual_content or re.search(r"\\bFailed\\b", manual_content):
  manual_status = "failed"
elif not MANUAL_LOG:
  manual_status = "not_run"
  manual_message = "Manual check was not executed."
elif not os.path.exists(MANUAL_LOG):
  manual_status = "error"
  manual_message = "Manual log missing."

manual_summary = {
    "status": manual_status,
    "exit_code": MANUAL_EXIT,
    "log_path": MANUAL_LOG or None,
    "message": manual_message,
}


iac_data = load_json(RESULT_JSON)
iac_cases = []
iac_failed = []
iac_warning = []
iac_total = 0
iac_notes = []

if iac_data:
  suites = ensure_list(get_field(iac_data, "Evaluation_Suites", "evaluation_suites", default=[]))
  for suite in suites:
    controls = ensure_list(get_field(suite, "Control_Evaluations", "control_evaluations", default=[]))
    for control in controls:
      ctrl_id = get_field(control, "Control_Id", "control_id", default="CCC.UNKNOWN")
      ctrl_result = classify(get_field(control, "Result", "result"))
      ctrl_message = get_field(control, "Message", "message", default="")
      assessments = ensure_list(get_field(control, "Assessments", "assessments", default=[]))
      if not assessments:
        case_name = ctrl_id
        case_result = ctrl_result
        case_message = ctrl_message
        iac_total += 1
        record = {
            "name": case_name,
            "classname": "iac.privateer",
            "status": case_result,
            "message": case_message,
            "details": ctrl_message,
        }
        if case_result == "failed":
          iac_failed.append(case_name)
        elif case_result == "warning":
          iac_warning.append(case_name)
        iac_cases.append(record)
        continue

      for assessment in assessments:
        req_id = get_field(assessment, "Requirement_Id", "requirement_id", default="REQ.UNKNOWN")
        result_value = classify(get_field(assessment, "Result", "result", default=get_field(control, "Result", "result")))
        message_value = get_field(assessment, "Message", "message", default=ctrl_message)
        case_name = f"{ctrl_id}.{req_id}"
        iac_total += 1
        record = {
            "name": case_name,
            "classname": "iac.privateer",
            "status": result_value,
            "message": message_value,
            "details": message_value,
        }
        if result_value == "failed":
          iac_failed.append(case_name)
        elif result_value == "warning":
          iac_warning.append(case_name)
        iac_cases.append(record)


if iac_data is None and RESULT_JSON:
  iac_notes.append("Privateer JSON missing; check plugin output.")


if iac_cases:
  iac_status = "passed"
  if iac_failed:
    iac_status = "failed"
  elif iac_warning:
    iac_status = "warning"
else:
  iac_status = "error" if RESULT_JSON else ("failed" if IAC_EXIT != 0 else "not_run")

if IAC_EXIT != 0 and iac_status == "passed":
  iac_status = "failed"

iac_summary = {
    "status": iac_status,
    "exit_code": IAC_EXIT,
    "log_path": IAC_LOG or None,
    "artifact_path": RESULT_JSON if RESULT_JSON else None,
    "total_requirements": iac_total,
    "failed_requirements": iac_failed,
    "warning_requirements": iac_warning,
}

if iac_notes:
  iac_summary["notes"] = iac_notes


runtime_data = load_json(RUNTIME_JSON)
runtime_status = "unknown"
runtime_message = "Runtime guard not executed."
if runtime_data:
  runtime_message = runtime_data.get("message", "") or ""
  runtime_status = classify(runtime_data.get("status"))
else:
  if RUNTIME_EXIT != 0:
    runtime_status = "failed"
    runtime_message = f"Runtime guard exited with code {RUNTIME_EXIT}."
  elif RUNTIME_JSON:
    runtime_status = "error"
    runtime_message = "Runtime JSON missing."  # file expected but absent

if RUNTIME_EXIT != 0 and runtime_status == "passed":
  runtime_status = "failed"

runtime_summary = {
    "status": runtime_status,
    "exit_code": RUNTIME_EXIT,
    "log_path": RUNTIME_LOG or None,
    "artifact_path": RUNTIME_JSON if runtime_data else None,
    "message": runtime_message,
}

overall = "passed"
for check in (manual_summary, iac_summary, runtime_summary):
  status = check.get("status", "unknown")
  if status in {"failed", "error"}:
    overall = "failed"
    break
  if status in {"warning", "unknown", "skipped", "not_run"} and overall == "passed":
    overall = "warning"


summary = {
    "generated_at": utc_now(),
    "mode": MODE,
    "strict": STRICT_FLAG,
    "overall_status": overall,
    "drift_note": DRIFT_NOTE or None,
    "artifacts": {
        "junit_xml": JUNIT_PATH,
        "summary_json": SUMMARY_PATH,
    },
    "checks": {
        "manual": manual_summary,
        "iac": iac_summary,
        "runtime": runtime_summary,
    },
}

if summary["drift_note"] is None:
  summary.pop("drift_note")


def build_testcases():
  cases = []

  manual_case = {
      "name": "manual.ccc_c04_cli",
      "classname": "ccc.validate",
      "status": manual_summary["status"],
      "message": manual_summary.get("message", ""),
      "details": manual_content,
  }
  cases.append(manual_case)

  for record in iac_cases:
    entry = record.copy()
    entry.setdefault("classname", "iac.privateer")
    cases.append(entry)

  runtime_details = read_text(RUNTIME_LOG)
  runtime_case = {
      "name": "runtime.flow_logs_guard",
      "classname": "ccc.validate",
      "status": runtime_summary["status"],
      "message": runtime_summary.get("message", ""),
      "details": runtime_details or read_text(RUNTIME_JSON),
  }
  cases.append(runtime_case)

  if DRIFT_NOTE:
    drift_case = {
        "name": "summary.drift_alignment",
        "classname": "ccc.validate",
        "status": "failed" if DRIFT_NOTE.strip().startswith("❗") else "passed",
        "message": DRIFT_NOTE,
        "details": DRIFT_NOTE,
    }
    cases.append(drift_case)

  return cases


testcases = build_testcases()

failures = sum(1 for case in testcases if case["status"] in {"failed", "error"})
skipped = sum(1 for case in testcases if case["status"] in {"warning", "unknown", "skipped", "not_run"})
errors = sum(1 for case in testcases if case["status"] == "error")

testsuite = ET.Element(
    "testsuite",
    attrib={
        "name": "ccc-validate",
        "tests": str(len(testcases)),
        "failures": str(failures),
        "errors": str(errors),
        "skipped": str(skipped),
        "timestamp": utc_now(truncate=False),
    },
)

for case in testcases:
  testcase = ET.SubElement(
      testsuite,
      "testcase",
      attrib={
          "name": case["name"],
          "classname": case.get("classname", "ccc.validate"),
      },
  )
  status = case["status"]
  message = case.get("message", "")
  details = case.get("details", "")
  if status in {"failed", "error"}:
    tag = "error" if status == "error" else "failure"
    failure = ET.SubElement(testcase, tag, attrib={"message": message or status})
    failure.text = details or message or status
  elif status in {"warning", "unknown", "skipped", "not_run"}:
    skipped_elem = ET.SubElement(testcase, "skipped", attrib={"message": message or status})
    skipped_elem.text = details or message or status


def ensure_parent(path):
  directory = os.path.dirname(path)
  if directory and not os.path.exists(directory):
    os.makedirs(directory, exist_ok=True)


ensure_parent(SUMMARY_PATH)
ensure_parent(JUNIT_PATH)

with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
  json.dump(summary, handle, indent=2)
  handle.write("\n")

tree = ET.ElementTree(testsuite)
tree.write(JUNIT_PATH, encoding="utf-8", xml_declaration=True)

print(f"Created {SUMMARY_PATH} and {JUNIT_PATH}")
PY
  printf "📦 CI artifacts saved to %s and %s\n" "$SUMMARY_JSON_PATH" "$JUNIT_XML_PATH"
else
  printf "⚠️  python3 not found; skipping CI artifact generation.\n"
fi

if [[ "$STRICT" == "true" ]]; then
  EXIT_CODE=0
  if [ $man_rc -ne 0 ]; then
    EXIT_CODE=1
  elif [ -f "$MANUAL_LOG" ] && grep -q "❌" "$MANUAL_LOG"; then
    EXIT_CODE=1
  fi
  if [ -n "$DRIFT_NOTE" ] && [[ "$DRIFT_NOTE" == ❗* ]]; then
    EXIT_CODE=1
  fi
  if [ $RUNTIME_RC -ne 0 ]; then
    EXIT_CODE=1
  elif [ -f "$RUNTIME_JSON" ] && command -v jq >/dev/null 2>&1; then
    RT_STATUS=$(jq -r '.status // ""' "$RUNTIME_JSON")
    if [[ "${RT_STATUS,,}" == "fail" || "${RT_STATUS,,}" == "failed" ]]; then
      EXIT_CODE=1
    fi
  fi
  if [ $IAC_RC -ne 0 ]; then
    EXIT_CODE=1
  elif [ -f "$RESULT_JSON" ] && command -v jq >/dev/null 2>&1; then
    FAILS=$(jq -r '
      def suites: (.Evaluation_Suites // .evaluation_suites // []);
      def ctrls(x): (x.Control_Evaluations // x.control_evaluations // []);
      def asmt(x): (x.Assessments // x.assessments // []);
      [suites[]? | ctrls(.)[]? | asmt(.)[]? | select((.Result // .result // "") == "Failed")] | length
    ' "$RESULT_JSON")
    if [ "$FAILS" -gt 0 ]; then
      EXIT_CODE=1
    fi
  fi
  exit $EXIT_CODE
fi
