#!/usr/bin/env bash
# Generate a merged CCC readiness report combining IaC, runtime guard, and Prowler outputs.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/env-loader.sh"
OUTPUT_DIR="$ROOT_DIR/output"
REPORT_DIR="$OUTPUT_DIR/reports"

ENV_FILE_PATH=${ENV_FILE:-.env.basic}
load_env_with_includes "$ROOT_DIR" "$ENV_FILE_PATH" || true

REGION=${REGION:-${TF_VAR_REGION:-unknown}}
AWS_PROFILE=${AWS_PROFILE:-${TF_VAR_AWS_PROFILE:-}}
ENABLE_VPC_FLOW_LOGS=${ENABLE_VPC_FLOW_LOGS:-${TF_VAR_ENABLE_VPC_FLOW_LOGS:-unknown}}

resolve_vpc_id() {
  local tfstate="$ROOT_DIR/iac/terraform.tfstate"
  local resolved=""
  if [[ -n "${TARGET_VPC_ID:-}" ]]; then
    resolved=$TARGET_VPC_ID
  elif [[ -f "$tfstate" ]]; then
    resolved=$(jq -r '.outputs.vpc_id.value // empty' "$tfstate" 2>/dev/null || true)
    if [[ -z "$resolved" ]]; then
      resolved=$(jq -r '.resources[]? | select(.type=="aws_vpc" and .name=="demo") | .instances[0].attributes.id // empty' "$tfstate" 2>/dev/null || true)
    fi
  fi
  echo "${resolved:-}"
}

TARGET_VPC_ID=$(resolve_vpc_id)

mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
REPORT_PATH="$REPORT_DIR/report-$TIMESTAMP.md"

note_missing() {
  local heading=$1
  local reason=$2
  {
    echo "## $heading"
    echo "_${reason}_"
    echo
  } >> "$REPORT_PATH"
}

write_header() {
  {
    echo "# CCC Readiness Report"
    echo
    echo "- Generated: $TIMESTAMP"
    echo "- Region: $REGION"
    if [[ -n "$AWS_PROFILE" ]]; then
      echo "- AWS Profile: $AWS_PROFILE"
    fi
    echo "- Flow Logs intent (ENABLE_VPC_FLOW_LOGS): $ENABLE_VPC_FLOW_LOGS"
    if [[ -n "$TARGET_VPC_ID" ]]; then
      echo "- Target VPC (report focus): $TARGET_VPC_ID"
    fi
    echo
  } >> "$REPORT_PATH"
}

write_privateer_section() {
  local result_file="$OUTPUT_DIR/ccc-vpc/ccc-vpc.json"
  if [[ ! -f "$result_file" ]]; then
    note_missing "IaC (Privateer)" "No Privateer output found at $result_file. Run \`make guard\` first."
    return
  fi

  {
    echo "## IaC (Privateer)"
    echo
    echo "| Control | Result | Message |"
    echo "|---------|--------|---------|"
    jq -r '
      def suites: (.evaluation_suites // .Evaluation_Suites // []);
      [ suites[]? | (.control_evaluations // .Control_Evaluations // [])[]? |
        {
          id: (.control_id // .Control_Id // ""),
          result: (.result // .Result // ""),
          message: (.message // .Message // "")
        }
      ]
      | sort_by(.id)
      | .[]
      | "| \(.id) | \(.result) | \(.message | gsub("\\n"; " ")) |"
    ' "$result_file"
    echo
  } >> "$REPORT_PATH"
}

write_runtime_section() {
  local runtime_file="$OUTPUT_DIR/runtime/runtime-guard.json"
  if [[ ! -f "$runtime_file" ]]; then
    note_missing "Runtime Guard" "No runtime guard artifact found at $runtime_file. Run \`make runtime-guard\` or \`make validate\`."
    return
  fi

  local expect has status message endpoint vpc enc_status enc_message
  expect=$(jq -r '.expected_enable_flow_logs' "$runtime_file")
  has=$(jq -r '.has_flow_logs' "$runtime_file")
  status=$(jq -r '.flow_logs_status // "Unknown"' "$runtime_file")
  message=$(jq -r '.flow_logs_message // ""' "$runtime_file")
  enc_status=$(jq -r '.encryption_status // "Unknown"' "$runtime_file")
  enc_message=$(jq -r '.encryption_message // ""' "$runtime_file")
  endpoint=$(jq -r '.endpoint // ""' "$runtime_file")
  vpc=$(jq -r '.vpc_id // "unknown"' "$runtime_file")

  {
    echo "## Runtime Guard"
    echo
    echo "- VPC: $vpc"
    echo "- Expected Flow Logs: $expect"
    echo "- Flow Logs Present: $has"
    echo "- Status: $status"
    echo "- Message: $message"
    echo "- S3 Encryption Status: $enc_status"
    echo "- S3 Encryption Message: $enc_message"
    if [[ -n "$endpoint" ]]; then
      echo "- Endpoint override: $endpoint"
    fi
    echo
  } >> "$REPORT_PATH"
}

write_drift_section() {
  local latest_dir=""
  if compgen -G "$OUTPUT_DIR/drift/*" >/dev/null 2>&1; then
    latest_dir=$(ls -1dt "$OUTPUT_DIR"/drift/* | head -n1)
  fi

  if [[ -z "$latest_dir" ]]; then
    note_missing "Drift Snapshot" "No drift snapshots found under output/drift/. Run \`make drift-detect-runtime\`."
    return
  fi

  {
    echo "## Drift Snapshot"
    echo
    echo "- Latest snapshot: $(basename "$latest_dir")"
  } >> "$REPORT_PATH"

  local runtime_file="$latest_dir/runtime-guard.json"
  local iac_file="$OUTPUT_DIR/ccc-vpc/ccc-vpc.json"
  local iac_flow="unknown" iac_flow_msg="" iac_enc="unknown" iac_enc_msg=""
  if [[ -f "$iac_file" ]] && command -v jq >/dev/null 2>&1; then
    local ctrl_data
    ctrl_data=$(jq -r '
      def ctrl($id):
        def suites: (.evaluation_suites // .Evaluation_Suites // []);
        [ suites[]? | (.control_evaluations // .Control_Evaluations // [])[]? |
          { id: (.control_id // .Control_Id // ""),
            result: (.result // .Result // ""),
            message: (.message // .Message // "") }
        ] | map(select(.id == $id)) | if length > 0 then .[0] else {} end;
      [
        ctrl("CCC.VPC.C04").result // "unknown",
        ctrl("CCC.VPC.C04").message // "",
        ctrl("CCC.C02").result // "unknown",
        ctrl("CCC.C02").message // ""
      ] | @tsv
    ' "$iac_file")
    IFS=$'\t' read -r iac_flow iac_flow_msg iac_enc iac_enc_msg <<<"$ctrl_data"
  fi

  if [[ -f "$runtime_file" ]] && command -v jq >/dev/null 2>&1; then
    local flow_expect flow_has flow_status flow_msg vpc enc_status enc_msg enc_failed subnet_status subnet_msg subnet_actual
    flow_expect=$(jq -r '.checks["CCC.VPC.C04"].expected.enable_flow_logs // .expected_enable_flow_logs // "unknown"' "$runtime_file" 2>/dev/null || echo unknown)
    flow_has=$(jq -r '.checks["CCC.VPC.C04"].observed.has_flow_logs // .has_flow_logs // false' "$runtime_file" 2>/dev/null || echo false)
    flow_status=$(jq -r '.checks["CCC.VPC.C04"].status // .flow_logs_status // "Unknown"' "$runtime_file" 2>/dev/null || echo Unknown)
    flow_msg=$(jq -r '.checks["CCC.VPC.C04"].message // .flow_logs_message // ""' "$runtime_file" 2>/dev/null || echo "")
    vpc=$(jq -r '.vpc_id // ""' "$runtime_file" 2>/dev/null || echo "")
    enc_status=$(jq -r '.checks["CCC.C02"].status // .encryption_status // "Unknown"' "$runtime_file" 2>/dev/null || echo Unknown)
    enc_msg=$(jq -r '.checks["CCC.C02"].message // .encryption_message // ""' "$runtime_file" 2>/dev/null || echo "")
    enc_failed=$(jq -r '[.checks["CCC.C02"].observed.buckets[]? | select(.status=="Fail") | .bucket | select(length>0)] | join(",")' "$runtime_file" 2>/dev/null || echo "")
    subnet_status=$(jq -r '.checks["CCC.VPC.C02"].status // .public_subnet_status // "Unknown"' "$runtime_file" 2>/dev/null || echo Unknown)
    subnet_msg=$(jq -r '.checks["CCC.VPC.C02"].message // .public_subnet_message // ""' "$runtime_file" 2>/dev/null || echo "")
    subnet_actual=$(jq -r '.map_public_ip_on_launch' "$runtime_file" 2>/dev/null || echo null)

    {
      local flow_status_lower
      flow_status_lower=$(printf '%s' "$flow_status" | tr '[:upper:]' '[:lower:]')
      local iac_flow_lower
      iac_flow_lower=$(printf '%s' "$iac_flow" | tr '[:upper:]' '[:lower:]')
      echo "- CCC.VPC.C04: IaC=$iac_flow | Runtime=$flow_status (expected=$flow_expect, present=$flow_has, VPC=${vpc:-unknown})"
      if [[ "$flow_status_lower" != "pass" ]]; then
        echo "  - ❗ Drift: Flow Logs runtime check reported failure: $flow_msg"
      elif [[ "$iac_flow_lower" != "passed" ]]; then
        echo "  - ⚠️ Check IaC status: $iac_flow_msg"
      else
        echo "  - ✅ No drift detected for Flow Logs."
      fi
      if [[ -n "$iac_flow_msg" && "$iac_flow_msg" != "$flow_msg" ]]; then
        echo "  - IaC note: $iac_flow_msg"
      fi
      local enc_status_lower
      enc_status_lower=$(printf '%s' "$enc_status" | tr '[:upper:]' '[:lower:]')
      local iac_enc_lower
      iac_enc_lower=$(printf '%s' "$iac_enc" | tr '[:upper:]' '[:lower:]')
      echo "- CCC.C02: IaC=$iac_enc | Runtime=$enc_status"
      if [[ "$enc_status_lower" == "fail" ]]; then
        if [[ -n "$enc_failed" ]]; then
          echo "  - ❗ Drift: Required S3 encryption missing for bucket(s): $enc_failed"
        else
          echo "  - ❗ Drift: $enc_msg"
        fi
      elif [[ "$enc_status_lower" == "unknown" ]]; then
        echo "  - ⚠️ Unable to confirm S3 encryption: $enc_msg"
      elif [[ "$iac_enc_lower" != "passed" ]]; then
        echo "  - ⚠️ Check IaC status: $iac_enc_msg"
      else
        echo "  - ✅ No drift detected for S3 encryption."
      fi
      local subnet_status_lower
      subnet_status_lower=$(printf '%s' "$subnet_status" | tr '[:upper:]' '[:lower:]')
      echo "- CCC.VPC.C02: Runtime=$subnet_status"
      if [[ "$subnet_status_lower" == "fail" ]]; then
        local actual_display="$subnet_actual"
        if [[ "$actual_display" != "true" && "$actual_display" != "false" ]]; then
          actual_display="unknown"
        fi
        echo "  - ❗ Drift: MapPublicIpOnLaunch=$actual_display ($subnet_msg)"
      elif [[ "$subnet_status_lower" == "unknown" ]]; then
        echo "  - ⚠️ Unable to confirm public subnet state: $subnet_msg"
      else
        echo "  - ✅ No drift detected for public subnet configuration."
      fi
    } >> "$REPORT_PATH"
  else
    {
      echo "- Runtime guard artifact missing in snapshot."
    } >> "$REPORT_PATH"
  fi

  if [[ -d "$latest_dir/prowler" ]]; then
    echo "- Prowler evidence captured in snapshot." >> "$REPORT_PATH"
  fi
  if [[ -f "$latest_dir/runtime-guard.json" ]]; then
    echo "- Snapshot includes runtime-guard.json artifact." >> "$REPORT_PATH"
  fi

  echo >> "$REPORT_PATH"
}

write_prowler_section() {
  local prowler_file=""
  if compgen -G "$OUTPUT_DIR/prowler/prowler-output-*.json" >/dev/null 2>&1; then
    prowler_file=$(ls -1t "$OUTPUT_DIR/prowler"/prowler-output-*.json | head -n1)
  fi
  if [[ -z "$prowler_file" ]]; then
    note_missing "Runtime Scan (Prowler)" "No Prowler JSON found under output/prowler/. Run \`make scan\`."
    return
  fi

  {
    echo "## Runtime Scan (Prowler)"
    echo
    echo "_Source: $(basename "$prowler_file")_"
    echo
    if [[ -z "$TARGET_VPC_ID" ]]; then
      echo "_Target VPC not resolved; showing all findings from latest Prowler run._"
      echo
    else
      echo "_Filtered to findings scoped to VPC ${TARGET_VPC_ID}._"
      echo
    fi
    echo "| Resource | Status | Title |"
    echo "|----------|--------|-------|"
    local prowler_rows
    if [[ -n "$TARGET_VPC_ID" ]]; then
      prowler_rows=$(jq -r --arg target "$TARGET_VPC_ID" '
        .[]?
        | ($target | ascii_upcase) as $target_up
        | select(
            any(.Resources[]?;
              (.Id // "" | ascii_upcase) as $id
              | ($id == $target_up) or ($id | endswith($target_up)) or ($id | contains($target_up))
            )
          )
        | {
            resource: ($target),
            status: ((.Compliance.Status // "UNKNOWN") | ascii_upcase),
            title: (.Title // "")
          }
        | "| \(.resource) | \(.status) | \(.title | gsub("\\n"; " ")) |"
      ' "$prowler_file")
    else
      prowler_rows=$(jq -r '
        .[]? |
        {
          resource: (.Resources[0].Id // "unknown"),
          status: ((.Compliance.Status // "UNKNOWN") | ascii_upcase),
          title: (.Title // "")
        } |
        "| \(.resource) | \(.status) | \(.title | gsub("\\n"; " ")) |"
      ' "$prowler_file")
    fi

   if [[ -z "$prowler_rows" ]]; then
     if [[ -n "$TARGET_VPC_ID" ]]; then
        echo "| $TARGET_VPC_ID | PASS | No failing Prowler findings for the target VPC |"
      else
        echo "| n/a | INFO | No Prowler findings present |"
      fi
    else
      echo "$prowler_rows"
    fi
    echo
  } >> "$REPORT_PATH"
}

write_summary_section() {
  echo "## Summary" >> "$REPORT_PATH"
  echo >> "$REPORT_PATH"
  # IaC summary
  local iac_summary="- IaC guard: missing (run \`make guard\`)"
  if [[ -f $OUTPUT_DIR/ccc-vpc/ccc-vpc.json ]]; then
    local iac_stats
    iac_stats=$(jq -r '
      def suites: (.evaluation_suites // .Evaluation_Suites // []);
      [ suites[]? | (.control_evaluations // .Control_Evaluations // [])[]? |
        { result: (.result // .Result // ""),
          message: (.message // .Message // "") }
      ] as $controls
      | {
          total: ($controls | length),
          fails: ($controls | map(select(.result=="Failed"))),
          warns: ($controls | map(select(.result=="Warning" or .result=="Needs Review")))
        }
      | [
          (.total | tostring),
          ((.fails | length) | tostring),
          ((.warns | length) | tostring),
          ((.fails | first // {message:""}) .message),
          ((.warns | first // {message:""}) .message)
        ] | @tsv
    ' "$OUTPUT_DIR/ccc-vpc/ccc-vpc.json")
    IFS=$'\t' read -r iac_total iac_fail_count iac_warn_count iac_fail_msg iac_warn_msg <<<"$iac_stats"
    if [[ "$iac_fail_count" -ne 0 ]]; then
      local detail=""
      if [[ -n "$iac_fail_msg" ]]; then
        detail=" ($iac_fail_msg)"
      fi
      iac_summary="- IaC guard: **FAIL** (failed=$iac_fail_count, warn=$iac_warn_count)$detail"
    elif [[ "$iac_warn_count" -ne 0 ]]; then
      local detail=""
      if [[ -n "$iac_warn_msg" ]]; then
        detail=" ($iac_warn_msg)"
      fi
      iac_summary="- IaC guard: **WARN** (warn=$iac_warn_count)$detail"
    else
      iac_summary="- IaC guard: **PASS** (controls=$iac_total)"
    fi
  fi
  echo "$iac_summary" >> "$REPORT_PATH"

  # Runtime summary
  local runtime_summary="- Runtime guard: missing (run \`make validate\`)"
  if [[ -f $OUTPUT_DIR/runtime/runtime-guard.json ]]; then
    local flow_status flow_msg enc_status enc_msg
    flow_status=$(jq -r '.flow_logs_status // "Unknown"' "$OUTPUT_DIR/runtime/runtime-guard.json")
    flow_msg=$(jq -r '.flow_logs_message // ""' "$OUTPUT_DIR/runtime/runtime-guard.json")
    enc_status=$(jq -r '.encryption_status // "Unknown"' "$OUTPUT_DIR/runtime/runtime-guard.json")
    enc_msg=$(jq -r '.encryption_message // ""' "$OUTPUT_DIR/runtime/runtime-guard.json")
    local flow_detail="" enc_detail=""
    if [[ -n "$flow_msg" ]]; then
      flow_detail=" ($flow_msg)"
    fi
    if [[ -n "$enc_msg" ]]; then
      enc_detail=" ($enc_msg)"
    fi
    runtime_summary="- Runtime guard: Flow Logs=$flow_status$flow_detail; S3=$enc_status$enc_detail"
  fi
  echo "$runtime_summary" >> "$REPORT_PATH"

  # Drift summary
  local drift_summary="- Drift snapshot: none recorded"
  if compgen -G "$OUTPUT_DIR/drift/*" >/dev/null 2>&1; then
    local latest_dir
    latest_dir=$(ls -1dt "$OUTPUT_DIR"/drift/* | head -n1)
    local runtime_file="$latest_dir/runtime-guard.json"
    if [[ -f "$runtime_file" ]] && command -v jq >/dev/null 2>&1; then
      local flow_status flow_msg enc_status enc_msg flow_expect flow_has
      flow_status=$(jq -r '.checks["CCC.VPC.C04"].status // .flow_logs_status // "Unknown"' "$runtime_file" 2>/dev/null || echo Unknown)
      flow_msg=$(jq -r '.checks["CCC.VPC.C04"].message // .flow_logs_message // ""' "$runtime_file" 2>/dev/null || echo "")
      flow_expect=$(jq -r '.checks["CCC.VPC.C04"].expected.enable_flow_logs // .expected_enable_flow_logs // "unknown"' "$runtime_file" 2>/dev/null || echo unknown)
      flow_has=$(jq -r '.checks["CCC.VPC.C04"].observed.has_flow_logs // .has_flow_logs // false' "$runtime_file" 2>/dev/null || echo false)
      enc_status=$(jq -r '.checks["CCC.C02"].status // .encryption_status // "Unknown"' "$runtime_file" 2>/dev/null || echo Unknown)
      enc_msg=$(jq -r '.checks["CCC.C02"].message // .encryption_message // ""' "$runtime_file" 2>/dev/null || echo "")
      local detail=""
      if [[ $(printf '%s' "$flow_status" | tr '[:upper:]' '[:lower:]') != "pass" ]]; then
        detail="❗ Flow Logs $flow_status ($flow_msg)"
      elif [[ $(printf '%s' "$enc_status" | tr '[:upper:]' '[:lower:]') != "pass" ]]; then
        detail="⚠️ S3 $enc_status ($enc_msg)"
      else
        detail="✅ No drift detected"
      fi
      drift_summary="- Drift snapshot: $(basename "$latest_dir") — $detail"
    else
      drift_summary="- Drift snapshot: $(basename "$latest_dir") — runtime artifact missing"
    fi
  fi
  echo "$drift_summary" >> "$REPORT_PATH"

  # Prowler summary
  local prowler_summary="- Prowler scan: none (run \`make scan\`)"
  if compgen -G "$OUTPUT_DIR/prowler/prowler-output-*.json" >/dev/null 2>&1; then
    local latest_prowler
    latest_prowler=$(ls -1t "$OUTPUT_DIR/prowler"/prowler-output-*.json | head -n1)
    prowler_summary="- Prowler scan: $(basename "$latest_prowler")"
    if [[ -n "$TARGET_VPC_ID" ]]; then
      prowler_summary+=" (filtered to $TARGET_VPC_ID)"
    fi
  fi
  echo "$prowler_summary" >> "$REPORT_PATH"

  echo >> "$REPORT_PATH"
}

main() {
  mkdir -p "$OUTPUT_DIR/runtime"
  write_header
  write_summary_section
  write_privateer_section
  write_runtime_section
  write_drift_section
  write_prowler_section

  ln -sf "report-$TIMESTAMP.md" "$REPORT_DIR/latest.md"
  echo "Report written to $REPORT_PATH"
}

main "$@"
