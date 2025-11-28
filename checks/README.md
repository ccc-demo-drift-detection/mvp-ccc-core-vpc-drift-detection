# Checks

Entry points for validation, drift simulations, and summaries. Together they cover the assurance layers: quick heartbeat, intent/state (IaC), runtime truth, and drift detection. Outputs land under `output/` by default.

## Quick reference

- `check-1-manual.sh`: AWS CLI heartbeat (CIDR, Flow Logs) with tfstate fallback; fast smoke without plugins.
- `check-2-privateer.sh`: Lightweight Privateer run; minimal env handling; quick summary.
- `iac-guard.sh`: Full Privateer guard (env overlays, RPC fallback, per-control summary, strict gating); writes `output/ccc-vpc/*` and `output/iac-guard-report.txt`.
- `check-3-prowler.sh`: Runtime Prowler scan mapped to CCC controls; outputs HTML/JSON and `ccc-vpc-runtime-map.json` under `output/prowler/`.
- `runtime-guard.sh`: Targeted AWS CLI drift checks (Flow Logs, S3 encryption); emits `output/runtime/runtime-guard.json`.
- `drift-*`: Simulate/detect drift (e.g., disable Flow Logs) and snapshot under `output/drift/<ts>/`.
- `terraform-refresh.sh`: `plan -refresh-only` to surface provider-reported drift (`output/terraform/*`).
- `validate.sh` / `validate-live.sh`: Orchestrate manual → Privateer → runtime guard (and Prowler for live) for consolidated validation.
