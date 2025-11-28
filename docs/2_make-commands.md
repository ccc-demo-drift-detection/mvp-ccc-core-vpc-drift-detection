# Make Command Reference

This project’s `Makefile` wraps the typical workflow into a set of easy commands. Keep this handy (and update it when new targets appear) so the demo flow stays clear.

## General
- `make help` — print the annotated list of targets (mirrors this document).
- `make all` — run `init`, `apply`, `guard`, and `scan` in sequence for a fresh baseline.
- `make vars` — print the resolved variables (region, profile, toggles, etc.).

## Terraform Lifecycle
- `make init` — run `terraform init` inside `iac/` to download providers and set up state.
- `make plan` — create a Terraform plan (`tfplan.out`/`tfplan.json`) using the current env vars.
- `make apply` — apply the Terraform plan with the same variables (region, Flow Log toggle, etc.).
- `make destroy` — tear the stack down with `terraform destroy` using those variables.
- `make clean` — wipe Terraform cache/state and the generated `output/` artifacts.

## Validation & Drift Detection
- `make guard` — run the Privateer IaC guard (`checks/iac-guard.sh`).
- `make validate` — orchestrate manual → Privateer → runtime guard with drift summary (`checks/validate.sh`).
- `make validate-live` — same as `make validate`, but keeps the long-running Terraform provider drift check enabled (`terraform plan -refresh-only`).
- `make validate-ci` — validation in CI mode (strict exit + `output/ci/validate-{summary.json,junit.xml}`).
- `make runtime-guard` — standalone runtime guard (Flow Logs, S3 encryption) without the full validation flow.
- `make drift-simulate-runtime` — delete Flow Logs to simulate runtime drift.
- `make drift-detect-runtime` — rerun the guard, print drift summary, and snapshot evidence under `output/drift/<ts>/`.

## Reporting & History
- `make scan` — call Prowler for the CCC VPC bundle (Flow Logs, subnet auto-IP, peering trust boundaries).
- `make report` — generate a merged readiness report in `output/reports/`.
- `make snapshot` — capture the current outputs under `output/snapshots/<timestamp>/` (unchanged files are hard-linked to the previous snapshot; skipped if nothing has changed).
- `make history-diff FROM=<ts1> TO=<ts2>` — compare two snapshots and write a diff summary.

## Demo Shortcuts
- `make demo-good` — apply the compliant posture (`envs/env.good_demo`), then run the Privateer plugin.
- `make demo-bad` — apply the failure overlay (`envs/env.bad_all`) and show plugin findings (non-strict exit).
- `make demo-bad-ci` — same failure overlay, but strict exit to mimic CI behaviour.
- `make demo-reset` — destroy resources and clean generated outputs.
- `make demo-runtime` — runtime guard + Prowler (quick runtime snapshot).
- `make demo-drift-runtime` — simulate runtime drift and immediately detect it.
- `make demo-all` — full storyline: good IaC posture → runtime check → drift demo.

## Privateer Helpers
- `make plugin-list` — list installed Privateer plugins.
- `make plugin-run` — run the VPC Privateer plugin (non-strict exit).
- `make plugin-run-ci` — same, but strict fail-on-control failures.
- `make plugin-build` — rebuild the external plugin when `PLUGIN_DIR` is set.

> Tip: All commands honor `ENV_FILE`, `AWS_PROFILE`, and `USE_LOCALSTACK`. Set those before running so the Makefile selects the right credentials and endpoints.

Keep this file updated whenever new Make targets are added or behavior changes.
