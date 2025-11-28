# CCC VPC MVP — CCC CORE / CCC VPC Compliance

This repository contains my implementation of **Common Cloud Controls (CCC)** and **CCC VPC** checks for an AWS VPC. It is a demo‑ready toolkit that:

- Uses **Terraform** to create a reference VPC with toggles for good/bad CCC posture.
- Uses a **CCC-VPC** plugin developed based on privateer (submodule under `plugins/plugin-ccc-vpc`) to validate Terraform plan/state against CCC CORE/CCC VPC controls.
- Uses selectively **Prowler** and a small runtime guard to corroborate live AWS configuration.
- Demonstrates drift: simulate changes, detect them, snapshot outputs, and compare runs over time.

Note:Tests and coverage are still evolving.

---

## Quick Links

- Drift detection overview: `docs/1_drift-detection.md`
- Demo flow and story: `docs/1_demo-flow.md`
- CCC VPC control cheat sheet: `docs/2_ccc-vpc-control-cheatsheet.md`
- Make commands: `docs/2_make-commands.md`
- Container/CI usage: `docs/3_container-ci.md`
- Terraform stack overview: `iac/README.md`
- Plugin docs: `plugins/plugin-ccc-vpc/docs/flow.md`, `plugins/plugin-ccc-vpc/docs/overview.md`

---

## Quick Start (Make)

1. Prepare environment:
   - Update `ccc-vpc-mvp/.env.basic` with your required demo vars/values
   - Or set `ENV_FILE` to point at another env file for setting up test IAC env
2. Initialize and apply:
   - `make init`
   - `make plan`
   - `make apply`
3. Run demos and validation:
   - Good posture demo (all pass): `make demo-good`
   - Full validation (manual → IaC → runtime guard): `make validate`
   - Include provider drift scan: `make validate-live`
   - Runtime scan only (Prowler): `make scan`
4. Reporting and history:
   - Generate merged Markdown report: `make report`
   - Snapshot current outputs: `make snapshot`
   - Compare two snapshots: `make history-diff FROM=<ts1> TO=<ts2>`
5. Reset environment:
   - `make demo-reset`

Run `make help` for the full list of targets.

---

## What This Project Demonstrates

- **CCC CORE / CCC VPC intent checks (IaC)**  
  CCC-plugin evaluates CCC.CORE and CCC.VPC controls such as:
  - C02 (encryption at rest), C04 (logging), C06 (region allowlist), C09/C10/C11 (log protection, replication, KMS controls), plus others.
  - CCC VPC controls C01–C04: default network removal, auto public IP prevention, peering allowlists, Flow Logs.

- **Runtime corroboration (AWS APIs)**  
  - Prowler-based checks and a small runtime guard check Flow Logs, SG exposure, S3 encryption, peering boundaries.
  - Runtime outputs are mapped back to CCC IDs for demos and reports.

- **Drift narrative (intent vs runtime)**  
  - Scripts to simulate drift (e.g., disable Flow Logs) and then detect/report it.
  - Snapshot/diff tooling to show how posture changes across runs.

This is intended as a practical example rather than a complete CCC implementation; you can extend the plugin and flows for your own controls.

---

## Main Components

- **`iac/` — Terraform stack for provisioning demo environment**  
  VPC, subnets, security groups/NACLs, Flow Logs intent, sample workloads (e.g., nginx), IAM/KMS resources for encryption/MFA demos. Driven by env files and overlays.

- **`checks/` — validation and drift scripts**  
  - `check-1-manual.sh`: quick AWS CLI heartbeat (CIDR, Flow Logs).
  - `iac-guard.sh`, `check-2-privateer.sh`: Privateer IaC guard using `plugins/plugin-ccc-vpc/ccc-yaml/config.yml`.
  - `check-3-prowler.sh`: runtime Prowler scan mapped to CCC.
  - `runtime-guard.sh`, `drift-*`, `terraform-refresh.sh`: drift detection and provider‑truth helpers.
  - `validate.sh`, `validate-live.sh`: orchestrate manual → IaC → runtime flows.

- **`plugins/plugin-ccc-vpc/` — CCC-plugin used for IAC checks(submodule)**  
  - `evaluations/*.go`: control logic and data collection for CCC/CCC VPC.
  - `ccc-yaml/`: CCC catalog (source + layer2) and Privateer run config.
  - `docs/`: plugin flow, notes, and testing/coverage docs.

- **`docs/` — documentation**  
  - Top‑level docs for demo flows, drift detection, make commands, container CI.
  - Deeper notes and roadmaps under `docs/misc/` (status, tests, decision flows, future goals).
  - Demo env files under `docs/env_misc/`.

- **`scripts/` — helpers**  
  Shared libraries and utilities used by the checks and Make targets (env loading, snapshot/history diffs, etc.).

- **`output/` — generated artifacts**  
  - IaC guard outputs: `output/ccc-vpc/ccc-vpc.(json|yaml|log)`.
  - Runtime guard JSON: `output/runtime/runtime-guard.json`.
  - Prowler outputs: `output/prowler/*`.
  - Reports and snapshots: `output/reports/*`, `output/snapshots/*`, `output/drift/*`.
  These can be cleaned and regenerated as needed.

---

## Status and Next Steps

- Improving coverage and developin UI/UX around this

If you want to adapt this repo for your own organization, the main extension points are:
- Adding/adjusting controls in the Privateer plugin (`plugins/plugin-ccc-vpc/evaluations/*.go`).
- Extending runtime coverage and mappings in Prowler/runtime guard.
- Tweaking env files and overlays to model your own pass/fail scenarios.
