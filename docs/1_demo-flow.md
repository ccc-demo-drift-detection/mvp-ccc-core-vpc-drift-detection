# CCC Readiness Demo Flow

This markdown visualises the end-to-end readiness demo, from control sourcing to drift detection history. Use it as a narrative during presentations or as an onboarding guide.

```
Start
 │
 │   (Preparation)
 │   ├─ Pull CCC layer2 YAML / control catalog
 │   ├─ Generate Privateer plugin (if needed)
 │   └─ Configure `.env.*` with region/profile toggles
 │
 ├──> Provision baseline IaC (make plan/apply)
 │      │
 │      ├─ Terraform deploys VPC, subnets, SGs, ACLs, Flow Logs intent
 │      └─ Demo web instance (nginx) ensures runtime surface exists
 │
 ├──> IaC Readiness Check (make guard / make validate)
 │      │
 │      └─ Privateer evaluates CCC controls (Flow Logs, Encryption, Region, etc.)
 │
 ├──> Runtime Guard (make validate / make runtime-guard)
 │      │
 │      └─ Custom script confirms Flow Logs status via AWS APIs
 │
 ├──> Runtime Scan (make scan)
 │      │
 │      └─ Prowler runs `vpc_flow_logs_enabled` (optionally SG/CloudTrail checks)
 │
 ├──> Report Aggregation (make report)
 │      │
 │      ├─ Merge Privateer + runtime guard + Prowler into one Markdown summary
 │      └─ Latest report symlink for quick reference
 │
 ├──> Snapshot Capture (make snapshot)
 │      │
 │      ├─ Hard-linked copy of readiness outputs (`output/snapshots/<ts>`)
 │      └─ Skip if no changes since previous snapshot
 │
 ├──> Drift Simulation (make drift-simulate-runtime)
 │      │
 │      └─ Delete Flow Logs to create out-of-band change
 │
 ├──> Drift Detection (make drift-detect-runtime / make validate)
 │      │
 │      ├─ Runtime guard re-checks Flow Logs (detects “missing at runtime”)
 │      └─ Report summarises intent vs reality
 │
 ├──> History Diff (make history-diff FROM=<ts1> TO=<ts2>)
 │      │
 │      └─ Markdown diff shows control/status changes between snapshots
 │
 └──> Continue / Iterate
        │
        ├─ Re-run IaC / runtime checks after remediation
        ├─ Extend reporting (dashboards, CI); multi-account readiness
        └─ Feed learnings into adoption playbooks / OSS contributions
```

## Narrative Summary

1. **Prep & Controls** – start from the CCC catalog (layer2 YAML), generate Privateer artefacts if needed, and set environment toggles (.env).
2. **Provision** – use Terraform to deploy the VPC, sample workloads, and Flow Log intent.
3. **IaC Check** – run Privateer via `make guard` or `make validate` to confirm control alignment before drift.
4. **Runtime Checks** – execute the custom runtime guard and Prowler scan to corroborate live AWS posture.
5. **Reporting** – `make report` composes a single Markdown summary; `make snapshot` captures the state.
6. **Drift** – simulate Flow Log deletion; re-run guard/report to catch the discrepancy.
7. **History** – use `make history-diff` to show the progression (controls flipping from Unknown to Passed, etc.).

Keep this file updated as demo capabilities expand (e.g., additional controls, dashboards, CI pipelines).
