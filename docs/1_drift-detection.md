# Drift Detection — Narrative and Approach

This document explains how we demonstrate CCC-aligned drift detection using complementary signals from IaC, runtime scanning, and a lightweight runtime guard. It clarifies what each piece contributes and why a hybrid is necessary.

## Objective
- Use CCC controls (starting with CCC.C04 Flow Logs, CCC.C02 Encryption, CCC.C06 Region) as the benchmark for readiness.
- Detect drift: differences between intended posture (IaC/config) and runtime truth (AWS APIs) with clear, demoable evidence.

## System Architecture (Overview + Figure)

The solution is a small, layered system designed for demos and extensibility. It separates “intent/state” from “runtime truth” and uses a thin, explainable connector to declare drift and capture evidence.

```mermaid
flowchart LR
  subgraph IaC_Path[Intent / IaC]
    TF[Terraform\n(iac/*)] -->|state/plan| PRIV[Privateer\n(IaC checker)]
    PRIV -->|CCC results\noutput/ccc-vpc/*| OUT1[(Artifacts)]
  end

  subgraph Runtime_Path[Runtime]
    AWS[(AWS APIs)] --> PROW[Prowler\n(runtime scan)]
    AWS --> GUARD[Runtime Guard\n(AWS CLI)]
    PROW -->|reports\noutput/prowler/*| OUT2[(Artifacts)]
    GUARD -->|runtime-guard.json| OUT3[(Artifacts)]
  end

  subgraph Drift_Aggregation[Detection & Evidence]
    OUT1 --> AGG[Drift Detect\n(merge/compare)]
    OUT2 --> AGG
    OUT3 --> AGG
    AGG --> SNAP[(output/drift/<ts>/)]
  end

  style OUT1 fill:#eef,stroke:#99f
  style OUT2 fill:#eef,stroke:#99f
  style OUT3 fill:#eef,stroke:#99f
  style SNAP fill:#efe,stroke:#9c9
```

Key idea: Any disagreement between “intent/state” and “runtime truth” is flagged as drift; all signals are preserved as artifacts for auditing and demos.

## Components (What, Why, Where)

- Terraform (baseline IaC)
  - Purpose: Provide a reproducible VPC with toggles to exercise CCC controls (Flow Logs, encryption).
  - Files: `iac/main.tf`, `iac/variables.tf`, `iac/outputs.tf`, `iac/tags.tf`.

- Privateer (IaC checker)
  - Purpose: Evaluate CCC controls against Terraform state/plan and env toggles; fast, CI‑friendly.
  - Coverage: CCC.VPC.C01–C04 (default network removal, subnet auto-IP, peering allowlist, Flow Logs) plus supporting catalog controls.
  - Files: `checks/iac-guard.sh`, `plugins/plugin-ccc-vpc/ccc-yaml/config.yml`, plugin code in `plugins/plugin-ccc-vpc/*`.
  - Output: `output/ccc-vpc/ccc-vpc.(json|yaml|log)`.

- Prowler (runtime scanner)
  - Purpose: Verify live AWS config via APIs; corroborates CCC.VPC.C02/C03/C04 (Flow Logs, subnet auto-IP, peering trust boundaries).
  - Files: `checks/check-3-prowler.sh`.
  - Output: `output/prowler/*` (HTML/JSON when installed) plus `output/prowler/ccc-vpc-runtime-map.json` / `output/prowler/ccc-vpc-runtime-checks.txt`.

- Runtime Guard (custom connector)
  - Purpose: Minimal AWS CLI probes tied to CCC signals (e.g., C04 Flow Logs, C02 encryption); compares runtime to toggles; emits small JSON used for drift lines.
  - Files: `checks/runtime-guard.sh`.
  - Output: `output/runtime/runtime-guard.json`.

- Drift Simulation
  - Purpose: Create real runtime drift out‑of‑band (delete Flow Logs) for demos.
  - Files: `checks/drift-simulate-runtime.sh`.

- Drift Detection (aggregation)
  - Purpose: Run guard (+ optional Prowler), snapshot artifacts, and print concise drift lines.
  - Files: `checks/drift-detect-runtime.sh`.
  - Output: `output/drift/<timestamp>/`.

- Terraform refresh-only drift (provider truth)
  - Purpose: Ask Terraform to reconcile state with runtime via `plan -refresh-only`, surfacing provider-reported drift alongside IaC/runtime evidence.
  - Files: `checks/terraform-refresh.sh`.
  - Output: `output/terraform/refresh-plan.json`, `output/terraform/refresh-summary.json`.

- Orchestration
  - Purpose: Make targets to run components independently or as chained demos.
  - Files: `Makefile` (targets: `demo-good`, `demo-runtime`, `demo-drift-runtime`, `demo-all`, plus individual commands).

## Scenarios and Variations

- Hybrid (Priority‑1)
  - Apply IaC → Privateer (intent/state) → Runtime guard + Prowler (runtime) → declare drift if disagreement; snapshot evidence.

- Runtime‑Only (no IaC)
  - Compare runtime posture against a CCC policy profile or against a prior baseline; treat regressions as drift (see “Runtime‑Only Scenario” below).

- IaC‑Only (CI)
  - Gate merges/deploys on Privateer results; use `IAC_GUARD_STRICT=true` for non‑zero on failure.

## Data Flow (Signals → Decision → Evidence)

- Signals in: Terraform state/plan (intent/state), AWS API results (runtime), environment toggles/policy.
- Decision: Compare intent vs runtime and produce a single drift line per control (“expected=true but missing at runtime”).
- Evidence: Persist all inputs and results to `output/` and snapshot directories for auditability and demos.

## Why CCC
- Structured controls: CCC gives stable control IDs (e.g., CCC.C04) and testable requirements (TRxx) to anchor results.
- Narrative clarity: Results map to controls stakeholders recognize, improving trust in findings.
- Practical scope: Some controls are straightforward to verify (e.g., Flow Logs), others need interpretation or are context‑dependent.

## Tools and Roles
- Privateer (IaC intent/state)
  - Reads Terraform state/plan and project variables; no AWS API calls.
  - Strength: Fast, deterministic, shift‑left; great for CI and pre‑deploy checks.
  - Limitation: No runtime truth; can miss out‑of‑band changes or unmanaged resources.

- Prowler (Runtime truth)
  - Scans live AWS accounts via APIs; rich checks including `vpc_flow_logs_enabled`.
  - Strength: Finds actual misconfigurations and unmanaged assets; broad coverage.
  - Limitation: No knowledge of your IaC intent; a fail might be expected by design, not drift.

- Runtime Guard (Glue/middle connector)
  - Custom script using AWS CLI for targeted checks tied to CCC controls (e.g., VPC Flow Logs for CCC.C04).
  - Strength: Compares runtime to intended toggles; produces a small, explainable JSON artifact for drift.
  - Limitation: Narrow scope by design; we keep it focused and fast for demos.

## Why No Single Tool Is Enough
- Only IaC (Privateer) ⇒ cannot confirm runtime truth; misses console edits and changes from other pipelines.
- Only Runtime (Prowler) ⇒ cannot infer your policy/intent; flags issues that may be intentional.
- Hybrid ⇒ intent + truth + narrow glue to declare “drift” when they disagree.

## Drift Definition (Priority‑1)
- IaC indicates a control should be enabled (e.g., Flow Logs), but runtime shows it is not present ⇒ Drift.
- IaC indicates disabled, but runtime shows it enabled ⇒ Drift (unexpected runtime deviation).
- Both align (enabled/enabled or disabled/disabled) ⇒ Aligned.

## Signals and Evidence
- IaC signals (Privateer): `output/ccc-vpc/ccc-vpc.(json|yaml)` with control results and messages.
- Runtime scan (Prowler): `output/` HTML/JSON; good for broader context and auditors.
- Runtime guard JSON: `output/runtime/runtime-guard.json` with intent vs runtime fields for fast, clear drift lines.
- Terraform refresh-only drift: `output/terraform/refresh-summary.json` (JSON summary) and `output/terraform/refresh-plan.json` (full provider diff).
- Optional (future): enrich the refresh summary with attribute-level diffs for high-signal resources.

## Demo Flows and Commands
- IaC baseline and guard
  - `make demo-good` → plan/apply + Privateer; shows intended posture
  - `make plugin-run` or `./checks/iac-guard.sh`

- Runtime snapshot
  - `make demo-runtime` → runtime guard + Prowler check
  - Direct: `make runtime-guard` and `make scan`
- Drift simulation and detection (runtime-focused)
  - Simulate: `make drift-simulate-runtime` (deletes VPC Flow Logs out-of-band)
  - Detect: `make drift-detect-runtime` (runs runtime guard; snapshots to `output/drift/<ts>/` and prints drift line)
  - Combined: `make demo-drift-runtime`

- End-to-end (chain IaC + runtime + drift)
  - `make demo-all`
  - `make validate` to capture Manual → Privateer → Runtime summary (use after `make demo-good` and again post-drift)
  - `make validate-live` to re-run validation with the long-running provider drift scan (`terraform plan -refresh-only`)

Environment tip: set `AWS_PROFILE` to choose credentials — e.g., `awslocal` for LocalStack demos or `awscloud` for a read-only AWS account — and flip `USE_LOCALSTACK=false` whenever you want Terraform and the runtime guard to target real AWS endpoints instead of LocalStack. Scripts fall back to explicit `AWS_ACCESS_KEY` / `AWS_SECRET_KEY` when no profile is supplied.

Observation: Some Prowler checks (for example `vpc_flow_logs_enabled`) only surface a VPC in results when runtime resources exist behind it. After `terraform apply` creates the demo EC2 instance in the public subnet, Prowler begins reporting the VPC (our target shows as a PASS alongside the four legacy FAILs); without associated resources the check emitted no findings at all.

## Example Output (Drift Line)
- “Drift: Flow Logs expected=true but missing at runtime (VPC=vpc-xxxx)”

## Limitations and Nuance
- CCC completeness: Some controls require business context or workload specifics; results may be Unknown without inputs.
- LocalStack vs AWS: Not all features are available in LocalStack; plan‑based fallbacks and clear messaging help avoid false negatives.
- Encryption signals: S3 encryption detection relies on dedicated SSE resources for deterministic IaC mapping; runtime checks may need per‑service APIs.
- Region policy (CCC.C06): Straightforward in IaC; runtime confirmation is implicit but not always necessary to call drift.

## Roadmap (to deepen coverage)
- Parse `terraform plan -refresh-only -json` and include provider‑reported drift in summaries. ✅ Implemented via `checks/terraform-refresh.sh` and surfaced in `make validate`.
- Expand runtime guard to a small set of additional CCC checks (encryption spot‑checks, critical SG rules).
- Add a merged rollup (`make validate`) and a snapshots diff (`output/history/<ts>/`) with a simple before/after view.
- Optional CI policy: fail build on any detected drift (toggleable).

## Runtime‑Only Scenario (No IaC or Orchestration)

When an account lacks Terraform or any orchestration metadata, we still detect “drift” — but we define it as deviation from policy/baseline rather than from code.

- What drift means here:
  - Deviation from a defined CCC policy profile (your runtime policy), or
  - Deviation from a previously captured runtime baseline (last known compliant state).

- Tools to use:
  - Prowler (runtime): broad AWS checks and export formats; strong coverage but no IaC intent.
  - Custom runtime guard (AWS CLI/SDK): crisp signals for key CCC controls (e.g., CCC.C04 Flow Logs) with small JSON outputs.
  - Optional AWS services: AWS Config (resource history, conformance packs), Security Hub, EventBridge for triggers.

- Minimum viable approach:
  - Define a small CCC runtime policy profile (YAML): require Flow Logs, require S3 encryption, allowed regions, critical SG rules.
  - Collect runtime facts: run Prowler for breadth; run a thin guard for specific CCC controls you care about most.
  - Evaluate and baseline: produce CCC‑mapped Pass/Fail/Unknown results and save as a timestamped snapshot.
  - Detect later: rerun and compare to the baseline; any control that regresses or config that changes is “runtime drift.”

- Robust variants:
  - Map Prowler findings to CCC control IDs via a small mapping layer for consistent CCC reporting.
  - Enable AWS Config to record resource changes and surface drift events (e.g., Flow Logs deleted on a VPC).
  - Schedule scans (cron/EventBridge) and append to a history folder for a time series.

- Strengths and limits:
  - Strengths: Works without IaC, produces CCC‑framed results, finds unmanaged resources, fits existing accounts.
  - Limits: No code intent means you can’t judge “approved” vs “unapproved” change; some CCC controls need business inputs → report Unknown when missing.

This runtime‑only mode complements the hybrid approach: you can start with policy/baseline today and add IaC intent later without changing the CCC framing.
