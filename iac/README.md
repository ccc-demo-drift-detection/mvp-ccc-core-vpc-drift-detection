# Terraform Infrastructure Overview

This directory contains the baseline Terraform configuration that powers the CCC VPC demo. It provisions a small but representative AWS environment that can be flipped between "good" and "failure" postures using the environment overlays under `envs/`.

## What Terraform Builds

**Networking**
- `aws_vpc.demo` (`10.42.0.0/16`) with DNS support enabled.
- Optional `aws_default_vpc.managed` when `MANAGE_DEFAULT_VPC=true` to demonstrate CCC.VPC.C01 failures.
- Public and private subnets, route tables, and internet gateway attachments.
- Network ACL with allow/deny rules driven by the CCC ingress variables.
- Security groups for web and database tiers, with rules sourced from the allowlist CSV variables.

**Logging & Monitoring**
- VPC Flow Logs (`aws_flow_log.vpc`) targeting a CloudWatch log group and protected by a dedicated IAM role + KMS key.
- CloudTrail trail, log bucket, and IAM role/metric filter resources used for CCC.C04/CCC.C07 scenarios.
- Enumeration alert CloudWatch metric filter + alarm.

**Storage & Encryption**
- Sample encrypted S3 bucket (`aws_s3_bucket.encrypted`) with optional SSE-KMS.
- Optional unencrypted bucket and replication pair to simulate CCC.C02 failures.
- Customer-managed KMS keys, aliases, and rotation toggles for encryption demos.

**Workload & IAM**
- Demo EC2 instance (`aws_instance.web`) that can be enabled for runtime scanning.
- IAM roles/policies for flow logs, demo admin MFA enforcement, CloudTrail delivery, and replication scenarios.
- Optional VPC peering and default VPC control knobs for VPC-specific CCC controls.

## Key Feature Toggles

All runtime/env toggles are declared in `variables.tf` and surfaced through the `.env.*` files at the repo root.

- `.env.basic` — minimal compliant baseline (used by default).
- `envs/env.good_demo` — baseline plus demo workload (EC2 instance) for runtime checks.
- `envs/env.bad_*` — targeted failure overlays (e.g., `env.bad_c04`, `env.bad_vpc_c02`).

Use `ENV_FILE=<path>` with `make` commands or scripts to switch posture, for example:

```bash
ENV_FILE=envs/env.bad_c04 make apply
ENV_FILE=.env.basic ./checks/validate.sh
```

## Inspecting the Infrastructure

- `terraform show iac/tfplan.out` — review the last plan output.
- `terraform state list` (from `iac/`) — enumerate created resources.
- `jq` queries on `iac/terraform.tfstate` — inspect attributes the Privateer plugin consumes.

The helper `make vars` prints the resolved variable set (including values from the selected `ENV_FILE`).

## Useful Commands

- `make init` / `make plan` / `make apply` — standard Terraform workflow.
- `make destroy` — tear everything down with the current toggle values.
- `make demo-good` / `make demo-bad` — provision good or intentionally failing postures.
- `make validate` — run the end-to-end validation (manual + IaC + runtime guard).

Refer to `docs/make-commands.md` for a complete command reference and to `docs/tests-summary.md` for control coverage details.
