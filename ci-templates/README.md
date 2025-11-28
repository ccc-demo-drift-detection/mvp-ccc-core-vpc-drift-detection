# CI Templates for `make validate-ci`

Use these samples to wire the CCC readiness demo into your CI pipelines. Each template runs `make validate-ci`, enforces strict exit codes, and uploads the machine-readable outputs (`output/ci/*.json`, `output/ci/*.xml`, logs).

- `github/validate-ci.yml` — drop under `.github/workflows/` or copy into an existing workflow.
- `gitlab/validate-ci.yml` — import as a standalone pipeline or include it via `include:` blocks. It ships three jobs: `deploy_demo` (runs `make apply` and publishes Terraform outputs/state), `validate_demo` (pulls those artifacts and runs `make validate-ci`), and an optional manual `destroy_demo` for teardown.

## How to customise
1. **Credentials** – the runtime guard talks to AWS. Configure credentials via your runner’s secrets (AWS identity, LocalStack endpoint, or skip runtime checks by toggling `ENABLE_VPC_FLOW_LOGS=false`).
2. **Environment toggles** – adjust `REGION`, `ENABLE_VPC_FLOW_LOGS`, and `ENV_FILE` to match whichever `.env.*` you keep in the repo. Many teams create `.env.ci` and inject secrets at runtime.
3. **Dependencies** – the templates install Terraform, Privateer, Prowler, jq, and Python. If your runners bake these in, remove the install steps. Conversely, add any extra tools (e.g., LocalStack, make plugins) your environment needs.
4. **Artifacts** – both templates upload the CI output folder plus raw JSON logs. The GitLab sample also shares `iac/terraform.tfstate` and `output/deployment-summary.json` between jobs so the validator can reuse the provisioned VPC details and, if you trigger `destroy_demo`, the same state is available for teardown.
5. **Strictness** – `make validate-ci` already exits non-zero on IaC, runtime, or manual failures. If you want to treat warnings as soft-failures, run the plain `make validate` target instead.

For more context on where `make validate-ci` sits in the overall readiness flow, see `docs/demo-flow.md` and `docs/make-commands.md`.
