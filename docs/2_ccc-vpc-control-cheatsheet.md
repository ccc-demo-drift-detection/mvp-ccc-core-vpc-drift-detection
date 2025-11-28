# CCC VPC Control Cheat Sheet

Quick reference for the controls evaluated in the demo. Use this to explain what each check does and where it is enforced across IaC (Privateer) and runtime (Prowler/runtime guard).

| Control | Focus | Privateer (IaC evidence) | Runtime corroboration |
|---------|-------|---------------------------|-----------------------|
| **CCC.C01** | TLS / SSH hardening on exposed ports | `check_tls_enforced` validates internet-facing rules allow only TLS ports; `check_ssh_network_restrictions` ensures SSH is restricted to trusted sources | – |
| **CCC.C02** | Encryption at rest (KMS by default) | `check_encryption_at_rest` fails on any unencrypted or non-KMS storage when strict mode enabled | Runtime guard queries S3 bucket encryption and surfaces drift; future Prowler bundle TBD |
| **CCC.C03** | MFA enforcement & admin network allowlists | `check_mfa_enforced` inspects IAM deny policies; `check_security_group_ingress_allowlist` / `check_authentication_allowlists` enforce trusted sources | – (runtime SG validation planned) |
| **CCC.C04** | CloudTrail logging for access/change events | `check_cloudtrail_logging` confirms multi-region CloudTrail + log delivery | Runtime guard currently focuses on Flow Logs (CCC.VPC.C04); CloudTrail runtime scan pending |
| **CCC.C05** | Block untrusted ingress | `check_security_group_ingress_allowlist` enforces IPv4/IPv6/SG allowlists (TR03/04 still placeholder) | – |
| **CCC.C06** | Deployment region allowlist | `check_region_allowed` compares Terraform region to allowed CSV list | – |
| **CCC.C07** | Enumeration alerting | `check_enumeration_logging` verifies CloudTrail metric filter + alarm | – |
| **CCC.C08** | Multi-AZ replication | `check_multi_zone_replication` ensures subnets span multiple AZs | Manual toggle: set both AZ vars equal to simulate failure |
| **CCC.C09** | Log storage protection | `check_log_protection` enforces CMEK + retention on log destinations (e.g., Flow Log group bucket) | – (runtime guard covers bucket encryption under CCC.C02) |
| **CCC.C10** | Trusted replication targets | `check_replication_trust_boundaries` validates replication allowlists / regions | – (runtime roadmap) |
| **CCC.C11** | CMEK policy & rotation | `check_kms_key_controls` verifies CMEK usage, approved algorithms, and rotation expectations | Runtime guard highlights KMS enforcement drift via CCC.C02 bucket check |
| **CCC.C12** | Restrict high-risk ingress | `check_network_access_restrictions` flags world-open or non-allowlisted high ports | – |
| **CCC.VPC.C01** | Remove default AWS network artefacts | `check_default_network_removed` detects `aws_default_*` resources | – (IaC only) |
| **CCC.VPC.C02** | Prevent auto public IPs | `check_public_subnets_no_public_ip` detects auto-assign subnets / resource associations | Prowler `vpc_subnet_no_public_ip_by_default` |
| **CCC.VPC.C03** | Authorize VPC peering | `check_vpc_peering_authorized` validates peer allowlists | Prowler trust-boundary checks: `vpc_peering_routing_tables_with_least_privilege`, `vpc_endpoint_connections_trust_boundaries`, `vpc_endpoint_services_allowed_principals_trust_boundaries` |
| **CCC.VPC.C04** | Capture VPC network traffic | `check_vpc_flow_logs_enabled` ensures Flow Log resources exist (plan/state fallback) | Runtime guard Flow Log drift detection + Prowler `vpc_flow_logs_enabled` |

> _Partial coverage_: CCC.C05 TR03/04 and some replication/key lifecycle nuances still use reusable stubs—track completion in `docs/0    To-do.md`.

> _MFA evidence:_ CCC.C03 now inspects IAM inline policies (e.g., `ccc-demo-admin`) for `aws:MultiFactorAuthPresent` conditions. The testing playbook documents how to toggle the policy on/off in Terraform to demonstrate pass/fail outcomes.

Environment toggles:
- `.env.basic` + `envs/env.good_demo` or the `envs/env.bad_*` overlays set `PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP`, `ASSOCIATE_PUBLIC_IP_WEB_INSTANCE`, and `CREATE_DEMO_VPC_PEERING` to flip CCC.VPC.C02/C03 outcomes.
- `ALLOWED_VPC_PEER_*_CSV` variables feed the Privateer allowlist for CCC.VPC.C03.
- `ENFORCE_MFA_DEMO_ADMIN_ROLE` toggles the IAM deny policy used to prove CCC.C03 pass/fail states.
- `ENABLE_CORE_AUDIT_LOGS` controls creation of the demo CloudTrail trail for CCC.C04.
- `ENABLE_ENUMERATION_ALERTS` toggles the CloudTrail metric filter/alarm used for CCC.C07.
- `APPROVED_DEPLOYMENT_REGIONS_CSV` sets the deployment allowlist used by CCC.C06 (with `CCC_BENCHMARK_ALLOWED_REGIONS` documenting the catalog baseline).
- `CCC_C01_ALLOW_WORLD_TLS_INGRESS` toggles the world-open ingress rule used for CCC.C01; `ALLOWED_INGRESS_*` CSV vars drive the CCC.C05 allowlist.
- `CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS` controls whether CCC.C12 allows the world-open ingress rule (`false` recreates 0.0.0.0/0`).
- `MANAGE_DEFAULT_VPC` manages the cloud default VPC to simulate CCC.VPC.C01 failures (leave `false` for compliant runs).
- `PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP` / `ASSOCIATE_PUBLIC_IP_WEB_INSTANCE` / `CREATE_WEB_INSTANCE` combine to simulate CCC.VPC.C02 pass/fail scenarios.

Related files:
- IaC evaluation logic: `plugins/plugin-ccc-vpc/evaluations/control-evaluations.go`
- Data collection helpers: `plugins/plugin-ccc-vpc/evaluations/data-collection.go`
- Runtime bundle: `checks/check-3-prowler.sh`
