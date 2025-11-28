.PHONY: all help init plan apply guard scan validate validate-ci validate-live destroy clean \
        plugin-list plugin-run plugin-run-ci plugin-build vars runtime-guard \
        drift-simulate-runtime drift-detect-runtime report snapshot history-diff \
        demo-good demo-bad demo-bad-ci demo-reset demo-runtime demo-drift-runtime demo-all

ENV_FILE?=.env.basic
VALIDATE_REFRESH_TIMEOUT ?= 0

# Resolve repo root so includes work regardless of CWD
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ENV_PATH := $(ROOT_DIR)$(ENV_FILE)

# Include env file if present; warn if missing
ifneq (,$(wildcard $(ENV_PATH)))
include $(ENV_PATH)
else
$(warning ENV file '$(ENV_PATH)' not found; proceeding with defaults)
endif

PLUGIN_DIR ?= plugins/plugin-ccc-vpc

# Allow selecting AWS credentials via named profile (aws configure)
AWS_PROFILE ?= $(if $(TF_VAR_AWS_PROFILE),$(TF_VAR_AWS_PROFILE))
AWS_PROFILE := $(strip $(AWS_PROFILE))

USE_LOCALSTACK ?= $(if $(TF_VAR_USE_LOCALSTACK),$(TF_VAR_USE_LOCALSTACK))

ifeq ($(AWS_PROFILE),)
  # no profile override
else
  TEMP_AWS_ACCESS_KEY := $(strip $(shell aws --profile $(AWS_PROFILE) configure get aws_access_key_id 2>/dev/null))
  ifneq ($(TEMP_AWS_ACCESS_KEY),)
    AWS_ACCESS_KEY := $(TEMP_AWS_ACCESS_KEY)
  endif
  TEMP_AWS_SECRET_KEY := $(strip $(shell aws --profile $(AWS_PROFILE) configure get aws_secret_access_key 2>/dev/null))
  ifneq ($(TEMP_AWS_SECRET_KEY),)
    AWS_SECRET_KEY := $(TEMP_AWS_SECRET_KEY)
  endif
  TEMP_AWS_SESSION_TOKEN := $(strip $(shell aws --profile $(AWS_PROFILE) configure get aws_session_token 2>/dev/null))
  ifneq ($(TEMP_AWS_SESSION_TOKEN),)
    AWS_SESSION_TOKEN := $(TEMP_AWS_SESSION_TOKEN)
  endif
  ifeq ($(AWS_PROFILE),awscloud)
    USE_LOCALSTACK ?= false
  endif
endif

USE_LOCALSTACK ?= true

# Fallbacks: allow TF_VAR_* to populate Make variables if set in the environment
IAC_GUARD_STRICT ?= false
REGION ?= $(if $(TF_VAR_REGION),$(TF_VAR_REGION))
AWS_ACCESS_KEY ?= $(if $(TF_VAR_AWS_ACCESS_KEY),$(TF_VAR_AWS_ACCESS_KEY))
AWS_SECRET_KEY ?= $(if $(TF_VAR_AWS_SECRET_KEY),$(TF_VAR_AWS_SECRET_KEY))
AWS_SESSION_TOKEN ?= $(if $(TF_VAR_AWS_SESSION_TOKEN),$(TF_VAR_AWS_SESSION_TOKEN))
ENABLE_VPC_FLOW_LOGS ?= $(if $(TF_VAR_ENABLE_VPC_FLOW_LOGS),$(TF_VAR_ENABLE_VPC_FLOW_LOGS),false)
ENABLE_FLOW_LOG_PROTECTION ?= $(if $(TF_VAR_ENABLE_FLOW_LOG_PROTECTION),$(TF_VAR_ENABLE_FLOW_LOG_PROTECTION),true)
FLOW_LOG_RETENTION_DAYS ?= $(if $(TF_VAR_FLOW_LOG_RETENTION_DAYS),$(TF_VAR_FLOW_LOG_RETENTION_DAYS),90)
CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS ?= $(if $(TF_VAR_CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS),$(TF_VAR_CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS),true)
CCC_C08_PUBLIC_SUBNET_AZ ?= $(if $(TF_VAR_CCC_C08_PUBLIC_SUBNET_AZ),$(TF_VAR_CCC_C08_PUBLIC_SUBNET_AZ),ap-northeast-1a)
CCC_C08_PRIVATE_SUBNET_AZ ?= $(if $(TF_VAR_CCC_C08_PRIVATE_SUBNET_AZ),$(TF_VAR_CCC_C08_PRIVATE_SUBNET_AZ),ap-northeast-1c)
CLOUDTRAIL_LOGS_ROLE_NAME ?= $(if $(TF_VAR_CLOUDTRAIL_LOGS_ROLE_NAME),$(TF_VAR_CLOUDTRAIL_LOGS_ROLE_NAME))
DEMO_ADMIN_ROLE_NAME ?= $(if $(TF_VAR_DEMO_ADMIN_ROLE_NAME),$(TF_VAR_DEMO_ADMIN_ROLE_NAME))
ENABLE_REPLICATION_DEMO ?= $(if $(TF_VAR_ENABLE_REPLICATION_DEMO),$(TF_VAR_ENABLE_REPLICATION_DEMO),true)
REPLICATION_DESTINATION_REGION ?= $(if $(TF_VAR_REPLICATION_DESTINATION_REGION),$(TF_VAR_REPLICATION_DESTINATION_REGION))
ENABLE_CMEK_DEMO ?= $(if $(TF_VAR_ENABLE_CMEK_DEMO),$(TF_VAR_ENABLE_CMEK_DEMO),true)
ENFORCE_CMEK_ROTATION ?= $(if $(TF_VAR_ENFORCE_CMEK_ROTATION),$(TF_VAR_ENFORCE_CMEK_ROTATION),true)
ENABLE_SAMPLE_ENCRYPTED_BUCKET ?= $(if $(TF_VAR_ENABLE_SAMPLE_ENCRYPTED_BUCKET),$(TF_VAR_ENABLE_SAMPLE_ENCRYPTED_BUCKET),true)
ENABLE_UNENCRYPTED_BUCKET ?= $(if $(TF_VAR_ENABLE_UNENCRYPTED_BUCKET),$(TF_VAR_ENABLE_UNENCRYPTED_BUCKET),false)
CCC_C01_ALLOW_WORLD_TLS_INGRESS ?= $(if $(TF_VAR_CCC_C01_ALLOW_WORLD_TLS_INGRESS),$(TF_VAR_CCC_C01_ALLOW_WORLD_TLS_INGRESS),true)
ENFORCE_MFA_DEMO_ADMIN_ROLE ?= $(if $(TF_VAR_ENFORCE_MFA_DEMO_ADMIN_ROLE),$(TF_VAR_ENFORCE_MFA_DEMO_ADMIN_ROLE),true)
ENABLE_CORE_AUDIT_LOGS ?= $(if $(TF_VAR_ENABLE_CORE_AUDIT_LOGS),$(TF_VAR_ENABLE_CORE_AUDIT_LOGS),true)
ENABLE_ENUMERATION_ALERTS ?= $(if $(TF_VAR_ENABLE_ENUMERATION_ALERTS),$(TF_VAR_ENABLE_ENUMERATION_ALERTS),true)
MANAGE_DEFAULT_VPC ?= $(if $(TF_VAR_MANAGE_DEFAULT_VPC),$(TF_VAR_MANAGE_DEFAULT_VPC),false)
CREATE_WEB_INSTANCE ?= $(if $(TF_VAR_CREATE_WEB_INSTANCE),$(TF_VAR_CREATE_WEB_INSTANCE),true)

# Common Terraform -var flags (deduplicated across plan/apply/destroy)
define TF_COMMON_VARS
        -var region=$(REGION) \
        -var aws_access_key=$(AWS_ACCESS_KEY) \
        -var aws_secret_key=$(AWS_SECRET_KEY) \
        -var aws_session_token=$(AWS_SESSION_TOKEN) \
        -var use_localstack=$(USE_LOCALSTACK) \
        -var enable_vpc_flow_logs=$(ENABLE_VPC_FLOW_LOGS) \
        -var enable_flow_log_protection=$(ENABLE_FLOW_LOG_PROTECTION) \
        -var flow_log_retention_days=$(FLOW_LOG_RETENTION_DAYS) \
        -var enable_sample_encrypted_bucket=$(ENABLE_SAMPLE_ENCRYPTED_BUCKET) \
        -var enable_unencrypted_bucket=$(ENABLE_UNENCRYPTED_BUCKET) \
        -var ccc_c12_enforce_strict_network_access=$(CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS) \
        -var ccc_c08_public_subnet_az=$(CCC_C08_PUBLIC_SUBNET_AZ) \
        -var ccc_c08_private_subnet_az=$(CCC_C08_PRIVATE_SUBNET_AZ) \
        -var public_subnet_auto_assign_public_ip=$(PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP) \
        -var associate_public_ip_web_instance=$(ASSOCIATE_PUBLIC_IP_WEB_INSTANCE) \
        -var create_demo_vpc_peering=$(CREATE_DEMO_VPC_PEERING) \
        -var ccc_c01_allow_world_tls_ingress=$(CCC_C01_ALLOW_WORLD_TLS_INGRESS) \
        -var enforce_mfa_demo_admin_role=$(ENFORCE_MFA_DEMO_ADMIN_ROLE) \
        -var enable_core_audit_logs=$(ENABLE_CORE_AUDIT_LOGS) \
        -var enable_enumeration_alerts=$(ENABLE_ENUMERATION_ALERTS) \
        -var cloudtrail_logs_role_name=$(CLOUDTRAIL_LOGS_ROLE_NAME) \
        -var demo_admin_role_name=$(DEMO_ADMIN_ROLE_NAME) \
        -var enable_replication_demo=$(ENABLE_REPLICATION_DEMO) \
        -var replication_destination_region=$(REPLICATION_DESTINATION_REGION) \
        -var enable_cmek_demo=$(ENABLE_CMEK_DEMO) \
        -var enforce_cmek_rotation=$(ENFORCE_CMEK_ROTATION) \
        -var allowed_ingress_cidrs_csv=$(ALLOWED_INGRESS_CIDRS_CSV) \
        -var allowed_ingress_ipv6_cidrs_csv=$(ALLOWED_INGRESS_IPV6_CIDRS_CSV) \
        -var allowed_ingress_security_groups_csv=$(ALLOWED_INGRESS_SECURITY_GROUPS_CSV) \
        -var manage_default_vpc=$(MANAGE_DEFAULT_VPC) \
        -var create_web_instance=$(CREATE_WEB_INSTANCE)
endef

all: init apply guard scan

help:
	@echo "Targets:"
	@echo "  make init           - terraform init (in iac/)"
	@echo "  make apply          - terraform apply using .env.basic vars"
	@echo "  make guard          - run Privateer checks (uses config.yml)"
	@echo "  make validate       - run manual + IaC + runtime checks with drift summary"
	@echo "  make validate-ci    - strict validate with CI artifacts (JUnit/JSON)"
	@echo "  make validate-live  - run validation + long-running provider drift check"
	@echo "  make scan           - run prowler VPC checks"
	@echo "  make destroy        - terraform destroy"
	@echo "  make plugin-list    - list installed Privateer plugins"
	@echo "  make plugin-run     - run vpc plugin (non-strict by default)"
	@echo "  make plugin-run-ci  - run vpc plugin (strict; exits non-zero on failures)"
	@echo "  make plugin-build   - rebuild vpc plugin (requires Go)"
	@echo "  make runtime-guard  - AWS runtime check (Flow Logs, S3 encryption)"
	@echo "  make drift-simulate-runtime - delete Flow Logs (simulate drift)"
	@echo "  make drift-detect-runtime   - runtime guard + snapshot"
	@echo "  (set ENV_FILE=envs/env.bad_<control> for targeted failure overlays)"
	@echo "  make clean          - remove iac state and output"

init:
	cd iac && terraform init -upgrade -input=false

plan:
	@echo "Using vars: REGION=$(REGION) ENABLE_VPC_FLOW_LOGS=$(ENABLE_VPC_FLOW_LOGS) USE_LOCALSTACK=$(USE_LOCALSTACK)"
	cd iac && terraform plan -input=false -out=tfplan.out $(TF_COMMON_VARS)
	cd iac && terraform show -json tfplan.out > tfplan.json || true

apply:
	@echo "Applying with vars: REGION=$(REGION) ENABLE_VPC_FLOW_LOGS=$(ENABLE_VPC_FLOW_LOGS) USE_LOCALSTACK=$(USE_LOCALSTACK)"
	cd iac && terraform apply -auto-approve -input=false $(TF_COMMON_VARS)

guard:
	ENV_FILE=$(ENV_FILE) ./checks/iac-guard.sh

validate:
	ENV_FILE=$(ENV_FILE) ./checks/validate.sh

validate-ci:
	ENV_FILE=$(ENV_FILE) VALIDATE_STRICT=true VALIDATE_MODE=ci ./checks/validate.sh

validate-live:
	ENV_FILE=$(ENV_FILE) VALIDATE_REFRESH=true TF_REFRESH_TIMEOUT=$(VALIDATE_REFRESH_TIMEOUT) ./checks/validate.sh

scan:
	ENV_FILE=$(ENV_FILE) ./checks/check-3-prowler.sh

report:
	ENV_FILE=$(ENV_FILE) ./scripts/generate-report.sh

snapshot:
	ENV_FILE=$(ENV_FILE) ./scripts/snapshot.sh

history-diff:
	@if [ -z "$(FROM)" ] || [ -z "$(TO)" ]; then \
		echo "Usage: make history-diff FROM=<timestamp> TO=<timestamp>"; \
		exit 1; \
	fi
	ENV_FILE=$(ENV_FILE) ./scripts/history-diff.sh $(FROM) $(TO)

destroy:
	@echo "Destroy with vars: REGION=$(REGION) ENABLE_VPC_FLOW_LOGS=$(ENABLE_VPC_FLOW_LOGS) USE_LOCALSTACK=$(USE_LOCALSTACK)"
	cd iac && terraform destroy -auto-approve -input=false $(TF_COMMON_VARS)

clean:
	rm -rf iac/.terraform iac/terraform.tfstate* output/*
	rm -f iac/tfplan.json iac/tfplan.out

plugin-list:
	privateer list -a || true

plugin-run:
	ENV_FILE=$(ENV_FILE) IAC_GUARD_STRICT=$(IAC_GUARD_STRICT) ./checks/iac-guard.sh

runtime-guard:
	./checks/runtime-guard.sh

drift-simulate-runtime:
	./checks/drift-simulate-runtime.sh

drift-detect-runtime:
	./checks/drift-detect-runtime.sh

.PHONY: plugin-run-ci
plugin-run-ci:
	ENV_FILE=$(ENV_FILE) IAC_GUARD_STRICT=true ./checks/iac-guard.sh

# Build the Privateer plugin (defaults to plugins/plugin-ccc-vpc)
plugin-build:
	@if [ ! -d "$(PLUGIN_DIR)" ]; then \
		echo "Plugin directory $(PLUGIN_DIR) not found."; \
		echo "Set PLUGIN_DIR=<path> or run make from repo root where plugins/plugin-ccc-vpc exists."; \
		exit 1; \
	fi
	cd $(PLUGIN_DIR) && GOTOOLCHAIN=auto go mod tidy && GOTOOLCHAIN=auto go build -o vpc && mkdir -p $$HOME/.privateer/bin && install -m 0755 vpc $$HOME/.privateer/bin/

vars:
	@echo "REGION=$(REGION)"
	@echo "AWS_PROFILE=$(AWS_PROFILE)"
	@echo "AWS_ACCESS_KEY=$(AWS_ACCESS_KEY)"
	@echo "AWS_SECRET_KEY=$(AWS_SECRET_KEY)"
	@echo "AWS_SESSION_TOKEN=$(AWS_SESSION_TOKEN)"
	@echo "USE_LOCALSTACK=$(USE_LOCALSTACK)"
	@echo "ENABLE_VPC_FLOW_LOGS=$(ENABLE_VPC_FLOW_LOGS)"
	@echo "ENABLE_SAMPLE_ENCRYPTED_BUCKET=$(ENABLE_SAMPLE_ENCRYPTED_BUCKET)"
	@echo "ENABLE_UNENCRYPTED_BUCKET=$(ENABLE_UNENCRYPTED_BUCKET)"
	@echo "PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP=$(PUBLIC_SUBNET_AUTO_ASSIGN_PUBLIC_IP)"
	@echo "ASSOCIATE_PUBLIC_IP_WEB_INSTANCE=$(ASSOCIATE_PUBLIC_IP_WEB_INSTANCE)"
	@echo "CREATE_DEMO_VPC_PEERING=$(CREATE_DEMO_VPC_PEERING)"
	@echo "CCC_C01_ALLOW_WORLD_TLS_INGRESS=$(CCC_C01_ALLOW_WORLD_TLS_INGRESS)"
	@echo "CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS=$(CCC_C12_ENFORCE_STRICT_NETWORK_ACCESS)"
	@echo "CCC_C08_PUBLIC_SUBNET_AZ=$(CCC_C08_PUBLIC_SUBNET_AZ)"
	@echo "CCC_C08_PRIVATE_SUBNET_AZ=$(CCC_C08_PRIVATE_SUBNET_AZ)"
	@echo "CLOUDTRAIL_LOGS_ROLE_NAME=$(CLOUDTRAIL_LOGS_ROLE_NAME)"
	@echo "DEMO_ADMIN_ROLE_NAME=$(DEMO_ADMIN_ROLE_NAME)"
	@echo "ENABLE_REPLICATION_DEMO=$(ENABLE_REPLICATION_DEMO)"
	@echo "REPLICATION_DESTINATION_REGION=$(REPLICATION_DESTINATION_REGION)"
	@echo "ENABLE_CMEK_DEMO=$(ENABLE_CMEK_DEMO)"
	@echo "ENFORCE_CMEK_ROTATION=$(ENFORCE_CMEK_ROTATION)"
	@echo "MANAGE_DEFAULT_VPC=$(MANAGE_DEFAULT_VPC)"
	@echo "CREATE_WEB_INSTANCE=$(CREATE_WEB_INSTANCE)"


demo-good:
	@echo "=== Demo: GOOD posture (ENV_FILE=envs/env.good_demo) ==="
	$(MAKE) -C . ENV_FILE=envs/env.good_demo IAC_GUARD_STRICT=false plan apply plugin-run


demo-bad:
	@echo "=== Demo: BAD posture (ENV_FILE=envs/env.bad_all) ==="
	# Show failures but do not fail the make target (gate off for demo)
	$(MAKE) -C . ENV_FILE=envs/env.bad_all IAC_GUARD_STRICT=false plan apply plugin-run

.PHONY: demo-bad-ci
demo-bad-ci:
	@echo "=== Demo: BAD posture (CI gate on, expect non-zero exit) ==="
	$(MAKE) -C . ENV_FILE=envs/env.bad_all IAC_GUARD_STRICT=true plan apply plugin-run
.PHONY: demo-reset
demo-reset:
	@echo "=== Resetting demo state (destroy + clean output) ==="
	$(MAKE) -C . destroy || true
	rm -rf output/* iac/tfplan.json iac/tfplan.out

.PHONY: demo-runtime
demo-runtime:
	@echo "=== Demo: Runtime checks (Flow Logs) ==="
	$(MAKE) -C . runtime-guard || true
	$(MAKE) -C . scan || true

.PHONY: demo-drift-runtime
demo-drift-runtime:
	@echo "=== Demo: Runtime drift (simulate → detect) ==="
	$(MAKE) -C . drift-simulate-runtime || true
	$(MAKE) -C . drift-detect-runtime || true

.PHONY: demo-all
demo-all:
	@echo "=== Demo: All (apply → plugin → runtime → drift) ==="
	$(MAKE) -C . demo-good
	$(MAKE) -C . demo-runtime
	$(MAKE) -C . demo-drift-runtime
