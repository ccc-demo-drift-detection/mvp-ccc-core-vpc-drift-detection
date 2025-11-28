variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "aws_access_key" {
  description = "Access key for AWS (LocalStack or real)"
  type        = string
  sensitive   = true
}

variable "aws_secret_key" {
  description = "Secret key for AWS (LocalStack or real)"
  type        = string
  sensitive   = true
}

variable "aws_session_token" {
  description = "Optional session token when using temporary AWS credentials"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_vpc_flow_logs" {
  description = "Whether to enable VPC flow logs"
  type        = bool
  default     = false
}

variable "enable_flow_log_protection" {
  description = "Whether to enforce retention + KMS protections on VPC Flow Log destinations"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Retention period (in days) for VPC Flow Log CloudWatch log groups"
  type        = number
  default     = 90
}

variable "ccc_c12_enforce_strict_network_access" {
  description = "CCC.C12 demo toggle: enforce allowlist-only ingress rules"
  type        = bool
  default     = true
}

variable "ccc_c08_public_subnet_az" {
  description = "CCC.C08 demo: availability zone for the public subnet"
  type        = string
  default     = "ap-northeast-1a"
}

variable "ccc_c08_private_subnet_az" {
  description = "CCC.C08 demo: availability zone for the private subnet"
  type        = string
  default     = "ap-northeast-1c"
}

variable "enable_replication_demo" {
  description = "Whether to create the S3 replication demo resources"
  type        = bool
  default     = true
}

variable "replication_destination_region" {
  description = "AWS region for the replication destination bucket (defaults to var.region when empty or using LocalStack)"
  type        = string
  default     = ""
}

variable "enable_cmek_demo" {
  description = "Whether to create a CMEK demo key and use it for encryption"
  type        = bool
  default     = true
}

variable "enforce_cmek_rotation" {
  description = "Whether to enable automatic rotation on the CMEK demo key"
  type        = bool
  default     = true
}

variable "enable_sample_encrypted_bucket" {
  description = "Whether to create a sample S3 bucket with SSE for CCC.C02 testing"
  type        = bool
  default     = true
}

variable "enable_unencrypted_bucket" {
  description = "Whether to create an unencrypted S3 bucket to simulate a failure for CCC.C02"
  type        = bool
  default     = false
}

variable "use_localstack" {
  description = "Whether to target LocalStack endpoints (true) or real AWS endpoints (false)"
  type        = bool
  default     = true
}

variable "create_web_instance" {
  description = "Whether to launch a demo web EC2 instance"
  type        = bool
  default     = true
}

variable "web_instance_type" {
  description = "Instance type for the demo web server"
  type        = string
  default     = "t3.micro"
}

variable "public_subnet_auto_assign_public_ip" {
  description = "Whether the public subnet auto-assigns public IPs to new ENIs"
  type        = bool
  default     = false
}

variable "associate_public_ip_web_instance" {
  description = "Whether the demo web instance receives a public IP"
  type        = bool
  default     = false
}

variable "web_trusted_cidrs" {
  description = "Approved IPv4 CIDRs that may reach the web security group"
  type        = list(string)
  default = [  ]
}

variable "ccc_c01_allow_world_tls_ingress" {
  description = "CCC.C01 demo toggle: expose high TCP ports to the world"
  type        = bool
  default     = true
}

variable "enforce_mfa_demo_admin_role" {
  description = "Require MFA for the demo admin IAM role"
  type        = bool
  default     = true
}

variable "allowed_ingress_cidrs_csv" {
  description = "Comma-separated IPv4 CIDRs allowed for ingress"
  type        = string
  default     = ""
}

variable "allowed_ingress_ipv6_cidrs_csv" {
  description = "Comma-separated IPv6 CIDRs allowed for ingress"
  type        = string
  default     = ""
}

variable "allowed_ingress_security_groups_csv" {
  description = "Comma-separated security group IDs allowed for ingress"
  type        = string
  default     = ""
}

variable "enable_core_audit_logs" {
  description = "Enable the demo CloudTrail trail for core logging control"
  type        = bool
  default     = true
}

variable "enable_enumeration_alerts" {
  description = "Enable CloudWatch metric filter/alarm for enumeration activity"
  type        = bool
  default     = true
}

variable "manage_default_vpc" {
  description = "Manage the AWS default VPC (demo toggle for CCC.VPC.C01 failure)"
  type        = bool
  default     = false
}

variable "create_demo_vpc_peering" {
  description = "Whether to create a demo VPC peering connection (used for CCC.VPC.C03 failures)"
  type        = bool
  default     = false
}

variable "peer_vpc_cidr" {
  description = "CIDR block for the optional peer VPC"
  type        = string
  default     = "10.99.0.0/16"
}

variable "flow_logs_role_name" {
  description = "Optional existing IAM role name to use for VPC Flow Logs"
  type        = string
  default     = "VpcFlowLogsRole-vpc-0f3cb783cf2ececc2"
}

variable "cloudtrail_logs_role_name" {
  description = "Optional existing IAM role name to use for CloudTrail delivery to CloudWatch Logs"
  type        = string
  default     = ""
}

variable "demo_admin_role_name" {
  description = "Optional existing IAM role name to use for the CCC demo admin role"
  type        = string
  default     = ""
}
