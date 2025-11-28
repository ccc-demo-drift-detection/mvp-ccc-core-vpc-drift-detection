terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  region                      = var.region
  access_key                  = var.aws_access_key
  secret_key                  = var.aws_secret_key
  token                       = var.aws_session_token
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  s3_use_path_style           = var.use_localstack

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      ec2  = "http://localhost:4566"
      iam  = "http://localhost:4566"
      logs = "http://localhost:4566"
      s3   = "http://localhost:4566"
    }
  }
}

provider "aws" {
  alias                       = "replication"
  region                      = var.use_localstack ? var.region : (trimspace(var.replication_destination_region) != "" ? trimspace(var.replication_destination_region) : var.region)
  access_key                  = var.aws_access_key
  secret_key                  = var.aws_secret_key
  token                       = var.aws_session_token
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  s3_use_path_style           = var.use_localstack

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      ec2  = "http://localhost:4566"
      iam  = "http://localhost:4566"
      logs = "http://localhost:4566"
      s3   = "http://localhost:4566"
    }
  }
}

data "aws_caller_identity" "current" {}

# -------------------------------
# VPC
# -------------------------------
resource "aws_vpc" "demo" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "ccc-demo-vpc"
  })
}

# Optional: manage the default AWS VPC to demonstrate CCC.VPC.C01 failures
resource "aws_default_vpc" "managed" {
  count = var.manage_default_vpc ? 1 : 0

  tags = merge(local.common_tags, {
    Name = "ccc-default-vpc"
  })
}

# -------------------------------
# Demo network scaffolding (public/private subnets)
# -------------------------------
resource "aws_internet_gateway" "demo" {
  vpc_id = aws_vpc.demo.id

  tags = merge(local.common_tags, {
    Name = "ccc-demo-igw"
  })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.demo.id
  cidr_block              = "10.42.0.0/24"
  map_public_ip_on_launch = var.public_subnet_auto_assign_public_ip
  availability_zone       = trimspace(var.ccc_c08_public_subnet_az) != "" ? trimspace(var.ccc_c08_public_subnet_az) : null

  tags = merge(local.common_tags, {
    Name = "ccc-public-subnet"
  })
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.demo.id
  cidr_block        = "10.42.1.0/24"
  availability_zone = trimspace(var.ccc_c08_private_subnet_az) != "" ? trimspace(var.ccc_c08_private_subnet_az) : null

  tags = merge(local.common_tags, {
    Name = "ccc-private-subnet"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.demo.id

  tags = merge(local.common_tags, {
    Name = "ccc-public-rt"
  })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.demo.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.demo.id

  tags = merge(local.common_tags, {
    Name = "ccc-private-rt"
  })
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_network_acl" "demo" {
  vpc_id     = aws_vpc.demo.id
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]

  tags = merge(local.common_tags, {
    Name = "ccc-demo-acl"
  })
}

resource "aws_network_acl_rule" "ingress" {
  for_each = { for rule in local.nacl_ingress_rules : rule.rule_number => rule }

  network_acl_id = aws_network_acl.demo.id
  egress         = false
  rule_number    = each.value.rule_number
  protocol       = each.value.protocol
  rule_action    = each.value.action
  cidr_block     = each.value.cidr
  from_port      = each.value.from_port
  to_port        = each.value.to_port

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_network_acl_rule" "egress" {
  for_each = { for rule in local.nacl_egress_rules : rule.rule_number => rule }

  network_acl_id = aws_network_acl.demo.id
  egress         = true
  rule_number    = each.value.rule_number
  protocol       = each.value.protocol
  rule_action    = each.value.action
  cidr_block     = each.value.cidr
  from_port      = each.value.from_port
  to_port        = each.value.to_port

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_security_group" "web" {
  name        = "ccc-web"
  description = "Allow public web traffic"
  vpc_id      = aws_vpc.demo.id

  dynamic "ingress" {
    for_each = local.web_sg_ingress_rules
    content {
      description      = ingress.value.description
      from_port        = ingress.value.from_port
      to_port          = ingress.value.to_port
      protocol         = ingress.value.protocol
      cidr_blocks      = [ingress.value.cidr]
      ipv6_cidr_blocks = local.allowed_ingress_ipv6_cidrs
      security_groups  = local.web_sg_allowed_sg
    }
  }

  dynamic "egress" {
    for_each = local.web_sg_egress_rules
    content {
      description = egress.value.description
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = [egress.value.cidr]
    }
  }

  tags = merge(local.common_tags, {
    Name = "ccc-web-sg"
  })
}

resource "aws_security_group" "db" {
  name        = "ccc-db"
  description = "Allow database access from web tier"
  vpc_id      = aws_vpc.demo.id

  ingress {
    description     = "Postgres from web"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "ccc-db-sg"
  })
}

data "aws_ami" "web" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

locals {
  allowed_ingress_cidrs           = [for cidr in compact(split(",", var.allowed_ingress_cidrs_csv)) : trimspace(cidr)]
  allowed_ingress_ipv6_cidrs      = [for cidr in compact(split(",", var.allowed_ingress_ipv6_cidrs_csv)) : trimspace(cidr)]
  allowed_ingress_security_groups = [for sg in compact(split(",", var.allowed_ingress_security_groups_csv)) : trimspace(sg)]

  web_user_data = <<-EOT
    #!/bin/bash
    dnf update -y
    dnf install -y nginx
    echo "<html><body><h1>CCC Demo Web App</h1><p>Flow Logs + SG checks demo</p></body></html>" > /usr/share/nginx/html/index.html
    systemctl enable nginx
    systemctl start nginx
  EOT

  web_trusted_ingress_rules = [
    for cidr in(length(local.allowed_ingress_cidrs) > 0 ? local.allowed_ingress_cidrs : var.web_trusted_cidrs) : {
      description = "Allow trusted CIDR ${cidr}"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      cidr        = cidr
    }
  ]

  web_world_high_port_rule = !var.ccc_c12_enforce_strict_network_access && var.ccc_c01_allow_world_tls_ingress ? [
    {
      description = "Allow high ports"
      protocol    = "tcp"
      from_port   = 1000
      to_port     = 65535
      cidr        = "0.0.0.0/0"
    }
  ] : []

  web_sg_ingress_rules = concat(local.web_trusted_ingress_rules, local.web_world_high_port_rule)
  web_sg_allowed_sg    = [for sg in local.allowed_ingress_security_groups : sg]

  web_sg_egress_rules = [
    {
      description = "Internal range"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      cidr        = "0.0.0.0/16"
    },
    {
      description = "HTTP"
      protocol    = "tcp"
      from_port   = 80
      to_port     = 80
      cidr        = "0.0.0.0/0"
    },
    {
      description = "HTTPS"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      cidr        = "0.0.0.0/0"
    },
    {
      description = "SSH"
      protocol    = "tcp"
      from_port   = 22
      to_port     = 22
      cidr        = "0.0.0.0/0"
    },
    {
      description = "Custom TCP"
      protocol    = "tcp"
      from_port   = 1024
      to_port     = 65535
      cidr        = "0.0.0.0/0"
    }
  ]

  nacl_ingress_rules = [
    { rule_number = 50, protocol = "-1", from_port = 0, to_port = 0, cidr = "10.0.0.0/16", action = "allow" },
    { rule_number = 100, protocol = "-1", from_port = 0, to_port = 0, cidr = "202.246.252.0/24", action = "allow" },
    { rule_number = 110, protocol = "-1", from_port = 0, to_port = 0, cidr = "202.246.252.96/27", action = "allow" },
    { rule_number = 120, protocol = "-1", from_port = 0, to_port = 0, cidr = "202.246.252.128/25", action = "allow" },
    { rule_number = 130, protocol = "-1", from_port = 0, to_port = 0, cidr = "202.246.251.240/28", action = "allow" },
    { rule_number = 300, protocol = "-1", from_port = 0, to_port = 0, cidr = "202.246.252.97/32", action = "allow" },
    { rule_number = 500, protocol = "-1", from_port = 0, to_port = 0, cidr = "114.49.147.145/32", action = "allow" },
    { rule_number = 10000, protocol = "6", from_port = 1000, to_port = 65535, cidr = "0.0.0.0/0", action = "allow" }
  ]

  nacl_egress_rules = [
    { rule_number = 50, protocol = "-1", from_port = 0, to_port = 0, cidr = "0.0.0.0/16", action = "allow" },
    { rule_number = 100, protocol = "6", from_port = 80, to_port = 80, cidr = "0.0.0.0/0", action = "allow" },
    { rule_number = 150, protocol = "6", from_port = 443, to_port = 443, cidr = "0.0.0.0/0", action = "allow" },
    { rule_number = 200, protocol = "6", from_port = 22, to_port = 22, cidr = "0.0.0.0/0", action = "allow" },
    { rule_number = 1000, protocol = "6", from_port = 1024, to_port = 65535, cidr = "0.0.0.0/0", action = "allow" }
  ]

  replication_destination_region = var.use_localstack ? var.region : (trimspace(var.replication_destination_region) != "" ? trimspace(var.replication_destination_region) : var.region)

  flow_logs_kms_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountRoot"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant",
          "kms:List*"
        ]
        Resource = "*"
      }
    ]
  })

  use_existing_flow_logs_role       = var.flow_logs_role_name != ""
  use_existing_demo_admin_role      = trimspace(var.demo_admin_role_name) != ""
  use_existing_cloudtrail_logs_role = trimspace(var.cloudtrail_logs_role_name) != ""
}

resource "aws_kms_key" "cmek_demo" {
  count                   = var.enable_cmek_demo ? 1 : 0
  description             = "CCC demo key for application data encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = var.enforce_cmek_rotation
  rotation_period_in_days = var.enforce_cmek_rotation ? 365 : null
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountRoot"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowS3Service"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "cmek_demo" {
  count         = var.enable_cmek_demo ? 1 : 0
  name          = "alias/ccc-demo-cmek"
  target_key_id = aws_kms_key.cmek_demo[0].key_id
}

resource "aws_instance" "web" {
  count                       = var.create_web_instance ? 1 : 0
  ami                         = data.aws_ami.web.id
  instance_type               = var.web_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = var.associate_public_ip_web_instance
  user_data                   = local.web_user_data

  tags = merge(local.common_tags, {
    Name = "ccc-demo-web"
  })
}

resource "aws_vpc" "peer" {
  count      = var.create_demo_vpc_peering ? 1 : 0
  cidr_block = var.peer_vpc_cidr

  tags = merge(local.common_tags, {
    Name = "ccc-peer-vpc"
  })
}

resource "aws_vpc_peering_connection" "demo" {
  count       = var.create_demo_vpc_peering ? 1 : 0
  vpc_id      = aws_vpc.demo.id
  peer_vpc_id = aws_vpc.peer[count.index].id
  auto_accept = true

  tags = merge(local.common_tags, {
    Name = "ccc-demo-peering"
  })
}

# -------------------------------
# Optional VPC Flow Logs
# -------------------------------
resource "aws_kms_key" "flow_logs" {
  count                   = var.enable_vpc_flow_logs && var.enable_flow_log_protection ? 1 : 0
  description             = "CCC demo key for protecting VPC Flow Logs"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = local.flow_logs_kms_policy
  tags                    = local.common_tags
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  count             = var.enable_vpc_flow_logs ? 1 : 0
  name              = "/aws/vpc/flowlogs/${aws_vpc.demo.id}"
  retention_in_days = var.enable_flow_log_protection ? var.flow_log_retention_days : 0
  kms_key_id        = var.enable_flow_log_protection && length(aws_kms_key.flow_logs) > 0 ? aws_kms_key.flow_logs[0].arn : null
  tags              = local.common_tags
}

# -------------------------------
# Sample Encrypted S3 Bucket (for CCC.C02 testing)
# -------------------------------
resource "random_id" "suffix" {
  count       = var.enable_sample_encrypted_bucket ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket" "encrypted" {
  count         = var.enable_sample_encrypted_bucket ? 1 : 0
  bucket        = "ccc-demo-encrypted-${random_id.suffix[0].hex}"
  force_destroy = true
  tags          = local.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted" {
  count  = var.enable_sample_encrypted_bucket ? 1 : 0
  bucket = aws_s3_bucket.encrypted[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.enable_cmek_demo ? "aws:kms" : "AES256"
      kms_master_key_id = var.enable_cmek_demo ? aws_kms_key.cmek_demo[0].arn : null
    }
  }
}

# Unencrypted S3 bucket to simulate failure
resource "random_id" "suffix_unenc" {
  count       = var.enable_unencrypted_bucket ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket" "unencrypted" {
  count         = var.enable_unencrypted_bucket ? 1 : 0
  bucket        = "ccc-demo-unencrypted-${random_id.suffix_unenc[0].hex}"
  force_destroy = true
  tags          = local.common_tags
}

# -------------------------------
# S3 replication demo (CCC.C10)
# -------------------------------
resource "random_id" "replication" {
  count       = var.enable_replication_demo ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket" "replication_source" {
  count         = var.enable_replication_demo ? 1 : 0
  bucket        = "ccc-demo-replication-src-${random_id.replication[0].hex}"
  force_destroy = true
  tags          = local.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replication_source" {
  count  = var.enable_replication_demo ? 1 : 0
  bucket = aws_s3_bucket.replication_source[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.enable_cmek_demo ? "aws:kms" : "AES256"
      kms_master_key_id = var.enable_cmek_demo ? aws_kms_key.cmek_demo[0].arn : null
    }
  }
}

resource "aws_s3_bucket" "replication_destination" {
  provider      = aws.replication
  count         = var.enable_replication_demo ? 1 : 0
  bucket        = "ccc-demo-replication-dst-${local.replication_destination_region}-${random_id.replication[0].hex}"
  force_destroy = true
  tags          = local.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replication_destination" {
  provider = aws.replication
  count    = var.enable_replication_demo ? 1 : 0
  bucket   = aws_s3_bucket.replication_destination[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.enable_cmek_demo ? "aws:kms" : "AES256"
      kms_master_key_id = var.enable_cmek_demo ? aws_kms_key.cmek_demo[0].arn : null
    }
  }
}

resource "aws_s3_bucket_versioning" "replication_source" {
  count  = var.enable_replication_demo ? 1 : 0
  bucket = aws_s3_bucket.replication_source[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "replication_destination" {
  provider = aws.replication
  count    = var.enable_replication_demo ? 1 : 0
  bucket   = aws_s3_bucket.replication_destination[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "replication" {
  count = var.enable_replication_demo ? 1 : 0
  name  = "ccc-demo-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "replication" {
  count = var.enable_replication_demo ? 1 : 0
  name  = "ccc-demo-replication-policy"
  role  = aws_iam_role.replication[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = [aws_s3_bucket.replication_source[0].arn]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersion",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = ["${aws_s3_bucket.replication_source[0].arn}/*"]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
          "s3:GetObjectVersionTagging"
        ]
        Resource = ["${aws_s3_bucket.replication_destination[0].arn}/*"]
      },
      {
        Effect   = "Deny"
        Action   = ["*"]
        Resource = ["*"]
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "replication_destination" {
  provider = aws.replication
  count    = var.enable_replication_demo ? 1 : 0
  bucket   = aws_s3_bucket.replication_destination[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowReplicationFromSource"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.replication[0].arn }
      Action = [
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags",
        "s3:GetObjectVersionTagging"
      ]
      Resource = ["${aws_s3_bucket.replication_destination[0].arn}/*"]
    }]
  })
}

resource "aws_s3_bucket_replication_configuration" "demo" {
  count = var.enable_replication_demo ? 1 : 0
  depends_on = [
    aws_s3_bucket_versioning.replication_source,
    aws_s3_bucket_versioning.replication_destination
  ]

  bucket = aws_s3_bucket.replication_source[0].id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "ccc-demo-replication"
    status = "Enabled"

    destination {
      bucket  = aws_s3_bucket.replication_destination[0].arn
      account = data.aws_caller_identity.current.account_id
    }
  }
}

data "aws_iam_policy_document" "vpc_flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vpc_flow" {
  count              = var.enable_vpc_flow_logs && !local.use_existing_flow_logs_role ? 1 : 0
  name               = var.flow_logs_role_name != "" ? var.flow_logs_role_name : "VpcFlowLogsRole-${aws_vpc.demo.id}"
  assume_role_policy = data.aws_iam_policy_document.vpc_flow_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "vpc_flow_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "vpc_flow" {
  count  = var.enable_vpc_flow_logs && !local.use_existing_flow_logs_role ? 1 : 0
  name   = "VpcFlowLogsPolicy-${aws_vpc.demo.id}"
  role   = aws_iam_role.vpc_flow[0].id
  policy = data.aws_iam_policy_document.vpc_flow_logs.json
}

data "aws_iam_role" "flow_logs" {
  count = var.enable_vpc_flow_logs && local.use_existing_flow_logs_role ? 1 : 0
  name  = var.flow_logs_role_name
}

locals {
  flow_logs_role_arn = local.use_existing_flow_logs_role && length(data.aws_iam_role.flow_logs) > 0 ? data.aws_iam_role.flow_logs[0].arn : (var.enable_vpc_flow_logs && length(aws_iam_role.vpc_flow) > 0 ? aws_iam_role.vpc_flow[0].arn : null)
}

resource "aws_flow_log" "vpc" {
  count                = var.enable_vpc_flow_logs ? 1 : 0
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow[0].arn
  iam_role_arn         = local.flow_logs_role_arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.demo.id

  tags = merge(local.common_tags, {
    Name = "ccc-demo-vpc-flow"
  })
}

# -------------------------------
# Demo IAM role for MFA enforcement (CCC.C03)
# -------------------------------

data "aws_iam_policy_document" "demo_admin_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "demo_admin" {
  count              = local.use_existing_demo_admin_role ? 0 : 1
  name               = "ccc-demo-admin"
  assume_role_policy = data.aws_iam_policy_document.demo_admin_assume.json

  tags = merge(local.common_tags, {
    Name = "ccc-demo-admin"
  })
}

data "aws_iam_policy_document" "demo_admin_permissions" {
  statement {
    sid     = "AllowAll"
    effect  = "Allow"
    actions = ["*"]
    resources = [
      "*"
    ]
  }

  dynamic "statement" {
    for_each = var.enforce_mfa_demo_admin_role ? [1] : []
    content {
      sid       = "DenyWithoutMFA"
      effect    = "Deny"
      actions   = ["*"]
      resources = ["*"]
      condition {
        test     = "BoolIfExists"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["false"]
      }
    }
  }
}

resource "aws_iam_role_policy" "demo_admin" {
  count  = local.use_existing_demo_admin_role ? 0 : 1
  name   = "ccc-demo-admin-policy"
  role   = aws_iam_role.demo_admin[0].name
  policy = data.aws_iam_policy_document.demo_admin_permissions.json
}

# -------------------------------
# Core audit logging (CloudTrail)
# -------------------------------

resource "random_id" "trail_suffix" {
  count       = var.enable_core_audit_logs ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket" "trail" {
  count         = var.enable_core_audit_logs ? 1 : 0
  bucket        = "ccc-demo-trail-${random_id.trail_suffix[0].hex}"
  force_destroy = true
  tags          = local.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  count  = var.enable_core_audit_logs ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.enable_cmek_demo ? "aws:kms" : "AES256"
      kms_master_key_id = var.enable_cmek_demo ? aws_kms_key.cmek_demo[0].arn : null
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  count  = var.enable_core_audit_logs ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail[0].arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

data "aws_iam_policy_document" "cloudtrail_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_group" "trail_logs" {
  count             = var.enable_core_audit_logs && var.enable_enumeration_alerts ? 1 : 0
  name              = "CloudTrail/ccc-demo-trail"
  retention_in_days = 14
  tags              = local.common_tags
}

resource "aws_iam_role" "cloudtrail_logs" {
  count              = var.enable_core_audit_logs && var.enable_enumeration_alerts && !local.use_existing_cloudtrail_logs_role ? 1 : 0
  name_prefix        = "ccc-cloudtrail-logs-"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_logs_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  count = var.enable_core_audit_logs && var.enable_enumeration_alerts && !local.use_existing_cloudtrail_logs_role ? 1 : 0
  name  = "ccc-cloudtrail-logs"
  role  = aws_iam_role.cloudtrail_logs[0].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          aws_cloudwatch_log_group.trail_logs[0].arn,
          replace(aws_cloudwatch_log_group.trail_logs[0].arn, ":*", ":log-stream:*")
        ]
      }
    ]
  })
}

resource "aws_cloudtrail" "core" {
  count                         = var.enable_core_audit_logs ? 1 : 0
  name                          = "ccc-demo-trail"
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = var.enable_core_audit_logs
  tags                          = local.common_tags
  depends_on                    = [aws_s3_bucket_policy.trail]
}

resource "aws_cloudwatch_log_metric_filter" "enumeration" {
  count          = var.enable_core_audit_logs && var.enable_enumeration_alerts ? 1 : 0
  name           = "ccc-enumeration-events"
  log_group_name = aws_cloudwatch_log_group.trail_logs[0].name
  pattern        = "{ ($.eventSource = \"iam.amazonaws.com\" && ($.eventName = \"List*\" || $.eventName = \"GetAccountAuthorizationDetails\" || $.eventName = \"GetCredentialReport\")) || ($.eventSource = \"sts.amazonaws.com\" && $.eventName = \"GetCallerIdentity\") }"

  metric_transformation {
    name      = "EnumerationCount"
    namespace = "CCC/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "enumeration" {
  count               = var.enable_core_audit_logs && var.enable_enumeration_alerts ? 1 : 0
  alarm_name          = "ccc-enumeration-alert"
  alarm_description   = "Alerts on suspicious enumeration API activity captured by CloudTrail."
  namespace           = "CCC/CloudTrail"
  metric_name         = "EnumerationCount"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  datapoints_to_alarm = 1
}
