output "vpc_id" {
  value = aws_vpc.demo.id
}

output "tags" {
  value = local.common_tags
}

output "flow_logs" {
  value = var.enable_vpc_flow_logs
}

output "encrypted_bucket" {
  value       = var.enable_sample_encrypted_bucket
  description = "Whether the sample encrypted S3 bucket was requested"
}

output "public_subnet_id" {
  value       = aws_subnet.public.id
  description = "Public subnet created for demo traffic"
}

output "private_subnet_id" {
  value       = aws_subnet.private.id
  description = "Private subnet created for demo workloads"
}

output "security_groups" {
  value = {
    web = aws_security_group.web.id
    db  = aws_security_group.db.id
  }
}

output "web_instance_public_ip" {
  value       = var.create_web_instance ? aws_instance.web[0].public_ip : null
  description = "Public IP of the demo web server"
}
