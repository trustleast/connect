output "config_s3_uri" {
  value       = "s3://${aws_s3_bucket.config.bucket}/config.json"
  description = "S3 URI for the instance config. Upload JSON here before launching instances."
}

output "config_bucket" {
  value       = aws_s3_bucket.config.bucket
  description = "S3 bucket name for instance config (also stores the binary at connect-arm64)"
}

output "security_group_id" {
  value       = module.asg.security_group_id
  description = "ID of the instance security group"
}

output "instance_profile_name" {
  value       = module.asg.instance_profile_name
  description = "Name of the IAM instance profile"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}

output "subnet_ids" {
  value       = module.vpc.public_subnet_ids
  description = "Public subnet IDs"
}

output "zone_name" {
  value       = local.zone_name
  description = "DNS zone name derived from domain"
}
