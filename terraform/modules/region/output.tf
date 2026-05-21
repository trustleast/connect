output "config_s3_uri" {
  value       = "s3://${aws_s3_bucket.config.bucket}/config.json"
  description = "S3 URI for the instance config. Upload JSON here before launching instances."
}

output "config_bucket" {
  value       = aws_s3_bucket.config.bucket
  description = "S3 bucket name for instance config"
}

output "ami_id" {
  value       = module.ami.ami_id
  description = "AMI ID used by instances in this region"
}

output "ops_bucket" {
  value       = module.ami.ops_bucket
  description = "S3 bucket name used by ops CLI to stage disk images during AMI creation"
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
