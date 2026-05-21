output "asg_name" {
  value = aws_autoscaling_group.this.name
}

output "security_group_id" {
  value       = aws_security_group.instance.id
  description = "ID of the instance security group"
}

output "instance_profile_name" {
  value       = aws_iam_instance_profile.instance.name
  description = "Name of the IAM instance profile"
}
