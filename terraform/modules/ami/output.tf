output "ami_id" {
  value       = data.aws_ami.connect.id
  description = "AMI ID for the connect image in this region"
}

output "ops_bucket" {
  value       = aws_s3_bucket.ops_images.bucket
  description = "S3 bucket name used by ops CLI to stage disk images during AMI creation"
}
