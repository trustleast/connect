variable "vpc_id" {
  type     = string
  nullable = false
}

variable "subnet_id" {
  type        = string
  nullable    = false
  description = "Single subnet ID the ASG launches into. Change this to move the ASG to a different AZ."
}

variable "name" {
  type     = string
  nullable = false
}

variable "stage" {
  type     = string
  nullable = false
}

variable "ami_id" {
  type        = string
  description = "AMI ID for EC2 instances in this region"
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"
}

variable "min_size" {
  type    = number
  default = 1
}

variable "max_size" {
  type    = number
  default = 6
}

variable "desired_capacity" {
  type    = number
  default = 1
}

variable "ssh_pub_key" {
  type        = string
  description = "SSH public key added to ec2-user's authorized_keys on each instance."
}

variable "zone_name" {
  type        = string
  description = "DNS zone for peer URL derivation, e.g. example.com"
}

variable "cert_pem" {
  type        = string
  description = "PEM-encoded TLS certificate (full chain, leaf + intermediates) for HTTPS."
}

variable "key_pem" {
  type        = string
  sensitive   = true
  description = "PEM-encoded TLS private key for the certificate."
}

variable "cluster_secret" {
  type        = string
  sensitive   = true
  description = "Shared HRW hash secret for cluster routing."
}
