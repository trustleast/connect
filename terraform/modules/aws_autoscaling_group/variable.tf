variable "vpc_id" {
  type     = string
  nullable = false
}

variable "subnets" {
  type     = set(string)
  nullable = false
}

variable "name" {
  type     = string
  nullable = false
}

variable "stage" {
  type     = string
  nullable = false
}

variable "extra_permissions" {
  type = list(object({
    Action   = list(string)
    Effect   = string
    Resource = list(string)
  }))
  default     = []
  description = "Additional IAM policy statements to include in the instance role (e.g. S3 bucket access)"
}

variable "min_size" {
  description = "Minimum number of instances in the ASG"
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Maximum number of instances in the ASG"
  type        = number
  default     = 6
}

variable "desired_capacity" {
  description = "Desired number of instances in the ASG"
  type        = number
  default     = 2
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"
}

variable "ami_id" {
  type        = string
  description = "AMI ID for EC2 instances in this region"
}

variable "user_data" {
  type        = string
  description = "Base64-encoded user data script run on first boot (installs systemd unit)"
  nullable    = false
}
