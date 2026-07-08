variable "stage" {
  type    = string
  default = "production"
}

variable "regions" {
  type = map(object({
    asg_availability_zone = string
  }))
  description = "Map of AWS region to its configuration. The VPC automatically spans all AZs in the region; asg_availability_zone is the single AZ the ASG deploys into."
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for signaling nodes"
  default     = "t4g.nano"
}

variable "cloudflare_zone_id" {
  type = string
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "domain" {
  type        = string
  description = "Base domain for signaling (e.g. connect.example.com). Node records are created as node-{hash}.{zone}."
}

variable "ssh_pub_key" {
  type        = string
  description = "SSH public key added to ec2-user's authorized_keys on each instance."
}

variable "acme_email" {
  type        = string
  description = "Email address for Let's Encrypt account registration and expiry notifications."
}

variable "cluster_secret" {
  type        = string
  sensitive   = true
  description = "Shared HRW hash secret for cluster routing. All nodes in all regions must use the same value."
}
