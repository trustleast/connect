variable "stage" {
  type    = string
  default = "production"
}

variable "regions" {
  type = map(object({
    availability_zones = list(string)
  }))
  description = "Map of AWS region to its configuration. AMI IDs are built automatically by the ami module using the Go source hash."

  validation {
    condition     = alltrue([for r in values(var.regions) : length(r.availability_zones) >= 1])
    error_message = "Each region must have at least one availability zone."
  }
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
