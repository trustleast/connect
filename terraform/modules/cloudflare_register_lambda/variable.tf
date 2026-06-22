variable "asg_name" {
  type        = string
  description = "Name of the Auto Scaling Group to track"
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
  description = "Signaling domain (e.g. signaling.example.com). All active node IPs are registered under this single domain."
}

variable "cf_api_token_ssm_path" {
  type    = string
  default = "/connect/cloudflare_api_token"
}

variable "lifecycle_hook_timeout" {
  type    = number
  default = 120
}
