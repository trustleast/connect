variable "availability_zones" {
  type = list(string)
}

variable "stage" {
  type    = string
  default = "production"
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"
}

variable "cloudflare_zone_id" {
  type = string
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "domain" {
  type = string
}

variable "ssh_pub_key" {
  type        = string
  description = "SSH public key added to ec2-user's authorized_keys on each instance."
}
