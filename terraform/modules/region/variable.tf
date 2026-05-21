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
