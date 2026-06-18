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
