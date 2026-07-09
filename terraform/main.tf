terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.4"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.52"
    }
    acme = {
      source  = "vancluever/acme"
      version = "~> 2.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# cloudflare_ip_ranges (used by the ASG security group) is unauthenticated.
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

provider "acme" {
  server_url = "https://acme-v02.api.letsencrypt.org/directory"
}

# Per-region providers for the regional infrastructure modules.
provider "aws" {
  for_each = var.regions
  alias    = "multi_region"
  region   = each.key
}

# ACME account key — generated once and stored in state. Used to authenticate
# all certificate operations against Let's Encrypt.
resource "tls_private_key" "acme_account" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.acme_account.private_key_pem
  email_address   = var.acme_email
}

# Certificate for the exact serving domain.
# Renewed automatically on the next `terraform apply` when fewer than 30 days remain.
resource "acme_certificate" "cert" {
  account_key_pem           = acme_registration.reg.account_key_pem
  common_name               = var.domain
  subject_alternative_names = []

  dns_challenge {
    provider = "cloudflare"
    config = {
      CF_DNS_API_TOKEN = var.cloudflare_api_token
    }
  }
}

module "region" {
  for_each = var.regions

  source = "./modules/region"

  asg_availability_zone = each.value.asg_availability_zone

  stage         = var.stage
  instance_type = var.instance_type

  cloudflare_zone_id   = var.cloudflare_zone_id
  cloudflare_api_token = var.cloudflare_api_token
  domain               = var.domain

  cert_pem       = "${acme_certificate.cert.certificate_pem}${acme_certificate.cert.issuer_pem}"
  key_pem        = acme_certificate.cert.private_key_pem
  cluster_secret = var.cluster_secret

  providers = {
    aws = aws.multi_region[each.key]
  }
}
