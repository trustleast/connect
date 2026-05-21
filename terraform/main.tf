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
  }
}

# cloudflare_ip_ranges (used by the ASG security group) is unauthenticated.
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# Per-region providers for the regional infrastructure modules.
provider "aws" {
  for_each = var.regions
  alias    = "multi_region"
  region   = each.key
}

module "region" {
  for_each = var.regions

  source = "./modules/region"

  availability_zones = each.value.availability_zones

  stage         = var.stage
  instance_type = var.instance_type

  cloudflare_zone_id   = var.cloudflare_zone_id
  cloudflare_api_token = var.cloudflare_api_token
  domain               = var.domain

  providers = {
    aws = aws.multi_region[each.key]
  }
}
