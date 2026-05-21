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

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  region = data.aws_region.current.region

  # zone_name is the registrable domain derived from the full signaling domain.
  # e.g. "connect.example.com" → "example.com"
  zone_name = join(".", slice(split(".", var.domain), 1, length(split(".", var.domain))))
}

# Instance config bucket — fetched at boot by each instance via its IAM role.
# Deterministic name so it can be referenced before the bucket is created (e.g.
# when computing the AMI args) without introducing a circular dependency.
resource "aws_s3_bucket" "config" {
  bucket_prefix = "connect-${var.stage}-${local.region}-"
}

module "vpc" {
  source = "../aws_ipv6_vpc"

  name               = "connect"
  availability_zones = var.availability_zones
}

module "ami" {
  source = "../ami"

  args = [
    "-addr", "[::]:443",
    "-network", "tcp6",
    "-aws-region", local.region,
    "-config-s3", "s3://${aws_s3_bucket.config.bucket}/config.json",
    "-zone-name", local.zone_name,
  ]

  instance_type = var.instance_type
}

module "asg" {
  source = "../aws_autoscaling_group"

  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnet_ids

  name  = "connect"
  stage = var.stage

  ami_id        = module.ami.ami_id
  instance_type = var.instance_type

  extra_permissions = [
    {
      Action   = ["s3:GetObject"]
      Resource = ["${aws_s3_bucket.config.arn}/config.json"]
      Effect   = "Allow"
    },
  ]
}

module "cf_lambda" {
  source = "../cloudflare_register_lambda"

  asg_name             = module.asg.asg_name
  cloudflare_zone_id   = var.cloudflare_zone_id
  cloudflare_api_token = var.cloudflare_api_token
  domain               = var.domain
}
