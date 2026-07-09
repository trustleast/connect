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

locals {
  # zone_name is the registrable domain derived from the full signaling domain.
  # e.g. "connect.example.com" → "example.com"
  zone_name = join(".", slice(split(".", var.domain), 1, length(split(".", var.domain))))
}

# Latest Amazon Linux 2023 ARM64 AMI. Instances only pick up a new AMI on the
# next instance refresh — changing this alone does not restart running instances.
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-arm64"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

module "vpc" {
  source = "../aws_ipv6_vpc"

  name = "connect"
}

module "asg" {
  source = "../aws_autoscaling_group"

  vpc_id    = module.vpc.vpc_id
  subnet_id = module.vpc.public_subnet_ids_by_az[var.asg_availability_zone]

  name  = "connect"
  stage = var.stage

  ami_id        = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  zone_name     = local.zone_name

  cert_pem       = var.cert_pem
  key_pem        = var.key_pem
  cluster_secret = var.cluster_secret
}

module "cf_lambda" {
  source = "../cloudflare_register_lambda"

  asg_name             = module.asg.asg_name
  cloudflare_zone_id   = var.cloudflare_zone_id
  cloudflare_api_token = var.cloudflare_api_token
  domain               = var.domain
}
