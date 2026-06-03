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

  repo_root = abspath("${path.module}/../../../signaling")

  # SHA1 over every Go source file (sorted for determinism). Pure computation —
  # no resource dependencies — so user_data can reference it without creating
  # a cycle through the ASG launch template.
  source_hash = sha1(join("", [
    for f in sort(tolist(fileset(local.repo_root, "**/*.go"))) :
    filesha1("${local.repo_root}/${f}")
  ]))

  binary_path = "connect-arm64"

  binary_s3_uri = "s3://${aws_s3_bucket.config.bucket}/connect-arm64"

  user_data = base64encode(templatefile("${path.module}/userdata.sh.tftpl", {
    source_hash   = local.source_hash
    binary_s3_uri = local.binary_s3_uri
    ssh_pub_key   = var.ssh_pub_key
    args = join(" ", [
      "-addr", "[::]:443",
      "-network", "tcp6",
      "-config-s3", "s3://${aws_s3_bucket.config.bucket}/config.json",
      "-zone-name", local.zone_name,
    ])
  }))
}

# Instance config bucket — fetched at boot by each instance via its IAM role.
resource "aws_s3_bucket" "config" {
  bucket_prefix = "connect-${var.stage}-${local.region}-"
}

# Build the Go binary (ARM64 Linux). Reruns only when a .go file changes.
resource "terraform_data" "build_binary" {
  triggers_replace = {
    sha = local.source_hash
  }

  provisioner "local-exec" {
    command = "go build -trimpath -o '${local.binary_path}' ../signaling/cmd/server/"
    environment = {
      CGO_ENABLED = "0"
      GOARCH      = "arm64"
      GOOS        = "linux"
    }
  }
}

# Upload the binary to S3. Instances pull it on each start via ExecStartPre.
# source_hash is the SHA1 of the Go source files — it changes exactly when the
# binary changes (deterministic build), without requiring the file to exist at
# plan time. filemd5/data.local_file both fail at plan time before the first
# build runs, since Terraform evaluates them before local-exec provisioners.
resource "aws_s3_object" "binary" {
  depends_on  = [terraform_data.build_binary]
  bucket      = aws_s3_bucket.config.bucket
  key         = "connect-arm64"
  source      = local.binary_path
  source_hash = local.source_hash
}

module "vpc" {
  source = "../aws_ipv6_vpc"

  name               = "connect"
  availability_zones = var.availability_zones
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

module "asg" {
  source = "../aws_autoscaling_group"

  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnet_ids

  name  = "connect"
  stage = var.stage

  ami_id        = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  user_data     = local.user_data

  extra_permissions = [
    {
      Action = ["s3:GetObject"]
      Resource = [
        "${aws_s3_bucket.config.arn}/connect-arm64",
        "${aws_s3_bucket.config.arn}/config.json",
      ]
      Effect = "Allow"
    },
    {
      Action   = ["ec2:DescribeInstances"]
      Resource = ["*"]
      Effect   = "Allow"
    }
  ]
}

module "cf_lambda" {
  source = "../cloudflare_register_lambda"

  asg_name             = module.asg.asg_name
  cloudflare_zone_id   = var.cloudflare_zone_id
  cloudflare_api_token = var.cloudflare_api_token
  domain               = var.domain
}
