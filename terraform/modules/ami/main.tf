terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.4"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

data "aws_region" "current" {}

locals {
  repo_root = abspath("${path.module}/../../../signaling")

  # SHA1 over every Go source file (sorted for determinism). Used as the
  # trigger for the build and publish steps — if no .go file changed, neither
  # step re-runs even across machines or CI runs.
  source_hash = sha1(join("", [
    for f in sort(tolist(fileset(local.repo_root, "**/*.go"))) :
    filesha1("${local.repo_root}/${f}")
  ]))

  image_name  = "connect-${substr(local.source_hash, 0, 11)}"
  config_name = "ops-${data.aws_region.current.region}.json"
  binary_name = "connect-arm64"
}

# S3 bucket used by the ops CLI to stage disk images during AMI creation.
resource "aws_s3_bucket" "ops_images" {
  bucket_prefix = "connect-ops-images-"
}

# ops.json used by `ops image create`. Written by Terraform so all values are
# visible in the plan and changes to args or config trigger a republish.
resource "local_file" "ops_json" {
  filename        = "${path.module}/${local.config_name}"
  file_permission = "0644"

  content = jsonencode({
    Args        = var.args
    NameServers = ["169.254.169.253"]
    RunConfig = {
      Ports = ["443"]
    }
    ManifestPassthrough = {
      exec_wait_for_ip6_secs = "5"
      so_rcvbuf              = "8192"
      so_sndbuf              = "8192"
    }
    CloudConfig = {
      Platform   = "aws"
      BucketName = aws_s3_bucket.ops_images.bucket
      Zone       = data.aws_region.current.region
      Flavor     = var.instance_type
    }
  })
}

# Step 1: Build the Go binary (ARM64 Linux). Triggered by source file hashes —
# only rebuilds when a .go file changes. The binary is written to the module
# directory so step 2 can reference it by relative path.
resource "terraform_data" "build_binary" {
  triggers_replace = {
    sha = local.source_hash
  }

  provisioner "local-exec" {
    command     = "go build -trimpath -o 'terraform/${path.module}/${local.binary_name}' ./cmd/server/"
    working_dir = local.repo_root
    environment = {
      CGO_ENABLED = "0"
      GOARCH      = "arm64"
      GOOS        = "linux"
    }
  }
}

# Step 2: Publish the AMI only when the binary or ops config has changed.
# Triggered by the same source hash plus the ops.json contents, so changes to
# either the code or the launch args cause a new AMI. Runs after build_binary.
resource "terraform_data" "publish_ami" {
  depends_on = [terraform_data.build_binary, local_file.ops_json, aws_s3_bucket.ops_images]

  triggers_replace = [
    local.source_hash,
    md5(local_file.ops_json.content),
  ]

  provisioner "local-exec" {
    command     = "ops image create '${local.binary_name}' --arch arm64 -c '${local.config_name}' -t aws -i '${local.image_name}' && echo 'Finished!'"
    working_dir = abspath(path.module)
    environment = {
      AWS_DEFAULT_REGION = data.aws_region.current.region
    }
  }
}

# Step 3: Resolve the AMI ID after publish_ami has run.
# depends_on causes Terraform to defer this data source to the apply phase
# whenever publish_ami is being replaced, so ami_id shows "known after apply"
# in the plan for new/changed builds and resolves immediately for unchanged ones.
data "aws_ami" "connect" {
  depends_on  = [terraform_data.publish_ami]
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "tag:Name"
    values = [local.image_name]
  }
}
