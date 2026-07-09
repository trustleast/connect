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
  repo_root = abspath("${path.module}/../../../signaling")

  # SHA1 over every Go source file (sorted for determinism). Changes exactly
  # when the binary changes, so a new build produces a new launch template
  # version and triggers an ASG instance refresh automatically.
  source_hash = sha1(join("", [
    for f in sort(tolist(fileset(local.repo_root, "**/*.go"))) :
    filesha1("${local.repo_root}/${f}")
  ]))

  binary_path   = "connect-arm64"
  binary_s3_uri = "s3://${aws_s3_bucket.config.bucket}/connect-arm64"

  # Known before the ASG resource is created — matches aws_autoscaling_group.this.name.
  asg_name = "${var.name}-${var.stage}"

  user_data = base64encode(templatefile("${path.module}/userdata.sh.tftpl", {
    source_hash   = local.source_hash
    binary_s3_uri = local.binary_s3_uri
    region        = data.aws_region.current.region
    args = join(" ", [
      "-config-s3", "s3://${aws_s3_bucket.config.bucket}/config.json",
    ])
  }))
}

resource "aws_s3_bucket" "config" {
  bucket_prefix = "connect-${var.stage}-${data.aws_region.current.region}-"
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

resource "aws_s3_object" "binary" {
  depends_on  = [terraform_data.build_binary]
  bucket      = aws_s3_bucket.config.bucket
  key         = "connect-arm64"
  source      = local.binary_path
  source_hash = local.source_hash
}

# Instance config. Cert and Key are base64-encoded PEM (matching buildTLS in
# main.go). ASG name is derived from variables so this can be uploaded before
# the ASG resource is created.
resource "aws_s3_object" "config" {
  bucket       = aws_s3_bucket.config.bucket
  key          = "config.json"
  content_type = "application/json"
  content = jsonencode({
    Cert          = base64encode(var.cert_pem)
    Key           = base64encode(var.key_pem)
    ASG           = local.asg_name
    ClusterSecret = var.cluster_secret
    Addr          = "[::]:443"
    GossipAddr    = "[::]:9876"
    Network       = "tcp6"
  })
}

data "aws_iam_policy_document" "instance_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name}-${var.stage}"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.instance_assume_role.json

  inline_policy {
    name = "instance_permissions"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = ["ec2:DescribeInstances"]
          Resource = "*"
        },
        {
          Effect = "Allow"
          Action = ["s3:GetObject"]
          Resource = [
            "${aws_s3_bucket.config.arn}/connect-arm64",
            "${aws_s3_bucket.config.arn}/config.json",
          ]
        },
      ]
    })
  }
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-${var.stage}"
  role = aws_iam_role.instance.name
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ── Security group ────────────────────────────────────────────────────────────

data "cloudflare_ip_ranges" "ip_ranges" {}

resource "aws_security_group" "instance" {
  name   = "${var.name}-${var.stage}"
  vpc_id = var.vpc_id

  # Accept signaling traffic from Cloudflare proxy IPs only.
  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = data.cloudflare_ip_ranges.ip_ranges.ipv6_cidr_blocks
    cidr_blocks      = data.cloudflare_ip_ranges.ip_ranges.ipv4_cidr_blocks
  }

  # Allow intra-cluster TCP 443 and gossip UDP 9876 between instances in the same SG.
  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 9876
    to_port   = 9876
    protocol  = "tcp"
    self      = true
  }

  # Outbound HTTPS for SSM, EC2 APIs, and NTP (all over IPv6).
  egress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port = 9876
    to_port   = 9876
    protocol  = "tcp"
    self      = true
  }
}

# ── Launch template + ASG ─────────────────────────────────────────────────────

resource "aws_launch_template" "this" {
  depends_on = [aws_s3_object.binary, aws_s3_object.config]

  name = "${var.name}-${var.stage}"

  iam_instance_profile {
    name = aws_iam_instance_profile.instance.name
  }

  image_id      = var.ami_id
  instance_type = var.instance_type
  user_data     = local.user_data

  credit_specification {
    cpu_credits = "standard"
  }

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
    instance_metadata_tags = "disabled"
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    description                 = "${var.name}-${var.stage}"
    security_groups             = [aws_security_group.instance.id]
    ipv6_address_count          = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.name}-${var.stage}"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.name}-${var.stage}"
    }
  }

  tag_specifications {
    resource_type = "network-interface"
    tags = {
      Name = "${var.name}-${var.stage}"
    }
  }
}

resource "aws_autoscaling_group" "this" {
  name             = local.asg_name
  min_size         = var.min_size
  max_size         = var.max_size
  desired_capacity = var.desired_capacity

  vpc_zone_identifier = [var.subnet_id]

  health_check_type         = "EC2"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.this.id
    version = tostring(aws_launch_template.this.latest_version)
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 100
      max_healthy_percentage = 150
      instance_warmup        = 10
    }
  }

  tag {
    key                 = "Name"
    value               = local.asg_name
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity, min_size, max_size]
  }
}

resource "aws_autoscaling_policy" "cpu" {
  name                   = "${var.name}-${var.stage}-cpu-tracking"
  autoscaling_group_name = aws_autoscaling_group.this.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 90.0
  }
}
