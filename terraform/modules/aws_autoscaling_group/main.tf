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
      Statement = concat(
        [
          {
            Action   = ["ec2:DescribeInstances"]
            Effect   = "Allow"
            Resource = "*"
          },
        ],
        var.extra_permissions
      )
    })
  }
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-${var.stage}"
  role = aws_iam_role.instance.name
}

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

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port        = 8080
    to_port          = 8080
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  # Outbound HTTPS for SSM, EC2 APIs, and NTP (all over IPv6).
  egress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_launch_template" "this" {
  name = "${var.name}-${var.stage}"

  iam_instance_profile {
    name = aws_iam_instance_profile.instance.name
  }

  image_id      = var.ami_id
  instance_type = var.instance_type

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
  name             = "${var.name}-${var.stage}"
  min_size         = var.min_size
  max_size         = var.max_size
  desired_capacity = var.desired_capacity

  vpc_zone_identifier = var.subnets

  health_check_type         = "EC2"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.this.id
    version = tostring(aws_launch_template.this.latest_version)
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 0
      instance_warmup        = 60
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name}-${var.stage}"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
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
