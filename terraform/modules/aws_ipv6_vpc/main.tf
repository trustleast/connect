terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.4"
    }
  }
}

data "aws_availability_zones" "available" {
  filter {
    name   = "zone-type"
    values = ["availability-zone"]
  }
}

locals {
  availability_zones = sort(data.aws_availability_zones.available.names)
}

# ── VPC ──────────────────────────────────────────────────────────────────────

resource "aws_vpc" "this" {
  # AWS requires a (dummy) IPv4 CIDR to create a VPC.
  # Use the smallest allowed block; no IPv4 routes are added.
  cidr_block = "10.0.0.0/16"

  # Request an Amazon-provided /56 IPv6 CIDR block
  assign_generated_ipv6_cidr_block = true

  # Disable all IPv4 DNS so nothing accidentally resolves over v4
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name}-vpc"
  }
}

# ── Internet Gateway (IPv6 traffic to/from internet) ─────────────────────────

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name}-igw"
  }
}

# ── Subnets ───────────────────────────────────────────────────────────────────
# Each subnet gets a /64 carved out of the VPC's /56.

resource "aws_subnet" "public" {
  count = length(local.availability_zones)

  vpc_id            = aws_vpc.this.id
  availability_zone = local.availability_zones[count.index]

  # Dummy /24 IPv4 block (required by AWS API); no traffic will use it
  cidr_block = "10.0.${count.index}.0/24"

  # Carve /64s starting at 0x00 for public subnets
  ipv6_cidr_block = cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, count.index)

  # Assign IPv6 addresses to instances automatically
  assign_ipv6_address_on_creation                = true
  enable_resource_name_dns_aaaa_record_on_launch = true

  # Do NOT assign public IPv4 addresses
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name}-public-${local.availability_zones[count.index]}"
    Tier = "public"
  }
}

# ── Route Tables ──────────────────────────────────────────────────────────────

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.this.id
  }

  tags = {
    Name = "${var.name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(local.availability_zones)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}


# ── Default Security Group (deny all — best practice) ────────────────────────

resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name}-default-sg-deny-all"
  }
}
