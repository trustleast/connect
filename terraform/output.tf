output "config_s3_uris" {
  description = "S3 URIs for instance config, keyed by region. Upload JSON config to each before launching instances."
  value       = { for r, m in module.region : r => m.config_s3_uri }
}

output "ami_ids" {
  description = "Map of region to AMI ID (built from Go source hash)"
  value       = { for r, m in module.region : r => m.ami_id }
}

# ops.json for each region — ready to write to disk for ad-hoc instance testing.
# Usage: tofu output -json ops_json | jq -r '.["us-east-1"]' > ops.json
output "ops_json" {
  description = "Per-region ops.json for ad-hoc instance creation with `ops instance create`. Includes CloudConfig. Not used in the ASG flow — instances get their config from S3."
  value = {
    for r, m in module.region : r => jsonencode({
      Args = [
        "-addr", "[::]:443",
        "-network", "tcp6",
        "-aws-region", r,
        "-config-s3", m.config_s3_uri,
        "-zone-name", m.zone_name,
        # -node-url intentionally omitted: single ad-hoc instance doesn't need
        # peer routing. The server runs in single-node mode without this flag.
      ]
      NameServers = ["169.254.169.253"]
      RunConfig = {
        Ports = ["443"]
      }
      ManifestPassthrough = {
        exec_wait_for_ip6_secs = "5"
      }
      CloudConfig = {
        Platform        = "aws"
        BucketName      = m.ops_bucket
        VPC             = m.vpc_id
        EnableIPv6      = true
        Zone            = var.regions[r].availability_zones[0]
        Flavor          = var.instance_type
        InstanceProfile = m.instance_profile_name
        SecurityGroup   = m.security_group_id
        Subnet          = m.subnet_ids[0]
      }
    })
  }
}
