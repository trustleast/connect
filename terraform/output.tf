output "config_s3_uris" {
  description = "S3 URIs for instance config, keyed by region. Upload JSON config to each before launching instances."
  value       = { for r, m in module.region : r => m.config_s3_uri }
}
