output "config_s3_uris" {
  description = "S3 URIs where instance config.json is stored, keyed by region."
  value       = { for r, m in module.region : r => m.config_s3_uri }
}

output "certificate_not_after" {
  description = "RFC3339 timestamp when the TLS certificate expires. The ACME provider auto-renews on terraform apply when fewer than 30 days remain."
  value       = acme_certificate.cert.certificate_not_after
}
