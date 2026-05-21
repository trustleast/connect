variable "name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "ipv6-only"
}

variable "availability_zones" {
  description = "List of AZs to create subnets in"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}
