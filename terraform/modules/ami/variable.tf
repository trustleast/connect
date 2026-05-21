variable "args" {
  type        = list(string)
  description = "Command-line arguments baked into the AMI's startup command"
  nullable    = false
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"
}