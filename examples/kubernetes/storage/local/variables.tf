variable "buckets" {
  description = "Logical bucket name -> S3 bucket name; empty by default."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name, bucket in var.buckets :
      contains(["rules", "loki", "tempo"], name) &&
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", bucket))
    ])
    error_message = "Only the rules/loki/tempo buckets with valid S3 names are supported."
  }
}

variable "s3_endpoint" {
  type        = string
  description = "RustFS in-cluster S3 URL supplied by cluster/local's output."
}

variable "rustfs_namespace" {
  type        = string
  description = "Namespace where both RustFS and its credential Secret already exist."
}

variable "rustfs_secret_name" {
  type        = string
  description = "Existing secret from the official RustFS Helm chart; never read its values into OpenTofu state."
  default     = "rustfs-secret"
}

variable "s3_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_cli_image" {
  description = "Pinned official AWS CLI image used by the short-lived bucket Jobs."
  type        = string
  default     = "amazon/aws-cli:2.36.31"
}
