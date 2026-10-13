variable "ingress_controller" {
  type = string
}

variable "namespace" {
  type = string
}

variable "observability" {
  type = object({
    log_level         = string
    log_format        = string
    metrics_enabled   = bool
    metrics_exporter  = string
    metrics_endpoint  = string
    metrics_protocol  = string
    tracing_enabled   = bool
    tracing_exporter  = string
    tracing_endpoint  = string
    tracing_protocol  = string
    profiling_enabled = bool
  })
  default = {
    log_level         = "info"
    log_format        = "gelf"
    metrics_enabled   = false
    metrics_exporter  = "otlp"
    metrics_endpoint  = ""
    metrics_protocol  = "grpc"
    tracing_enabled   = false
    tracing_exporter  = "otlp"
    tracing_endpoint  = ""
    tracing_protocol  = "grpc"
    profiling_enabled = false
  }
}

# Default to the existing published dev image outside the kind development root.
variable "image_repository" {
  type    = string
  default = "ghcr.io/dadrus/heimdall"
}

variable "image_tag" {
  type    = string
  default = "dev"
}

variable "image_pull_policy" {
  type    = string
  default = "IfNotPresent"
}

variable "rule_provider" {
  type    = string
  default = "kubernetes"
}

variable "http_rules_endpoint" {
  type    = string
  default = ""
}

# Cloud blob inputs are provided by the deployment's S3-oriented contract.
variable "blob_rules_prefix" {
  type    = string
  default = "echo-app/"
}

variable "blob_sync_rustfs_credentials" {
  type    = bool
  default = false
}

variable "blob_s3_secret_name" {
  type    = string
  default = ""
}

variable "blob_use_path_style" {
  type    = bool
  default = false
}

variable "blob_disable_https" {
  type    = bool
  default = false
}

variable "blob_bucket_name" {
  type    = string
  default = ""
}

variable "blob_s3_endpoint" {
  type    = string
  default = ""
}

variable "blob_s3_region" {
  type    = string
  default = "us-east-1"
}

variable "rustfs_namespace" {
  type    = string
  default = "object-storage"
}

variable "rustfs_secret_name" {
  type    = string
  default = "rustfs-secret"
}
