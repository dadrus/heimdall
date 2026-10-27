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
    log_format        = "text"
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

variable "rule_provider" {
  type    = string
  default = "kubernetes"
}

variable "http_rules_endpoint" {
  type    = string
  default = ""
}

variable "blob_rules_prefix" {
  type = string
}

variable "s3_ca_config_map_name" {
  type        = string
  default     = ""
  description = "Optional CA ConfigMap to trust for the S3 rule source."
}

variable "blob_secret_name" {
  type    = string
  default = ""
}

variable "blob_rules_url" {
  description = "S3 bucket URL"
  type        = string
  default     = ""
}
