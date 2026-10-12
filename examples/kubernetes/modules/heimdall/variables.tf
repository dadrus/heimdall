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
