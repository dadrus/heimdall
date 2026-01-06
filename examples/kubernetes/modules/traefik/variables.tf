variable "namespace" {
  type        = string
  description = "Namespace to install traefik into"
}

variable "global_integration_enabled" {
  type = bool
  description = "How integration with heimdall happens (global or not)"
}

variable "gateway_api_enabled" {
  type = bool
  description = "Whether to perform integration via k8s Gateway API"
}

variable "observability" {
  type = object({
    log_level         = string
    metrics_enabled   = bool
    metrics_exporter  = string
    metrics_endpoint  = string
    metrics_protocol  = string
    tracing_enabled   = bool
    tracing_endpoint  = string
    tracing_protocol  = string
  })
  default = {
    log_level         = "INFO"
    metrics_enabled   = false
    metrics_exporter  = "otlp"
    metrics_endpoint  = ""
    metrics_protocol  = "grpc"
    tracing_enabled   = false
    tracing_endpoint  = ""
    tracing_protocol  = "grpc"
  }
}