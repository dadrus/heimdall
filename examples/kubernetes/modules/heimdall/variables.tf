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
