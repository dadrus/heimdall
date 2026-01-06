variable "ingress_controller" {
  type    = string
  default = "emissary"

  validation {
    condition     = contains(["contour", "emissary", "envoy-gateway", "haproxy", "istio", "nginx", "traefik"], var.ingress_controller)
    error_message = "unsupported ingress controller type"
  }
}

variable "namespace" {
  type = string
}

variable "global_integration_enabled" {
  type = bool
  description = "How integration with heimdall happens (global or not)"
}

variable "gateway_api_enabled" {
  type = bool
  description = "Whether to perform integration via k8s Gateway API"
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to the Kubeconfig of the cluster (used to monitor creation of the resources)"
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