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

variable "trusted_proxy_cidrs" {
  type        = list(string)
  description = "CIDRs of the actual ExtAuth peers; supplied by the deployment platform."

  validation {
    condition = length(var.trusted_proxy_cidrs) > 0 && alltrue([
      for cidr in var.trusted_proxy_cidrs :
      can(cidrhost(cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], cidr)
    ])
    error_message = "Provide non-empty, valid, non-universal trusted proxy CIDRs."
  }
}

variable "ingress_proxy" {
  type = object({
    namespace = string
    labels    = map(string)
  })
  description = "Selected data-plane Pod selector supplied by ingress."

  validation {
    condition     = length(trimspace(var.ingress_proxy.namespace)) > 0 && length(var.ingress_proxy.labels) > 0
    error_message = "ExtAuth proxy requires a namespace and non-empty Pod labels."
  }
}

variable "scraper_peer" {
  type = object({
    namespace = string
    labels    = map(string)
  })
  nullable    = true
  description = "Optional metrics/profiles scraper Pod selector, supplied by observability."
  validation {
    condition = var.scraper_peer == null ? true : (
      length(trimspace(var.scraper_peer.namespace)) > 0 && length(var.scraper_peer.labels) > 0
    )
    error_message = "The scraper peer must have a namespace and non-empty Pod labels."
  }
}

variable "network_policy" {
  type = object({
    ingress_proxy_cidrs = list(string)
    kubelet_cidrs       = list(string)
    api_server_cidrs    = list(string)
  })
  description = "Platform-managed CIDRs; explicitly null disables NetworkPolicy."

  validation {
    condition = var.network_policy == null ? true : (
      length(var.network_policy.kubelet_cidrs) > 0 &&
      (var.rule_provider != "kubernetes" || length(var.network_policy.api_server_cidrs) > 0) &&
      alltrue([
        for cidr in concat(var.network_policy.ingress_proxy_cidrs, var.network_policy.kubelet_cidrs, var.network_policy.api_server_cidrs) :
        can(cidrhost(cidr, 0)) && !endswith(cidr, "/0")
      ])
    )
    error_message = "NetworkPolicy needs restricted kubelet and API-server CIDRs (for Kubernetes rules); universal CIDRs are forbidden."
  }
}
