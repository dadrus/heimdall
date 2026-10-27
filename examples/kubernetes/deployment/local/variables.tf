variable "kubeconfig_path" {
  type        = string
  description = "Pass cluster/local's kubeconfig_path output from just."

  validation {
    condition     = length(trimspace(var.kubeconfig_path)) > 0
    error_message = "kubeconfig_path must not be empty."
  }
}

variable "ingress_controller" {
  type    = string
  default = "contour"

  validation {
    condition     = contains(["contour", "emissary", "envoy-gateway", "haproxy", "istio", "nginx", "traefik"], var.ingress_controller)
    error_message = "Unsupported ingress controller."
  }
}

variable "global_integration_enabled" {
  type    = bool
  default = true
}

variable "gateway_api_enabled" {
  type    = bool
  default = false
}

variable "cluster_domain" {
  type    = string
  default = "cluster.local"
}

variable "observability_enabled" {
  type    = bool
  default = false
}

variable "rules_bucket_enabled" {
  type    = bool
  default = false
}

variable "observability_buckets_enabled" {
  type    = bool
  default = false
}

variable "rustfs_bucket_names" {
  type = object({
    rules = string
    loki  = string
    tempo = string
  })
  default = { rules = "rules", loki = "loki", tempo = "tempo" }
}

variable "blob_credentials_secret_name" {
  type    = string
  default = "heimdall-s3-credentials"

  validation {
    condition     = length(trimspace(var.blob_credentials_secret_name)) > 0
    error_message = "blob_credentials_secret_name must not be empty."
  }
}

variable "rustfs_s3_region" {
  type    = string
  default = "us-east-1"
}

variable "s3_endpoint" {
  type        = string
  default     = ""
  description = "In-cluster endpoint from cluster/local's s3_endpoint output."
}

variable "rustfs_namespace" {
  type    = string
  default = "object-storage"
}

variable "rustfs_secret_name" {
  type        = string
  description = "Existing secret from the RustFS chart, named <release>-secret by default."
  default     = "rustfs-secret"
}

variable "rule_provider" {
  type    = string
  default = "kubernetes"

  validation {
    condition     = contains(["kubernetes", "http_endpoint", "cloud_blob"], var.rule_provider)
    error_message = "rule_provider must be 'kubernetes', 'http_endpoint' or 'cloud_blob'."
  }
}
