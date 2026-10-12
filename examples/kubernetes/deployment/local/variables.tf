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

# Pull the published image by default; maintainers may load a local build with the same tag.
variable "heimdall_image_repository" {
  type    = string
  default = "ghcr.io/dadrus/heimdall"
}

variable "heimdall_image_tag" {
  type    = string
  default = "dev"
}

variable "heimdall_image_pull_policy" {
  type    = string
  default = "IfNotPresent"
}

# AP 3 bucket flags remain useful for isolated storage tests; AP 5 will
# also request observability buckets automatically when enabled.
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

variable "rustfs_s3_endpoint" {
  type        = string
  default     = ""
  description = "In-cluster endpoint from cluster/local's rustfs_s3_endpoint output."
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
