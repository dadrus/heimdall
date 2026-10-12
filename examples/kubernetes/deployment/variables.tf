variable "kubeconfig_path" {
  type        = string
  description = "Path to the kubeconfig of the already running Kubernetes cluster."
}

variable "ingress_controller" {
  type    = string
  default = "contour"
}

variable "global_integration_enabled" {
  type    = bool
  default = true
}

variable "gateway_api_enabled" {
  type    = bool
  default = false
}

variable "ingress_namespace" {
  type    = string
  default = "ingress"
}

variable "heimdall_namespace" {
  type    = string
  default = "heimdall"
}

variable "demo_namespace" {
  type    = string
  default = "demo"
}

variable "cluster_domain" {
  type    = string
  default = "cluster.local"
}

# Published image remains the default for reusable/cloud deployment roots.
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

# AP 5 is optional. Only the local deployment enables RustFS-backed monitoring.
variable "observability_enabled" {
  type    = bool
  default = false
}

variable "rustfs_s3_endpoint" {
  type    = string
  default = ""
}

variable "rustfs_namespace" {
  type    = string
  default = "object-storage"
}

variable "rustfs_secret_name" {
  type    = string
  default = "rustfs-secret"
}

variable "loki_bucket_name" {
  type    = string
  default = "loki"
}

variable "tempo_bucket_name" {
  type    = string
  default = "tempo"
}
