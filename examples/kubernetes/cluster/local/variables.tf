variable "cluster_name" {
  type    = string
  default = "local"
}

variable "control_plane_nodes" {
  type    = number
  default = 1
}

variable "worker_nodes" {
  type    = number
  default = 3
}

variable "kubeconfig_path" {
  type        = string
  default     = null
  nullable    = true
  description = "Absolute or relative output path for the locally generated kubeconfig."
}

locals {
  kubeconfig_path = var.kubeconfig_path == null ? abspath("${path.root}/.kubeconfig") : abspath(pathexpand(var.kubeconfig_path))
}

variable "cluster_domain" {
  type    = string
  default = "cluster.local"
}

variable "rustfs_namespace" {
  type    = string
  default = "object-storage"
}

variable "rustfs_storage_class" {
  type        = string
  default     = "standard"
  description = "kind's default local-storage StorageClass, not the upstream chart's k3s default."
}

variable "rustfs_data_size" {
  type    = string
  default = "10Gi"
}

# Fixed demo credentials are intentionally simple for a non-public kind cluster.
# Override these via TF_VAR_rustfs_* variables for a shared/non-local cluster.
variable "rustfs_access_key" {
  type      = string
  sensitive = true
  default   = "heimdall-local-dev"
}

variable "rustfs_secret_key" {
  type      = string
  sensitive = true
  default   = "heimdall-local-dev-only-change-me"
}

variable "headlamp_namespace" {
  type    = string
  default = "headlamp"
}
