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

variable "storage_namespace" {
  type    = string
  default = "object-storage"
}

variable "storage_class" {
  type        = string
  default     = "standard"
  description = "kind's default local-storage StorageClass, not the upstream chart's k3s default."
}

variable "rustfs_data_size" {
  type    = string
  default = "10Gi"
}

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

variable "pod_subnet" {
  type        = string
  default     = "10.244.0.0/16"
  description = "The local Kind Pod subnet; the Kind module uses this value by default."
}
