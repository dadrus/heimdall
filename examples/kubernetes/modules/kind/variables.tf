variable "cluster_name" {
  type        = string
  default     = "local"
  description = "Name of the kind cluster"
}

variable "control_plane_nodes" {
  type    = number
  default = 1
  validation {
    condition     = var.control_plane_nodes >= 1 && var.control_plane_nodes <= 10
    error_message = "control_plane_nodes must be between 1 and 10"
  }
}

variable "worker_nodes" {
  type    = number
  default = 3
  validation {
    condition     = var.worker_nodes >= 1 && var.worker_nodes <= 20
    error_message = "worker_nodes must be between 1 and 20"
  }
}

variable "image_registry_proxy_name" {
  type    = string
  default = "registry-proxy"
}

variable "lb_namespace" {
  type        = string
  default     = "metallb-system"
  description = "Namespace to install the LB into"
}

variable "kubeconfig_path" {
  type        = string
  description = "Local kubeconfig file path, supplied by the cluster/local root."
}

variable "pod_subnet" {
  type        = string
  description = "Pod network for the Kind cluster; declared explicitly for consumers."

  validation {
    condition     = can(cidrhost(var.pod_subnet, 0)) && !endswith(var.pod_subnet, "/0")
    error_message = "pod_subnet must be a restricted, valid CIDR."
  }
}
