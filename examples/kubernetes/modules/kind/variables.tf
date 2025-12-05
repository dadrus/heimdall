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
    error_message = "worker_nodes must be between 1 and 10"
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
