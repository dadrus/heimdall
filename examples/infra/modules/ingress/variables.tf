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

variable "observability_stack_enabled" {
  type = bool
  default = false
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to the Kubeconfig of the cluster (used to monitor creation of the resources)"
}