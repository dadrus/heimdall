variable "ingress_controller" {
  type    = string
  default = "contour"

  validation {
    condition     = contains(["contour", "emissary", "envoy-gateway", "haproxy", "istio", "nginx", "traefik"], var.ingress_controller)
    error_message = "unsupported ingress controller type"
  }
}

variable "observability_stack_enabled" {
  type = bool
  default = false
}