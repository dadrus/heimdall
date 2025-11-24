variable "ingress_controller" {
  type    = string
}

variable "namespace" {
  type = string
}

variable "global_integration_enabled" {
  type = bool
  description = "How integration with heimdall happens (global or not)"
}

variable "gateway_api_enabled" {
  type = bool
  description = "Whether to perform integration via k8s Gateway API"
}

variable "observability_stack_enabled" {
  type = bool
}