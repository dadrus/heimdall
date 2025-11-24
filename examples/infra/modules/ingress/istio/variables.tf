variable "namespace" {
  type        = string
  description = "Namespace to install emissary into"
}

variable "gateway_api_enabled" {
  type = bool
  description = "Whether to perform integration via k8s Gateway API"
}