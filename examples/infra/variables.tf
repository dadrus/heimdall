variable "environment" {
  type    = string
  default = "local"
}

variable "cluster_provider" {
  type    = string
  default = "kind"        # local → kind, aws → eks
}

variable "storage_provider" {
  type    = string
  default = "minio"       # local → minio, aws → s3
}

variable "ingress_controller" {
  type    = string
  default = "contour"
}

variable "observability_stack_enabled" {
  type    = bool
  default = false
}

variable "global_integration_enabled" {
  type = bool
  description = "How integration with heimdall happens (global or not)"
  default = true
}

variable "gateway_api_enabled" {
  type = bool
  description = "Whether to perform integration via k8s Gateway API"
  default = true
}