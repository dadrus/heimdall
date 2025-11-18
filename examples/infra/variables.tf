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