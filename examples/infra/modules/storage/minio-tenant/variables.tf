variable "namespace" {
  type        = string
  description = "Namespace to install the minio tenant into"
}

variable "tenant_name" {
  type        = string
  default     = "minio"
  description = "The name of the tenant to create"
}
