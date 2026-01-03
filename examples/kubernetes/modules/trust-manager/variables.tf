variable "namespace" {
  type        = string
  description = "Namespace to install trust manager into"
  default     = "cert-manager"
}

variable "metrics_enabled" {
  type = bool
}
