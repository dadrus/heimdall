variable "namespace" {
  type        = string
  description = "Namespace to install cert manager into"
  default     = "cert-manager"
}

variable "metrics_enabled" {
  type = bool
}
