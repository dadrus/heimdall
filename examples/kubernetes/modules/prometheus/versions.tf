variable "prometheus_version" {
  type        = string
  default     = "27.45.0"
  description = "Helm chart version for Prometheus"
}

variable "prometheus_operator_crd_version" {
  type        = string
  default     = "24.0.2"
  description = "Helm chart version for Prometheus Operator CRDs"
}
