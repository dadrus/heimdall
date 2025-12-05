variable "istio_version" {
  type = string
  description = "Helm chart version for Istio"
  default = "v1.28.0"
}

variable "certmanager_istio_csr_version" {
  type = string
  description = "Helm chart version for Certmanager Istio CSR"
  default = "v0.14.3"
}
