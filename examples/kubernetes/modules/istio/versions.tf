variable "istio_version" {
  type = string
  description = "Helm chart version for Istio"
  default = "1.31.1"
}

variable "certmanager_istio_csr_version" {
  type = string
  description = "Helm chart version for Certmanager Istio CSR"
  default = "v0.17.0"
}
