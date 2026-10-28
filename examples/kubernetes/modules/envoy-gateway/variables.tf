variable "namespace" {
  type        = string
  description = "Namespace to install Envoy Gateway into"
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to the kubeconfig used for the Envoy Gateway CRD apply step."
}
