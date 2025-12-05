variable "namespace" {
  type        = string
  description = "Namespace to install emissary into"
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to the Kubeconfig of the cluster (used to monitor creation of the resources)"
}