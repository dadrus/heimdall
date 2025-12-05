variable "storage_provider" {
  type    = string
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to the Kubeconfig of the cluster (used to monitor creation of the resources)"
}