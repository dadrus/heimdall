variable "kubeconfig_path" {
  type        = string
  description = "Path to the kubeconfig of the already running Kubernetes cluster."
}

variable "ingress_controller" {
  type    = string
  default = "contour"
}

variable "global_integration_enabled" {
  type    = bool
  default = true
}

variable "gateway_api_enabled" {
  type    = bool
  default = false
}

variable "ingress_namespace" {
  type    = string
  default = "ingress"
}

variable "heimdall_namespace" {
  type    = string
  default = "heimdall"
}

variable "demo_namespace" {
  type    = string
  default = "demo"
}

variable "cluster_domain" {
  type    = string
  default = "cluster.local"
}

variable "observability_enabled" {
  type    = bool
  default = false
}

variable "rustfs_s3_endpoint" {
  type    = string
  default = ""
}

variable "rustfs_namespace" {
  type    = string
  default = "object-storage"
}

variable "rustfs_secret_name" {
  type    = string
  default = "rustfs-secret"
}

variable "loki_bucket_name" {
  type    = string
  default = "loki"
}

variable "tempo_bucket_name" {
  type    = string
  default = "tempo"
}

variable "rule_provider" {
  type    = string
  default = "kubernetes"

  validation {
    condition     = contains(["kubernetes", "http_endpoint", "cloud_blob"], var.rule_provider)
    error_message = "rule_provider must be 'kubernetes', 'http_endpoint' or 'cloud_blob'."
  }
}

variable "blob_s3_secret_name" {
  type    = string
  default = ""
}

variable "blob_rules_url" {
  description = "Complete Go CDK S3 bucket URL, supplied by the platform root."
  type        = string
  default     = ""
}

variable "rules_bucket_name" {
  type    = string
  default = "rules"
}

variable "s3_region" {
  type    = string
  default = "us-east-1"
}

variable "rules_server_namespace" {
  type    = string
  default = "rules-server"
}
