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

variable "observability_enabled" {
  type    = bool
  default = false
}

variable "s3_endpoint" {
  type    = string
  default = ""
}

variable "s3_ca_config_map_name" {
  type        = string
  default     = ""
  description = "Optional CA bundle ConfigMap for S3 TLS in the target namespaces."
}

variable "blob_rules_namespace" {
  type    = string
  default = ""
}

variable "blob_rules_secret_name" {
  type    = string
  default = ""
}

variable "loki_s3_secret_name" {
  type = string
}

variable "tempo_s3_secret_name" {
  type = string
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

variable "blob_secret_name" {
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
