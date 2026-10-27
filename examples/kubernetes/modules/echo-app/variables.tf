variable "ingress_controller" {
  type    = string
}

variable "namespace" {
  type = string
}

variable "global_integration_enabled" {
  type = bool
  description = "How integration with heimdall happens (global or not)"
}

variable "gateway_api_enabled" {
  type = bool
  description = "Whether to perform integration via k8s Gateway API"
}

variable "cluster_domain" {
  type = string
}

variable "rule_provider" {
  type    = string
  default = "kubernetes"
}

variable "http_rules_namespace" {
  type    = string
  default = ""
}

variable "blob_rules_prefix" {
  type    = string
  default = "echo-app/"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_/-]+/$", var.blob_rules_prefix)) && !strcontains(var.blob_rules_prefix, "..")
    error_message = "blob_rules_prefix must be a nonempty S3 key prefix ending with '/'."
  }
}

variable "blob_rules_bucket_name" {
  type    = string
  default = ""
}

variable "blob_rules_s3_ca_config_map_name" {
  type        = string
  default     = ""
  description = "Optional ConfigMap containing ca.crt for the S3 upload Job."
}

variable "blob_rules_s3_endpoint" {
  type    = string
  default = ""
}

variable "blob_rules_s3_region" {
  type    = string
  default = ""
}

variable "blob_rules_namespace" {
  type    = string
  default = ""
}

variable "blob_rules_secret_name" {
  type    = string
  default = ""
}
