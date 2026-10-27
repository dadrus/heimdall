variable "namespace" {
  type    = string
  default = "monitoring"
}

variable "s3_ca_config_map_name" {
  type        = string
  default     = ""
  description = "Optional trust-manager CA ConfigMap for S3 TLS."
}

variable "s3_endpoint" {
  type = string
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
