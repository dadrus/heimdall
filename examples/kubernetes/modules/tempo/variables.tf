variable "namespace" {
  type        = string
  description = "Namespace to install tempo into"
}

variable "prometheus_url" {
  type = string
  description = "Prometheus URL to push metrics to"
}

variable "s3_endpoint" {
  description = "S3 compatible API URL"
}

variable "s3_access_key" {
  description = "S3 Access Key"
  sensitive   = false
}

variable "s3_secret_key" {
  description = "S3 Secret Key"
  sensitive   = true
}

variable "bucket_name" {
  description = "Bucket name for tempo"
}