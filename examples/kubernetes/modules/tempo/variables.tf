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

variable "s3_secret_name" {
  type        = string
  description = "Kubernetes Secret with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."

  validation {
    condition     = length(trimspace(var.s3_secret_name)) > 0
    error_message = "s3_secret_name must not be empty."
  }
}

variable "bucket_name" {
  description = "Bucket name for tempo"
}
