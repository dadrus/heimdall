variable "namespace" {
  type        = string
  description = "Namespace to install loki into"
}

variable "s3_endpoint" {
  description = "S3 compatible API URL"
}

variable "bucket_name" {
  description = "Bucket name for loki chunks, ruler and admin"
}