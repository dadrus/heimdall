variable "namespace" {
  type    = string
  default = "monitoring"
}

variable "s3_endpoint" {
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
