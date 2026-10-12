variable "namespace" {
  type    = string
  default = "monitoring"
}

variable "s3_endpoint" {
  type = string
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
