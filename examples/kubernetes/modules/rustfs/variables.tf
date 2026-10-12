variable "namespace" {
  type = string
}

variable "release_name" {
  type = string
}

variable "chart_repository" {
  type = string
}

variable "chart_version" {
  type = string
}

variable "storage_class" {
  type = string
}

variable "data_size" {
  type = string
}

variable "cluster_domain" {
  type = string
}

variable "s3_port" {
  type    = number
  default = 9000
}

variable "console_port" {
  type    = number
  default = 9001
}

variable "access_key" {
  type      = string
  sensitive = true
}

variable "secret_key" {
  type      = string
  sensitive = true
}
