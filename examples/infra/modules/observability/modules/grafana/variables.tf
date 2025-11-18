variable "namespace" {
  type        = string
  description = "Namespace to install grafana into"
}

variable "admin_user" {
  description = "The admin user for grafana"
}

variable "admin_password" {
  description = "The password of the admin user"
}

variable "loki_url" {
  type        = string
  description = "The endpoint of loki"
}

variable "prometheus_url" {
  type        = string
  description = "The endpoint of prometheus"
}

variable "tempo_url" {
  type        = string
  description = "The endpoint of tempo"
}

variable "pyroscope_url" {
  type        = string
  description = "The endpoint of pyroscope"
}