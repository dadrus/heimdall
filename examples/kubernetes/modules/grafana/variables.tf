variable "namespace" {
  type        = string
  description = "Namespace to install grafana into"
}

variable "admin_user" {
  type        = string
  description = "The admin user for grafana"
}

variable "admin_password" {
  type        = string
  description = "The password of the admin user"
}
