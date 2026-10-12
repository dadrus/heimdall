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
