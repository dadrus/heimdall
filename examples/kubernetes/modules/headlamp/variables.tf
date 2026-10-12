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

variable "service_port" {
  type    = number
  default = 80
}

variable "local_admin_auto_login" {
  description = "UNSAFE: use Headlamp's cluster-admin pod identity without login. Only enable for a disposable, localhost-only kind cluster."
  type        = bool
  default     = false
}
