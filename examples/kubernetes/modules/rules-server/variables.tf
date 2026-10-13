variable "namespace" {
  type    = string
  default = "rules-server"
}

variable "cluster_domain" {
  type    = string
  default = "cluster.local"
}

variable "rules_configmap_name" {
  type    = string
  default = "echo-app-rules"
}

variable "image" {
  type    = string
  default = "nginx:1.31.6-alpine"
}
