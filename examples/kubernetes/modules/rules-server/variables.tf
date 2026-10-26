variable "namespace" {
  type    = string
  default = "rules-server"
}

variable "cluster_domain" {
  type    = string
  default = "cluster.local"
}

variable "image" {
  type    = string
  default = "nginx:1.31.6-alpine"
}
