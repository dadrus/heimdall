variable "node_image" {
  type        = string
  default     = "kindest/node:v1.32.0@sha256:c48c62eac5da28cdadcf560d1d8616cfa6783b58f0d94cf63ad1bf49600cb027"
  description = "Node image for kind nodes"
}

variable "image_registry_proxy" {
  type        = string
  default     = "ghcr.io/rpardini/docker-registry-proxy:0.6.5@sha256:b70b2ef2371171a630e3fcbf2217e04057c1dbe114fa46d332ebde67349869e9"
  description = "Image for the mirror/cache registry proxy"
}

variable "metallb_version" {
  type        = string
  default     = "0.15.2"
  description = "Helm chart version for MetalLB"
}
