variable "node_image" {
  type        = string
  default     = "kindest/node:v1.35.0@sha256:4613778f3cfcd10e615029370f5786704559103cf27bef934597ba562b269661"
  description = "Node image for kind nodes"
}

variable "image_registry_proxy" {
  type        = string
  default     = "ghcr.io/rpardini/docker-registry-proxy:0.6.5@sha256:b70b2ef2371171a630e3fcbf2217e04057c1dbe114fa46d332ebde67349869e9"
  description = "Image for the mirror/cache registry proxy"
}

variable "metallb_version" {
  type        = string
  default     = "0.15.3"
  description = "Helm chart version for MetalLB"
}
