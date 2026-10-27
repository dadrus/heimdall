locals {
  node_image           = "kindest/node:v1.35.0@sha256:4613778f3cfcd10e615029370f5786704559103cf27bef934597ba562b269661"
  image_registry_proxy = "ghcr.io/rpardini/docker-registry-proxy:0.7.0@sha256:413c340ea5f827345434e0f0656eff97f266ae7f9cde089f5dc2d6af42ea3f77"

  metallb_chart = {
    repository = "https://metallb.github.io/metallb"
    name       = "metallb"
    version    = "0.16.1"
  }
}
