locals {
  node_image           = "kindest/node:v1.32.0@sha256:c48c62eac5da28cdadcf560d1d8616cfa6783b58f0d94cf63ad1bf49600cb027"
  image_registry_proxy = "ghcr.io/rpardini/docker-registry-proxy:0.8.0@sha256:fe958e7a4b7ef01a646d903347a0522b6a9065b44b451c5ef87eb4b6b0f3d770"

  metallb_chart = {
    repository = "https://metallb.github.io/metallb"
    name       = "metallb"
    version    = "0.16.1"
  }
}
