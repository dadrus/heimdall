locals {
  chart = {
    repository = "oci://docker.io/envoyproxy"
    name       = "gateway-helm"
    version    = "v1.9.2"
  }
}
