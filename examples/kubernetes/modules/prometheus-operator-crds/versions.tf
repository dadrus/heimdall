locals {
  chart = {
    repository = "oci://ghcr.io/prometheus-community/charts"
    name       = "prometheus-operator-crds"
    version    = "32.0.1"
  }
}
