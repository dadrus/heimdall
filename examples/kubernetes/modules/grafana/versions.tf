locals {
  chart = {
    repository = "oci://ghcr.io/grafana/helm-charts"
    name       = "grafana-operator"
    version    = "5.25.0"
  }
}
