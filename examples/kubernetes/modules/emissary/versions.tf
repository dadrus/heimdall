locals {
  chart_repository = "oci://ghcr.io/emissary-ingress"
  chart_version    = "4.1.0"
  chart_names = {
    crds       = "emissary-crds-chart"
    controller = "emissary-ingress"
  }
}
