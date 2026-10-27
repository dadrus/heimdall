locals {
  chart_repository = "oci://quay.io/jetstack/charts"

  cert_manager_chart = {
    name    = "cert-manager"
    version = "v1.21.2"
  }
  trust_manager_chart = {
    name    = "trust-manager"
    version = "v0.25.0"
  }
}
