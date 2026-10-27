locals {
  # Chart 3.14.0 bundles metrics-server v0.9.0 for Kubernetes v1.35.
  metrics_server_chart = {
    repository = "https://kubernetes-sigs.github.io/metrics-server/"
    name       = "metrics-server"
    version    = "3.14.0"
  }
}
