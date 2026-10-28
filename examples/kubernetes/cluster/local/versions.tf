locals {
  metrics_server_chart = {
    repository = "https://kubernetes-sigs.github.io/metrics-server/"
    name       = "metrics-server"
    version    = "3.14.0"
  }
}
