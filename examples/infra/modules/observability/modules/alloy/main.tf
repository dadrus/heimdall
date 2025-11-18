resource "kubernetes_config_map" "alloy_config" {
  metadata {
    name      = "alloy-config"
    namespace = var.namespace
  }

  data = {
    "config.alloy" = templatefile("${path.module}/configs/config.alloy", {
      cluster_name         = var.cluster_name
      loki_endpoint        = var.loki_endpoint
      prometheus_endpoint  = var.prometheus_endpoint
      otel_traces_endpoint = var.otel_traces_endpoint
    })
  }
}

resource "helm_release" "alloy" {
  name       = "alloy"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "alloy"
  version    = var.alloy_version
  namespace  = var.namespace

  upgrade_install = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait = true
}
