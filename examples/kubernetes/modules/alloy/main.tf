resource "kubernetes_config_map_v1" "alloy_config" {
  metadata {
    name      = "alloy-config"
    namespace = var.namespace
  }

  data = {
    "config.alloy" = templatefile("${path.module}/configs/config.alloy", {
      cluster_name         = var.cluster_name
      loki_endpoint        = var.loki_endpoint
      prometheus_endpoint  = var.prometheus_endpoint
      otlp_traces_endpoint = var.otlp_traces_endpoint
      pyroscope_endpoint   = var.pyroscope_endpoint
    })
  }
}

resource "helm_release" "alloy" {
  depends_on = [kubernetes_config_map_v1.alloy_config]
  name       = "alloy"
  repository = local.chart.repository
  chart      = local.chart.name
  version    = local.chart.version
  namespace  = var.namespace

  upgrade_install = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait = true
}
