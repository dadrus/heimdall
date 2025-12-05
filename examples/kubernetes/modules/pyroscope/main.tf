resource "helm_release" "pyroscope" {
  name       = "pyroscope"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "pyroscope"
  version    = var.pyroscope_version
  namespace  = var.namespace

  upgrade_install  = true
  create_namespace = true

  set = [{
    name  = "serviceMonitor.enabled"
    value = "true"
  }]

  wait = true
}