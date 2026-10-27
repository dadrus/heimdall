resource "helm_release" "prometheus_operator_crds" {
  name       = "prometheus-crds"
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