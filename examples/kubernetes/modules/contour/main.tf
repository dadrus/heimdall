resource "helm_release" "contour" {
  name       = "contour"
  repository = local.chart.repository
  chart      = local.chart.name
  version    = local.chart.version
  namespace  = var.namespace

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  upgrade_install  = true

  # not waiting as heimdall is not yet installed
  # and contour will fail to start
  wait = false
}
