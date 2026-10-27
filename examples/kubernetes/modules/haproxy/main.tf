resource "helm_release" "haproxy" {
  name       = "haproxy-controller"
  repository = local.chart.repository
  chart      = local.chart.name
  version    = local.chart.version
  namespace  = var.namespace

  values = [
    templatefile("${path.module}/helm/values.yaml",{
      global_integration_enabled = var.global_integration_enabled
    })
  ]

  upgrade_install = true
  wait            = true
}
