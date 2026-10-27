resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  repository = local.chart_repository
  chart      = local.cert_manager_chart.name
  namespace  = var.namespace
  version    = local.cert_manager_chart.version

  create_namespace = true
  upgrade_install = true

  values = [
    templatefile("${path.module}/helm/cert-manager.yaml", {
      prometheus_enabled = var.metrics_enabled
    })
  ]

  wait = true
}

resource "helm_release" "trust_manager" {
  depends_on = [helm_release.cert_manager]

  name       = "trust-manager"
  repository = local.chart_repository
  chart      = local.trust_manager_chart.name
  namespace  = var.namespace
  version    = local.trust_manager_chart.version

  upgrade_install = true

  values = [
    templatefile("${path.module}/helm/trust-manager.yaml", {
      namespace          = var.namespace
      prometheus_enabled = var.metrics_enabled
    })
  ]

  wait = true
}
