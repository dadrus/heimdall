resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  namespace  = var.namespace
  version    = var.certmanager_version

  create_namespace = true
  upgrade_install = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      prometheus_enabled = var.metrics_enabled
    })
  ]

  wait = true
}
