resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  repository = "oci://quay.io/jetstack/charts"
  chart      = "cert-manager"
  namespace  = var.namespace
  version    = var.certmanager_version

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
  repository = "oci://quay.io/jetstack/charts"
  chart      = "trust-manager"
  namespace  = var.namespace
  version    = var.trustmanager_version

  upgrade_install = true

  values = [
    templatefile("${path.module}/helm/trust-manager.yaml", {
      namespace          = var.namespace
      prometheus_enabled = var.metrics_enabled
    })
  ]

  wait = true
}
