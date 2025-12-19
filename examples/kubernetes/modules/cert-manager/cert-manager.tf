resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  namespace  = "cert-manager"
  version    = var.certmanager_version

  create_namespace = true
  upgrade_install = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait = true
}
