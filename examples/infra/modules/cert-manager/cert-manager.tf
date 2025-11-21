resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  namespace  = "cert-manager"
  version    = var.certmanager_version

  create_namespace = true
  upgrade_install = true

  set = [
    {
      name  = "crds.enabled"
      value = "true"
    },
    {
      name  = "featureGates"
      value = "AdditionalCertificateOutputFormats=true"
    },
    {
      name  = "webhook.featureGates"
      value = "AdditionalCertificateOutputFormats=true"
    },
    {
      name  = "extraArgs[0]"
      value = "--enable-gateway-api"
    }
  ]

  wait = true
}
