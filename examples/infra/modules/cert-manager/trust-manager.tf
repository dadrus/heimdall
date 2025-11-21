resource "helm_release" "trust_manager" {
  depends_on = [kubectl_manifest.root_ca]

  name       = "trust-manager"
  repository = "https://charts.jetstack.io"
  chart      = "trust-manager"
  namespace  = "cert-manager"
  version    = var.trustmanager_version

  replace = true
  upgrade_install = true

  set = [
    {
      name  = "app.trust.namespace"
      value = "cert-manager"
    },
    {
      name  = "secretTargets.enabled"
      value = "true"
    },
    {
      name  = "secretTargets.authorizedSecrets[0]"
      value = "cacerts"
    }
  ]

  wait = true
}

resource "kubectl_manifest" "cacerts_bundle" {
  depends_on = [helm_release.trust_manager]

  yaml_body = file("${path.module}/manifests/cacerts_bundle.yaml")
}
