resource "helm_release" "trust_manager" {
  name       = "trust-manager"
  repository = "https://charts.jetstack.io"
  chart      = "trust-manager"
  namespace  = var.namespace
  version    = var.trustmanager_version

  replace          = true
  upgrade_install  = true
  create_namespace = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      namespace          = var.namespace
      prometheus_enabled = var.metrics_enabled
    })
  ]

  wait = true
}

resource "kubectl_manifest" "cacerts_bundle" {
  depends_on = [helm_release.trust_manager]

  yaml_body = file("${path.module}/manifests/bundle.yaml")
}
